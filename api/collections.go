package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type CollectionFieldModel struct {
	Type      string `json:"type" validate:"required"`
	IsIndexed bool   `json:"indexed" validate:"required, boolean"`
}

type CollectionModel struct {
	Name   string                          `json:"name" validate:"required,vaultResourceNames"`
	Fields map[string]CollectionFieldModel `json:"fields" validate:"required"`
}

func (core *Core) GetCollection(c *fiber.Ctx) error {
	collectionName := c.Params("name")
	principal := GetSessionPrincipal(c)
	dbCollection, err := core.vault.GetCollection(c.Context(), principal, collectionName)
	if err != nil {
		switch err.(type) {
		case *_vault.NotFoundError:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Collection not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}

	collection := CollectionModel{
		Name:   dbCollection.Name,
		Fields: make(map[string]CollectionFieldModel, len(dbCollection.Fields)),
	}
	for _, field := range dbCollection.Fields {
		collection.Fields[field.Name] = CollectionFieldModel{
			Type:      field.Type,
			IsIndexed: field.IsIndexed,
		}
	}
	return c.JSON(collection)
}

func (core *Core) GetCollections(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collections, err := core.vault.GetCollections(c.Context(), principal)
	if err != nil {
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusOK).JSON(collections)
}

func (core *Core) CreateCollection(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	inputCollection := new(CollectionModel)
	if err := c.BodyParser(inputCollection); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	if err := Validate(inputCollection); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	newCollection := _vault.Collection{
		Name:   inputCollection.Name,
		Fields: make(map[string]_vault.Field, len(inputCollection.Fields)),
	}
	for fieldName, field := range inputCollection.Fields {
		newCollection.Fields[fieldName] = _vault.Field{
			Name:      fieldName,
			Type:      field.Type,
			IsIndexed: field.IsIndexed,
		}
	}

	_, err := core.vault.CreateCollection(c.Context(), principal, newCollection)
	if err != nil {
		var valueErr *_vault.ValueError
		if errors.As(err, &valueErr) {
			return c.Status(http.StatusBadRequest).JSON(valueErr.Unwrap().Error())
		}
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.ConflictError:
			return c.Status(http.StatusConflict).JSON(ErrorResponse{http.StatusConflict, "Collection already exists", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusCreated).SendString("Collection created")
}

func (core *Core) CreateRecords(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	records := new([]_vault.Record)
	if err := c.BodyParser(records); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	recordIds, err := core.vault.CreateRecords(c.Context(), principal, collectionName, *records)
	if err != nil {
		core.logger.Error("An error occurred creating a record", err)
		var valueErr *_vault.ValueError
		if errors.As(err, &valueErr) {
			return c.Status(http.StatusBadRequest).JSON(valueErr.Unwrap().Error())
		}
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.NotFoundError:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Collection not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusCreated).JSON(recordIds)
}

func parseFieldsQuery(fieldsQuery string) map[string]string {
	fieldFormats := map[string]string{}
	for _, field := range strings.Split(fieldsQuery, ",") {
		splitFieldFormat := strings.Split(field, ".")
		fieldFormats[splitFieldFormat[0]] = splitFieldFormat[1]
	}

	return fieldFormats
}

func (core *Core) GetRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	recordId := c.Params("id")
	// /records/users/<id>?formats=fname.plain,lname.masked
	fieldsQuery := c.Query("formats")

	if fieldsQuery == "" {
		return core.SendErrorResponse(c, http.StatusBadRequest, "fields query is required", nil)
	}

	returnFormats := parseFieldsQuery(fieldsQuery)

	if collectionName == "" {
		return core.SendErrorResponse(c, http.StatusBadRequest, "collection name is required", nil)
	}
	if recordId == "" {
		return core.SendErrorResponse(c, http.StatusBadRequest, "record_id is required", nil)
	}

	recordIds := []string{recordId}
	records, err := core.vault.GetRecords(c.Context(), principal, collectionName, recordIds, returnFormats)
	if err != nil {
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.NotFoundError:
			return core.SendErrorResponse(c, http.StatusNotFound, err.Error(), err)
		case *_vault.ValueError:
			return core.SendErrorResponse(c, http.StatusBadRequest, err.Error(), err)
		default:
			return core.SendErrorResponse(c, http.StatusInternalServerError, "Something went wrong", err)
		}
	}

	// Loop through the record and figure out which fields were accessed
	accessedFields := []string{}
	for _, record := range records {
		for fieldName := range record {
			accessedFields = append(accessedFields, fieldName)
		}
	}

	core.logger.WriteAuditLog(
		c.Method(),
		c.Path(),
		c.IP(),
		c.Get("User-Agent"),
		c.Get("X-Trace-Id"),
		c.Response().StatusCode(),
		principal.Username,
		principal.Description,
		principal.Policies,
		recordIds,
		recordIds,
		accessedFields,
	)
	return c.Status(http.StatusOK).JSON(records)
}
