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
	Name   string                          `json:"name" validate:"required,collectionName"`
	Fields map[string]CollectionFieldModel `json:"fields" validate:"required"`
}

func (core *Core) GetCollection(c *fiber.Ctx) error {
	collectionName := c.Params("name")
	principal := GetSessionPrincipal(c)
	dbCollection, err := core.vault.GetCollection(c.Context(), principal, collectionName)
	if err != nil {
		switch err {
		case _vault.ErrNotFound:
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
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		}
		switch err {
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
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		}
		switch err {
		case _vault.ErrConflict:
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
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		}
		switch err {
		case _vault.ErrNotFound:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Collection not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusCreated).JSON(recordIds)
}

func parseFieldsQuery(fieldsQuery string) map[string]string {
	fieldFormats := map[string]string{}
	if fieldsQuery == "" {
		return nil
	}
	for _, field := range strings.Split(fieldsQuery, ",") {
		splitFieldFormat := strings.Split(field, ".")
		if len(splitFieldFormat) != 2 {
			continue
		}
		fieldFormats[splitFieldFormat[0]] = splitFieldFormat[1]
	}

	return fieldFormats
}

func (core *Core) GetRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	recordId := c.Params("id")
	// /records/users/<id>?fields=fname.plain,lname.masked
	if c.Query("fields") == "" {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Fields query is required", nil})
	}
	fieldsQuery := parseFieldsQuery(c.Query("fields"))
	// TODO: validate fields query and return error if invalid
	// TODO: add default fields query to get all fields

	if collectionName == "" {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Collection name is required", nil})
	}
	if recordId == "" {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Record id is required", nil})
	}

	recordIds := []string{recordId}
	records, err := core.vault.GetRecords(c.Context(), principal, collectionName, recordIds, fieldsQuery)
	if err != nil {
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		}
		switch err {
		case _vault.ErrNotFound:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Record not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}

	core.logger.WriteAuditLog(
		c.Method(),
		c.Path(),
		c.IP(),
		c.Get("User-Agent"),
		c.Get("X-Trace-Id"),
		c.Response().StatusCode(),
		principal.AccessKey,
		principal.Description,
		principal.Policies,
		recordIds,
		recordIds,
		// TODO: Add fields
	)
	return c.Status(http.StatusOK).JSON(records)
}
