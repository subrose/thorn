package main

import (
	"fmt"
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
		return err
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
	return c.Status(http.StatusOK).JSON(collection)
}

func (core *Core) GetCollections(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collections, err := core.vault.GetCollections(c.Context(), principal)
	if err != nil {
		return err
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
		return err
	}
	return c.Status(http.StatusCreated).SendString("Collection created")
}

func (core *Core) DeleteCollection(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")

	err := core.vault.DeleteCollection(c.Context(), principal, collectionName)
	if err != nil {
		return err
	}

	return c.Status(http.StatusOK).SendString("Collection deleted")
}

func (core *Core) CreateRecords(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	records := new([]_vault.Record)
	if err := c.BodyParser(records); err != nil {
		core.logger.Error(fmt.Sprintf("An error occurred parsing records: %s", records))
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "malformed record body",
		}
	}

	recordIds, err := core.vault.CreateRecords(c.Context(), principal, collectionName, *records)
	if err != nil {
		core.logger.Error("An error occurred creating a record")
		return err
	}
	return c.Status(http.StatusCreated).JSON(recordIds)
}

func (core *Core) UpdateRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	recordId := c.Params("id")
	record := new(_vault.Record)
	if err := c.BodyParser(record); err != nil {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "malformed record body",
		}
	}

	err := core.vault.UpdateRecord(c.Context(), principal, collectionName, recordId, *record)
	if err != nil {
		core.logger.Error("An error occurred updating a record")
		return err
	}
	return c.Status(http.StatusOK).SendString("Record updated")
}

func (core *Core) DeleteRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	recordId := c.Params("id")

	err := core.vault.DeleteRecord(c.Context(), principal, collectionName, recordId)
	if err != nil {
		core.logger.Error("An error occurred deleting a record")
		return err
	}
	return c.Status(http.StatusOK).SendString("Record deleted")
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
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "formats query is required",
		}
	}

	returnFormats := parseFieldsQuery(fieldsQuery)

	if collectionName == "" {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "collection name is required",
		}
	}

	if recordId == "" {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "record id is required",
		}
	}

	recordIds := []string{recordId}
	records, err := core.vault.GetRecords(c.Context(), principal, collectionName, recordIds, returnFormats)
	if err != nil {
		return err
	}

	// Replace loop with append function
	accessedFields := []string{}
	accessedFields = append(accessedFields, strings.Split(fieldsQuery, ",")...)

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
