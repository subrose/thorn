package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func (core *Core) GetCollection(c *fiber.Ctx) error {
	collectionName := c.Params("name")
	principal := GetSessionPrincipal(c)
	collection, err := core.vault.GetCollection(c.Context(), principal, collectionName)

	if err != nil {
		return err
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
	collection := &_vault.Collection{}
	if err := core.ParseJsonBody(c.Body(), collection); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&ErrorResponse{
			Message: "Invalid body",
			Errors:  []string{err.Error()},
		})
	}

	err := core.vault.CreateCollection(c.Context(), principal, collection)
	if err != nil {
		return err
	}
	return c.Status(http.StatusCreated).JSON(collection)
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

func (core *Core) CreateRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	if collectionName == "" {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "collection name is required",
		}
	}

	record := new(_vault.Record)
	if err := core.ParseJsonBody(c.Body(), record); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", nil})
	}

	recordId, err := core.vault.CreateRecord(c.Context(), principal, collectionName, *record)
	if err != nil {
		core.logger.Error(fmt.Sprintf("An error occurred creating a record: %s", err))
		return err
	}
	return c.Status(http.StatusCreated).JSON(recordId)
}

func (core *Core) UpdateRecord(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")
	recordId := c.Params("id")
	record := new(_vault.Record)
	if err := core.ParseJsonBody(c.Body(), &record); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", nil})
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
		if len(splitFieldFormat) < 2 {
			continue
		}
		fieldFormats[splitFieldFormat[0]] = splitFieldFormat[1]
	}

	return fieldFormats
}

func (core *Core) GetRecords(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")

	if collectionName == "" {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "collection name is required",
		}
	}

	records, err := core.vault.GetRecords(c.Context(), principal, collectionName)
	if err != nil {
		return err
	}

	return c.Status(http.StatusOK).JSON(records)

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
	if len(returnFormats) == 0 {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "formats query is required",
		}
	}

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

	record, err := core.vault.GetRecord(c.Context(), principal, collectionName, recordId, returnFormats)
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
		[]string{recordId},
		[]string{recordId},
		accessedFields,
	)
	return c.Status(http.StatusOK).JSON(record)
}

func (core *Core) SearchRecords(c *fiber.Ctx) error {
	principal := GetSessionPrincipal(c)
	collectionName := c.Params("name")

	if collectionName == "" {
		return &fiber.Error{
			Code:    http.StatusBadRequest,
			Message: "collection name is required",
		}
	}

	filters := new(map[string]string)
	if err := core.ParseJsonBody(c.Body(), &filters); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", nil})
	}

	records, err := core.vault.SearchRecords(c.Context(), principal, collectionName, *filters)
	if err != nil {
		return err
	}

	return c.Status(http.StatusOK).JSON(records)
}
