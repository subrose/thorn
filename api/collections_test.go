package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func TestCollections(t *testing.T) {
	app, _, core := InitTestingVault(t)
	adminJwt, _ := core.generateJWT(_vault.Principal{
		AccessKey:    "test",
		AccessSecret: "test",
		Policies:     []string{"admin-read", "admin-write"},
	})

	t.Run("can create a collection", func(t *testing.T) {
		collectionJSON := strings.NewReader(
			`{
					"name": "customers",
					"fields": {
						"name": {"type": "name", "indexed": true},
						"phone_number": {"type": "phoneNumber", "indexed": true},
						"dob": {"type": "date","indexed": false}
					}
			}`,
		)
		req := httptest.NewRequest(http.MethodPost, "/collections", collectionJSON)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err := app.Test(req, -1)

		if err != nil {
			t.Error("Error creating collection", err)
		}

		// Assertions
		assert.Equal(t, http.StatusCreated, res.StatusCode)
	})

	t.Run("can get a collection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/collections/customers", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err := app.Test(req, -1)
		if err != nil {
			t.Error("Error getting collection", err)
		}
		var returnedCollection CollectionModel
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedCollection)
		if err != nil {
			t.Error("Error parsing returned collection", err)
		}
		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "customers", returnedCollection.Name)
	})

	t.Run("can get all collections", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/collections", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err := app.Test(req, -1)
		if err != nil {
			t.Error("Error getting collection", err)
		}
		var returnedCollections []string
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedCollections)
		if err != nil {
			t.Error("Error parsing returned collection", err)
		}
		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 1, len(returnedCollections))
	})

	t.Run("can create and get a record", func(t *testing.T) {
		recordJSON := strings.NewReader(
			`[
				{"name": "123345","phone_number": "12345","dob": "12345"}
			]`,
		)
		req := httptest.NewRequest(http.MethodPost, "/collections/customers/records", recordJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, err := app.Test(req, -1)
		if err != nil {
			t.Error("Error creating record", err)
		}
		// Assertions
		parsedRecordIds := []string{}
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &parsedRecordIds)
		if err != nil {
			t.Error("Error parsing returned records", err)
		}
		assert.Equal(t, http.StatusCreated, res.StatusCode)

		// Test getting the record
		req = httptest.NewRequest(http.MethodGet, "/collections/customers/records/"+parsedRecordIds[0], nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err = app.Test(req, -1)
		if err != nil {
			t.Error("Error getting record", err)
		}
		var returnedRecord map[string]_vault.Record // A map of the record id to the record
		body, _ = io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedRecord)
		if err != nil {
			t.Error("Error parsing returned record", err)
		}
		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)

	})

	t.Run("cant create a bad record", func(t *testing.T) {
		recordJSON := strings.NewReader(
			`[
				{"xxx": "123345","phone_number": "12345","dob": "12345"}
			]`,
		)
		req := httptest.NewRequest(http.MethodPost, "/collections/customers/records", recordJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, _ := app.Test(req, -1)
		// Assertions
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("unauthenticated user cant crud a collection", func(t *testing.T) { // TODO: Can probably make this a table test?
		// Create
		collectionJSON := strings.NewReader(
			`{
					"name": "customers2",
					"fields": {
						"name": {"type": "name", "indexed": true},
						"phone_number": {"type": "phoneNumber", "indexed": true},
						"dob": {"type": "date","indexed": false}
					}
			}`,
		)
		req := httptest.NewRequest(http.MethodPost, "/collections", collectionJSON)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, _ := app.Test(req, -1)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Get
		req = httptest.NewRequest(http.MethodGet, "/collections/customers2", nil)
		res, _ = app.Test(req, -1)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Get all
		req = httptest.NewRequest(http.MethodGet, "/collections", nil)
		res, _ = app.Test(req, -1)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Delete
		req = httptest.NewRequest(http.MethodDelete, "/collections/customers2", nil)
		res, _ = app.Test(req, -1)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})
}
