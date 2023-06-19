package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func TestPrincipals(t *testing.T) {
	app, _, core := InitTestingVault(t)
	adminJwt, _ := core.generateJWT(_vault.Principal{
		AccessKey:    "test",
		AccessSecret: "test",
		Policies:     []string{"admin-read", "admin-write"},
	})

	t.Run("can create a principal", func(t *testing.T) {
		principalJson := strings.NewReader(
			`{
					"name": "newprincipal",
					"description": "A new principal",
					"policies": ["test-read", "test-write"]
			}`,
		)
		req := httptest.NewRequest(http.MethodPost, "/principals", principalJson)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, _ := app.Test(req, -1)
		createdPrincipal := NewPrincipal{}
		body, _ := io.ReadAll(res.Body)
		err := json.Unmarshal(body, &createdPrincipal)

		if err != nil {
			t.Error("Error creating principal", err)
		}

		// Assertions
		assert.Equal(t, http.StatusCreated, res.StatusCode)
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/principals/%s", createdPrincipal.AccessKey), nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err = app.Test(req, -1)
		if err != nil {
			t.Error("Error getting prinipal", err)
		}
		var returnedPrincipal PrincipalModel
		body, _ = io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedPrincipal)
		if err != nil {
			t.Error("Error parsing returned collection", err)
		}
		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "newprincipal", returnedPrincipal.Name)
	})

	t.Run("can't create principals without assigned roles", func(t *testing.T) {
		principalJson := strings.NewReader(
			`{
					"name": "newprincipal",
					"description": "A new principal",
					"policies": ["test-read", "test-write"]
			}`,
		)
		req := httptest.NewRequest(http.MethodPost, "/principals", principalJson)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, err := app.Test(req, -1)

		if err != nil {
			t.Error("Error creating principal", err)
		}

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})
}
