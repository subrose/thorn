package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	_vault "github.com/subrose/vault"
)

func TestPrincipals(t *testing.T) {
	app, _, core := InitTestingVault(t)
	adminJwt, _ := core.generateJWT(_vault.Principal{
		Username:    "admin",
		Password:    "admin",
		Description: "admin principal",
		Policies:    []string{"root"},
	})

	principalToCreate := PrincipalModel{
		Username:    "username",
		Password:    "password",
		Description: "test description",
		Policies:    []string{"test-read", "test-write"},
	}

	t.Run("can create a principal", func(t *testing.T) {
		jsonData, err := json.Marshal(principalToCreate)
		if err != nil {
			t.Fatalf("Failed to marshal the principal: %v", err)
		}

		principalJson := bytes.NewReader(jsonData)
		req := httptest.NewRequest(http.MethodPost, "/principals", principalJson)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, _ := app.Test(req, -1)
		assert.Equal(t, http.StatusCreated, res.StatusCode)

		// Can get principal
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/principals/%s", principalToCreate.Username), nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminJwt)
		res, err = app.Test(req, -1)
		if err != nil {
			t.Error("Error getting prinipal", err)
		}
		var returnedPrincipal PrincipalModel
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedPrincipal)
		if err != nil {
			t.Error("Error parsing returned principal", err)
		}
		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, principalToCreate.Username, returnedPrincipal.Username)
		assert.Equal(t, principalToCreate.Description, returnedPrincipal.Description)
		for _, policy := range principalToCreate.Policies {
			assert.Contains(t, returnedPrincipal.Policies, policy)
		}
		assert.NotEqual(t, principalToCreate.Password, returnedPrincipal.Password)
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
