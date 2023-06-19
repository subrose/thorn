package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func TestAuth(t *testing.T) {
	app, _, core := InitTestingVault(t)

	t.Run("can generate a valid JWT for a principal", func(t *testing.T) {
		inputP := _vault.Principal{
			AccessKey:    "test",
			AccessSecret: "test",
			Policies:     []string{"admin-read", "admin-write"},
		}
		jwt, err := core.generateJWT(inputP)
		if err != nil {
			t.Error("Error generating JWT", err)
		}

		// Parse and verify jwt
		outputP, err := core.validateJWT(jwt)
		if err != nil {
			t.Error("Error validating JWT", err)
		}

		// Assertions
		assert.Equal(t, inputP.AccessKey, outputP.AccessKey)
		assert.Equal(t, inputP.Policies, outputP.Policies)

	})

	t.Run("valid principal can get a token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		creds := fmt.Sprintf("%s:%s", core.conf.VAULT_ADMIN_ACCESS_KEY, core.conf.VAULT_ADMIN_ACCESS_SECRET)
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		res, err := app.Test(req, -1)

		if err != nil {
			t.Error("Error getting a token", err)
		}

		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		var token Token
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &token)
		if err != nil {
			t.Error("Error parsing returned token", err)
		}

		// Parse and verify jwt
		assert.Equal(t, "Bearer", token.Type)
		outputP, err := core.validateJWT(token.AccessToken)
		if err != nil {
			t.Error("Error validating JWT", err)
		}

		// Assertions
		assert.Equal(t, core.conf.VAULT_ADMIN_ACCESS_KEY, outputP.AccessKey)
	})

	t.Run("invalid principal can't get a token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		creds := fmt.Sprintf("%s:%s", "invalid", "invalid")
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		res, err := app.Test(req, -1)

		if err != nil {
			t.Error("Error getting a token", err)
		}

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

}
