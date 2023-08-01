package main

import (
	"context"
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
	app, vault, _ := InitTestingVault(t)

	ctx := context.Background()
	adminPrincipal := _vault.Principal{
		Username:    "admin",
		Password:    "admin",
		Description: "admin principal",
		Policies:    []string{"root"},
	}

	normalPrincipal := _vault.Principal{
		Username:    "normal-username",
		Password:    "normal-password",
		Description: "normal test principal",
		Policies:    []string{"test-policy"},
	}

	err := vault.CreatePrincipal(ctx, adminPrincipal, normalPrincipal.Username, normalPrincipal.Password, normalPrincipal.Description, normalPrincipal.Policies)
	if err != nil {
		t.Fatalf("Failed to create normal principal: %v", err)
	}

	t.Run("valid principal can get a token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		creds := fmt.Sprintf("%s:%s", normalPrincipal.Username, normalPrincipal.Password)
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		res, err := app.Test(req, -1)

		if err != nil {
			t.Fatalf("Error getting a token: %v", err)
		}

		assert.Equal(t, http.StatusOK, res.StatusCode)

		var token ClientToken
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v", err)
		}

		err = json.Unmarshal(body, &token)
		if err != nil {
			t.Fatalf("Error parsing returned token: %v", err)
		}

		assert.Equal(t, normalPrincipal.Username, token.Principal)
		assert.Equal(t, 1, len(token.Policies))
		assert.Equal(t, normalPrincipal.Policies[0], token.Policies[0])
		assert.NotEqual(t, "", token.AccessToken)
	})

	t.Run("invalid principal can't get a token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		creds := fmt.Sprintf("%s:%s", "invalid", "invalid")
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		res, err := app.Test(req, -1)

		if err != nil {
			t.Fatalf("Error getting a token: %v", err)
		}

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("request without authorization header fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		res, err := app.Test(req, -1)

		if err != nil {
			t.Fatalf("Error getting a token: %v", err)
		}

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("request with invalid authorization header format fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte("invalid-format")))
		res, err := app.Test(req, -1)

		if err != nil {
			t.Fatalf("Error getting a token: %v", err)
		}

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})
}
