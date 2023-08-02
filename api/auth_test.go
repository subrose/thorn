package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	_vault "github.com/subrose/vault"
)

const loginRoute = "/auth/userpass/login"

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

	t.Run("Test Login with valid credentials", func(t *testing.T) {
		request := LoginRequest{
			Username:  "admin",
			Password:  "admin",
			Policies:  []string{"root"},
			NotBefore: time.Now().Unix(),
			ExpiresAt: -1,
		}

		req := newRequest(t, http.MethodPost, loginRoute, nil, request)
		response := performRequest(t, app, req)

		var loginResponse LoginResponse
		checkResponse(t, response, http.StatusOK, &loginResponse)

		assert.NotEmpty(t, loginResponse.AccessToken)
		assert.Equal(t, "admin", loginResponse.Principal)
		assert.ElementsMatch(t, []string{"root"}, loginResponse.Policies)
		assert.NotEmpty(t, loginResponse.IssuedAt)
		assert.NotEmpty(t, loginResponse.NotBefore)
		assert.NotEmpty(t, loginResponse.ExpiresAt)
	})

	t.Run("Test Login with invalid credentials", func(t *testing.T) {
		request := LoginRequest{
			Username:  "non_existing_user",
			Password:  "invalid_password",
			Policies:  []string{"test-policy"},
			NotBefore: time.Now().Unix(),
			ExpiresAt: -1,
		}

		req := newRequest(t, http.MethodPost, loginRoute, nil, request)
		response := performRequest(t, app, req)

		checkResponse(t, response, http.StatusForbidden, nil)
	})

	t.Run("Test Login with missing required fields", func(t *testing.T) {
		request := LoginRequest{}
		req := newRequest(t, http.MethodPost, loginRoute, nil, request)
		response := performRequest(t, app, req)

		checkResponse(t, response, http.StatusBadRequest, nil)
	})

	t.Run("Test Login with custom Not-Before and Expires-At timestamps", func(t *testing.T) {
		notBefore := time.Now().Unix() + 3600 // 1 hour from now
		expiresAt := time.Now().Unix() + 7200 // 2 hours from now
		request := LoginRequest{
			Username:  "admin",
			Password:  "admin",
			Policies:  []string{"root"},
			NotBefore: notBefore,
			ExpiresAt: expiresAt,
		}

		// Perform the request to the API endpoint
		req := newRequest(t, http.MethodPost, loginRoute, nil, request)
		response := performRequest(t, app, req)

		var loginResponse LoginResponse
		checkResponse(t, response, http.StatusOK, &loginResponse)

		assert.Equal(t, notBefore, loginResponse.NotBefore)
		assert.Equal(t, expiresAt, loginResponse.ExpiresAt)
	})

	t.Run("Test can't login with expires_at > not_before", func(t *testing.T) {
		notBefore := time.Now().Unix() + 7200 // 1 hour from now
		expiresAt := time.Now().Unix() + 3600 // 1 hours from now
		request := LoginRequest{
			Username:  "admin",
			Password:  "admin",
			Policies:  []string{"root"},
			NotBefore: notBefore,
			ExpiresAt: expiresAt,
		}

		req := newRequest(t, http.MethodPost, loginRoute, nil, request)
		response := performRequest(t, app, req)

		checkResponse(t, response, http.StatusBadRequest, nil)

	})
}
