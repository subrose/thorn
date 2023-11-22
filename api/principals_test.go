package main

import (
	"fmt"
	"net/http"
	"testing"
)

func TestPrincipals(t *testing.T) {
	app, core := InitTestingVault(t)

	newPrincipal := NewPrincipal{
		Username:    "newprincipal",
		Password:    "password",
		Description: "A new principal",
		Policies:    []string{"test-read", "test-write"},
	}

	t.Run("can create a principal", func(t *testing.T) {

		request := newRequest(t, http.MethodPost, "/principals", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, newPrincipal)

		response := performRequest(t, app, request)
		var principalResponse PrincipalResponse
		checkResponse(t, response, http.StatusCreated, &principalResponse)

		if principalResponse.Username != newPrincipal.Username {
			t.Errorf("Expected username to be 'newprincipal', got '%s'", principalResponse.Username)
		}

		if principalResponse.Description != newPrincipal.Description {
			t.Errorf("Expected description to be 'A new principal', got '%s'", principalResponse.Description)
		}

		if len(principalResponse.Policies) != len(newPrincipal.Policies) {
			t.Errorf("Expected 2 policies, got %d", len(principalResponse.Policies))
		}
	})

	t.Run("can get a principal", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, fmt.Sprintf("/principals/%s", newPrincipal.Username), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)
		var principalResponse PrincipalResponse
		checkResponse(t, response, http.StatusOK, &principalResponse)
	})

	t.Run("can't create principals without assigned roles", func(t *testing.T) {
		request := newRequest(t, http.MethodPost, "/principals", nil, NewPrincipal{
			Username:    "newprincipal",
			Password:    "password",
			Description: "A new principal",
			Policies:    []string{"test-read", "test-write"},
		})

		response := performRequest(t, app, request)

		checkResponse(t, response, http.StatusUnauthorized, nil)

	})

	t.Run("can delete a principal", func(t *testing.T) {
		request := newRequest(t, http.MethodDelete, fmt.Sprintf("/principals/%s", newPrincipal.Username), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)

		checkResponse(t, response, http.StatusNoContent, nil)

		// Check that the principal has been deleted
		request = newRequest(t, http.MethodGet, fmt.Sprintf("/principals/%s", newPrincipal.Username), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusNotFound, nil)
	})

}
