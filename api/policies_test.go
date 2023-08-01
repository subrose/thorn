package main

import (
	"context"
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

func TestPolicies(t *testing.T) {
	app, vault, core := InitTestingVault(t)
	ctx := context.Background()
	adminToken, _, err := vault.Login(ctx, core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD)

	if err != nil {
		t.Fatalf("Failed to login as admin: %v", err)
	}

	testPolicyId := "test-policy"

	t.Run("can create policy", func(t *testing.T) {
		policyJson := strings.NewReader(
			fmt.Sprintf(
				`{
					"policy_id": "%s",
					"effect": "allow",
					"actions": ["read"],
					"resources": ["/policies/%s"]
				}`,
				testPolicyId,
				testPolicyId,
			),
		)
		req := httptest.NewRequest(http.MethodPost, "/policies", policyJson)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminToken)
		res, _ := app.Test(req, -1)
		createdPolicy := _vault.Policy{}
		body, _ := io.ReadAll(res.Body)
		err := json.Unmarshal(body, &createdPolicy)

		if err != nil {
			t.Error("Error creating policy", err)
		}

		// Assertions
		assert.Equal(t, http.StatusCreated, res.StatusCode)
	})

	t.Run("can get policy", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/policies/%s", testPolicyId), nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+adminToken)
		res, err := app.Test(req, -1)
		if err != nil {
			t.Error("Error getting policy", err)
		}
		var returnedPolicy _vault.Policy
		body, _ := io.ReadAll(res.Body)
		err = json.Unmarshal(body, &returnedPolicy)
		if err != nil {
			t.Error("Error parsing returned policy", err)
		}

		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, _vault.EffectAllow, returnedPolicy.Effect)
		assert.Equal(t, []_vault.PolicyAction{_vault.PolicyActionRead}, returnedPolicy.Actions)
		assert.Equal(t, []string{fmt.Sprintf("/policies/%s", testPolicyId)}, returnedPolicy.Resources)
	})
}
