package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	_logger "github.com/subrose/logger"
	_vault "github.com/subrose/vault"
)

var rootPolicyId = _vault.GenerateId("pol")
var adminPrincipal = _vault.Principal{Username: "admin", Password: "admin", Policies: []string{rootPolicyId}}

func InitTestingVault(t *testing.T) (*fiber.App, *Core) {
	// Read environment variables if a test.env file exists, error is ignored on purpose
	_ = godotenv.Load("../test.env")

	coreConfig, err := ReadConfigs()
	if err != nil {
		t.Fatal("Failed to read config", err)
	}
	core, err := CreateCore(coreConfig)
	if err != nil {
		t.Fatal("Failed to create core", err)
	}
	app := SetupApi(core)

	db, err := _vault.NewSqlStore(coreConfig.DATABASE_URL)
	if err != nil {
		t.Fatal("Failed to create db", err)
	}

	priv, err := _vault.NewAESPrivatiser("abc&1*~#^2^#s0^=)^^7%b34")
	if err != nil {
		t.Fatal("Failed to create privatiser", err)
	}
	signer, err := _vault.NewHMACSigner([]byte("testkey"))
	if err != nil {
		t.Fatal("Failed to create signer", err)
	}
	vaultLogger, err := _logger.NewLogger("TEST_VAULT", "none", "text", "debug", true)
	if err != nil {
		t.Fatal("Failed to create logger", err)
	}
	vault := _vault.Vault{Db: db, Priv: priv, Logger: vaultLogger, Signer: signer, Validator: _vault.NewValidator()}
	bootstrapContext := context.Background()
	err = vault.Db.Flush(bootstrapContext)
	if err != nil {
		t.Fatal("Failed to flush db", err)
	}

	err = db.CreatePolicy(bootstrapContext, &_vault.Policy{
		Id:        rootPolicyId,
		Name:      "root",
		Effect:    _vault.EffectAllow,
		Actions:   []_vault.PolicyAction{_vault.PolicyActionRead, _vault.PolicyActionWrite},
		Resources: []string{"*"},
	})

	if err != nil {
		t.Fatal("Failed to create root policy", err)
	}

	err = vault.CreatePrincipal(bootstrapContext, adminPrincipal, &_vault.Principal{
		Id:          _vault.GenerateId("prin"),
		Username:    coreConfig.ADMIN_USERNAME,
		Password:    coreConfig.ADMIN_PASSWORD,
		Description: "admin principal",
		Policies:    []string{rootPolicyId},
	})
	if err != nil {
		t.Fatal("Failed to create admin principal", err)
	}
	return app, core
}

func createBasicAuthHeader(username, password string) string {
	// Encode username and password into Basic Auth header
	authValue := username + ":" + password
	encodedAuthValue := base64.StdEncoding.EncodeToString([]byte(authValue))
	return "Basic " + encodedAuthValue
}

func newRequest(t *testing.T, method, url string, headers map[string]string, payload interface{}) *http.Request {
	jsonRequest, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Error marshaling request: %v", err)
	}
	req := httptest.NewRequest(method, url, bytes.NewBuffer(jsonRequest))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func performRequest(t *testing.T, app *fiber.App, req *http.Request) *http.Response {
	response, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error performing request: %v", err)
	}
	return response
}

func checkResponse(t *testing.T, response *http.Response, expectedStatusCode int, target interface{}) {
	if response.StatusCode != expectedStatusCode {
		if response.StatusCode > 299 {
			var errorResponse ErrorResponse
			responseBody, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v - body: %s", err, responseBody)
			}
			err = json.Unmarshal(responseBody, &errorResponse)
			if err != nil {
				t.Fatalf("Error parsing response body json: %v - body: %s", err, responseBody)
			}
			t.Fatalf("Expected status code %d, got %d - Error Message: %s", expectedStatusCode, response.StatusCode, errorResponse.Message)
		}
		t.Fatalf("Expected status code %d, got %d", expectedStatusCode, response.StatusCode)
	}

	// If target is provided, unmarshal the response body into the target struct
	if target != nil {
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v - %s", err, responseBody)
		}
		err = json.Unmarshal(responseBody, &target)
		if err != nil {
			t.Fatalf("Error parsing response body json: %v - %s", err, responseBody)
		}

		// Validate the response data against the struct tags
		// Check if target is a struct
		if _, ok := target.(struct{}); ok {

			validate := _vault.NewValidator()
			if err := validate.Struct(target); err != nil {
				t.Fatalf("Error validating response: %v", err)
			}
		}
	}
}
