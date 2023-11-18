package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	_logger "github.com/subrose/logger"
	_vault "github.com/subrose/vault"
)

// Common testing utils?
var testConfigPath = flag.String("testConfigFile", "../conf/test.conf.toml", "Path to config file")
var adminPrincipal = _vault.Principal{Username: "admin", Password: "admin", Policies: []string{"root"}}

func InitTestingVault(t *testing.T) (*fiber.App, *Core) {
	// Setup
	if *testConfigPath == "" {
		panic("Config path not specified")
	}

	coreConfig, err := ReadConfigs(*testConfigPath)

	if err != nil {
		t.Fatal("Failed to read config", err)
	}
	core, err := CreateCore(coreConfig)
	if err != nil {
		t.Fatal("Failed to create core", err)
	}
	app := SetupApi(core)

	// TODO: Switch on db type
	// db, _ = _vault.NewRedisStore(
	// 	fmt.Sprintf("%s:%d", coreConfig.DB_HOST, coreConfig.DB_PORT),
	// 	coreConfig.DB_PASSWORD,
	// 	coreConfig.DB_DB,
	// )
	db, err := _vault.NewSqlStore(_vault.FormatDsn(
		coreConfig.DB_HOST,
		coreConfig.DB_USER,
		coreConfig.DB_PASSWORD,
		coreConfig.DB_NAME,
		coreConfig.DB_PORT))

	if err != nil {
		t.Fatal("Failed to create db", err)
	}

	priv := _vault.NewAESPrivatiser([]byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}, "abc&1*~#^2^#s0^=)^^7%b34")
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
	vault := _vault.Vault{Db: db, Priv: priv, Logger: vaultLogger, Signer: signer}
	bootstrapContext := context.Background()
	err = vault.Db.Flush(bootstrapContext)
	if err != nil {
		t.Fatal("Failed to flush db", err)
	}
	_, err = db.CreatePolicy(bootstrapContext, _vault.Policy{
		PolicyId:  "root",
		Effect:    _vault.EffectAllow,
		Actions:   []_vault.PolicyAction{_vault.PolicyActionRead, _vault.PolicyActionWrite},
		Resources: []string{"*"},
	})

	if err != nil {
		t.Fatal("Failed to create root policy", err)
	}

	err = vault.CreatePrincipal(bootstrapContext, adminPrincipal, coreConfig.VAULT_ADMIN_USERNAME, coreConfig.VAULT_ADMIN_PASSWORD, "admin principal", []string{"root"})
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
		if err := Validate(target); err != nil {
			t.Fatalf("Error validating response: %v", err)
		}
	}
}
