package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
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
	// TODO: Use a mock db for unit testing
	db, _ := _vault.NewRedisStore(
		fmt.Sprintf("%s:%d", coreConfig.DB_HOST, coreConfig.DB_PORT),
		coreConfig.DB_PASSWORD,
		coreConfig.DB_DB,
	)

	priv := _vault.NewAESPrivatiser([]byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}, "abc&1*~#^2^#s0^=)^^7%b34")
	signer, _ := _vault.NewHMACSigner([]byte("testkey"))
	var pm _vault.PolicyManager = db
	vaultLogger, _ := _logger.NewLogger("TEST_VAULT", "none", "debug", true)
	vault := _vault.Vault{Db: db, Priv: priv, PrincipalManager: db, PolicyManager: pm, Logger: vaultLogger, Signer: signer}
	bootstrapContext := context.Background()
	_ = vault.Db.Flush(bootstrapContext)
	_, _ = pm.CreatePolicy(bootstrapContext, _vault.Policy{
		PolicyId:  "root",
		Effect:    _vault.EffectAllow,
		Actions:   []_vault.PolicyAction{_vault.PolicyActionRead, _vault.PolicyActionWrite},
		Resources: []string{"*"},
	})

	err = vault.CreatePrincipal(bootstrapContext, adminPrincipal, coreConfig.VAULT_ADMIN_USERNAME, coreConfig.VAULT_ADMIN_PASSWORD, "admin principal", []string{"root"})
	if err != nil {
		t.Fatal("Failed to create admin principal", err)
	}
	return app, core
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
		var errorResponse ErrorResponse
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v", err)
		}
		err = json.Unmarshal(responseBody, &errorResponse)
		if err != nil {
			t.Fatalf("Error parsing response body json: %v", err)
		}
		t.Fatalf("Expected status code %d, got %d - Error Message: %s", expectedStatusCode, response.StatusCode, errorResponse.Message)
	}

	// If target is provided, unmarshal the response body into the target struct
	if target != nil {
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v", err)
		}
		err = json.Unmarshal(responseBody, &target)
		if err != nil {
			t.Fatalf("Error parsing response body json: %v", err)
		}

		// Validate the response data against the struct tags
		validate := validator.New()
		err = validate.Struct(target)
		if err != nil {
			t.Fatalf("Response data validation failed: %v", err)
		}
	}
}
