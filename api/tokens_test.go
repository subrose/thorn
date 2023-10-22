package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/subrose/vault"
)

func TestTokens(t *testing.T) {
	app, core := InitTestingVault(t)

	customerCollection := vault.Collection{
		Name: "test",
		Fields: map[string]vault.Field{
			"name":         {Name: "name", Type: "name", IsIndexed: true},
			"phone_number": {Name: "phone_number", Type: "phone_number", IsIndexed: true},
			"dob":          {Name: "dob", Type: "date", IsIndexed: false},
		},
	}
	core.vault.CreateCollection(context.Background(), adminPrincipal, customerCollection)
	records, err := core.vault.CreateRecords(context.Background(), adminPrincipal, "test", []vault.Record{
		{"name": "Jiminson McFoo", "phone_number": "+447890123456", "dob": "1980-01-01"},
		{"name": "Asdaf Fardas", "phone_number": "+447890123457", "dob": "1990-01-01"},
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	var tokenId string

	t.Run("can create a token", func(t *testing.T) {
		request := newRequest(t, http.MethodPost, fmt.Sprintf("/tokens?collectionName=test&recordId=%s&fieldName=name&returnFormat=plain", records[0]), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		// var tokenId string
		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusOK, &tokenId)

	})
	t.Run("can get a token", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, fmt.Sprintf("/tokens/%s", tokenId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)

		var value struct {
			Name string `json:"name" validate:"required"`
		}
		checkResponse(t, response, http.StatusOK, &value)
		assert.Equal(t, value.Name, "Jiminson McFoo")

	})
}
