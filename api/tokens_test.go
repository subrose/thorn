package main

import (
	"context"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/subrose/vault"
)

func TestTokens(t *testing.T) {
	_, core := InitTestingVault(t)

	customerCollection := vault.Collection{
		Name: "test",
		Fields: map[string]vault.Field{
			"name":         {Name: "name", Type: "name", IsIndexed: true},
			"phone_number": {Name: "phone_number", Type: "phone_number", IsIndexed: true},
			"dob":          {Name: "dob", Type: "date", IsIndexed: false},
		},
	}
	_, err := core.vault.CreateCollection(context.Background(), adminPrincipal, customerCollection)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
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
		tokenRequest := &TokenRequest{
			Collection: "test",
			RecordId:   records[0],
			Field:      "name",
			Format:     "plain",
		}
		tokenId, err = core.vault.CreateToken(context.Background(), adminPrincipal, tokenRequest.Collection, tokenRequest.RecordId, tokenRequest.Field, tokenRequest.Format)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		assert.NotEqual(t, tokenId, "")
	})
	t.Run("can get a token", func(t *testing.T) {
		token, err := core.vault.GetTokenValue(context.Background(), adminPrincipal, tokenId)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		assert.Equal(t, token["name"], "Jiminson McFoo")
	})
}
