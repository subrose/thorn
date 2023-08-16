package main

import (
	"fmt"
	"net/http"
	"testing"
)

func TestCollections(t *testing.T) {
	app, core := InitTestingVault(t)

	customerCollection := CollectionModel{
		Name: "customers",
		Fields: map[string]CollectionFieldModel{
			"name":         {Type: "name", IsIndexed: true},
			"phone_number": {Type: "phoneNumber", IsIndexed: true},
			"dob":          {Type: "date", IsIndexed: false},
		},
	}

	t.Run("can create a collection", func(t *testing.T) {
		request := newRequest(t, http.MethodPost, "/collections", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, customerCollection)

		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusCreated, nil)

	})

	t.Run("can get a collection", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, "/collections/customers", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)
		var returnedCollection CollectionModel
		checkResponse(t, response, http.StatusOK, &returnedCollection)

		if returnedCollection.Name != "customers" {
			t.Error("Error getting collection", returnedCollection)
		}

		if returnedCollection.Fields["name"].Type != "name" {
			t.Error("Error getting collection", returnedCollection)
		}
	})

	t.Run("can get all collections", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, "/collections", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)

		var returnedCollections []string
		checkResponse(t, response, http.StatusOK, &returnedCollections)
	})

	t.Run("can create and get a record", func(t *testing.T) {
		records := []map[string]interface{}{
			{
				"name":         "123345",
				"phone_number": "12345",
				"dob":          "12345",
			},
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, records)

		response := performRequest(t, app, request)
		var returnedRecordIds []string
		checkResponse(t, response, http.StatusCreated, &returnedRecordIds)
		if len(returnedRecordIds) != 1 {
			t.Error("Error creating record", returnedRecordIds)
		}
		// Get the record
		request = newRequest(t, http.MethodGet, fmt.Sprintf("/collections/customers/records/%s?formats=name.plain", returnedRecordIds[0]), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		var returnedRecords map[string]interface{}
		checkResponse(t, response, http.StatusOK, returnedRecords)
	})

	t.Run("cant create a bad record", func(t *testing.T) {
		badRecords := []map[string]interface{}{
			{
				"xxx":          "123345",
				"phone_number": "12345",
				"dob":          "12345",
			},
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.VAULT_ADMIN_USERNAME, core.conf.VAULT_ADMIN_PASSWORD),
		}, badRecords)

		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusBadRequest, nil)
	})

	t.Run("unauthenticated user cant crud a collection", func(t *testing.T) { // TODO: Can probably make this a table test?
		records := []map[string]interface{}{
			{
				"name":         "123345",
				"phone_number": "12345",
				"dob":          "12345",
			},
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{}, records)

		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusUnauthorized, nil)

		request = newRequest(t, http.MethodGet, "/collections/customers/records/123345", map[string]string{
			"Authorization": createBasicAuthHeader("bad", "bad"),
		}, nil)
		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusUnauthorized, nil)

	})
}
