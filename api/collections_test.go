package main

import (
	"fmt"
	"net/http"
	"testing"

	_vault "github.com/subrose/vault"
)

func TestCollections(t *testing.T) {
	app, core := InitTestingVault(t)

	customerCollection := &_vault.Collection{
		Name: "customers",
		Fields: map[string]_vault.Field{
			"name":         {Type: "name", IsIndexed: true},
			"phone_number": {Type: "phone_number", IsIndexed: true},
			"dob":          {Type: "date", IsIndexed: false},
		},
	}

	t.Run("can create a collection", func(t *testing.T) {
		request := newRequest(t, http.MethodPost, "/collections", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, customerCollection)

		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusCreated, nil)

	})

	t.Run("can get a collection", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, "/collections/customers", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)
		var returnedCollection _vault.Collection
		checkResponse(t, response, http.StatusOK, &returnedCollection)

		if returnedCollection.Name != "customers" {
			t.Errorf("Error getting collection name, got %s", returnedCollection.Name)
		}

		if returnedCollection.Fields["name"].Type != "name" {
			t.Errorf("Error getting collection field name type, got %s", returnedCollection.Fields["name"].Type)
		}
	})

	t.Run("can get all collections", func(t *testing.T) {
		request := newRequest(t, http.MethodGet, "/collections", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response := performRequest(t, app, request)

		checkResponse(t, response, http.StatusOK, nil)
	})

	t.Run("can delete a collection", func(t *testing.T) {
		// Create a dummy collection
		collectionToDelete := _vault.Collection{
			Name: "delete_me",
			Fields: map[string]_vault.Field{
				"name": {Type: "name", IsIndexed: true},
			},
		}
		request := newRequest(t, http.MethodPost, "/collections", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, collectionToDelete)

		response := performRequest(t, app, request)
		checkResponse(t, response, http.StatusCreated, nil)
		// Delete it
		request = newRequest(t, http.MethodDelete, "/collections/delete_me", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusOK, nil)
	})

	t.Run("can create and get a record", func(t *testing.T) {
		record := map[string]interface{}{
			"name":         "123345",
			"phone_number": "+447890123456",
			"dob":          "1970-01-01",
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, record)

		response := performRequest(t, app, request)
		var returnedRecordId string
		checkResponse(t, response, http.StatusCreated, &returnedRecordId)

		// Get the record
		request = newRequest(t, http.MethodGet, fmt.Sprintf("/collections/customers/records/%s?formats=name.plain", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusOK, nil)
	})

	t.Run("can update a record", func(t *testing.T) {
		// Create a record to update
		record := map[string]interface{}{
			"name":         "123345",
			"phone_number": "+447890123456",
			"dob":          "1970-01-01",
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, record)

		response := performRequest(t, app, request)
		var returnedRecordId string
		checkResponse(t, response, http.StatusCreated, &returnedRecordId)

		// Update the record
		updateRecord := map[string]interface{}{
			"name":         "54321",
			"phone_number": "+447890123457",
			"dob":          "1980-01-01",
		}

		request = newRequest(t, http.MethodPut, fmt.Sprintf("/collections/customers/records/%s", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, updateRecord)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusOK, nil)

		// Get the updated record
		request = newRequest(t, http.MethodGet, fmt.Sprintf("/collections/customers/records/%s?formats=name.plain,dob.plain,phone_number.plain", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		var returnedRecord _vault.Record
		checkResponse(t, response, http.StatusOK, &returnedRecord)

		if returnedRecord["name"] != updateRecord["name"] ||
			returnedRecord["phone_number"] != updateRecord["phone_number"] ||
			returnedRecord["dob"] != updateRecord["dob"] {
			t.Errorf("Error updating record, got %s", returnedRecord)
		}
	})

	t.Run("can delete a record", func(t *testing.T) {
		// Create a record to delete
		record := map[string]interface{}{
			"name":         "123345",
			"phone_number": "+447890123456",
			"dob":          "1970-01-01",
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, record)

		response := performRequest(t, app, request)
		var returnedRecordId string
		checkResponse(t, response, http.StatusCreated, &returnedRecordId)

		// Delete the record
		request = newRequest(t, http.MethodDelete, fmt.Sprintf("/collections/customers/records/%s", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusOK, nil)

		// Try to get the deleted record
		request = newRequest(t, http.MethodGet, fmt.Sprintf("/collections/customers/records/%s?formats=name.plain", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)

		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusNotFound, nil)

		// Delete the record again (should return 404)
		request = newRequest(t, http.MethodDelete, fmt.Sprintf("/collections/customers/records/%s", returnedRecordId), map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, nil)
		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusNotFound, nil)
	})

	t.Run("cant create a bad record", func(t *testing.T) {
		badRecord := map[string]interface{}{
			"xxx":          "123345",
			"phone_number": "+447890123456",
			"dob":          "1970-01-01",
		}

		request := newRequest(t, http.MethodPost, "/collections/customers/records", map[string]string{
			"Authorization": createBasicAuthHeader(core.conf.ADMIN_USERNAME, core.conf.ADMIN_PASSWORD),
		}, badRecord)

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
			"Authorization": createBasicAuthHeader("admin", "bad"),
		}, nil)
		response = performRequest(t, app, request)
		checkResponse(t, response, http.StatusUnauthorized, nil)

	})
}
