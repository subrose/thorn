package vault

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	_logger "github.com/subrose/logger"
)

func initVault(t *testing.T) (Vault, VaultDB, Privatiser) {
	_ = godotenv.Load("../test.env")
	ctx := context.Background()
	db, err := NewSqlStore(os.Getenv("THORN_DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	db.Flush(ctx)
	priv := NewAESPrivatiser([]byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}, "abc&1*~#^2^#s0^=)^^7%b34")
	signer, _ := NewHMACSigner([]byte("testkey"))
	_ = db.CreatePolicy(ctx, &Policy{
		Id:          "root",
		Name:        "root",
		Description: "",
		Effect:      EffectAllow,
		Actions:     []PolicyAction{PolicyActionRead, PolicyActionWrite},
		Resources:   []string{"*"},
		CreatedAt:   time.Now().String(),
		UpdatedAt:   time.Now().String(),
	})
	_ = db.CreatePolicy(ctx, &Policy{
		Id:          "read-all-customers",
		Name:        "read-all-customers",
		Description: "",
		Effect:      EffectAllow,
		Actions:     []PolicyAction{PolicyActionRead},
		Resources:   []string{"/collections/customers*"},
		CreatedAt:   time.Now().String(),
		UpdatedAt:   time.Now().String(),
	})
	vaultLogger, _ := _logger.NewLogger("TEST_VAULT", "none", "text", "debug", true)
	vault := Vault{Db: db, Priv: priv, Logger: vaultLogger, Signer: signer, Validator: NewValidator()}
	return vault, db, priv
}

func TestVault(t *testing.T) {
	ctx := context.Background()
	testPrincipal := Principal{
		Username:    "admin",
		Password:    "admin",
		Policies:    []string{"root"},
		Description: "test admin",
	}
	t.Run("can store and get collections and records", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Type:      "string",
				IsIndexed: false,
			},
			"last_name": {
				Type:      "string",
				IsIndexed: false,
			},
			"email": {
				Type:      "string",
				IsIndexed: true,
			},
			"phone_number": {
				Type:      "string",
				IsIndexed: true,
			},
		}}

		// Can create collection
		err := vault.CreateCollection(ctx, testPrincipal, &col)
		if err != nil || col.Id == "" {
			t.Fatal(err)
		}

		// Can get collection
		dbCol, err := vault.GetCollection(ctx, testPrincipal, col.Name)

		if err != nil {
			t.Fatal(err)
		}

		if col.Name != dbCol.Name {
			t.Fatalf("Expected collection name to be %s, got %s", col.Name, dbCol.Name)
		}

		// Can store records
		inputRecord := Record{
			"first_name":   "John",
			"last_name":    "Crawford",
			"email":        "john@crawford.com",
			"phone_number": "1234567890",
		}

		record_id, err := vault.CreateRecord(ctx, testPrincipal, col.Name, inputRecord)
		if err != nil {
			t.Fatal(err)
		}

		// Can get records
		vaultRecord, err := vault.GetRecord(ctx, testPrincipal, col.Name, record_id, map[string]string{
			"first_name": "plain", "last_name": "plain", "email": "plain", "phone_number": "plain",
		})
		if err != nil {
			t.Fatal(err)
		}

		// Check if input and output records match

		for k, v := range inputRecord {
			val := v
			if val != vaultRecord[k] {
				t.Fatalf("Expected %s to be %s, got %s", k, v, vaultRecord[k])
			}
		}

	})

	t.Run("can delete collections and associated records", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Type:      "string",
				IsIndexed: false,
			},
		}}
		_ = vault.CreateCollection(ctx, testPrincipal, &col)
		// Create a dummy record
		recordID, err := vault.CreateRecord(ctx, testPrincipal, col.Name, Record{"first_name": "dummy"})
		if err != nil {
			t.Fatal(err)
		}
		err = vault.DeleteCollection(ctx, testPrincipal, col.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, err = vault.GetCollection(ctx, testPrincipal, col.Name)
		switch err.(type) {
		case *NotFoundError:
			// success
		default:
			t.Error("Should throw a not found error when getting a deleted collection, got:", err)
		}
		// Try to get the deleted record
		_, err = vault.GetRecord(ctx, testPrincipal, col.Name, recordID, map[string]string{
			"first_name": "plain",
		})
		// Expect a NotFoundError
		var notFoundErr *NotFoundError
		if err == nil || !errors.As(err, &notFoundErr) {
			t.Fatalf("Expected a NotFoundError for records of deleted collection, got %s", err)
		}
	})

	t.Run("can update records", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "testing", Fields: map[string]Field{
			"test_field": {
				Type:      "string",
				IsIndexed: false,
			},
		}}

		// Create collection
		_ = vault.CreateCollection(ctx, testPrincipal, &col)

		// Create a dummy record
		recordID, err := vault.CreateRecord(ctx, testPrincipal, col.Name, Record{"test_field": "dummy"})

		if err != nil {
			t.Fatal(err)
		}

		// Update the record
		updateRecord := Record{"test_field": "updated"}
		err = vault.UpdateRecord(ctx, testPrincipal, col.Name, recordID, updateRecord)
		if err != nil {
			t.Fatal(err)
		}

		// Verify update of the record
		updatedRecord, err := vault.GetRecord(ctx, testPrincipal, col.Name, recordID, map[string]string{
			"test_field": "plain",
		})
		if err != nil {
			t.Fatal(err)
		}
		if updatedRecord["test_field"] != "updated" {
			t.Fatal("Record not updated correctly.")
		}
	})

	t.Run("cant store records with invalid fields", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "test_collection", Fields: map[string]Field{
			"first_name": {
				Type:      "string",
				IsIndexed: false,
			},
		}}
		_ = vault.CreateCollection(ctx, testPrincipal, &col)
		_, err := vault.CreateRecord(ctx, testPrincipal, col.Name, Record{"invalid_field": "John"})

		var ve *ValueError
		if err == nil || !errors.As(err, &ve) {
			t.Fatalf("Expected a value error, got %s", err)
		}
	})

	t.Run("can delete records", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "test_collection", Fields: map[string]Field{
			"test_field": {
				Type:      "string",
				IsIndexed: false,
			},
		}}

		// Create collection
		_ = vault.CreateCollection(ctx, testPrincipal, &col)

		// Create a dummy record
		recordID, err := vault.CreateRecord(ctx, testPrincipal, col.Name, Record{"test_field": "dummy"})

		if err != nil {
			t.Fatal(err)
		}

		// Delete the record
		err = vault.DeleteRecord(ctx, testPrincipal, col.Name, recordID)
		if err != nil {
			t.Fatal(err)
		}

		// Try to get the deleted record
		_, err = vault.GetRecord(ctx, testPrincipal, col.Name, recordID, map[string]string{
			"test_field": "plain",
		})

		// Expect a NotFoundError
		var notFoundErr *NotFoundError
		if err == nil || !errors.As(err, &notFoundErr) {
			t.Fatalf("Expected a NotFoundError, got %s", err)
		}
	})

	t.Run("can create and get principals", func(t *testing.T) {
		vault, _, _ := initVault(t)
		// Can't get principals that don't exist:
		_, err := vault.GetPrincipal(ctx, testPrincipal, testPrincipal.Username)
		switch err.(type) {
		case *NotFoundError:
		default:
			t.Error("Should throw a not found error!", err)
		}
		// Can create a principal
		err = vault.CreatePrincipal(ctx, testPrincipal, &Principal{Username: testPrincipal.Username, Password: testPrincipal.Password, Description: "a test principal, again", Policies: []string{"read-all-customers"}})
		if err != nil {
			t.Fatal(err)
		}

	})

	t.Run("can delete a principal", func(t *testing.T) {
		vault, _, _ := initVault(t)
		// Create a principal
		err := vault.CreatePrincipal(ctx, testPrincipal, &Principal{Username: "test_user", Password: "test_password", Description: "test principal", Policies: []string{"root"}})
		if err != nil {
			t.Fatal(err)
		}
		// Delete the principal
		err = vault.DeletePrincipal(ctx, testPrincipal, "test_user")
		if err != nil {
			t.Fatal(err)
		}
		// Try to get the deleted principal
		_, err = vault.GetPrincipal(ctx, testPrincipal, "test_user")
		switch err.(type) {
		case *NotFoundError:
			// success
		default:
			t.Error("Should throw a not found error when trying to get a deleted principal, got:", err)
		}
	})

	t.Run("cant create the same principal twice", func(t *testing.T) {
		vault, _, _ := initVault(t)
		err := vault.CreatePrincipal(ctx, testPrincipal, &Principal{Username: testPrincipal.Username, Password: testPrincipal.Password, Description: "a test principal", Policies: []string{"read-all-customers"}})
		if err != nil {
			t.Fatal(err)
		}

		err2 := vault.CreatePrincipal(ctx, testPrincipal, &Principal{Username: testPrincipal.Username, Password: testPrincipal.Password, Description: "a test principal", Policies: []string{"read-all-customers"}})
		switch err2.(type) {
		case *ConflictError:
			// success
		default:
			t.Error("Should throw a conflict error when trying to create the same principal twice, got:", err2)
		}
	})

	t.Run("principal has access to customer records", func(t *testing.T) {
		limitedPrincipal := Principal{
			Username:    "foo",
			Password:    "bar",
			Policies:    []string{"read-all-customers"},
			Description: "test principal",
		}
		vault, _, _ := initVault(t)
		// TODO: Smelly test, make this DRY
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Type:      "string",
				IsIndexed: false,
			},
		}}

		// Can create collection
		_ = vault.CreateCollection(ctx, testPrincipal, &col)
		record_id, _ := vault.CreateRecord(ctx, testPrincipal, col.Name, Record{"first_name": "John"})
		_, err := vault.GetRecord(ctx, limitedPrincipal, "customers", record_id, map[string]string{
			"first_name": "plain",
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("principal does not have access to credit-card records", func(t *testing.T) {
		limitedPrincipal := Principal{
			Username:    "foo",
			Password:    "bar",
			Policies:    []string{"read-all-customers"},
			Description: "test principal",
		}
		vault, _, _ := initVault(t)
		_, err := vault.GetRecord(ctx, limitedPrincipal, "credit-cards", "1", map[string]string{
			"first_name": "plain",
		})
		switch err.(type) {
		case *ForbiddenError:
			// worked
		default:
			t.Fatal(err)
		}
	})
	// t.Run("get records by field value", func(t *testing.T) {
	// 	vault, _, _ := initVault(t)
	// 	col := Collection{Name: "customers", Fields: map[string]Field{
	// 		"first_name": {
	// 			Name:      "first_name",
	// 			Type:      "string",
	// 			IsIndexed: true,
	// 		},
	// 	}}

	// 	// Can create collection
	// 	_, _ = vault.CreateCollection(ctx, testPrincipal, col)
	// 	_, _ = vault.CreateRecord(ctx, testPrincipal, col.Name, []Record{
	// 		{"first_name": "John"},
	// 		{"first_name": "Jane"},
	// 		{"first_name": "Bob"},
	// 	})
	// 	res, err := vault.GetRecordsFilter(ctx, testPrincipal, "customers", "first_name", "Bob", map[string]string{
	// 		"first_name": "plain",
	// 	})
	// 	assert.Equal(t, err, nil)
	// 	assert.Equal(
	// 		t,
	// 		len(res),
	// 		1,
	// 	)
	// })
	// t.Run("get records by field fails when field not indexed", func(t *testing.T) {
	// 	vault, _, _ := initVault(t)
	// 	col := Collection{Name: "customers", Fields: map[string]Field{
	// 		"first_name": {
	// 			Name:      "first_name",
	// 			Type:      "string",
	// 			IsIndexed: false,
	// 		},
	// 	}}

	//		// Can create collection
	//		_, _ = vault.CreateCollection(ctx, testPrincipal, col)
	//		_, _ = vault.CreateRecord(ctx, testPrincipal, col.Name, []Record{
	//			{"first_name": "John"},
	//			{"first_name": "Jane"},
	//			{"first_name": "Bob"},
	//		})
	//		_, err := vault.GetRecordsFilter(ctx, testPrincipal, "customers", "first_name", "Bob", map[string]string{
	//			"first_name": "plain",
	//		})
	//		assert.Equal(t, err, ErrIndexError)
	//	})
}

func TestVaultLogin(t *testing.T) {
	ctx := context.Background()
	vault, _, _ := initVault(t)

	testPrincipal := Principal{
		Username:    "test_user",
		Password:    "test_password",
		Description: "test principal",
		Policies:    []string{"root"},
	}

	err := vault.CreatePrincipal(ctx, testPrincipal, &Principal{Username: testPrincipal.Username, Password: testPrincipal.Password, Description: testPrincipal.Description, Policies: testPrincipal.Policies})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("can login successfully", func(t *testing.T) {
		principal, err := vault.Login(ctx, testPrincipal.Username, testPrincipal.Password)
		if err != nil {
			t.Fatal(err)
		}

		if principal.Username != testPrincipal.Username {
			t.Fatalf("Expected principal username to be %s, got %s", testPrincipal.Username, principal.Username)
		}

		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("can't login with invalid credentials", func(t *testing.T) {
		_, err := vault.Login(ctx, testPrincipal.Username, "invalid_password")
		if err == nil {
			t.Fatal("Expected an error, got nil")
		}
	})
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	vault, _, _ := initVault(t)

	// create principals
	rootPrincipal := Principal{
		Username:    "root",
		Password:    "root",
		Policies:    []string{"root"},
		Description: "root principal",
	}
	testPrincipal := Principal{
		Username:    "test_user",
		Password:    "test_password",
		Policies:    []string{"read-all-customers"},
		Description: "test principal",
	}
	err := vault.CreatePrincipal(ctx, rootPrincipal, &Principal{Username: rootPrincipal.Username, Password: rootPrincipal.Password, Description: rootPrincipal.Description, Policies: rootPrincipal.Policies})
	assert.NoError(t, err, "failed to create root principal")

	err = vault.CreatePrincipal(ctx, rootPrincipal, &Principal{Username: testPrincipal.Username, Password: testPrincipal.Password, Description: testPrincipal.Description, Policies: testPrincipal.Policies})
	assert.NoError(t, err, "failed to create test principal")

	// create collections
	err = vault.CreateCollection(ctx, rootPrincipal, &Collection{
		Name:   "customers",
		Fields: map[string]Field{"name": {"string", false}, "foo": {"string", false}},
	})
	assert.NoError(t, err, "failed to create customer collection")
	err = vault.CreateCollection(ctx, rootPrincipal, &Collection{
		Name:   "employees",
		Fields: map[string]Field{"name": {"string", false}, "foo": {"string", false}},
	})
	assert.NoError(t, err, "failed to create employees collection")

	// create records
	customerRecord, err := vault.CreateRecord(ctx, rootPrincipal, "customers", Record{"name": "Joe Buyer", "foo": "bar"})
	assert.NoError(t, err, "failed to create customer records")
	employeeRecord, err := vault.CreateRecord(ctx, rootPrincipal, "employees", Record{"name": "Joe Boss", "foo": "baz"})
	assert.NoError(t, err, "failed to create employee records")

	t.Run("create token fails without access to underlying record", func(t *testing.T) {
		rId := employeeRecord
		_, err := vault.CreateToken(ctx, testPrincipal, "employees", rId, "name", "plain")
		var fe *ForbiddenError
		assert.ErrorAs(t, err, &fe)
	})

	t.Run("create and retrieve token", func(t *testing.T) {
		rId := customerRecord
		tokenId, err := vault.CreateToken(ctx, testPrincipal, "customers", rId, "name", "plain")
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(tokenId), "tokenId was empty")

		record, err := vault.GetTokenValue(ctx, testPrincipal, tokenId)
		if assert.NoError(t, err, "failed to get token value") {
			assert.Equal(t, "Joe Buyer", record["name"])
		}
	})
	t.Run("create and retrieve token by another principal", func(t *testing.T) {
		rId := customerRecord
		tokenId, err := vault.CreateToken(ctx, rootPrincipal, "customers", rId, "name", "plain")
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(tokenId), "tokenId was empty")

		record, err := vault.GetTokenValue(ctx, testPrincipal, tokenId)
		if assert.NoError(t, err, "failed to get token value") {
			assert.Equal(t, "Joe Buyer", record["name"])
		}
	})
	t.Run("getting token value fails without access to underlying record", func(t *testing.T) {
		rId := employeeRecord
		tokenId, err := vault.CreateToken(ctx, rootPrincipal, "employees", rId, "name", "plain")
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(tokenId), "tokenId was empty")

		_, err = vault.GetTokenValue(ctx, testPrincipal, tokenId)
		var fe *ForbiddenError
		assert.ErrorAs(t, err, &fe)
	})
}
