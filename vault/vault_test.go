package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	_logger "github.com/subrose/logger"
)

// I have customer PII in my database which I want to move to a PII vault.
// The customer object looks like this: {first_name: "John", last_name: "Crawford", "email": "john.crawford@gmail.com", "phone": "1234567890""}
// I want to store the customer object in the vault and get back a unique ID.
// I want to be able to retrieve the customer object from the vault using the unique ID.

func initVault(t *testing.T) (Vault, VaultDB, Privatiser) {
	ctx := context.Background()
	db, err := NewRedisStore(
		os.Getenv("KEYDB_CONN_STRING"),
		"",
		0,
	)
	if err != nil {
		panic(err)
	}
	db.Flush(ctx)
	priv := NewAESPrivatiser([]byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}, "abc&1*~#^2^#s0^=)^^7%b34")
	signer, _ := NewHMACSigner([]byte("testkey"))
	var pm PolicyManager = db
	_, _ = pm.CreatePolicy(ctx, Policy{
		"root",
		EffectAllow,
		[]PolicyAction{PolicyActionRead, PolicyActionWrite},
		[]string{"*"},
	})
	_, _ = pm.CreatePolicy(ctx, Policy{
		"read-all-customers",
		EffectAllow,
		[]PolicyAction{PolicyActionRead},
		[]string{"/collections/customers*"},
	})
	vaultLogger, _ := _logger.NewLogger("TEST_VAULT", "none", "debug", true)
	vault := Vault{Db: db, Priv: priv, PrincipalManager: db, PolicyManager: pm, Logger: vaultLogger, Signer: signer}
	return vault, db, priv
}

func TestVault(t *testing.T) {
	ctx := context.Background()
	testPrincipal := Principal{
		Username:    "test_user",
		Password:    "test_password",
		Policies:    []string{"root"},
		Description: "test principal",
	}
	t.Run("can store and get collections and records", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Name:      "first_name",
				Type:      "string",
				IsIndexed: false,
			},
			"last_name": {
				Name:      "last_name",
				Type:      "string",
				IsIndexed: false,
			},
			"email": {
				Name:      "email",
				Type:      "string",
				IsIndexed: true,
			},
			"phone_number": {
				Name:      "phone_number",
				Type:      "string",
				IsIndexed: true,
			},
		}}

		// Can create collection
		colID, err := vault.CreateCollection(ctx, testPrincipal, col)
		if err != nil || colID == "" {
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
		inputRecords := []Record{
			{
				"first_name":   "John",
				"last_name":    "Crawford",
				"email":        "john@crawford.com",
				"phone_number": "1234567890",
			},

			{
				"first_name":   "Jane",
				"last_name":    "Doe",
				"email":        "jane@doeindustries.com",
				"phone_number": "0987654321",
			},
			{
				"first_name":   "Bob",
				"last_name":    "Alice",
				"email":        "bob@gmail.com",
				"phone_number": "09873243323423",
			},
		}

		ids, err := vault.CreateRecords(ctx, testPrincipal, col.Name, inputRecords)
		if err != nil {
			t.Fatal(err)
		}

		if len(ids) != len(inputRecords) {
			t.Fatalf("Expected %d records to be created, got %d", len(inputRecords), len(ids))
		}

		// Can get records
		vaultRecords, err := vault.GetRecords(ctx, testPrincipal, col.Name, ids, "plain")
		if err != nil {
			t.Fatal(err)
		}

		// Check if input and output records match
		for i, id := range ids {
			inputRecord := inputRecords[i]
			vaultRecord := vaultRecords[id]

			for k, v := range inputRecord {
				val := v
				if val != vaultRecord[k] {
					t.Fatalf("Expected %s to be %s, got %s", k, v, vaultRecord[k])
				}
			}
		}
	})

	t.Run("cant store records with invalid fields", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "smol_collection", Fields: map[string]Field{
			"first_name": {
				Name:      "first_name",
				Type:      "string",
				IsIndexed: false,
			},
		}}
		_, _ = vault.CreateCollection(ctx, testPrincipal, col)
		inputRecords := []Record{{"invalid_field": "John"}}
		_, err := vault.CreateRecords(ctx, testPrincipal, col.Name, inputRecords)
		var valueErr *ValueError
		if err == nil || !errors.As(err, &valueErr) {
			t.Fatalf("Expected an invalid field error, got %s", err)
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
		err = vault.CreatePrincipal(ctx, testPrincipal, testPrincipal.Username, testPrincipal.Password, "a test principal, again", []string{"read-all-customers"})
		if err != nil {
			t.Fatal(err)
		}

	})

	t.Run("cant create the same principal twice", func(t *testing.T) {
		vault, _, _ := initVault(t)
		err := vault.CreatePrincipal(ctx, testPrincipal, testPrincipal.Username, testPrincipal.Password, "a test principal", []string{"read-all-customers"})
		if err != nil {
			t.Fatal(err)
		}

		err2 := vault.CreatePrincipal(ctx, testPrincipal, testPrincipal.Username, testPrincipal.Password, "a test principal", []string{"read-all-customers"})
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
				Name:      "first_name",
				Type:      "string",
				IsIndexed: false,
			},
		}}

		// Can create collection
		_, _ = vault.CreateCollection(ctx, testPrincipal, col)
		record_ids, _ := vault.CreateRecords(ctx, testPrincipal, col.Name, []Record{
			{"first_name": "John"},
			{"first_name": "Jane"},
			{"first_name": "Bob"},
		})
		_, err := vault.GetRecords(ctx, limitedPrincipal, "customers", record_ids, "plain")
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
		_, err := vault.GetRecords(ctx, limitedPrincipal, "credit-cards", []string{"1", "2"}, "plain")
		switch err.(type) {
		case *ForbiddenError:
			// worked
		default:
			t.Fatal(err)
		}
	})
	t.Run("get records by field value", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Name:      "first_name",
				Type:      "string",
				IsIndexed: true,
			},
		}}

		// Can create collection
		_, _ = vault.CreateCollection(ctx, testPrincipal, col)
		_, _ = vault.CreateRecords(ctx, testPrincipal, col.Name, []Record{
			{"first_name": "John"},
			{"first_name": "Jane"},
			{"first_name": "Bob"},
		})
		res, err := vault.GetRecordsFilter(ctx, testPrincipal, "customers", "first_name", "Bob", "plain")
		assert.Equal(t, err, nil)
		assert.Equal(
			t,
			len(res),
			1,
		)
	})
	t.Run("get records by field fails when field not indexed", func(t *testing.T) {
		vault, _, _ := initVault(t)
		col := Collection{Name: "customers", Fields: map[string]Field{
			"first_name": {
				Name:      "first_name",
				Type:      "string",
				IsIndexed: false,
			},
		}}

		// Can create collection
		_, _ = vault.CreateCollection(ctx, testPrincipal, col)
		_, _ = vault.CreateRecords(ctx, testPrincipal, col.Name, []Record{
			{"first_name": "John"},
			{"first_name": "Jane"},
			{"first_name": "Bob"},
		})
		_, err := vault.GetRecordsFilter(ctx, testPrincipal, "customers", "first_name", "Bob", "plain")
		assert.Equal(t, err, ErrIndexError)
	})
}

func TestTokenGenerationAndValidation(t *testing.T) {
	ctx := context.Background()
	vault, _, _ := initVault(t)

	testPrincipal := Principal{
		Username:    "test_user",
		Password:    "test_password",
		Policies:    []string{"root"},
		Description: "test principal",
	}

	t.Run("can create and validate a token", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		tokenString, _, err := vault.createToken(ctx, testPrincipal, testPrincipal.Policies, notBefore, expiresAt)
		if err != nil {
			t.Fatal(err)
		}

		_, err = vault.ValidateAndGetToken(ctx, tokenString)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cannot validate a token that is not valid yet", func(t *testing.T) {
		notBefore := time.Now().Unix() + 3600
		expiresAt := notBefore + 3600
		tokenString, _, err := vault.createToken(ctx, testPrincipal, testPrincipal.Policies, notBefore, expiresAt)
		if err != nil {
			t.Fatal(err)
		}

		_, err = vault.ValidateAndGetToken(ctx, tokenString)
		var tokenErr *NotYetValidTokenError
		if err == nil || !errors.As(err, &tokenErr) {
			t.Fatalf("Expected a token error for not valid yet token, got %s", err)
		}
	})

	t.Run("cannot validate a tampered token", func(t *testing.T) {
		tests := []struct {
			name         string
			tamperFunc   func(tokenString string) string
			expectError  bool
			errorMessage string
		}{
			{
				name: "missing token",
				tamperFunc: func(tokenString string) string {
					return ""
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for tampered signature",
			},
			{
				name: "tampered signature",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf("%s.%sx", tokenSplits[0], tokenSplits[1])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for tampered signature",
			},
			{
				name: "missing signature",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf("%s.", tokenSplits[0])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for missing signature",
			},
			{
				name: "space in signature",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf("%s. %s", tokenSplits[0], tokenSplits[1])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for missing signature",
			},
			{
				name: "tampered secret",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf("x%s.%s", tokenSplits[0], tokenSplits[1])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for extra data in token",
			},
			{
				name: "missing secret",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf(".%s", tokenSplits[1])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for extra data in token",
			},
			{
				name: "space in secret",
				tamperFunc: func(tokenString string) string {
					tokenSplits := strings.Split(tokenString, ".")
					return fmt.Sprintf(" %s.%s", tokenSplits[0], tokenSplits[1])
				},
				expectError:  true,
				errorMessage: "Expected an invalid token error for extra data in token",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				notBefore := time.Now().Unix()
				expiresAt := notBefore + 3600
				tokenString, _, err := vault.createToken(ctx, testPrincipal, testPrincipal.Policies, notBefore, expiresAt)
				if err != nil {
					t.Fatal(err)
				}

				tamperedToken := test.tamperFunc(tokenString)

				_, err = vault.ValidateAndGetToken(ctx, tamperedToken)
				var tokenErr *InvalidTokenError
				if (err == nil || !errors.As(err, &tokenErr)) != !test.expectError {
					t.Fatalf(test.errorMessage+" got %s", err)
				}
			})
		}

	})

	t.Run("cannot validate a token with incorrect secret", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		tokenString, _, err := vault.createToken(ctx, testPrincipal, testPrincipal.Policies, notBefore, expiresAt)
		if err != nil {
			t.Fatal(err)
		}

		tamperedToken := "x" + tokenString

		_, err = vault.ValidateAndGetToken(ctx, tamperedToken)
		var tokenErr *InvalidTokenError
		if err == nil || !errors.As(err, &tokenErr) {
			t.Fatalf("Expected an invalid token error for tampered token, got %s", err)
		}
	})

}

func TestLoginFunctionality(t *testing.T) {
	ctx := context.Background()
	vault, _, _ := initVault(t)
	testPrincipal := Principal{
		Username:    "test_user",
		Password:    "test_password",
		Policies:    []string{"root"},
		Description: "test principal",
	}
	err := vault.CreatePrincipal(ctx, testPrincipal, testPrincipal.Username, testPrincipal.Password, testPrincipal.Description, testPrincipal.Policies)
	if err != nil {
		t.Fatalf("Failed to create test principal: %v", err)
	}

	t.Run("can succesfully login", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		_, _, err := vault.Login(ctx, testPrincipal.Username, testPrincipal.Password, testPrincipal.Policies, notBefore, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("can't login without a username or password", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		userPassCombo := []struct {
			username string
			password string
		}{
			{"", ""},
			{"", testPrincipal.Password},
			{testPrincipal.Username, ""},
		}

		for _, combo := range userPassCombo {
			_, _, err := vault.Login(ctx, combo.username, combo.password, testPrincipal.Policies, notBefore, expiresAt)
			var valueErr *ValueError
			if err == nil || !errors.As(err, &valueErr) {
				t.Fatalf("Expected a value error for non-existing policy, got %s", err)
			}
		}

	})

	t.Run("can't login with invalid credentials", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		_, _, err := vault.Login(ctx, "xx", "yy", testPrincipal.Policies, notBefore, expiresAt)
		var forbiddenErr *ForbiddenError
		if err == nil || !errors.As(err, &forbiddenErr) {
			t.Fatalf("Expected a forbidden error for invalid credentials, got %s", err)
		}
	})
	t.Run("can't login with a notBefore > expiresAt", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore - 3600
		_, _, err := vault.Login(ctx, testPrincipal.Username, testPrincipal.Password, testPrincipal.Policies, notBefore, expiresAt)
		var valueErr *ValueError
		if err == nil || !errors.As(err, &valueErr) {
			t.Fatalf("Expected a value error for non-existing policy, got %s", err)
		}
	})
	t.Run("principal can't specify login policies without having ownership of them", func(t *testing.T) {
		notBefore := time.Now().Unix()
		expiresAt := notBefore + 3600
		_, _, err := vault.Login(ctx, testPrincipal.Username, testPrincipal.Password, []string{"not-real-policy"}, notBefore, expiresAt)
		var valueErr *ValueError
		if err == nil || !errors.As(err, &valueErr) {
			t.Fatalf("Expected a value error for non-existing policy, got %s", err)
		}
	})

}
