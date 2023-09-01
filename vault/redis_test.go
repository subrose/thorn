package vault

import (
	"context"
	"os"
	"sort"
	"testing"
)

func initDB() (VaultDB, error) {
	db, err := NewRedisStore(
		os.Getenv("KEYDB_CONN_STRING"),
		"",
		0,
	)
	if err != nil {
		return nil, err
	}
	db.Flush(context.Background())

	return db, nil
}

// TODO: These need to be separate tests latr on and probably mocked...

func TestRedisStore(t *testing.T) {
	t.Run("can crud collections and records", func(t *testing.T) {
		ctx := context.Background()
		db, err := initDB()

		if err != nil {
			t.Fatal(err)
		}

		dbCols, err := db.GetCollections(ctx)
		if err != nil {
			t.Fatal(err)
		}

		if len(dbCols) != 0 {
			t.Fatal("Expected 0 collections, got", len(dbCols))
		}

		col := Collection{Name: "customers", Fields: map[string]Field{
			"name": {
				Type:      "string",
				IsIndexed: false,
			},
			"age": {
				Name:      "age",
				Type:      "integer",
				IsIndexed: false,
			},
			"country": {
				Name:      "country",
				Type:      "string",
				IsIndexed: true,
			},
		}}

		// Can create collection
		colID, err := db.CreateCollection(ctx, col)
		if err != nil || colID == "" {
			t.Fatal(err)
		}

		dbCols, err = db.GetCollections(ctx)
		if err != nil {
			t.Fatal(err)
		}

		if len(dbCols) != 1 {
			t.Fatal("Expected 1 collection, got", len(dbCols))
		}

		if dbCols[0] != col.Name {
			t.Fatal("Expected collection name to be 'test', got", dbCols[0])
		}

		newCol, _ := db.GetCollection(ctx, dbCols[0])
		fields := newCol.Fields
		if fields["country"].Name != "country" || fields["country"].Type != "string" || !fields["country"].IsIndexed {
			t.Fatal("Field props not matching.")
		}

		// Can add records
		records := []Record{
			{"name": "Simon", "age": "10", "country": "Ahibia"},
			{"name": "Ali", "age": "11", "country": "Bolonesia"},
			{"name": "Jim", "age": "22", "country": "Sarumania"},
			{"name": "Jeff", "age": "22", "country": "Ahibia"},
		}

		recordIds, err := db.CreateRecords(ctx, col.Name, records)
		if err != nil {
			t.Fatal(err)
		}

		// Can get records
		dbRecords, err := db.GetRecords(ctx, recordIds)
		if err != nil {
			t.Fatal(err)
		}
		if len(dbRecords) != len(records) {
			t.Fatalf("Expected %d records, got %d", len(records), len(dbRecords))
		}

		// Can delete records
		err = db.DeleteRecord(ctx, col.Name, recordIds[0])
		if err != nil {
			t.Fatal(err)
		}

		// Verify deletion of the record
		deleteRecord, err := db.GetRecords(ctx, []string{recordIds[0]})
		if err == nil {
			t.Fatal(err)
		}
		if len(deleteRecord) != 0 {
			t.Fatal("Record not deleted.")
		}

	})

	t.Run("can create and get principals", func(t *testing.T) {
		ctx := context.Background()
		db, err := initDB()

		if err != nil {
			t.Fatal(err)
		}

		// Note: password is not encrypted when storing this way, but it's just for testing purposes.
		// The principal object should be created at the vault level.
		principal := Principal{
			Username:    "test",
			Password:    "test",
			Description: "test",
			CreatedAt:   "0",
			Policies:    []string{"read-customers", "write-credit-cards"},
		}

		// Can create principal
		err = db.(PrincipalManager).CreatePrincipal(ctx, principal)
		if err != nil {
			t.Fatal(err)
		}

		// Can get principal
		dbPrincipalRead, err := db.(PrincipalManager).GetPrincipal(ctx, principal.Username)
		if err != nil {
			t.Fatal(err)
		}

		if dbPrincipalRead.Username != principal.Username || dbPrincipalRead.Description != principal.Description {
			t.Fatal("Principal props not matching.")
		}

		// Returned policies match
		if len(principal.Policies) != len(dbPrincipalRead.Policies) {
			t.Fatalf("Principal policies not matching. Expected %d, got %d", len(principal.Policies), len(dbPrincipalRead.Policies))
		}

		sort.Strings(principal.Policies)
		sort.Strings(dbPrincipalRead.Policies)
		for i, role := range principal.Policies {
			if role != dbPrincipalRead.Policies[i] {
				t.Fatalf("Principal policies not matching at index %d. Expected %s, got %s", i, role, dbPrincipalRead.Policies[i])
			}
		}
	})

}
