package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Record map[string]interface{}

type Collection struct {
	Name   string `db:"name"`
	Fields []CollectionField
}

type CollectionField struct {
	Name    string `db:"name"`
	Type    string `db:"type"`
	Indexed bool   `db:"indexed"`
}

type SQLiteVaultDB struct {
	db *sqlx.DB
}

func NewSQLiteVaultDB(dataSourceName string) *SQLiteVaultDB {
	db, err := sqlx.Connect("sqlite3", dataSourceName)
	if err != nil {
		log.Fatalln(err)
	}
	v := &SQLiteVaultDB{db: db}
	v.initialize()
	return v
}

func (v *SQLiteVaultDB) initialize() {
	// Define the collections_metadata table
	collectionsSchema := `
        CREATE TABLE IF NOT EXISTS collections_metadata (
            name TEXT PRIMARY KEY NOT NULL
        );
    `

	_, err := v.db.Exec(collectionsSchema)
	if err != nil {
		log.Fatalln(err)
	}

	// Define the fields_metadata table
	fieldsSchema := `
        CREATE TABLE IF NOT EXISTS fields_metadata (
            collection_name TEXT NOT NULL REFERENCES collections_metadata(name) ON DELETE CASCADE,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            PRIMARY KEY (collection_name, name)
        );
    `

	_, err = v.db.Exec(fieldsSchema)
	if err != nil {
		log.Fatalln(err)
	}
}

func (v *SQLiteVaultDB) CreateCollection(ctx context.Context, collection Collection) error {
	tx, err := v.db.Beginx()
	if err != nil {
		return err
	}

	// Insert into collections_metadata table
	_, err = tx.Exec("INSERT INTO collections_metadata (name) VALUES (?)", collection.Name)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Insert into fields_metadata table
	for _, field := range collection.Fields {
		query := `INSERT INTO fields_metadata (collection_name, name, type) VALUES (?, ?, ?)`
		_, err := tx.Exec(query, collection.Name, field.Name, field.Type)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Dynamically create a new table for the collection using the provided fields
	fieldDeclarations := make([]string, 0, len(collection.Fields))
	for _, field := range collection.Fields {
		fieldDeclarations = append(fieldDeclarations, fmt.Sprintf("%s %s", field.Name, field.Type))
	}

	createTableSQL := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s (%s)",
		collection.Name,
		strings.Join(fieldDeclarations, ", "),
	)
	_, err = tx.Exec(createTableSQL)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, field := range collection.Fields {
		if field.Indexed {
			indexSQL := fmt.Sprintf(
				"CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)",
				collection.Name, field.Name, collection.Name, field.Name,
			)
			_, err = tx.Exec(indexSQL)
			if err != nil {
				tx.Rollback()
				return err
			}
		}
	}

	return tx.Commit()
}

func (v *SQLiteVaultDB) GetCollection(ctx context.Context, collectionName string) (*Collection, error) {
	fields := []CollectionField{}

	err := v.db.Select(&fields, "SELECT name, type FROM fields_metadata WHERE collection_name=?", collectionName)
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		Name:   collectionName,
		Fields: fields,
	}

	return collection, nil
}

func (v *SQLiteVaultDB) CreateRecords(ctx context.Context, collectionName string, records []Record) error {
	if len(records) == 0 {
		return nil
	}

	// Fetch the schema for the collection
	collection, err := v.GetCollection(ctx, collectionName)
	if err != nil {
		return err
	}

	// Create a map of the expected fields for easier checking
	expectedFields := make(map[string]string)
	for _, field := range collection.Fields {
		expectedFields[field.Name] = field.Type
	}

	for _, record := range records {
		// Check if the record contains all required fields and no extras
		for fieldName, fieldVal := range record {
			if expectedType, ok := expectedFields[fieldName]; ok {
				// Check the type (as a simple example, just check if it's text)
				if expectedType == "TEXT" && fmt.Sprintf("%T", fieldVal) != "string" {
					return fmt.Errorf("field '%s' should be of type 'TEXT'", fieldName)
				} else if expectedType == "REAL" && fmt.Sprintf("%T", fieldVal) != "float64" {
					return fmt.Errorf("field '%s' should be of type 'REAL'", fieldName)
				}
			} else {
				return fmt.Errorf("extra field '%s' found in record, not part of the schema", fieldName)
			}
		}
	}

	// Bulk insert
	keys := make([]string, 0, len(records[0]))
	for key := range records[0] {
		keys = append(keys, key)
	}

	// Individual record placeholder, e.g., (?, ?, ?)
	recordPlaceholder := "(" + strings.Join(strings.Split(strings.Repeat("?", len(keys)), ""), ", ") + ")"

	// All records placeholders, e.g., (?, ?, ?), (?, ?, ?), ...
	allPlaceholders := strings.Repeat(recordPlaceholder+",", len(records)-1) + recordPlaceholder

	values := make([]interface{}, 0, len(records)*len(keys))
	for _, record := range records {
		for _, key := range keys {
			values = append(values, record[key])
		}
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s", // Note: removed the inner () around placeholders.
		collectionName,
		strings.Join(keys, ", "),
		allPlaceholders,
	)

	_, err = v.db.ExecContext(ctx, query, values...)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	db := NewSQLiteVaultDB("vault.db")

	collection1 := Collection{
		Name: "users",
		Fields: []CollectionField{
			{Name: "username", Type: "TEXT", Indexed: true},
			{Name: "email", Type: "TEXT", Indexed: true},
		},
	}

	err := db.CreateCollection(context.Background(), collection1)
	if err != nil {
		log.Fatalln(err)
	}

	collection2 := Collection{
		Name: "products",
		Fields: []CollectionField{
			{Name: "product_name", Type: "TEXT", Indexed: true},
			{Name: "price", Type: "REAL"},
		},
	}

	err = db.CreateCollection(context.Background(), collection2)
	if err != nil {
		log.Fatalln(err)
	}

	records1 := []Record{
		{
			"username": "alice",
			"email":    "alice@example.com",
		},
		{
			"username": "bob",
			"email":    "bob@example.com",
		},
	}

	err = db.CreateRecords(context.Background(), "users", records1)
	if err != nil {
		log.Fatalln(err)
	}

	records2 := []Record{
		{
			"product_name": "laptop",
			"price":        1000.0,
		},
		{
			"product_name": "phone",
			"price":        500.0,
		},
	}

	err = db.CreateRecords(context.Background(), "products", records2)
	if err != nil {
		log.Fatalln(err)
	}
}
