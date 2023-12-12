package main

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Define your models
type dbPolicy struct {
	Id          string `gorm:"primaryKey"`
	Name        string
	Description string
	Effect      string
	Actions     pq.StringArray `gorm:"type:text[]"`
	Resources   pq.StringArray `gorm:"type:text[]"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (dbPolicy) TableName() string {
	return "policies"
}

type dbPrincipal struct {
	Id          string `gorm:"primaryKey"`
	Username    string
	Password    string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Policies    []dbPolicy `gorm:"many2many:principal_policies;"`
}

func (dbPrincipal) TableName() string {
	return "principals"
}

type dbToken struct {
	Id        string `gorm:"primaryKey"`
	value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (dbToken) TableName() string {
	return "tokens"
}

type PrincipalPolicy struct {
	PrincipalId string `gorm:"primaryKey;autoIncrement:false"`
	PolicyId    string `gorm:"primaryKey;autoIncrement:false"`
}

func (PrincipalPolicy) TableName() string {
	return "principal_policies"
}

type Field struct {
	Type      string `json:"type"`
	IsIndexed bool   `json:"indexed"`
}

type FieldSchemaMap map[string]Field

func (f *FieldSchemaMap) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSONB value")
	}

	result := FieldSchemaMap{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return err
	}

	*f = result
	return nil
}

func (f FieldSchemaMap) Value() (driver.Value, error) {
	if len(f) == 0 {
		return nil, nil
	}

	return json.Marshal(f)
}

type dbCollectionMetadata struct {
	Id          string         `gorm:"primaryKey"`
	Name        string         `gorm:"unique"`
	FieldSchema FieldSchemaMap `gorm:"type:json"` // Ensures JSON storage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (dbCollectionMetadata) TableName() string {
	return "collections_metadata"
}

func main() {
	// Setup database connection
	time.Local = time.UTC
	dsn := "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Drop tables
	db.Exec("DROP TABLE IF EXISTS principal_policies")
	db.Exec("DROP TABLE IF EXISTS principals")
	db.Exec("DROP TABLE IF EXISTS policies")
	db.Exec("DROP TABLE IF EXISTS collections_metadata")

	// AutoMigrate models
	db.AutoMigrate(&dbPrincipal{}, &dbPolicy{}, &PrincipalPolicy{}, &dbCollectionMetadata{})

	// Create a Policy

	policy := dbPolicy{
		Id:          "policy1",
		Name:        "Test Policy",
		Description: "A test policy",
		Effect:      "allow",
		Actions:     []string{"read", "write"},
		Resources:   []string{"resource1", "resource2"},
	}

	db.Create(&policy)

	// Create a Principal with the created Policy
	principal := dbPrincipal{
		Id:          "principal1",
		Username:    "john_doe",
		Password:    "secret",
		Description: "A test principal",
		Policies:    []dbPolicy{policy},
	}
	db.Create(&principal)

	// Retrieve a Principal with their Policies - this can be looped over
	var retrievedPrincipal dbPrincipal
	db.Preload("Policies").First(&retrievedPrincipal, "id = ?", "principal1")

	// Pattern for deleting a Principal and associated records
	// Start a new transaction
	tx := db.Begin()

	// Defer a function that will commit the transaction if no errors, or rollback if there were any
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// Delete a Principal and cascade delete associated records in PrincipalPolicy
	if err := tx.Where("principal_id = ?", principal.Id).Delete(&PrincipalPolicy{}).Error; err != nil {
		log.Fatal(err)
	}

	// Then, delete the principal
	if err := tx.Delete(principal).Error; err != nil {
		log.Fatal(err)
	}

	// Create a CollectionMetadata
	collectionMetadata := dbCollectionMetadata{
		Id:          "collection1",
		Name:        "customers",
		FieldSchema: map[string]Field{"name": {Type: "phone", IsIndexed: true}},
	}

	db.Create(&collectionMetadata)
	result := db.Create(&collectionMetadata)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			log.Print("Collection already exists") // we'd return a 409 here
		} else {
			log.Fatal(result.Error)
		}
	}

	// Now let's retrieve the CollectionMetadata
	var retrievedCollectionMetadata dbCollectionMetadata
	db.First(&retrievedCollectionMetadata, "id = ?", "collection1")
	fmt.Println(retrievedCollectionMetadata.FieldSchema["name"].Type)
}
