package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"database/sql"

	_ "github.com/jackc/pgx/v5"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type SqlStore struct {
	db *sqlx.DB
}

type DbRecord struct {
	Id             string
	CollectionName string
	Record         json.RawMessage
}

type DbCollection struct {
	Name       string `db:"name"`
	Collection json.RawMessage
}

type DbToken struct {
	ID    string `db:"id"`
	Value string
}

type CollectionMetadata struct {
	Name        string
	FieldSchema json.RawMessage `db:"field_schema"`
}

func NewSqlStore(dsn string) (*SqlStore, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	store := &SqlStore{db}

	err = store.CreateSchemas()
	if err != nil {
		return nil, err
	}

	return store, nil
}

func (st *SqlStore) CreateSchemas() error {
	tables := map[string]string{
		"principals":          "CREATE TABLE IF NOT EXISTS principals (username TEXT PRIMARY KEY, password TEXT, description TEXT)",
		"policies":            "CREATE TABLE IF NOT EXISTS policies (id TEXT, effect TEXT, actions TEXT[], resources TEXT[])",
		"tokens":              "CREATE TABLE IF NOT EXISTS tokens (id TEXT, value TEXT)",
		"collection_metadata": "CREATE TABLE IF NOT EXISTS collection_metadata (name TEXT, field_schema JSON)",
		"principal_policies":  "CREATE TABLE IF NOT EXISTS principal_policies (username TEXT, policy_id TEXT)",
	}

	for _, query := range tables {
		_, err := st.db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

func (st SqlStore) createCollectionTable(ctx context.Context, c Collection) error {
	// Define a dynamic struct based on the Fields of the collection
	var dynamicStructFields []reflect.StructField

	// Add an ID field to the struct
	idField := reflect.StructField{
		Name: "ID",
		Type: reflect.TypeOf(""),
		Tag:  reflect.StructTag(`db:"id"`),
	}
	dynamicStructFields = append(dynamicStructFields, idField)

	for fieldName := range c.Fields {
		exportedFieldName := strings.Title(fieldName)
		structField := reflect.StructField{
			Name: exportedFieldName,
			Type: reflect.TypeOf(""), // Assuming all fields are strings for simplicity
			Tag:  reflect.StructTag(fmt.Sprintf(`db:"%s"`, fieldName)),
		}
		dynamicStructFields = append(dynamicStructFields, structField)
	}

	// dynamicStruct := reflect.StructOf(dynamicStructFields)
	// dynamicStructPtr := reflect.New(dynamicStruct).Interface() // Create a pointer to a new instance of the dynamic struct

	tableName := "collection_" + c.Name // Create a unique table name

	// Create the table using SQLX's MustExec with a pointer to the dynamic struct
	// st.db.MustExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+tableName+" (?)", dynamicStructPtr)
	// Instead of using the dynamic struct directly, we will generate the SQL query manually
	var queryBuilder strings.Builder
	queryBuilder.WriteString("CREATE TABLE IF NOT EXISTS " + tableName + " (id TEXT")
	for fieldName := range c.Fields {
		queryBuilder.WriteString(", " + fieldName + " TEXT")
	}
	queryBuilder.WriteString(")")
	st.db.MustExecContext(ctx, queryBuilder.String())

	return nil
}

func (st SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	// Convert the Fields map to JSON for storing in the collection_metadata table
	fieldSchema, err := json.Marshal(c.Fields)
	if err != nil {
		return "", err
	}

	// Create a new CollectionMetadata instance
	collectionMetadata := CollectionMetadata{
		Name:        c.Name,
		FieldSchema: fieldSchema,
	}

	// Save the collection metadata
	_, err = st.db.NamedExecContext(ctx, "INSERT INTO collection_metadata (name, field_schema) VALUES (:name, :field_schema)", &collectionMetadata)
	if err != nil {
		return "", err
	}

	// Dynamically create a table for the collection
	if err := st.createCollectionTable(ctx, c); err != nil {
		return "", err
	}

	return collectionMetadata.Name, nil
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var collectionMetadata CollectionMetadata
	err := st.db.GetContext(ctx, &collectionMetadata, "SELECT * FROM collection_metadata WHERE name = $1", name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", name}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(collectionMetadata.FieldSchema, &fields)
	if err != nil {
		return nil, err
	}
	return &Collection{Name: collectionMetadata.Name, Fields: fields}, nil
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var collectionMetadatas []CollectionMetadata

	err := st.db.SelectContext(ctx, &collectionMetadatas, "SELECT * FROM collection_metadata")

	collectionNames := make([]string, len(collectionMetadatas))
	for i, collectionMetadata := range collectionMetadatas {
		collectionNames[i] = collectionMetadata.Name
	}
	return collectionNames, err
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	// Start a transaction
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	// Delete the collection metadata
	_, err = tx.ExecContext(ctx, "DELETE FROM collection_metadata WHERE name = $1", name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return &NotFoundError{"collection", name}
		}
		tx.Rollback()
		return err
	}

	// Delete the dynamic table
	tableName := "collection_" + name
	_, err = tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+tableName)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	var collectionMetadata CollectionMetadata
	err := st.db.GetContext(ctx, &collectionMetadata, "SELECT * FROM collection_metadata WHERE name = $1", collectionName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(collectionMetadata.FieldSchema, &fields)
	if err != nil {
		return nil, err
	}

	// Create slice for field names and initialize placeholders
	fieldNames := make([]string, 0, len(fields))
	placeholders := make([]string, 0, len(fields))
	idx := 2 // Start from 2 because $1 is reserved for recordId

	for fieldName := range fields {
		fieldNames = append(fieldNames, fieldName)
		placeholders = append(placeholders, fmt.Sprintf("$%d", idx))
		idx++
	}

	// Prepare SQL statement
	query := fmt.Sprintf("INSERT INTO collection_%s (id, %s) VALUES ($1, %s)", collectionName, strings.Join(fieldNames, ", "), strings.Join(placeholders, ", "))
	stmt, err := st.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	// Processing records
	recordIds := make([]string, len(records))
	for i, record := range records {
		// Validate record fields
		if len(record) != len(fields) {
			return nil, errors.New("record does not match schema")
		}

		recordId := GenerateId()
		recordIds[i] = recordId

		// Prepare values for insertion
		values := make([]interface{}, len(fields)+1)
		values[0] = recordId
		for j, fieldName := range fieldNames {
			if value, ok := record[fieldName]; ok {
				values[j+1] = value
			} else {
				return nil, fmt.Errorf("missing field: %s", fieldName)
			}
		}

		// Execute the prepared statement
		_, err = stmt.ExecContext(ctx, values...)
		if err != nil {
			return nil, err
		}
	}
	return recordIds, nil
}

// func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
// 	var collectionMetadata CollectionMetadata
// 	err := st.db.GetContext(ctx, &collectionMetadata, "SELECT * FROM collection_metadata WHERE name = $1", collectionName)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return nil, &NotFoundError{"collection", collectionName}
// 		}
// 		return nil, err
// 	}

// 	var fields map[string]Field
// 	err = json.Unmarshal(collectionMetadata.FieldSchema, &fields)
// 	if err != nil {
// 		return nil, err
// 	}

// 	recordIds := make([]string, len(records))
// 	for i, record := range records {
// 		recordId := GenerateId()
// 		recordIds[i] = recordId
// 		// Create a slice to hold the field names and values
// 		var fieldNames []string
// 		var fieldValues []interface{}
// 		for fieldName, fieldValue := range record {
// 			if _, ok := fields[fieldName]; ok {
// 				fieldNames = append(fieldNames, fieldName)
// 				fieldValues = append(fieldValues, fieldValue)
// 			}
// 		}

// 		// Generate placeholders for each field value
// 		placeholders := make([]string, len(fieldValues))
// 		for i := range placeholders {
// 			placeholders[i] = "$" + strconv.Itoa(i+2) // Start from $2 as $1 is reserved for recordId
// 		}

// 		// Construct the query
// 		query := fmt.Sprintf(
// 			"INSERT INTO collection_%s (id, %s) VALUES ($1, %s)",
// 			collectionName,
// 			strings.Join(fieldNames, ", "),
// 			strings.Join(placeholders, ", "),
// 		)

// 		// Append the recordId and fieldValues to form the final values for the query
// 		values := make([]interface{}, len(fieldValues)+1)
// 		values[0] = recordId
// 		copy(values[1:], fieldValues)

// 		_, err = st.db.ExecContext(ctx, query, values...)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	return recordIds, nil
// }

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var collectionMetadata CollectionMetadata
	err := st.db.GetContext(ctx, &collectionMetadata, "SELECT * FROM collection_metadata WHERE name = $1", collectionName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(collectionMetadata.FieldSchema, &fields)
	if err != nil {
		return nil, err
	}

	records := make(map[string]*Record)
	for _, recordId := range recordIDs {
		record := make(Record)
		for fieldName := range fields {
			var fieldValue string
			err := st.db.GetContext(ctx, &fieldValue, "SELECT "+fieldName+" FROM collection_"+collectionName+" WHERE id = $1", recordId)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil, &NotFoundError{"record", recordId}
				}
				return nil, err
			}
			record[fieldName] = fieldValue
		}
		records[recordId] = &record
	}
	return records, nil
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	var collectionMetadata CollectionMetadata
	err := st.db.GetContext(ctx, &collectionMetadata, "SELECT * FROM collection_metadata WHERE name = $1", collectionName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &NotFoundError{"collection", collectionName}
		}
		return err
	}

	var fields map[string]Field
	err = json.Unmarshal(collectionMetadata.FieldSchema, &fields)
	if err != nil {
		return err
	}

	var fieldNames []string
	var fieldValues []interface{}
	for fieldName, fieldValue := range record {
		if _, ok := fields[fieldName]; ok {
			fieldNames = append(fieldNames, fieldName)
			fieldValues = append(fieldValues, fieldValue)
		}
	}

	setClause := make([]string, len(fieldNames))
	for i, fieldName := range fieldNames {
		setClause[i] = fmt.Sprintf("%s = $%d", fieldName, i+1)
	}

	query := fmt.Sprintf("UPDATE collection_%s SET %s WHERE id = $%d", collectionName, strings.Join(setClause, ", "), len(fieldNames)+1)
	_, err = st.db.ExecContext(ctx, query, append(fieldValues, recordID)...)
	return err
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	_, err := st.db.ExecContext(ctx, "DELETE FROM collection_"+collectionName+" WHERE id = $1", recordID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &NotFoundError{"record", recordID}
		}
		return err
	}
	return nil
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	var principal Principal
	err := st.db.GetContext(ctx, &principal, "SELECT * FROM principals WHERE username = $1", username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	rows, err := st.db.QueryxContext(ctx, "SELECT policy_id FROM principal_policies WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policyIds []string
	for rows.Next() {
		var policyId string
		if err := rows.Scan(&policyId); err != nil {
			return nil, err
		}
		policyIds = append(policyIds, policyId)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	principal.Policies = policyIds

	return &principal, nil
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = tx.NamedExecContext(ctx, "INSERT INTO principals (username, password, description) VALUES (:username, :password, :description)", &principal)
	if err != nil {
		tx.Rollback()
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				return &ConflictError{principal.Username}
			}
		}
		return err
	}

	for _, policyId := range principal.Policies {
		_, err = tx.ExecContext(ctx, "INSERT INTO principal_policies (username, policy_id) VALUES ($1, $2)", principal.Username, policyId)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) DeletePrincipal(ctx context.Context, username string) error {
	// Start a transaction
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	// First, delete associations in the many-to-many join table
	_, err = tx.ExecContext(ctx, "DELETE FROM principal_policies WHERE username = $1", username)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Now, delete the principal itself
	_, err = tx.ExecContext(ctx, "DELETE FROM principals WHERE username = $1", username)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	var p Policy
	err := st.db.GetContext(ctx, &p, "SELECT * FROM policies WHERE id = $1", policyId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"policy", policyId}
		}
		return nil, err
	}

	return &p, err
}

func (st SqlStore) GetPoliciesById(ctx context.Context, policyIds []string) ([]*Policy, error) {
	if len(policyIds) == 0 {
		return []*Policy{}, nil
	}
	query, args, err := sqlx.In("SELECT id, effect, actions, resources FROM policies WHERE id IN (?)", policyIds)
	if err != nil {
		return nil, err
	}
	query = st.db.Rebind(query)
	rows, err := st.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := make([]*Policy, 0)
	for rows.Next() {
		var id, effect string
		var actions []string
		var resources []string

		err = rows.Scan(&id, &effect, pq.Array(&actions), pq.Array(&resources))
		if err != nil {
			return nil, err
		}

		actionList := make([]PolicyAction, len(actions))
		for i, action := range actions {
			actionList[i] = PolicyAction(action)
		}

		policies = append(policies, &Policy{
			PolicyId:  id,
			Effect:    PolicyEffect(effect),
			Actions:   actionList,
			Resources: resources,
		})
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return policies, nil
}

func (st SqlStore) CreatePolicy(ctx context.Context, p Policy) (string, error) {

	// Start a transaction
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", err
	}

	query := "INSERT INTO policies (id, effect, actions, resources) VALUES (:id, :effect, :actions, :resources)"
	actions := make(pq.StringArray, len(p.Actions))
	for i, action := range p.Actions {
		actions[i] = string(action)
	}
	resources := make(pq.StringArray, len(p.Resources))
	for i, resource := range p.Resources {
		resources[i] = resource
	}
	query, args, err := sqlx.Named(query, map[string]interface{}{
		"id":        p.PolicyId,
		"effect":    string(p.Effect),
		"actions":   actions,
		"resources": resources,
	})

	if err != nil {
		tx.Rollback()
		return "", err
	}
	query = tx.Rebind(query)
	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return "", &ConflictError{p.PolicyId}
		}
		return "", err
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return "", err
	}

	return p.PolicyId, nil
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyID string) error {
	// Start a transaction
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	// Delete the policy itself
	result, err := tx.ExecContext(ctx, "DELETE FROM policies WHERE id = $1", policyID)
	if err != nil {
		tx.Rollback()
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		tx.Rollback()
		return err
	}
	if rowsAffected == 0 {
		tx.Rollback()
		return &NotFoundError{"policy", policyID}
	}

	// Directly delete associations in the many-to-many join table
	_, err = tx.ExecContext(ctx, "DELETE FROM principal_policies WHERE policy_id = $1", policyID)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	gt := DbToken{ID: tokenId, Value: value}
	_, err := st.db.NamedExecContext(ctx, "INSERT INTO tokens (id, value) VALUES (:id, :value)", &gt)
	return err
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	_, err := st.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = $1", tokenId)
	return err
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var gt DbToken
	err := st.db.GetContext(ctx, &gt, "SELECT * FROM tokens WHERE id = $1", tokenId)
	return gt.Value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	// Drop all tables
	tables := []string{}
	err := st.db.SelectContext(ctx, &tables, "SELECT tablename FROM pg_tables WHERE schemaname='public'")
	if err != nil {
		return err
	}
	for _, table := range tables {
		_, err = st.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+table)
		if err != nil {
			return err
		}
	}
	// Recreate schemas
	err = st.CreateSchemas()
	if err != nil {
		return err
	}
	return nil
}

// func (st SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
// 	b, err := json.Marshal(c)
// 	if err != nil {
// 		return "", err
// 	}

// 	gormCol := DbCollection{Name: c.Name, Collection: datatypes.JSON(b)}
// 	result := st.db.Create(&gormCol)
// 	if result.Error != nil {
// 		switch result.Error {
// 		case gorm.ErrDuplicatedKey:
// 			return "", &ConflictError{c.Name}
// 		}
// 	}

// 	return c.Name, nil
// }
