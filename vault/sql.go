package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		"policies":            "CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, effect TEXT, actions TEXT[], resources TEXT[])",
		"principal_policies":  "CREATE TABLE IF NOT EXISTS principal_policies (username TEXT, policy_id TEXT, UNIQUE(username, policy_id))",
		"tokens":              "CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, value TEXT)",
		"collection_metadata": "CREATE TABLE IF NOT EXISTS collection_metadata (name TEXT PRIMARY KEY, field_schema JSON)",
	}

	for _, query := range tables {
		_, err := st.db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

func (st *SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", err
	}

	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	fieldSchema, err := json.Marshal(c.Fields)
	if err != nil {
		return "", err
	}

	_, err = tx.NamedExecContext(ctx, "INSERT INTO collection_metadata (name, field_schema) VALUES (:name, :field_schema)", map[string]interface{}{
		"name":         c.Name,
		"field_schema": fieldSchema,
	})
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return "", &ConflictError{c.Name}
			}
		}
		return "", err
	}

	tableName := "collection_" + c.Name
	var queryBuilder strings.Builder
	queryBuilder.WriteString("CREATE TABLE IF NOT EXISTS " + tableName + " (id TEXT PRIMARY KEY")
	for fieldName := range c.Fields {
		queryBuilder.WriteString(", " + fieldName + " TEXT")
	}
	queryBuilder.WriteString(")")
	_, err = tx.ExecContext(ctx, queryBuilder.String())
	if err != nil {
		return "", err
	}

	err = tx.Commit()
	if err != nil {
		return "", err
	}

	return c.Name, nil
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var fieldSchema json.RawMessage
	err := st.db.GetContext(ctx, &fieldSchema, "SELECT field_schema FROM collection_metadata WHERE name = $1", name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", name}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(fieldSchema, &fields)
	if err != nil {
		return nil, err
	}
	return &Collection{Name: name, Fields: fields}, nil
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var collectionNames []string

	err := st.db.SelectContext(ctx, &collectionNames, "SELECT name FROM collection_metadata")

	return collectionNames, err
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			rbErr := tx.Rollback()
			if rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	result, err := tx.ExecContext(ctx, "DELETE FROM collection_metadata WHERE name = $1", name)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"collection", name}
	}

	tableName := "collection_" + name
	_, err = tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+tableName)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	var fieldSchema json.RawMessage
	err := st.db.GetContext(ctx, &fieldSchema, "SELECT field_schema FROM collection_metadata WHERE name = $1", collectionName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(fieldSchema, &fields)
	if err != nil {
		return nil, err
	}

	fieldNames := make([]string, 0, len(fields))
	placeholders := make([]string, 0, len(fields))
	idx := 2 // Start from 2 because $1 is reserved for recordId

	for fieldName := range fields {
		fieldNames = append(fieldNames, fieldName)
		placeholders = append(placeholders, fmt.Sprintf("$%d", idx))
		idx++
	}

	query := fmt.Sprintf("INSERT INTO collection_%s (id, %s) VALUES ($1, %s)", collectionName, strings.Join(fieldNames, ", "), strings.Join(placeholders, ", "))
	stmt, err := st.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	recordIds := make([]string, len(records))
	for i, record := range records {
		// Validate record fields
		if len(record) != len(fields) {
			return nil, &ValueError{fmt.Sprintf("expected %d fields, got %d", len(fields), len(record))}
		}

		recordId := GenerateId()
		recordIds[i] = recordId

		values := make([]interface{}, len(fields)+1)
		values[0] = recordId
		for j, fieldName := range fieldNames {
			if value, ok := record[fieldName]; ok {
				values[j+1] = value
			} else {
				return nil, &ValueError{fmt.Sprintf("missing field %s", fieldName)}
			}
		}

		_, err = stmt.ExecContext(ctx, values...)
		if err != nil {
			return nil, err
		}
	}
	return recordIds, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var fieldSchema json.RawMessage
	err := st.db.GetContext(ctx, &fieldSchema, "SELECT field_schema FROM collection_metadata WHERE name = $1", collectionName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, err
	}

	var fields map[string]Field
	err = json.Unmarshal(fieldSchema, &fields)
	if err != nil {
		return nil, err
	}

	query, args, err := sqlx.In("SELECT * FROM collection_"+collectionName+" WHERE id IN (?)", recordIDs)
	if err != nil {
		return nil, err
	}
	query = st.db.Rebind(query)

	rows, err := st.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make(map[string]*Record)
	for rows.Next() {
		recordMap := make(map[string]interface{})
		err = rows.MapScan(recordMap)
		if err != nil {
			return nil, err
		}
		recordID := recordMap["id"].(string)
		record := make(Record)
		for k, v := range recordMap {
			if str, ok := v.(string); ok {
				record[k] = str
			} else {
				// We're assuming all record fields are strings as they are encrypted in the db, this might change
				return nil, fmt.Errorf("unexpected type for field %s", k)
			}
		}
		records[recordID] = &record
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	var fieldNames []string
	var fieldValues []interface{}
	for fieldName, fieldValue := range record {
		fieldNames = append(fieldNames, fieldName)
		fieldValues = append(fieldValues, fieldValue)
	}

	setClause := make([]string, len(fieldNames))
	for i, fieldName := range fieldNames {
		setClause[i] = fmt.Sprintf("%s = $%d", fieldName, i+1)
	}

	query := fmt.Sprintf("UPDATE collection_%s SET %s WHERE id = $%d", collectionName, strings.Join(setClause, ", "), len(fieldNames)+1)
	_, err := st.db.ExecContext(ctx, query, append(fieldValues, recordID)...)
	return err
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	res, err := st.db.ExecContext(ctx, "DELETE FROM collection_"+collectionName+" WHERE id = $1", recordID)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"record", recordID}
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

	defer func() {
		if err != nil {
			rbErr := tx.Rollback()
			if rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	_, err = tx.NamedExecContext(ctx, "INSERT INTO principals (username, password, description) VALUES (:username, :password, :description)", &principal)
	if err != nil {
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

	defer func() {
		if p := recover(); p != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after panic: %v", rbErr, p)
			}
		} else if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	_, err = tx.ExecContext(ctx, "DELETE FROM principal_policies WHERE username = $1", username)
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, "DELETE FROM principals WHERE username = $1", username)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"principal", username}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	var id, effect string
	var actions []string
	var resources []string

	err := st.db.QueryRowxContext(ctx, "SELECT id, effect, actions, resources FROM policies WHERE id = $1", policyId).Scan(&id, &effect, pq.Array(&actions), pq.Array(&resources))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"policy", policyId}
		}
		return nil, err
	}

	actionList := make([]PolicyAction, len(actions))
	for i, action := range actions {
		actionList[i] = PolicyAction(action)
	}

	p := Policy{
		PolicyId:  id,
		Effect:    PolicyEffect(effect),
		Actions:   actionList,
		Resources: resources,
	}

	return &p, nil
}

func (st SqlStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
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
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", err
	}

	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	query := "INSERT INTO policies (id, effect, actions, resources) VALUES (:id, :effect, :actions, :resources)"
	actions := make(pq.StringArray, len(p.Actions))
	for i, action := range p.Actions {
		actions[i] = string(action)
	}
	resources := make(pq.StringArray, len(p.Resources))
	copy(resources, p.Resources)
	query, args, err := sqlx.Named(query, map[string]interface{}{
		"id":        p.PolicyId,
		"effect":    string(p.Effect),
		"actions":   actions,
		"resources": resources,
	})

	if err != nil {
		return "", err
	}
	query = tx.Rebind(query)
	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return "", &ConflictError{p.PolicyId}
			}
		}
		return "", err
	}

	err = tx.Commit()
	if err != nil {
		return "", err
	}

	return p.PolicyId, nil
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyID string) error {
	tx, err := st.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = fmt.Errorf("rollback failed: %v, after error: %v", rbErr, err)
			}
		}
	}()

	result, err := tx.ExecContext(ctx, "DELETE FROM policies WHERE id = $1", policyID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"policy", policyID}
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM principal_policies WHERE policy_id = $1", policyID)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	_, err := st.db.ExecContext(ctx, "INSERT INTO tokens (id, value) VALUES ($1, $2)", tokenId, value)
	return err
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	_, err := st.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = $1", tokenId)
	return err
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var value string
	err := st.db.GetContext(ctx, &value, "SELECT value FROM tokens WHERE id = $1", tokenId)
	return value, err
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
	err = st.CreateSchemas()
	if err != nil {
		return err
	}
	return nil
}
