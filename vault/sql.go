package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	_ "github.com/jackc/pgx/v5"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
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
	ctb := sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable("principals").IfNotExists()
	ctb.Define("id", "TEXT", "PRIMARY KEY")
	ctb.Define("username", "TEXT", "UNIQUE")
	ctb.Define("password", "TEXT")
	ctb.Define("description", "TEXT")
	_, err := st.db.Exec(ctb.String())
	if err != nil {
		return err
	}

	ctb = sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable("policies").IfNotExists()
	ctb.Define("id", "TEXT", "PRIMARY KEY")
	ctb.Define("effect", "TEXT")
	ctb.Define("actions", "TEXT[]")
	ctb.Define("resources", "TEXT[]")
	_, err = st.db.Exec(ctb.String())
	if err != nil {
		return err
	}

	ctb = sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable("principal_policies").IfNotExists()
	ctb.Define("principal_id", "TEXT")
	ctb.Define("policy_id", "TEXT")
	ctb.Define("UNIQUE", "(principal_id, policy_id)")
	_, err = st.db.Exec(ctb.String())
	if err != nil {
		return err
	}

	ctb = sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable("tokens").IfNotExists()
	ctb.Define("id", "TEXT", "PRIMARY KEY")
	ctb.Define("value", "TEXT")
	_, err = st.db.Exec(ctb.String())
	if err != nil {
		return err
	}

	ctb = sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable("collection_metadata").IfNotExists()
	ctb.Define("id", "TEXT", "PRIMARY KEY")
	ctb.Define("name", "TEXT", "UNIQUE")
	ctb.Define("field_schema", "JSON")
	_, err = st.db.Exec(ctb.String())
	if err != nil {
		return err
	}

	return nil
}

func (st *SqlStore) CreateCollection(ctx context.Context, c *Collection) error {
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

	fieldSchema, err := json.Marshal(c.Fields)
	if err != nil {
		return err
	}

	ib := sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertIgnoreInto("collection_metadata")
	ib.Cols("id", "name", "field_schema")
	ib.Values(c.Id, c.Name, fieldSchema)

	sql, args := ib.Build()
	_, err = tx.ExecContext(ctx, sql, args...)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return &ConflictError{c.Name}
			}
		}
		return err
	}

	tableName := "collection_" + c.Name
	ctb := sqlbuilder.NewCreateTableBuilder()
	ctb.CreateTable(tableName).IfNotExists()
	ctb.Define("id", "TEXT", "PRIMARY KEY")
	for fieldName := range c.Fields {
		ctb.Define(fieldName, "TEXT")
	}
	_, err = tx.ExecContext(ctx, ctb.String())
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func getCollectionFields(ctx context.Context, db *sqlx.DB, collectionName string) (map[string]Field, error) {
	var fieldSchema json.RawMessage
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("field_schema").From("collection_metadata").Where(sb.Equal("name", collectionName))
	query, args := sb.Build()
	err := db.GetContext(ctx, &fieldSchema, query, args...)
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

	return fields, nil
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	fields, err := getCollectionFields(ctx, st.db, name)
	if err != nil {
		return nil, err
	}
	return &Collection{Name: name, Fields: fields}, nil
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var collectionNames []string
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("name").From("collection_metadata")
	cmd, args := sb.Build()
	err := st.db.SelectContext(ctx, &collectionNames, cmd, args...)
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

	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("collection_metadata").Where(db.Equal("name", name))
	cmd, args := db.Build()
	result, err := tx.ExecContext(ctx, cmd, args...)
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

	sql, args := sqlbuilder.WithFlavor(sqlbuilder.Buildf(fmt.Sprintf("DROP TABLE IF EXISTS collection_%v", name)), sqlbuilder.PostgreSQL).Build()
	_, err = tx.ExecContext(ctx, sql, args...)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) CreateRecord(ctx context.Context, collectionName string, record Record) (string, error) {
	fields, err := getCollectionFields(ctx, st.db, collectionName)
	if err != nil {
		return "", err
	}

	// Validate that the record matches the schema
	for fieldName := range fields {
		if _, ok := record[fieldName]; !ok {
			return "", &ValueError{Msg: fmt.Sprintf("Required field %s is missing from the record", fieldName)}
		}
		if _, ok := fields[fieldName]; !ok {
			return "", &ValueError{Msg: fmt.Sprintf("Field %s is not existent in the schema", fieldName)}
		}
	}

	ib := sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertInto(fmt.Sprintf("collection_%s", collectionName))

	recordId := GenerateId("rec")
	columns := []string{"id"}
	values := []interface{}{recordId}

	for fieldName, fieldValue := range record {
		columns = append(columns, fieldName)
		values = append(values, fieldValue)
	}

	ib.Cols(columns...)
	ib.Values(values...)
	query, args := ib.Build()

	_, err = st.db.ExecContext(ctx, query, args...)
	if err != nil {
		return "", err
	}

	return recordId, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string) ([]string, error) {
	var recordIds []string
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("id").From(fmt.Sprintf("collection_%s", collectionName))
	query, args := sb.Build()
	err := st.db.SelectContext(ctx, &recordIds, query, args...)
	if err != nil {
		return nil, err
	}

	return recordIds, nil
}

func (st SqlStore) GetRecord(ctx context.Context, collectionName string, recordID string) (Record, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("*").From(fmt.Sprintf("collection_%s", collectionName)).Where(sb.Equal("id", recordID))
	query, args := sb.Build()
	rows, err := st.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, &NotFoundError{"record", recordID}
	}

	recordMap := make(map[string]interface{})
	err = rows.MapScan(recordMap)
	if err != nil {
		return nil, err
	}

	record := make(Record)
	for k, v := range recordMap {
		if str, ok := v.(string); ok {
			record[k] = str
		} else {
			// We're assuming all record fields are strings as they are encrypted in the db, this might change
			return nil, fmt.Errorf("unexpected type for field %s", k)
		}
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return record, nil
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	fields, err := getCollectionFields(ctx, st.db, collectionName)
	if err != nil {
		return err
	}

	ub := sqlbuilder.PostgreSQL.NewUpdateBuilder()
	ub.Update(fmt.Sprintf("collection_%s", collectionName))
	for fieldName, fieldValue := range record {
		if _, ok := fields[fieldName]; !ok {
			return &ValueError{Msg: fmt.Sprintf("Field %s does not exist in collection %s", fieldName, collectionName)}
		}
		if _, ok := record[fieldName]; !ok {
			return &ValueError{Msg: fmt.Sprintf("Record is missing field %s present in collection %s", fieldName, collectionName)}
		}
		ub.Set(ub.Assign(fieldName, fieldValue))
	}
	ub.Where(ub.Equal("id", recordID))
	query, args := ub.Build()
	_, err = st.db.ExecContext(ctx, query, args...)
	return err
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom(fmt.Sprintf("collection_%s", collectionName))
	db.Where(db.Equal("id", recordID))
	query, args := db.Build()
	res, err := st.db.ExecContext(ctx, query, args...)
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
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("*").From("principals").Where(sb.Equal("username", username))
	query, args := sb.Build()

	var dbPrincipal Principal
	err := st.db.GetContext(ctx, &dbPrincipal, query, args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	sb = sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("policy_id").From("principal_policies").Where(sb.Equal("principal_id", dbPrincipal.Id))
	query, args = sb.Build()

	rows, err := st.db.QueryxContext(ctx, query, args...)
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

	dbPrincipal.Policies = policyIds

	return &dbPrincipal, nil
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal *Principal) error {
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

	ib := sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertInto("principals").Cols("id", "username", "password", "description").Values(principal.Id, principal.Username, principal.Password, principal.Description)
	query, args := ib.Build()

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				return &ConflictError{principal.Username}
			}
		}
		return err
	}

	ib = sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertInto("principal_policies").Cols("principal_id", "policy_id")
	for _, policyId := range principal.Policies {
		ib.Values(principal.Id, policyId)
	}
	query, args = ib.Build()

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) DeletePrincipal(ctx context.Context, id string) error {
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

	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("principal_policies").Where(db.Equal("principal_id", id))
	query, args := db.Build()

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	db = sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("principals").Where(db.Equal("username", id))
	query, args = db.Build()

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"principal", id}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("id", "effect", "actions", "resources").From("policies").Where(sb.Equal("id", policyId))
	query, args := sb.Build()

	var id, effect string
	var actions []string
	var resources []string

	err := st.db.QueryRowxContext(ctx, query, args...).Scan(&id, &effect, pq.Array(&actions), pq.Array(&resources))
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
		Name:      id,
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
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("id", "effect", "actions", "resources").From("policies").Where(sb.In("id", sqlbuilder.List(policyIds)))
	query, args := sb.Build()

	// query = st.db.Rebind(query)
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
			Name:      id,
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

func (st SqlStore) CreatePolicy(ctx context.Context, p *Policy) error {
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

	ib := sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertInto("policies").Cols("id", "effect", "actions", "resources").Values(p.Id, string(p.Effect), pq.Array(p.Actions), pq.Array(p.Resources))
	query, args := ib.Build()

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return &ConflictError{p.Id}
			}
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
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

	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("policies").Where(db.Equal("id", policyID))
	query, args := db.Build()

	result, err := tx.ExecContext(ctx, query, args...)
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

	db = sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("principal_policies").Where(db.Equal("policy_id", policyID))
	query, args = db.Build()

	_, err = tx.ExecContext(ctx, query, args...)
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
	ib := sqlbuilder.PostgreSQL.NewInsertBuilder()
	ib.InsertInto("tokens").Cols("id", "value").Values(tokenId, value)
	query, args := ib.Build()
	_, err := st.db.ExecContext(ctx, query, args...)
	return err
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("tokens").Where(db.Equal("id", tokenId))
	query, args := db.Build()
	_, err := st.db.ExecContext(ctx, query, args...)
	return err
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var value string
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("value").From("tokens").Where(sb.Equal("id", tokenId))
	query, args := sb.Build()
	err := st.db.GetContext(ctx, &value, query, args...)
	return value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	// Drop all tables
	tables := []string{}
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("tablename").From("pg_tables").Where(sb.Equal("schemaname", "public"))
	query, args := sb.Build()
	err := st.db.SelectContext(ctx, &tables, query, args...)
	if err != nil {
		return err
	}
	for _, table := range tables {
		query = fmt.Sprintf("DROP TABLE IF EXISTS %s;", table)
		_, err = st.db.ExecContext(ctx, query)
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
