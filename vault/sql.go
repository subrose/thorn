package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/doug-martin/goqu/v9"
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"
	"github.com/huandu/go-sqlbuilder"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type SqlStore struct {
	db *goqu.Database
}

func NewSqlStore(dsn string) (*SqlStore, error) {
	pgDb, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	dialect := goqu.Dialect("postgres")
	db := dialect.DB(pgDb)

	store := &SqlStore{db}

	err = store.CreateSchemas()
	if err != nil {
		return nil, err
	}

	return store, nil
}

func (st *SqlStore) CreateSchemas() error {
	// Create principals table
	_, err := st.db.Exec(`CREATE TABLE IF NOT EXISTS principals (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE,
		password TEXT,
		description TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	// Create policies table
	_, err = st.db.Exec(`CREATE TABLE IF NOT EXISTS policies (
		id TEXT PRIMARY KEY,
		effect TEXT,
		actions TEXT[],
		resources TEXT[]
	)`)
	if err != nil {
		return err
	}

	// Create principal_policies table
	_, err = st.db.Exec(`CREATE TABLE IF NOT EXISTS principal_policies (
		principal_id TEXT,
		policy_id TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, policy_id)
		
	)`)
	if err != nil {
		return err
	}

	// Create tokens table
	_, err = st.db.Exec(`CREATE TABLE IF NOT EXISTS tokens (
		id TEXT PRIMARY KEY,
		value TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	// Create collection_metadata table
	_, err = st.db.Exec(`CREATE TABLE IF NOT EXISTS collection_metadata (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE,
		field_schema JSON,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	return nil
}

func (st *SqlStore) CreateCollection(ctx context.Context, c *Collection) error {
	tx, err := st.db.Begin()
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

	insertSql, args, _ := st.db.Insert("collection_metadata").Rows(
		goqu.Record{"id": c.Id, "name": c.Name, "field_schema": string(fieldSchema)},
	).ToSQL()

	_, err = tx.ExecContext(ctx, insertSql, args...)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return &ConflictError{c.Name}
			}
		}
		return err
	}

	// TODO: Build this with goqu expressions: https://github.com/doug-martin/goqu/blob/master/docs/expressions.md#C
	tableName := "collection_" + c.Name
	query := `CREATE TABLE IF NOT EXISTS ` + tableName + ` (id TEXT PRIMARY KEY`
	for fieldName := range c.Fields {
		query += `, ` + fieldName + ` TEXT`
	}
	query += `)`

	_, err = tx.Exec(query)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func getCollectionFields(ctx context.Context, db *goqu.Database, collectionName string) (map[string]Field, error) {
	var fieldSchema string
	_, err := db.From("collection_metadata").Where(goqu.C("name").Eq(collectionName)).Select("field_schema").ScanVal(&fieldSchema)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, err
	}

	fields := make(map[string]Field)
	err = json.Unmarshal([]byte(fieldSchema), &fields)
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
	err := st.db.From("collection_metadata").Select("name").ScanVals(&collectionNames)
	return collectionNames, err
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	tx, err := st.db.Begin()
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

	// Delete from collection_metadata
	res, err := tx.Exec(`DELETE FROM collection_metadata WHERE name = ?`, name)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return &NotFoundError{"collection", name}
	}

	// Drop collection table
	_, err = tx.Exec(`DROP TABLE IF EXISTS collection_` + name)
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

	// Insert into collection table
	recordId := GenerateId("rec")
	record["id"] = recordId

	insert := st.db.Insert(fmt.Sprintf("collection_%s", collectionName)).Rows(record).Executor()
	fmt.Println(insert.ToSQL())
	if _, err := insert.Exec(); err != nil {
		return "", err
	}

	return recordId, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string) ([]string, error) {
	var recordIds []string
	err := st.db.From(fmt.Sprintf("collection_%s", collectionName)).Select("id").ScanVals(&recordIds)
	if err != nil {
		return nil, err
	}

	return recordIds, nil
}

func (st SqlStore) GetRecord(ctx context.Context, collectionName string, recordID string) (Record, error) {
	rows, err := st.db.From(fmt.Sprintf("collection_%s", collectionName)).Where(goqu.C("id").Eq(recordID)).Executor().Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, &NotFoundError{"record", recordID}
	}

	recordMap := make(map[string]interface{})
	cols, _ := rows.Columns()
	values := make([]interface{}, len(cols))
	for i := range values {
		values[i] = new(sql.RawBytes)
	}
	err = rows.Scan(values...)
	if err != nil {
		return nil, err
	}
	for i, colName := range cols {
		if rb, ok := values[i].(*sql.RawBytes); ok {
			recordMap[colName] = string(*rb)
		}
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

	var dbPrincipal Principal
	found, err := st.db.From("principals").Where(goqu.C("username").Eq(username)).ScanStructContext(ctx, &dbPrincipal)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || !found {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	// TODO: Get policies
	var policyIds []string
	err = st.db.From("principal_policies").Where(goqu.C("principal_id").Eq(dbPrincipal.Id)).Select("policy_id").ScanValsContext(ctx, &policyIds)
	if err != nil {
		return nil, err
	}

	dbPrincipal.Policies = policyIds

	return &dbPrincipal, nil
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal *Principal) error {
	tx, err := st.db.Begin()
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

	query, _, _ := goqu.Insert("principals").Rows(goqu.Record{"id": principal.Id, "username": principal.Username, "password": principal.Password, "description": principal.Description}).ToSQL()

	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				return &ConflictError{principal.Username}
			}
		}
		return err
	}

	for _, policyId := range principal.Policies {
		query, _, _ = goqu.Insert("principal_policies").Rows(goqu.Record{"principal_id": principal.Id, "policy_id": policyId}).ToSQL()

		_, err = tx.ExecContext(ctx, query)
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

func (st SqlStore) DeletePrincipal(ctx context.Context, id string) error {
	tx, err := st.db.Begin()
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

	query, _, _ := goqu.Delete("principal_policies").Where(goqu.C("principal_id").Eq(id)).ToSQL()

	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	query, _, _ = goqu.Delete("principals").Where(goqu.C("username").Eq(id)).ToSQL()

	result, err := tx.ExecContext(ctx, query)
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
	var id, effect string
	var actions []string
	var resources []string

	policy := Policy{}
	found, err := st.db.From("policies").Select("id", "effect", "actions", "resources").Where(goqu.C("id").Eq(policyId)).ScanStructContext(ctx, &policy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || !found {
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
	query, _, _ := goqu.From("policies").Select("id", "effect", "actions", "resources").Where(goqu.C("id").In(policyIds)).ToSQL()

	rows, err := st.db.QueryContext(ctx, query)
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
	tx, err := st.db.Begin()
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

	query, _, _ := goqu.Insert("policies").Rows(goqu.Record{"id": p.Id, "effect": string(p.Effect), "actions": pq.Array(p.Actions), "resources": pq.Array(p.Resources)}).ToSQL()

	_, err = tx.ExecContext(ctx, query)
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
	tx, err := st.db.Begin()
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

	query, _, _ := goqu.Delete("policies").Where(goqu.C("id").Eq(policyID)).ToSQL()

	result, err := tx.ExecContext(ctx, query)
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

	db := sqlbuilder.PostgreSQL.NewDeleteBuilder()
	db.DeleteFrom("principal_policies").Where(db.Equal("policy_id", policyID))
	query, args := db.Build()

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
	err := st.db.QueryRowContext(ctx, query, args...).Scan(&value)
	return value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	// Drop all tables
	tables := []string{}
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("tablename").From("pg_tables").Where(sb.Equal("schemaname", "public"))
	query, args := sb.Build()
	rows, err := st.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
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
