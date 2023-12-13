package vault

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type SqlStore struct {
	db *gorm.DB
}

func NewSqlStore(dsn string) (*SqlStore, error) {
	time.Local = time.UTC
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true, Logger: logger.Default.LogMode(logger.Silent)})
	// db = db.Debug()
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
	Username    string `gorm:"unique"`
	Password    string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Policies    []dbPolicy `gorm:"many2many:principal_policies;foreignKey:Id;references:Id;joinForeignKey:PrincipalId;joinReferences:PolicyId"`
}

func (dbPrincipal) TableName() string {
	return "principals"
}

type dbToken struct {
	Id        string `gorm:"primaryKey"`
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (dbToken) TableName() string {
	return "tokens"
}

type dbPrincipalPolicy struct {
	PrincipalId string `gorm:"primaryKey;autoIncrement:false;column:principal_id"`
	PolicyId    string `gorm:"primaryKey;autoIncrement:false;column:policy_id"`
}

func (dbPrincipalPolicy) TableName() string {
	return "principal_policies"
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
	Id          string `gorm:"primaryKey"`
	Name        string `gorm:"unique"`
	Description string
	Type        string
	FieldSchema FieldSchemaMap `gorm:"type:json"` // Ensures JSON storage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (dbCollectionMetadata) TableName() string {
	return "collections_metadata"
}

func (st *SqlStore) CreateSchemas() error {
	// Use GORM's automigrate to create tables
	err := st.db.AutoMigrate(&dbPrincipal{}, &dbPolicy{}, &dbPrincipalPolicy{}, &dbToken{}, &dbCollectionMetadata{})
	if err != nil {
		return err
	}

	return nil
}

func validateInput(input string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, input)
	return match
}

func (st *SqlStore) CreateCollection(ctx context.Context, c *Collection) error {
	tx := st.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	collectionMetadata := dbCollectionMetadata{
		Id:          c.Id,
		Name:        c.Name,
		Type:        string(c.Type),
		FieldSchema: c.Fields,
	}

	result := tx.Create(&collectionMetadata)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return &ConflictError{c.Name}
		} else {
			return result.Error
		}
	}

	if !validateInput(c.Name) {
		return &ValueError{Msg: fmt.Sprintf("collection name '%s' is not alphanumeric", c.Name)}
	}
	tableName := "collection_" + c.Name

	query := `CREATE TABLE IF NOT EXISTS ` + tableName + ` (id TEXT PRIMARY KEY`
	for fieldName := range c.Fields {
		if !validateInput(fieldName) {
			return &ValueError{Msg: fmt.Sprintf("field name '%s' is not alphanumeric", fieldName)}
		}
		query += `, ` + fieldName + ` TEXT`
	}
	if c.Type == CollectionTypeData {
		query += `, subject_id TEXT`
	}
	query += `, created_at TIMESTAMP, updated_at TIMESTAMP)`
	result = tx.Exec(query)
	if result.Error != nil {
		return result.Error
	}
	tx.Commit()
	if tx.Error != nil {
		return tx.Error
	}

	return nil
}

func getCollectionFields(ctx context.Context, db *gorm.DB, collectionName string) (map[string]Field, error) {
	var collectionMetadata dbCollectionMetadata
	result := db.Where("name = ?", collectionName).First(&collectionMetadata)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"collection", collectionName}
		}
		return nil, result.Error
	}

	return collectionMetadata.FieldSchema, nil
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	if !validateInput(name) {
		return nil, &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", name)}
	}

	dbCollectionMetadata := dbCollectionMetadata{}
	result := st.db.Where("name = ?", name).First(&dbCollectionMetadata)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"collection", name}
		}
		return nil, result.Error
	}
	return &Collection{
		Id:          dbCollectionMetadata.Id,
		Name:        dbCollectionMetadata.Name,
		Description: dbCollectionMetadata.Description,
		Type:        CollectionType(dbCollectionMetadata.Type),
		Fields:      dbCollectionMetadata.FieldSchema,
		CreatedAt:   dbCollectionMetadata.CreatedAt,
		UpdatedAt:   dbCollectionMetadata.UpdatedAt,
	}, nil
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var collectionMetadatas []dbCollectionMetadata
	result := st.db.Find(&collectionMetadatas)
	if result.Error != nil {
		return nil, result.Error
	}
	collectionNames := make([]string, len(collectionMetadatas))
	for i, collectionMetadata := range collectionMetadatas {
		collectionNames[i] = collectionMetadata.Name
	}
	return collectionNames, nil
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	if !validateInput(name) {
		return &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", name)}
	}
	tx := st.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	result := tx.Where("name = ?", name).Delete(&dbCollectionMetadata{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return &NotFoundError{"collection", name}
	}

	// Drop collection table
	result = tx.Exec(`DROP TABLE IF EXISTS collection_` + name)
	if result.Error != nil {
		return result.Error
	}

	tx.Commit()
	if tx.Error != nil {
		return tx.Error
	}

	return nil
}

func (st SqlStore) CreateRecord(ctx context.Context, collectionName string, record Record) error {
	if !validateInput(collectionName) {
		return &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", collectionName)}
	}

	newRecord := make(map[string]interface{})
	for fieldName := range record {
		newRecord[fieldName] = record[fieldName]
	}

	result := st.db.Table(fmt.Sprintf("collection_%s", collectionName)).Create(&newRecord)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string) ([]string, error) {
	if !validateInput(collectionName) {
		return nil, &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", collectionName)}
	}

	var recordIds []string
	result := st.db.Table(fmt.Sprintf("collection_%s", collectionName)).Pluck("id", &recordIds)
	if result.Error != nil {
		return nil, result.Error
	}

	return recordIds, nil
}

func (st SqlStore) GetRecord(ctx context.Context, collectionName string, recordID string) (Record, error) {
	if !validateInput(collectionName) {
		return nil, &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", collectionName)}
	}

	record := make(Record)
	rows, err := st.db.Table(fmt.Sprintf("collection_%s", collectionName)).Where("id = ?", recordID).Select("*").Rows()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotFoundError{"record", recordID}
		}
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil || len(cols) == 0 {
		return nil, &NotFoundError{"record", recordID}
	}

	vals := make([]interface{}, len(cols))
	for i := range cols {
		vals[i] = new(sql.RawBytes)
	}
	for rows.Next() {
		err = rows.Scan(vals...)
		if err != nil {
			return nil, err
		}
		for i, col := range cols {
			record[col] = string(*vals[i].(*sql.RawBytes))
		}
	}

	if len(record) == 0 {
		return nil, &NotFoundError{"record", recordID}
	}

	return record, nil
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	if !validateInput(collectionName) {
		return &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", collectionName)}
	}

	fields, err := getCollectionFields(ctx, st.db, collectionName)
	if err != nil {
		return err
	}

	newRecord := make(map[string]interface{})
	newRecord["id"] = recordID
	for fieldName := range fields {
		if fieldValue, ok := record[fieldName]; !ok {
			return &ValueError{Msg: fmt.Sprintf("Field %s is missing from the record", fieldName)}
		} else {
			newRecord[fieldName] = fieldValue
		}
	}

	for fieldName := range record {
		if _, ok := fields[fieldName]; !ok {
			return &ValueError{Msg: fmt.Sprintf("Field %s is not existent in the schema", fieldName)}
		}
	}

	result := st.db.Table(fmt.Sprintf("collection_%s", collectionName)).Where("id = ?", recordID).Updates(newRecord)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return &NotFoundError{"record", recordID}
	}

	return nil
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	if !validateInput(collectionName) {
		return &ValueError{Msg: fmt.Sprintf("Invalid collection name %s", collectionName)}
	}

	result := st.db.Table(fmt.Sprintf("collection_%s", collectionName)).Where("id = ?", recordID).Delete(&Record{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return &NotFoundError{"record", recordID}
	}

	return nil
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	var dbPrincipal dbPrincipal
	err := st.db.Preload("Policies").Where("username = ?", username).First(&dbPrincipal).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	var policyIds []string = make([]string, len(dbPrincipal.Policies))

	for _, policy := range dbPrincipal.Policies {
		policyIds = append(policyIds, policy.Id)
	}

	principal := Principal{
		Id:          dbPrincipal.Id,
		Username:    dbPrincipal.Username,
		Password:    dbPrincipal.Password,
		Description: dbPrincipal.Description,
		Policies:    policyIds,
	}

	return &principal, nil
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal *Principal) error {
	tx := st.db.Begin()

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	dbPrincipal := dbPrincipal{
		Id:          principal.Id,
		Username:    principal.Username,
		Password:    principal.Password,
		Description: principal.Description,
	}

	err := tx.Create(&dbPrincipal).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &NotFoundError{"principal", principal.Username}
		} else if errors.Is(err, gorm.ErrDuplicatedKey) {
			return &ConflictError{principal.Username}
		}
		tx.Rollback()
		return err
	}

	for _, policyId := range principal.Policies {
		principalPolicy := dbPrincipalPolicy{
			PrincipalId: principal.Id,
			PolicyId:    policyId,
		}

		err = tx.Create(&principalPolicy).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit().Error
	if err != nil {
		return err
	}

	return nil
}

func (st SqlStore) DeletePrincipal(ctx context.Context, id string) error {
	tx := st.db.Begin()

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Where("principal_id = ?", id).Delete(&dbPrincipalPolicy{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Where("username = ?", id).Delete(&dbPrincipal{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &NotFoundError{"principal", id}
		}
		tx.Rollback()
		return err
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	var dbPolicy dbPolicy

	if err := st.db.Where("id = ?", policyId).First(&dbPolicy).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"policy", policyId}
		}
		return nil, err
	}

	actions := make([]PolicyAction, len(dbPolicy.Actions))
	for i, action := range dbPolicy.Actions {
		actions[i] = PolicyAction(action)
	}

	p := Policy{
		Name:      dbPolicy.Id,
		Effect:    PolicyEffect(dbPolicy.Effect),
		Actions:   actions,
		Resources: dbPolicy.Resources,
	}
	return &p, nil
}

func (st SqlStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	if len(policyIds) == 0 {
		return []*Policy{}, nil
	}

	var dbPolicies []dbPolicy
	if err := st.db.Where("id IN ?", policyIds).Find(&dbPolicies).Error; err != nil {
		return nil, err
	}

	policies := make([]*Policy, len(dbPolicies))
	for i, dbPolicy := range dbPolicies {
		actions := make([]PolicyAction, len(dbPolicy.Actions))
		for i, action := range dbPolicy.Actions {
			actions[i] = PolicyAction(action)
		}
		policies[i] = &Policy{
			Name:      dbPolicy.Id,
			Effect:    PolicyEffect(dbPolicy.Effect),
			Actions:   actions,
			Resources: dbPolicy.Resources,
		}
	}

	return policies, nil
}

func (st SqlStore) CreatePolicy(ctx context.Context, p *Policy) error {
	tx := st.db.Begin()

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	actions := make(pq.StringArray, len(p.Actions))
	for i, action := range p.Actions {
		actions[i] = string(action)
	}
	dbPolicy := dbPolicy{
		Id:        p.Id,
		Effect:    string(p.Effect),
		Actions:   actions,
		Resources: p.Resources,
	}

	if err := tx.Create(&dbPolicy).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyID string) error {
	tx := st.db.Begin()

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	result := tx.Delete(&dbPolicy{Id: policyID})
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	// If no rows were affected, the policy did not exist
	if result.RowsAffected == 0 {
		tx.Rollback()
		return &NotFoundError{"policy", policyID}
	}

	if err := tx.Where("policy_id = ?", policyID).Delete(&dbPrincipalPolicy{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	dbToken := dbToken{
		Id:    tokenId,
		Value: value,
	}
	err := st.db.Create(&dbToken).Error
	return err
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	err := st.db.Where("id = ?", tokenId).Delete(&dbToken{}).Error
	return err
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var dbToken dbToken
	err := st.db.Where("id = ?", tokenId).First(&dbToken).Error
	return dbToken.Value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	tables, err := st.db.Migrator().GetTables()
	for _, table := range tables {
		if err := st.db.Migrator().DropTable(table); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	err = st.CreateSchemas()
	if err != nil {
		return err
	}

	return nil
}
