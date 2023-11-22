package vault

// TODO:
// - Dynamic collection creation (no updates)
// - Add indexes

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"time"

	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type SqlStore struct {
	db *gorm.DB
}

type DbRecord struct {
	Id             string
	CollectionName string
	Record         datatypes.JSON
}

type DbCollection struct {
	Name       string `gorm:"primaryKey"`
	Collection datatypes.JSON
}

type DbPrincipal struct {
	Username    string `gorm:"primaryKey"`
	Password    string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Policies    []DbPolicy `gorm:"many2many:principal_policies;"`
}

type DbPolicy struct {
	ID        string `gorm:"primaryKey"`
	Effect    string
	Actions   pq.StringArray `gorm:"type:text[]"`
	Resources pq.StringArray `gorm:"type:text[]"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type DbToken struct {
	ID    string `gorm:"primaryKey"`
	Value string
}

func NewSqlStore(dsn string) (*SqlStore, error) {
	// Todo: Make sure we never log in production
	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,   // Slow SQL threshold
			LogLevel:                  logger.Silent, // Log level
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
		Logger:         dbLogger,
	})

	if err != nil {
		return nil, err
	}
	err = db.AutoMigrate(&DbCollection{}, &DbRecord{}, &DbPrincipal{}, &DbPolicy{}, &DbToken{})
	if err != nil {
		return nil, err
	}

	return &SqlStore{db}, err
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var gc DbCollection
	err := st.db.First(&gc, "name = ?", name).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"collection", name}
		}
		return nil, err
	}

	var col Collection
	err = json.Unmarshal(gc.Collection, &col)
	if err != nil {
		return nil, err
	}
	return &col, err
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var gcs []DbCollection

	err := st.db.Find(&gcs).Error

	colNames := make([]string, len(gcs))
	for i, col := range gcs {
		colNames[i] = col.Name
	}
	return colNames, err
}

func (st SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	gormCol := DbCollection{Name: c.Name, Collection: datatypes.JSON(b)}
	result := st.db.Create(&gormCol)
	if result.Error != nil {
		switch result.Error {
		case gorm.ErrDuplicatedKey:
			return "", &ConflictError{c.Name}
		}
	}

	return c.Name, nil
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	gc := DbCollection{Name: name, Collection: nil}

	return st.db.Delete(&gc).Error
}

func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	recordIds := make([]string, len(records))
	gormRecords := make([]DbRecord, len(records))

	for i, record := range records {
		recordId := GenerateId()
		jsonBytes, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		gormRecords[i] = DbRecord{Id: recordId, CollectionName: collectionName, Record: datatypes.JSON(jsonBytes)}
		recordIds[i] = recordId
	}
	err := st.db.CreateInBatches(&gormRecords, len(records)).Error
	if err != nil {
		return nil, err
	}
	return recordIds, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var grs []DbRecord
	err := st.db.Where("id IN ?", recordIDs).Find(&grs).Error
	if err != nil {
		return nil, err
	}
	var records = make(map[string]*Record)
	for _, gr := range grs {
		var record Record
		err := json.Unmarshal(gr.Record, &record)
		if err != nil {
			return nil, err
		}
		records[gr.Id] = &record
	}
	return records, nil

}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	r, err := json.Marshal(record)
	if err != nil {
		return err
	}
	gr := DbRecord{Id: recordID, CollectionName: collectionName, Record: datatypes.JSON(r)}
	return st.db.Model(&DbRecord{}).Where("id = ?", recordID).Updates(gr).Error
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	gr := DbRecord{Id: recordID, CollectionName: collectionName}
	return st.db.Delete(&gr).Error
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	var dbPrincipal DbPrincipal
	err := st.db.Preload("Policies").First(&dbPrincipal, "username = ?", username).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	policyIds := make([]string, len(dbPrincipal.Policies))
	for i, policy := range dbPrincipal.Policies {
		policyIds[i] = policy.ID
	}

	principal := Principal{
		Username:    dbPrincipal.Username,
		Password:    dbPrincipal.Password,
		Description: dbPrincipal.Description,
		Policies:    policyIds,
	}

	return &principal, err
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal Principal) error {

	dbPrincipal := DbPrincipal{
		Username:    principal.Username,
		Password:    principal.Password,
		Description: principal.Description,
	}
	tx := st.db.Begin()
	if err := tx.Error; err != nil {
		return err
	}
	err := tx.Create(&dbPrincipal).Error
	if err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return &ConflictError{principal.Username}
		}
		return err
	}
	var dbPolicies []DbPolicy
	if err := tx.Where("id IN ?", principal.Policies).Find(&dbPolicies).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Model(&dbPrincipal).Association("Policies").Append(&dbPolicies); err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()

	return nil
}

func (st SqlStore) DeletePrincipal(ctx context.Context, username string) error {
	// Start a transaction
	tx := st.db.Begin()
	if err := tx.Error; err != nil {
		return err
	}

	// First, delete associations in the many-to-many join table
	if err := tx.Table("principal_policies").Where("db_principal_username = ?", username).Delete(nil).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Now, delete the principal itself
	if err := tx.Where("username = ?", username).Delete(&DbPrincipal{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	return tx.Commit().Error
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	var gp DbPolicy
	err := st.db.First(&gp, "id = ?", policyId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"policy", policyId}
		}
		return nil, err
	}

	var policyActions []PolicyAction
	for _, action := range gp.Actions {
		policyActions = append(policyActions, PolicyAction(action))
	}
	p := Policy{
		PolicyId:  gp.ID,
		Effect:    PolicyEffect(gp.Effect),
		Actions:   policyActions,
		Resources: gp.Resources,
	}

	return &p, err
}

func (st SqlStore) GetPoliciesById(ctx context.Context, policyIds []string) ([]*Policy, error) {
	var dBPolicies []DbPolicy
	err := st.db.Where("id IN ?", policyIds).Find(&dBPolicies).Error
	if err != nil {
		return nil, err
	}

	policies := make([]*Policy, len(dBPolicies))
	for i, dbp := range dBPolicies {
		actions := dbp.Actions
		var policyActions []PolicyAction
		for _, action := range actions {
			policyActions = append(policyActions, PolicyAction(action))
		}

		policies[i] = &Policy{
			PolicyId:  dbp.ID,
			Effect:    PolicyEffect(dbp.Effect),
			Actions:   policyActions,
			Resources: dbp.Resources,
		}
	}
	return policies, nil
}

func (st SqlStore) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	actionStrings := make([]string, len(p.Actions))
	for i, action := range p.Actions {
		actionStrings[i] = string(action)
	}
	dbPolicy := DbPolicy{ID: p.PolicyId, Effect: string(p.Effect), Actions: actionStrings, Resources: p.Resources}
	err := st.db.Create(&dbPolicy).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return "", &ConflictError{p.PolicyId}
		}
		return "", err
	}
	return p.PolicyId, nil
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyID string) error {
	// Start a transaction
	tx := st.db.Begin()
	if err := tx.Error; err != nil {
		return err
	}

	// Check if the policy exists
	var policy DbPolicy
	if err := tx.First(&policy, "id = ?", policyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &NotFoundError{"policy", policyID}
		}
		return err
	}

	// Directly delete associations in the many-to-many join table
	if err := tx.Table("principal_policies").Where("db_policy_id = ?", policyID).Delete(nil).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Delete the policy itself
	if err := tx.Where("id = ?", policyID).Delete(&DbPolicy{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	return tx.Commit().Error
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	gt := DbToken{ID: tokenId, Value: value}
	return st.db.Create(&gt).Error
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	gt := DbToken{ID: tokenId}
	return st.db.Delete(&gt).Error
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var gt DbToken
	err := st.db.First(&gt, "id = ?", tokenId).Error
	return gt.Value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	// Delete fk constraints first
	st.db.Exec("delete from principal_policies")
	// Delete all records
	tables := []string{}
	st.db.Raw("SELECT tablename FROM pg_tables WHERE schemaname='public'").Scan(&tables)
	for _, table := range tables {
		st.db.Exec("DELETE FROM " + table)
	}
	return nil
}
