package vault

// TODO:
// - Dynamic collection creation (no updates)
// - Error handling
// - Tidy DB Models
// - Ensure we never log sensitive data
// - Add indexes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SqlStore struct {
	db *gorm.DB
}

type GormRecord struct {
	Id             string
	CollectionName string
	Record         datatypes.JSON
}

type GormCollection struct {
	Name       string `gorm:"primaryKey"`
	Collection datatypes.JSON
}

type GormPrincipal struct {
	Username  string `gorm:"primaryKey"`
	Principal datatypes.JSON
}

type DbPolicy struct {
	ID        string `gorm:"primaryKey"`
	Effect    string
	Actions   pq.StringArray `gorm:"type:text[]"`
	Resources pq.StringArray `gorm:"type:text[]"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GormToken struct {
	TokenId string `gorm:"primaryKey"`
	Value   string
}

func FormatDsn(host string, user string, password string, dbName string, port int) string {
	// TODO: Add sslmode
	return fmt.Sprintf("host=%v user=%v password=%v dbname=%v port=%v sslmode=disable", host, user, password, dbName, port)
}

func NewSqlStore(dsn string) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
	})
	db.AutoMigrate(&GormCollection{}, &GormRecord{}, &GormPrincipal{}, &DbPolicy{}, &GormToken{})

	return &SqlStore{db}, err
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var gc GormCollection
	err := st.db.First(&gc, "name = ?", name).Error
	if err != nil {
		return nil, err
	}

	var col Collection
	json.Unmarshal(gc.Collection, &col)
	return &col, err
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var gcs []GormCollection

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

	gormCol := GormCollection{Name: c.Name, Collection: datatypes.JSON(b)}
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
	gc := GormCollection{Name: name, Collection: nil}

	return st.db.Delete(&gc).Error
}

func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	recordIds := make([]string, len(records))
	gormRecords := make([]GormRecord, len(records))

	for i, record := range records {
		recordId := GenerateId()
		jsonBytes, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		gormRecords[i] = GormRecord{Id: recordId, CollectionName: collectionName, Record: datatypes.JSON(jsonBytes)}
		recordIds[i] = recordId
	}
	err := st.db.CreateInBatches(&gormRecords, len(records)).Error
	if err != nil {
		return nil, err
	}
	return recordIds, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var grs []GormRecord
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
	gr := GormRecord{Id: recordID, CollectionName: collectionName, Record: datatypes.JSON(r)}
	return st.db.Model(&GormRecord{}).Where("id = ?", recordID).Updates(gr).Error
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	gr := GormRecord{Id: recordID, CollectionName: collectionName}
	return st.db.Delete(&gr).Error
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	var gPrincipal GormPrincipal
	err := st.db.First(&gPrincipal, "username = ?", username).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &NotFoundError{"principal", username}
		}
		return nil, err
	}

	var principal Principal
	err = json.Unmarshal(gPrincipal.Principal, &principal)
	return &principal, err
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	p, err := json.Marshal(principal)
	if err != nil {
		return err
	}
	gPrincipal := GormPrincipal{Username: principal.Username, Principal: datatypes.JSON(p)}
	err = st.db.Create(&gPrincipal).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return &ConflictError{principal.Username}
		}
		return err
	}
	return nil
}

func (st SqlStore) DeletePrincipal(ctx context.Context, username string) error {
	return st.db.Delete(&GormPrincipal{}, "username = ?", username).Error
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
	var p Policy

	return &p, err
}

func (st SqlStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	var dBPolicies []DbPolicy
	err := st.db.Find(&dBPolicies, policyIds).Error
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

func (st SqlStore) DeletePolicy(ctx context.Context, policyId string) error {
	gp := DbPolicy{ID: policyId}
	return st.db.Delete(gp).Error
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	gt := GormToken{TokenId: tokenId, Value: value}
	return st.db.Create(&gt).Error
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	gt := GormToken{TokenId: tokenId}
	return st.db.Delete(&gt).Error
}
func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var gt GormToken
	err := st.db.First(&gt, "token_id = ?", tokenId).Error
	return gt.Value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	tables := []string{}
	st.db.Raw("SELECT tablename FROM pg_tables WHERE schemaname='public'").Scan(&tables)
	for _, table := range tables {
		st.db.Exec("DELETE FROM " + table)
	}
	return nil
}
