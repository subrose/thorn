package vault

import (
	"context"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type SqlStore struct {
	db *gorm.DB
}

type GormRecord struct {
	Id     string
	Record Record
}

func NewSqlStore() (*SqlStore, error) {
	dsn := "host=localhost user=postgres password=postgres dbname=postgres port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	db.AutoMigrate(&Collection{}, &Record{}, &Principal{}, &Policy{})
	return &SqlStore{db}, err
}

func (st SqlStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	var col Collection
	err := st.db.First(&col, "name = ?", name).Error

	return &col, err
}

func (st SqlStore) GetCollections(ctx context.Context) ([]string, error) {
	var cols []Collection
	err := st.db.Find(&cols).Error
	var names []string
	for _, col := range cols {
		names = append(names, col.Name)
	}
	return names, err
}

func (st SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	return c.Name, st.db.Create(&c).Error
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	var col Collection
	err := st.db.First(&col, "name = ?", name).Error
	if err != nil {
		return err
	}
	return st.db.Delete(&col).Error
}

func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	var recordIds []string
	for _, record := range records {
		recordId := GenerateId()
		gormRecord := GormRecord{Id: recordId, Record: record}
		err := st.db.Create(&gormRecord).Error
		if err != nil {
			return nil, err
		}
		recordIds = append(recordIds, recordId)
	}
	return recordIds, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var gormRecords []GormRecord
	err := st.db.Where("id IN ?", recordIDs).Find(&gormRecords).Error
	if err != nil {
		return nil, err
	}
	var records = make(map[string]*Record)
	for _, gormRecord := range gormRecords {
		records[gormRecord.Id] = &gormRecord.Record
	}
	return records, nil

}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement}

}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	return st.db.Model(&Record{}).Where("id = ?", recordID).Updates(record).Error
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	return st.db.Delete(&Record{}, recordID).Error
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	var principal Principal
	err := st.db.First(&principal, "username = ?", username).Error
	return &principal, err
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	return st.db.Create(&principal).Error
}

func (st SqlStore) DeletePrincipal(ctx context.Context, username string) error {
	return st.db.Delete(&Principal{}, username).Error
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	var policy Policy
	err := st.db.First(&policy, "id = ?", policyId).Error
	return &policy, err
}

func (st SqlStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	var policies []Policy
	err := st.db.Where("id IN ?", policyIds).Find(&policies).Error
	var policyPtrs []*Policy
	for _, policy := range policies {
		policyPtrs = append(policyPtrs, &policy)
	}
	return policyPtrs, err
}

func (st SqlStore) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	return p.PolicyId, st.db.Create(&p).Error
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyId string) error {
	return st.db.Delete(&Policy{}, policyId).Error
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	panic("not implemented") // TODO: Implement
}
func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) Flush(ctx context.Context) error {
	return st.db.Exec("DELETE FROM collections; DELETE FROM records; DELETE FROM principals; DELETE FROM policies; DELETE FROM tokens;").Error
}
