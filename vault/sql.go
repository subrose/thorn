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
	var ids []string
	for _, record := range records {
		err := st.db.Create(&record).Error
		if err != nil {
			return nil, err
		}
		ids = append(ids, record.ID)
	}
	return ids, nil
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	var records []Record
	err := st.db.Where("id IN ?", recordIDs).Find(&records).Error
	recordMap := make(map[string]*Record)
	for _, record := range records {
		recordMap[record.ID] = &record
	}
	return recordMap, err
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	var records []Record
	err := st.db.Where(fieldName+" = ?", value).Find(&records).Error
	var ids []string
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids, err
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
	return p.ID, st.db.Create(&p).Error
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyId string) error {
	return st.db.Delete(&Policy{}, policyId).Error
}

func (st SqlStore) CreateToken(ctx context.Context, tokenId string, value string) error {
	token := Token{ID: tokenId, Value: value}
	return st.db.Create(&token).Error
}

func (st SqlStore) DeleteToken(ctx context.Context, tokenId string) error {
	return st.db.Delete(&Token{}, tokenId).Error
}

func (st SqlStore) GetTokenValue(ctx context.Context, tokenId string) (string, error) {
	var token Token
	err := st.db.First(&token, "id = ?", tokenId).Error
	return token.Value, err
}

func (st SqlStore) Flush(ctx context.Context) error {
	return st.db.Exec("DELETE FROM collections; DELETE FROM records; DELETE FROM principals; DELETE FROM policies; DELETE FROM tokens;").Error
}
