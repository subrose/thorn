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
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	return c.Name, st.db.Create(&c).Error
}

func (st SqlStore) DeleteCollection(ctx context.Context, name string) error {
	return st.db.Delete(name).Error
}

func (st SqlStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) GetRecords(ctx context.Context, collectionName string, recordIDs []string) (map[string]*Record, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) DeleteRecord(ctx context.Context, collectionName string, recordID string) error {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) DeletePrincipal(ctx context.Context, username string) error {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	panic("not implemented") // TODO: Implement
}

func (st SqlStore) DeletePolicy(ctx context.Context, policyId string) error {
	panic("not implemented") // TODO: Implement
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
	panic("not implemented") // TODO: Implement
}
