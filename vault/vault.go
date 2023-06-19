package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Field struct {
	Name      string `redis:"name"`
	Type      string `redis:"type"`
	IsIndexed bool   `redis:"is_indexed"`
}

type Collection struct {
	Name   string           `redis:"name"`
	Fields map[string]Field `redis:"fields"`
}

type Record map[string]string // field name -> value

type Principal struct {
	Name         string   `redis:"name"`
	AccessKey    string   `redis:"access_key"`
	AccessSecret string   `redis:"access_secret"`
	Description  string   `redis:"description"`
	CreatedAt    string   `redis:"created_at"`
	Policies     []string `redis:"policies"`
}

type VaultDB interface {
	GetCollection(ctx context.Context, name string) (Collection, error)
	GetCollections(ctx context.Context) ([]string, error)
	CreateCollection(ctx context.Context, c Collection) (string, error)
	CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error)
	GetRecords(ctx context.Context, recordIDs []string) (map[string]Record, error)
	GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error)
	Flush(ctx context.Context) error
}

type Privatiser interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type PrincipalManager interface {
	CreatePrincipal(ctx context.Context, principal Principal) (Principal, error)
	GetPrincipal(ctx context.Context, accessKey string) (Principal, error)
}

type Logger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string, err error)
}

type Vault struct {
	Db               VaultDB
	Priv             Privatiser
	PrincipalManager PrincipalManager
	PolicyManager    PolicyManager
	Logger           Logger
}

func (vault Vault) GetCollection(
	ctx context.Context,
	principal Principal,
	name string) (Collection, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionRead, fmt.Sprintf("collections/%s/", name)},
	)
	if err != nil {
		return Collection{}, err
	}
	if !allowed {
		return Collection{}, ErrForbidden
	}

	col, err := vault.Db.GetCollection(ctx, name)
	if err != nil {
		return Collection{}, err
	}

	if col.Name == "" {
		return Collection{}, ErrNotFound
	}

	return col, nil
}

func (vault Vault) GetCollections(
	ctx context.Context,
	principal Principal,
) ([]string, error) {
	vault.Logger.Debug("A debug message for GetCollections")
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionRead, "collections/"},
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrForbidden
	}

	cols, err := vault.Db.GetCollections(ctx)
	if err != nil {
		return nil, err
	}
	return cols, nil
}

func (vault Vault) CreateCollection(
	ctx context.Context,
	principal Principal,
	col Collection,
) (string, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionWrite, "collections/"},
	)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrForbidden
	}

	if len(col.Name) < 3 {
		return "", newValueError(fmt.Errorf("collection name must be at least 3 characters"))
	}
	collectionId, err := vault.Db.CreateCollection(ctx, col)
	if err != nil {
		return "", err
	}
	return collectionId, nil
}

func (vault Vault) CreateRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
	records []Record,
) ([]string, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionWrite, fmt.Sprintf("collections/%s/records/", collectionName)},
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrForbidden
	}

	encryptedRecords := make([]Record, len(records))

	for i, record := range records {
		encryptedRecord := make(Record)
		for recordFieldName, recordFieldValue := range record {
			encryptedValue, err := vault.Priv.Encrypt(recordFieldValue)
			if err != nil {
				return nil, err
			}
			encryptedRecord[recordFieldName] = encryptedValue
		}
		encryptedRecords[i] = encryptedRecord
	}
	return vault.Db.CreateRecords(ctx, collectionName, encryptedRecords)
}

func (vault Vault) GetRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
	recordIDs []string,
) (map[string]Record, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionRead, fmt.Sprintf("collections/%s/records/", collectionName)},
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrForbidden
	}

	col, err := vault.GetCollection(ctx, principal, collectionName)
	if err != nil {
		return nil, err
	}

	encryptedRecords, err := vault.Db.GetRecords(ctx, recordIDs)
	if err != nil {
		return nil, err
	}

	if len(encryptedRecords) == 0 {
		return nil, ErrNotFound
	}

	records := make(map[string]Record, len(encryptedRecords))
	for recordId, record := range encryptedRecords {
		decryptedRecord := make(Record)
		for k, v := range record {
			decryptedValue, err := vault.Priv.Decrypt(v)
			if err != nil {
				return nil, err
			}
			privValue, err := GetPType(PTypeName(col.Fields[k].Type), decryptedValue)
			if err != nil {
				return nil, err
			}
			decryptedRecord[k], err = privValue.Get("plain") // TODO: change "plain" to getFormat[k]
			if err != nil {
				return nil, err
			}
		}
		records[recordId] = decryptedRecord
	}
	return records, nil
}

func (vault Vault) GetRecordsFilter(
	ctx context.Context,
	principal Principal,
	collectionName string,
	fieldName string,
	value string,
) (map[string]Record, error) {
	val, _ := vault.Priv.Encrypt(value)
	recordIds, err := vault.Db.GetRecordsFilter(ctx, collectionName, fieldName, val)
	if err != nil {
		return nil, err
	}

	return vault.GetRecords(ctx, principal, collectionName, recordIds)
}

func (vault Vault) CreatePrincipal(
	ctx context.Context,
	principal Principal,
	name,
	accessKey,
	accessSecret,
	description string,
	policies []string,
) (Principal, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionWrite, "principals/"},
	)
	if err != nil {
		return Principal{}, err
	}
	if !allowed {
		return Principal{}, ErrForbidden
	}

	hashedAccessSecret, _ := bcrypt.GenerateFromPassword([]byte(accessSecret), bcrypt.DefaultCost)
	dbPrincipal := Principal{
		Name:         name,
		AccessKey:    strings.ToLower(accessKey),
		AccessSecret: string(hashedAccessSecret),
		CreatedAt:    time.Now().Format(time.RFC3339),
		Description:  description,
		Policies:     policies,
	}

	newPrincipal, err := vault.PrincipalManager.CreatePrincipal(ctx, dbPrincipal)
	if err != nil {
		return Principal{}, err
	}
	newPrincipal.AccessSecret = accessSecret
	return newPrincipal, nil
}

func (vault Vault) GetPrincipal(
	ctx context.Context,
	principal Principal,
	accessKey string,
) (Principal, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionRead, fmt.Sprintf("principals/%s/", accessKey)},
	)
	if err != nil {
		return Principal{}, err
	}
	if !allowed {
		return Principal{}, ErrForbidden
	}

	return vault.PrincipalManager.GetPrincipal(ctx, accessKey)
}

func (vault Vault) AuthenticateUser(
	ctx context.Context,
	accessKey,
	inputAccessSecret string,
) (Principal, error) {
	dbUser, err := vault.PrincipalManager.GetPrincipal(ctx, accessKey)
	if err != nil {
		return Principal{}, ErrForbidden
	}
	compareErr := bcrypt.CompareHashAndPassword([]byte(dbUser.AccessSecret), []byte(inputAccessSecret))
	if compareErr != nil {
		return Principal{}, ErrForbidden
	}
	return dbUser, nil
}

func (vault Vault) CreatePolicy(
	ctx context.Context,
	principal Principal,
	p Policy,
) (string, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionWrite, "policies/"},
	)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrForbidden
	}

	return vault.PolicyManager.CreatePolicy(ctx, p)
}

func (vault Vault) GetPolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) (Policy, error) {
	allowed, err := vault.ValidateAction(
		ctx,
		Action{principal, PolicyActionRead, fmt.Sprintf("policies/%s", policyId)},
	)
	if err != nil {
		return Policy{}, err
	}
	if !allowed {
		return Policy{}, ErrForbidden
	}

	return vault.PolicyManager.GetPolicy(ctx, policyId)
}

func (vault Vault) ValidateAction(ctx context.Context, a Action) (bool, error) {
	allowed, err := EvaluateAction(ctx, a, vault.PolicyManager)
	if err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}

	return false, nil
}
