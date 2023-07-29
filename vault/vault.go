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
	Username    string   `redis:"username"`
	Password    string   `redis:"password"`
	Description string   `redis:"description"`
	CreatedAt   string   `redis:"created_at"`
	Policies    []string `redis:"policies"`
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
	CreatePrincipal(ctx context.Context, principal Principal) error
	GetPrincipal(ctx context.Context, username string) (Principal, error)
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

// TODO: These probably should be renamed to have _PATH
const (
	COLLECTIONS_PPATH = "/collections"
	PRINCIPALS_PPATH  = "/principals"
	RECORDS_PPATH     = "/records"
	POLICIES_PPATH    = "/policies"
	FIELDS_PPATH      = "/fields"
)

func (vault Vault) GetCollection(
	ctx context.Context,
	principal Principal,
	name string,
) (Collection, error) {
	action := Action{principal, PolicyActionRead, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return Collection{}, err
	}
	if !allowed {
		return Collection{}, &ForbiddenError{action}
	}

	col, err := vault.Db.GetCollection(ctx, name)
	if err != nil {
		return Collection{}, err
	}

	if col.Name == "" {
		return Collection{}, &NotFoundError{name}
	}

	return col, nil
}

func (vault Vault) GetCollections(
	ctx context.Context,
	principal Principal,
) ([]string, error) {
	action := Action{principal, PolicyActionRead, COLLECTIONS_PPATH}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{action}
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
	action := Action{principal, PolicyActionWrite, COLLECTIONS_PPATH}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", &ForbiddenError{action}
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
	action := Action{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{action}
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
	format string,
) (map[string]Record, error) {

	if format != PLAIN_FORMAT && format != MASKED_FORMAT {
		return nil, newValueError(fmt.Errorf("invalid format: %s", format))
	}

	if len(recordIDs) == 0 {
		return nil, newValueError(fmt.Errorf("record ids must be provided"))
	}
	actions := Actions{principal, make([]Action, len(recordIDs))}
	for i, recordID := range recordIDs {
		actions.Actions[i] = Action{PolicyActionRead, fmt.Sprintf("%s/%s%s/%s/%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH, recordID, format)}
	}
	allowed, err := vault.ValidateActions(ctx, actions)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{actions.Actions[0]} // TODO: throw on the right action
	}
	col, err := vault.Db.GetCollection(ctx, collectionName)
	if err != nil {
		return nil, err
	}

	encryptedRecords, err := vault.Db.GetRecords(ctx, recordIDs)
	if err != nil {
		return nil, err
	}

	if len(encryptedRecords) == 0 {
		return nil, &NotFoundError{recordIDs[0]} //TODO: specify the records that were not found...
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
			decryptedRecord[k], err = privValue.Get(format)
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
	format string,
) (map[string]Record, error) {
	val, _ := vault.Priv.Encrypt(value)
	recordIds, err := vault.Db.GetRecordsFilter(ctx, collectionName, fieldName, val)
	if err != nil {
		return nil, err
	}

	return vault.GetRecords(ctx, principal, collectionName, recordIds, format)
}

func (vault Vault) CreatePrincipal(
	ctx context.Context,
	principal Principal,
	username,
	password,
	description string,
	policies []string,
) error {
	action := Action{principal, PolicyActionWrite, PRINCIPALS_PPATH}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{action}
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	dbPrincipal := Principal{
		Username:    username,
		Password:    string(hashedPassword),
		CreatedAt:   time.Now().Format(time.RFC3339),
		Description: description,
		Policies:    policies,
	}

	err = vault.PrincipalManager.CreatePrincipal(ctx, dbPrincipal)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) GetPrincipal(
	ctx context.Context,
	principal Principal,
	username string,
) (Principal, error) {
	action := Action{principal, PolicyActionRead, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return Principal{}, err
	}
	if !allowed {
		return Principal{}, &ForbiddenError{action}
	}

	return vault.PrincipalManager.GetPrincipal(ctx, username)
}

func (vault Vault) AuthenticateUser(
	ctx context.Context,
	username,
	inputAccessSecret string,
) (Principal, error) {
	dbUser, err := vault.PrincipalManager.GetPrincipal(ctx, username)
	if err != nil {
		return Principal{}, err
	}
	compareErr := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(inputAccessSecret))
	if compareErr != nil {
		return Principal{}, compareErr
	}
	return dbUser, nil
}

func (vault Vault) CreatePolicy(
	ctx context.Context,
	principal Principal,
	p Policy,
) (string, error) {
	action := Action{principal, PolicyActionWrite, POLICIES_PPATH}
	// Ensure resource starts with a slash
	if !strings.HasPrefix(p.Resource, "/") {
		return "", newValueError(fmt.Errorf("resource must start with a slash"))
	}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", &ForbiddenError{action}
	}

	return vault.PolicyManager.CreatePolicy(ctx, p)
}

func (vault Vault) GetPolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) (Policy, error) {
	action := Action{principal, PolicyActionRead, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}
	allowed, err := vault.ValidateAction(ctx, action)
	if err != nil {
		return Policy{}, err
	}
	if !allowed {
		return Policy{}, &ForbiddenError{action}
	}

	return vault.PolicyManager.GetPolicy(ctx, policyId)
}

func (vault Vault) ValidateActions(
	ctx context.Context,
	actions Actions,
) (bool, error) {
	allowed, err := EvaluateActions(ctx, actions, vault.PolicyManager)
	if err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}

	return false, nil
}
