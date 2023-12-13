package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type Field struct {
	Type      string `json:"type" validate:"required"`
	IsIndexed bool   `json:"indexed" validate:"required,boolean"`
}

type Collection struct {
	Id          string           `json:"id"`
	Name        string           `json:"name" validate:"required,min=3,max=32"`
	Description string           `json:"description"`
	Fields      map[string]Field `json:"fields" validate:"required"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type Record map[string]string // field name -> value

type Privatiser interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type Signer interface {
	Sign(message string) (string, error)
	Verify(message, signature string) (bool, error)
}

type Logger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string)
}

type PolicyAction string

const (
	PolicyActionRead  PolicyAction = "read"
	PolicyActionWrite PolicyAction = "write"
	// TODO: Add more
)

type PolicyEffect string

const (
	EffectDeny  PolicyEffect = "deny"
	EffectAllow PolicyEffect = "allow"
)

type Policy struct {
	Id          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Effect      PolicyEffect   `json:"effect" validate:"required"`
	Actions     []PolicyAction `json:"actions" validate:"required"`
	Resources   []string       `json:"resources" validate:"required"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type Principal struct {
	Id          string    `json:"id" db:"id"`
	Username    string    `json:"username" validate:"required,min=3,max=32" db:"username"`
	Password    string    `json:"password" validate:"required,min=3" db:"password"` // This is to limit the size of the password hash.
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	Policies    []string  `json:"policies" db:"-"`
}

type Request struct {
	Actor    Principal
	Action   PolicyAction
	Resource string
}

type Vault struct {
	Db        VaultDB
	Priv      Privatiser
	Logger    Logger
	Signer    Signer
	Validator *validator.Validate
}

const (
	COLLECTIONS_PPATH = "/collections"
	PRINCIPALS_PPATH  = "/principals"
	RECORDS_PPATH     = "/records"
	POLICIES_PPATH    = "/policies"
)

type VaultDB interface {
	GetCollection(ctx context.Context, name string) (*Collection, error)
	GetCollections(ctx context.Context) ([]string, error)
	CreateCollection(ctx context.Context, col *Collection) error
	DeleteCollection(ctx context.Context, name string) error
	CreateRecord(ctx context.Context, collectionName string, record Record) error
	GetRecords(ctx context.Context, collectionName string) ([]string, error)
	GetRecord(ctx context.Context, collectionName string, recordId string) (Record, error)
	SearchRecords(ctx context.Context, collectionName string, filters map[string]string) ([]string, error)
	UpdateRecord(ctx context.Context, collectionName string, recordID string, record Record) error
	DeleteRecord(ctx context.Context, collectionName string, recordID string) error
	GetPrincipal(ctx context.Context, username string) (*Principal, error)
	CreatePrincipal(ctx context.Context, principal *Principal) error
	DeletePrincipal(ctx context.Context, username string) error
	GetPolicy(ctx context.Context, policyId string) (*Policy, error)
	GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error)
	CreatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, policyId string) error
	CreateToken(ctx context.Context, tokenId string, value string) error
	DeleteToken(ctx context.Context, tokenId string) error
	GetTokenValue(ctx context.Context, tokenId string) (string, error)
	Flush(ctx context.Context) error
}

func (vault Vault) GetCollection(
	ctx context.Context,
	principal Principal,
	name string,
) (*Collection, error) {
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
	}

	col, err := vault.Db.GetCollection(ctx, name)
	if err != nil {
		return nil, err
	}

	return col, nil
}

func (vault Vault) GetCollections(
	ctx context.Context,
	principal Principal,
) ([]string, error) {
	request := Request{principal, PolicyActionRead, COLLECTIONS_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
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
	col *Collection,
) error {
	request := Request{principal, PolicyActionWrite, COLLECTIONS_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}
	if err := vault.Validate(col); err != nil {
		return err
	}
	col.Id = GenerateId("col")

	err = vault.Db.CreateCollection(ctx, col)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) DeleteCollection(
	ctx context.Context,
	principal Principal,
	name string,
) error {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	err = vault.Db.DeleteCollection(ctx, name)
	if err != nil {
		return err
	}

	return nil
}

func (vault Vault) CreateRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	record Record,
) (string, error) {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", &ForbiddenError{request}
	}
	collection, err := vault.Db.GetCollection(ctx, collectionName)
	if err != nil {
		return "", err
	}

	// Ensure all fields are present
	for fieldName := range collection.Fields {
		if _, ok := record[fieldName]; !ok {
			return "", &ValueError{Msg: fmt.Sprintf("Field %s is missing from the record", fieldName)}
		}
	}

	encryptedRecord := make(Record)
	for fieldName, fieldValue := range record {
		// Ensure field name is allowed
		if fieldName == "" || fieldName == "id" || fieldName == "created_at" || fieldName == "updated_at" {
			return "", &ValueError{Msg: fmt.Sprintf("Invalid field name: %s", fieldName)}
		}

		// Ensure field exists on collection
		if _, ok := collection.Fields[fieldName]; !ok {
			return "", &ValueError{fmt.Sprintf("Field %s not found on collection %s", fieldName, collectionName)}
		}

		// Validate field PType
		_, err := GetPType(PTypeName(collection.Fields[fieldName].Type), fieldValue)
		if err != nil {
			return "", err
		}
		// Encrypt field value
		encryptedValue, err := vault.Priv.Encrypt(fieldValue)
		if err != nil {
			return "", err
		}
		encryptedRecord[fieldName] = encryptedValue
	}
	encryptedRecord["id"] = GenerateId("rec")
	encryptedRecord["created_at"] = time.Now().Format(time.RFC3339)
	encryptedRecord["updated_at"] = time.Now().Format(time.RFC3339)

	err = vault.Db.CreateRecord(ctx, collectionName, encryptedRecord)
	if err != nil {
		return "", err
	}
	return encryptedRecord["id"], nil
}

func (vault Vault) GetRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
) ([]string, error) {
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
	}
	return vault.Db.GetRecords(ctx, collectionName)
}

func (vault Vault) GetRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	recordID string,
	returnFormats map[string]string,
) (Record, error) {

	if recordID == "" {
		return nil, &ValueError{Msg: "recordID must not be empty"}
	}

	for field, format := range returnFormats {
		_request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s/%s/%s.%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH, recordID, field, format)}
		allowed, err := vault.ValidateAction(ctx, _request)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, &ForbiddenError{_request}
		}
	}

	col, err := vault.Db.GetCollection(ctx, collectionName)
	if err != nil {
		return nil, err
	}
	// Ensure requested fields exist on collection
	for field := range returnFormats {
		if _, ok := col.Fields[field]; !ok {
			return nil, &NotFoundError{resourceName: fmt.Sprintf("Field %s not found on collection %s", field, collectionName)}
		}
	}

	encryptedRecord, err := vault.Db.GetRecord(ctx, collectionName, recordID)
	if err != nil {
		return nil, err
	}

	decryptedRecord := make(Record)
	for field, format := range returnFormats {

		decryptedValue, err := vault.Priv.Decrypt(encryptedRecord[field])
		if err != nil {
			return nil, err
		}

		privValue, err := GetPType(PTypeName(col.Fields[field].Type), decryptedValue)
		if err != nil {
			return nil, err
		}

		decryptedRecord[field], err = privValue.Get(format)
		if err != nil {
			return nil, err
		}
	}

	return decryptedRecord, nil
}

func (vault Vault) SearchRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
	filters map[string]string,
) ([]string, error) {

	if len(filters) == 0 {
		return nil, &ValueError{Msg: "filters must not be empty"}
	}

	encryptedFilters := make(map[string]string)
	for field, value := range filters {
		// To search records we need to have read access to all records and the field we are searching on in plain format as this leak information about the record.
		request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s/%s/%s.%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH, "*", field, "plain")}
		allowed, err := vault.ValidateAction(ctx, request)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, &ForbiddenError{request}
		}

		val, err := vault.Priv.Encrypt(value)
		if err != nil {
			return nil, err
		}
		encryptedFilters[field] = val
	}

	recordIds, err := vault.Db.SearchRecords(ctx, collectionName, encryptedFilters)
	if err != nil {
		return nil, err
	}

	return recordIds, nil
}

func (vault Vault) UpdateRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	recordID string,
	record Record,
) error {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	encryptedRecord := make(Record)
	for recordFieldName, recordFieldValue := range record {
		encryptedValue, err := vault.Priv.Encrypt(recordFieldValue)
		if err != nil {
			return err
		}
		encryptedRecord[recordFieldName] = encryptedValue
	}

	err = vault.Db.UpdateRecord(ctx, collectionName, recordID, encryptedRecord)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) DeleteRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	recordID string,
) error {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	err = vault.Db.DeleteRecord(ctx, collectionName, recordID)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) GetPrincipal(
	ctx context.Context,
	principal Principal,
	username string,
) (*Principal, error) {
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
	}

	return vault.Db.GetPrincipal(ctx, username)
}

func (vault Vault) CreatePrincipal(
	ctx context.Context,
	actor Principal,
	principal *Principal,
) error {
	request := Request{actor, PolicyActionWrite, PRINCIPALS_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(principal.Password), bcrypt.DefaultCost)
	principal.Password = string(hashedPassword)
	principal.Id = GenerateId("prin")
	principal.CreatedAt = time.Now()
	principal.UpdatedAt = time.Now()

	if err := vault.Validate(principal); err != nil {
		return err
	}

	err = vault.Db.CreatePrincipal(ctx, principal)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) DeletePrincipal(
	ctx context.Context,
	principal Principal,
	username string,
) error {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	err = vault.Db.DeletePrincipal(ctx, username)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) Login(
	ctx context.Context,
	username,
	password string,
) (principal *Principal, err error) {

	if username == "" || password == "" {
		return nil, &ValueError{Msg: "username and password must not be empty"}
	}

	dbPrincipal, err := vault.Db.GetPrincipal(ctx, username)
	if err != nil {
		vault.Logger.Error("Error getting principal")
		return nil, &ForbiddenError{}
	}
	if dbPrincipal.Username == "" || dbPrincipal.Password == "" {
		return nil, &ForbiddenError{}
	}

	compareErr := bcrypt.CompareHashAndPassword([]byte(dbPrincipal.Password), []byte(password))
	if compareErr != nil {
		return nil, &ForbiddenError{}
	}

	return dbPrincipal, nil
}

func (vault Vault) CreatePolicy(
	ctx context.Context,
	principal Principal,
	p *Policy,
) error {
	request := Request{principal, PolicyActionWrite, POLICIES_PPATH}
	// Ensure resource starts with a slash
	for _, resource := range p.Resources {
		if !strings.HasPrefix(resource, "/") {
			return &ValueError{Msg: fmt.Sprintf("resources must start with a slash - '%s' is not a valid resource", resource)}
		}
	}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}
	err = vault.Validate(p)
	if err != nil {
		return err
	}
	p.Id = GenerateId("pol")

	return vault.Db.CreatePolicy(ctx, p)
}

func (vault Vault) GetPolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) (*Policy, error) {
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
	}

	return vault.Db.GetPolicy(ctx, policyId)
}

func (vault Vault) DeletePolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) error {
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
	}

	err = vault.Db.DeletePolicy(ctx, policyId)
	if err != nil {
		return err
	}
	return nil
}

func (vault Vault) GetPrincipalPolicies(
	ctx context.Context,
	principal Principal,
) ([]*Policy, error) {
	request := Request{principal, PolicyActionRead, POLICIES_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
	}

	policies, err := vault.Db.GetPolicies(ctx, principal.Policies)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (vault Vault) ValidateAction(
	ctx context.Context,
	request Request,
) (bool, error) {
	policies, err := vault.Db.GetPolicies(ctx, request.Actor.Policies)
	if err != nil {
		return false, err
	}

	allowed := EvaluateRequest(request, policies)
	if allowed {
		return true, nil
	}

	return false, nil
}

func (vault Vault) CreateToken(ctx context.Context, principal Principal, collectionName string, recordId string, fieldName string, returnFormat string) (string, error) {
	_, err := vault.GetRecord(ctx, principal, collectionName, recordId, map[string]string{fieldName: returnFormat})

	if err != nil {
		return "", err
	}

	tokenId := GenerateId("tok")
	err = vault.Db.CreateToken(ctx, tokenId, fmt.Sprintf("%s/%s/%s/%s", collectionName, recordId, fieldName, returnFormat))
	if err != nil {
		return "", err
	}
	return tokenId, nil
}

func (vault Vault) DeleteToken(ctx context.Context, tokenId string) error {
	return vault.Db.DeleteToken(ctx, tokenId)
}

func (vault Vault) GetTokenValue(ctx context.Context, principal Principal, tokenId string) (Record, error) {
	recordAndFieldStr, err := vault.Db.GetTokenValue(ctx, tokenId)
	if err != nil {
		return nil, err
	}

	splitRecordAndFieldStr := strings.Split(recordAndFieldStr, "/")
	if len(splitRecordAndFieldStr) != 4 {
		return nil, fmt.Errorf("invalid token value: %s stored in token: %s", recordAndFieldStr, tokenId)
	}

	collectionName, recordId, fieldName, returnFormat := splitRecordAndFieldStr[0], splitRecordAndFieldStr[1], splitRecordAndFieldStr[2], splitRecordAndFieldStr[3]
	record, err := vault.GetRecord(ctx, principal, collectionName, recordId, map[string]string{fieldName: returnFormat})
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (vault *Vault) Validate(payload interface{}) error {
	if vault.Validator == nil {
		panic("Validator not set")
	}
	var errors []*ValidationError

	err := vault.Validator.Struct(payload)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return &ValidationErrors{errors}
		}
		for _, err := range err.(validator.ValidationErrors) {
			var element ValidationError
			element.FailedField = err.Field()
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, &element)
		}
	}
	if len(errors) == 0 {
		return nil
	}
	return ValidationErrors{errors}
}
