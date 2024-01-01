package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

type Field struct {
	Type      string `json:"type" validate:"required"`
	IsIndexed bool   `json:"is_indexed" validate:"boolean"`
}

type CollectionType string

type Collection struct {
	Id          string           `json:"id"`
	Name        string           `json:"name" validate:"required,min=3,max=32"`
	Description string           `json:"description"`
	Parent      string           `json:"parent" validate:"omitempty,min=3,max=32"`
	Fields      map[string]Field `json:"fields" validate:"dive,required"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type Record map[string]string // field name -> value

const subject_id_field = "subject_id"

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
	Effect      PolicyEffect   `json:"effect" validate:"required,oneof=allow deny"`
	Actions     []PolicyAction `json:"actions" validate:"dive,required,oneof=read write"`
	Resources   []string       `json:"resources" validate:"required"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type Principal struct {
	Id          string    `json:"id"`
	Username    string    `json:"username" validate:"required,min=3,max=32"`
	Password    string    `json:"password" validate:"required,min=3"` // This is to limit the size of the password hash.
	Description string    `json:"description"`
	Policies    []string  `json:"policies"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}); err != nil {
		return nil, err
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, COLLECTIONS_PPATH}); err != nil {
		return nil, err
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, COLLECTIONS_PPATH}); err != nil {
		return err
	}

	if err := vault.Validate(col); err != nil {
		return err
	}

	col.Id = GenerateId("col")
	if col.Parent != "" {
		col.Fields["subject_id"] = Field{Type: "string", IsIndexed: true}
	}
	err := vault.Db.CreateCollection(ctx, col)
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}); err != nil {
		return err
	}

	return vault.Db.DeleteCollection(ctx, name)
}

func (vault Vault) CreateRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	record Record,
) (string, error) {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}); err != nil {
		return "", err
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

	// Validate parent relationship
	if collection.Parent != "" {
		if _, ok := record[subject_id_field]; !ok {
			return "", &ValueError{Msg: "subject record must be provided for data collections as field: subject_id"}
		}
		_, err := vault.Db.GetRecord(ctx, collection.Parent, record[subject_id_field])
		if err != nil {
			return "", &ValueError{Msg: fmt.Sprintf("referenced subject record %s does not exist", record[subject_id_field])}
		}
	}

	encryptedRecord := make(Record)
	for fieldName, fieldValue := range record {
		// Ensure field name is allowed
		if fieldName == "" || fieldName == "id" || fieldName == "created_at" || fieldName == "updated_at" {
			return "", &ValueError{Msg: fmt.Sprintf("reserved field name is not allowed to be set: %s", fieldName)}
		}

		// Ensure passed in field exists on collection
		if _, ok := collection.Fields[fieldName]; !ok {
			if collection.Parent != "" && fieldName == subject_id_field {
				encryptedRecord[subject_id_field] = fieldValue
				continue
			}
			return "", &ValueError{fmt.Sprintf("field %s does not exist on collection %s", fieldName, collectionName)}
		}

		// Validate field PType
		if _, err := GetPType(PTypeName(collection.Fields[fieldName].Type), fieldValue); err != nil {
			return "", err
		}

		if fieldName == subject_id_field {
			encryptedRecord[subject_id_field] = fieldValue
			continue
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

	if err := vault.Db.CreateRecord(ctx, collectionName, encryptedRecord); err != nil {
		return "", err
	}
	return encryptedRecord["id"], nil
}

func (vault Vault) GetRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
) ([]string, error) {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}); err != nil {
		return nil, err
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
		if err := vault.ValidateAction(ctx, _request); err != nil {
			return nil, err
		}
	}

	col, err := vault.Db.GetCollection(ctx, collectionName)
	if err != nil {
		return nil, err
	}
	for field := range returnFormats {
		// Ensure requested fields exist on collection
		if _, ok := col.Fields[field]; !ok {
			return nil, &NotFoundError{resourceName: fmt.Sprintf("Field %s not found on collection %s", field, collectionName)}
		}

		// Ensure requested fields are not internal fields
		if field == "id" || field == "created_at" || field == "updated_at" || field == subject_id_field {
			return nil, &ValueError{Msg: fmt.Sprintf("reserved field name is not allowed to be returned as a ptype: %s", field)}
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

	decryptedRecord["id"] = recordID
	decryptedRecord["created_at"] = encryptedRecord["created_at"]
	decryptedRecord["updated_at"] = encryptedRecord["updated_at"]
	if col.Parent != "" {
		decryptedRecord[subject_id_field] = encryptedRecord[subject_id_field]
	}

	return decryptedRecord, nil
}

func (vault Vault) SearchRecords(
	ctx context.Context,
	principal Principal,
	collectionName string,
	filters map[string]string, // Todo: type and validate filters
) ([]string, error) {

	if len(filters) == 0 {
		return nil, &ValueError{Msg: "filters must not be empty"}
	}

	encryptedFilters := make(map[string]string)
	for field, value := range filters {
		// To search records we need to have read access to all records and the field we are searching on in plain format as this leak information about the record.
		request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s/%s/%s.%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH, "*", field, "plain")}
		if err := vault.ValidateAction(ctx, request); err != nil {
			return nil, err
		}

		if field == subject_id_field {
			encryptedFilters[field] = value
			continue
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}); err != nil {
		return err
	}

	encryptedRecord := make(Record)
	for recordFieldName, recordFieldValue := range record {
		encryptedValue, err := vault.Priv.Encrypt(recordFieldValue)
		if err != nil {
			return err
		}
		encryptedRecord[recordFieldName] = encryptedValue
	}

	return vault.Db.UpdateRecord(ctx, collectionName, recordID, encryptedRecord)
}

func (vault Vault) DeleteRecord(
	ctx context.Context,
	principal Principal,
	collectionName string,
	recordID string,
) error {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}); err != nil {
		return err
	}
	return vault.Db.DeleteRecord(ctx, collectionName, recordID)
}

func (vault Vault) GetPrincipal(
	ctx context.Context,
	principal Principal,
	username string,
) (*Principal, error) {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}); err != nil {
		return nil, err
	}
	return vault.Db.GetPrincipal(ctx, username)
}

func (vault Vault) CreatePrincipal(
	ctx context.Context,
	actor Principal,
	principal *Principal,
) error {
	if err := vault.ValidateAction(ctx, Request{actor, PolicyActionWrite, PRINCIPALS_PPATH}); err != nil {
		return err
	}

	// hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(principal.Password), bcrypt.DefaultCost)
	hashedPassword, _ := vault.Priv.Encrypt(principal.Password)
	principal.Password = string(hashedPassword)
	principal.Id = GenerateId("prin")
	principal.CreatedAt = time.Now()
	principal.UpdatedAt = time.Now()

	if err := vault.Validate(principal); err != nil {
		return err
	}
	return vault.Db.CreatePrincipal(ctx, principal)
}

func (vault Vault) DeletePrincipal(
	ctx context.Context,
	principal Principal,
	username string,
) error {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}); err != nil {
		return err
	}
	return vault.Db.DeletePrincipal(ctx, username)
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

	decryptedPassword, err := vault.Priv.Decrypt(dbPrincipal.Password)
	if err != nil {
		vault.Logger.Error(fmt.Sprintf("Error decrypting password: %s", err.Error()))
		return nil, &ForbiddenError{}
	}
	if decryptedPassword != password {
		return nil, &ForbiddenError{}
	}

	return dbPrincipal, nil
}

func (vault Vault) CreatePolicy(
	ctx context.Context,
	principal Principal,
	p *Policy,
) error {
	// Ensure resource starts with a slash
	for _, resource := range p.Resources {
		if !strings.HasPrefix(resource, "/") {
			return &ValueError{Msg: fmt.Sprintf("resources must start with a slash - '%s' is not a valid resource", resource)}
		}
	}
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, POLICIES_PPATH}); err != nil {
		return err
	}
	if err := vault.Validate(p); err != nil {
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
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}); err != nil {
		return nil, err
	}
	return vault.Db.GetPolicy(ctx, policyId)
}

func (vault Vault) DeletePolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) error {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}); err != nil {
		return err
	}
	return vault.Db.DeletePolicy(ctx, policyId)
}

func (vault Vault) GetPrincipalPolicies(
	ctx context.Context,
	principal Principal,
) ([]*Policy, error) {
	if err := vault.ValidateAction(ctx, Request{principal, PolicyActionRead, POLICIES_PPATH}); err != nil {
		return nil, err
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
) error {
	policies, err := vault.Db.GetPolicies(ctx, request.Actor.Policies)
	if err != nil {
		return err
	}

	allowed := EvaluateRequest(request, policies)
	if allowed {
		return nil
	}

	return &ForbiddenError{request}
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
			element.FailedField = err.Namespace()
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, &element)
		}
	}
	if len(errors) == 0 {
		return nil
	}
	return &ValidationErrors{errors}
}
