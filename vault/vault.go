package vault

import (
	"context"
	"errors"
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

type Token struct {
	PrincipalUsername string   `redis:"principal_username"` // principal username associated with the token
	Policies          []string `redis:"policies"`
	IssuedAt          int64    `redis:"issued_at"`  // timestamp the token was issued at
	NotBefore         int64    `redis:"not_before"` // timestamp the token is valid from
	ExpiresAt         int64    `redis:"expires_at"` // timestamp the token is set to expire
}

type VaultDB interface {
	GetCollection(ctx context.Context, name string) (Collection, error)
	GetCollections(ctx context.Context) ([]string, error)
	CreateCollection(ctx context.Context, c Collection) (string, error)
	CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error)
	GetRecords(ctx context.Context, recordIDs []string) (map[string]Record, error)
	GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error)
	GetPrincipal(ctx context.Context, username string) (Principal, error)
	CreatePrincipal(ctx context.Context, principal Principal) error
	CreateToken(ctx context.Context, tokenHash string, t Token) error
	GetToken(ctx context.Context, tokenHash string) (Token, error)
	Flush(ctx context.Context) error
}

type Privatiser interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type Signer interface {
	Sign(message string) (string, error)
	Verify(message, signature string) (bool, error)
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
	Signer           Signer
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
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", COLLECTIONS_PPATH, name)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return Collection{}, err
	}
	if !allowed {
		return Collection{}, &ForbiddenError{request}
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
	col Collection,
) (string, error) {
	request := Request{principal, PolicyActionWrite, COLLECTIONS_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", &ForbiddenError{request}
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
	request := Request{principal, PolicyActionWrite, fmt.Sprintf("%s/%s%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &ForbiddenError{request}
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
	// TODO: This is horribly inefficient, we should be able to do this in one go using ValidateActions(...)
	for _, recordID := range recordIDs {
		_request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s%s/%s/%s", COLLECTIONS_PPATH, collectionName, RECORDS_PPATH, recordID, format)}
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
	request := Request{principal, PolicyActionWrite, PRINCIPALS_PPATH}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return err
	}
	if !allowed {
		return &ForbiddenError{request}
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
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s/", PRINCIPALS_PPATH, username)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return Principal{}, err
	}
	if !allowed {
		return Principal{}, &ForbiddenError{request}
	}

	return vault.PrincipalManager.GetPrincipal(ctx, username)
}

func (vault Vault) ValidateAndGetToken(
	ctx context.Context,
	token string,
) (Token, error) {
	tokenSplits := strings.Split(token, ".")
	if len(tokenSplits) != 2 {
		return Token{}, &InvalidTokenError{Message: "invalid token"}
	}

	secret := tokenSplits[0]
	signature := tokenSplits[1]

	if secret == "" || signature == "" {
		return Token{}, &InvalidTokenError{Message: "invalid token"}
	}

	hashedSecret := Hash(secret)
	valid, err := vault.Signer.Verify(hashedSecret, signature)
	if err != nil {
		vault.Logger.Error("Error verifying token", err)
		return Token{}, &InvalidTokenError{Message: "invalid token"}
	}

	if !valid {
		return Token{}, &InvalidTokenError{Message: "invalid token"}
	}
	dbTokenId := fmt.Sprintf("%s.%s", hashedSecret, signature)
	dbToken, err := vault.Db.GetToken(ctx, dbTokenId)
	if err != nil {
		var notFoundErr *NotFoundError
		if errors.As(err, &notFoundErr) {
			return Token{}, &NonExistentTokenError{Message: "token not found"}
		}
		vault.Logger.Error("Error getting token", err)
		return Token{}, &InvalidTokenError{Message: "invalid token"}
	}

	if dbToken.ExpiresAt < time.Now().Unix() && dbToken.ExpiresAt != -1 {
		return Token{}, &ExpiredTokenError{Message: "token expired"}
	}

	if dbToken.NotBefore > time.Now().Unix() {
		return Token{}, &NotYetValidTokenError{Message: "token not valid yet"}
	}

	return dbToken, nil
}

func (vault Vault) createToken(
	ctx context.Context,
	principal Principal,
	policies []string,
	notBefore int64,
	expiresAt int64,
) (string, Token, error) {
	secret, err := GenerateSecret()
	if err != nil {
		return "", Token{}, err
	}
	hashedSecret := Hash(secret)
	signature, err := vault.Signer.Sign(hashedSecret)
	if err != nil {
		vault.Logger.Error("Error signing token", err)
		return "", Token{}, err
	}

	dbTokenId := fmt.Sprintf("%s.%s", hashedSecret, signature)
	token := fmt.Sprintf("%s.%s", secret, signature)
	if err != nil {
		vault.Logger.Error("Error signing token", err)
		return "", Token{}, err
	}

	tokenMetadata := Token{
		PrincipalUsername: principal.Username,
		Policies:          policies,
		IssuedAt:          time.Now().Unix(),
		NotBefore:         notBefore,
		ExpiresAt:         expiresAt,
	}

	err = vault.Db.CreateToken(ctx, dbTokenId, tokenMetadata)
	if err != nil {
		return "", Token{}, err
	}
	return token, tokenMetadata, nil
}

func (vault Vault) Login(
	ctx context.Context,
	username,
	password string,
	policies []string,
	notBefore int64,
	expiresAt int64,
) (token string, tokenMetadata Token, err error) {

	if username == "" || password == "" {
		return "", Token{}, newValueError(fmt.Errorf("username and password must be provided"))
	}

	dbPrincipal, err := vault.PrincipalManager.GetPrincipal(ctx, username)
	if err != nil {
		vault.Logger.Error("Error getting principal", err)
		return "", Token{}, &ForbiddenError{}
	}
	if dbPrincipal.Username == "" || dbPrincipal.Password == "" {
		return "", Token{}, &ForbiddenError{}
	}

	compareErr := bcrypt.CompareHashAndPassword([]byte(dbPrincipal.Password), []byte(password))
	if compareErr != nil {
		return "", Token{}, &ForbiddenError{}
	}

	// Default to principals policies if none provided
	policiesToApply := policies
	if len(policies) == 0 {
		policiesToApply = dbPrincipal.Policies
	} else {
		// Ensure requested policies exist on principal
		for _, policy := range policies {
			if !StringInSlice(policy, dbPrincipal.Policies) {
				return "", Token{}, newValueError(fmt.Errorf("policy '%s' does not exist on principal '%s'", policy, username))
			}
		}
	}

	// Ensure expiresAt is greater than notBefore
	if expiresAt != -1 && expiresAt < notBefore {
		return "", Token{}, newValueError(fmt.Errorf("expiresAt must be greater than notBefore"))
	}

	token, tokenMetadata, err = vault.createToken(
		ctx,
		dbPrincipal,
		policiesToApply,
		notBefore,
		expiresAt,
	)
	if err != nil {
		return "", Token{}, err
	}
	return token, tokenMetadata, nil
}

func (vault Vault) CreatePolicy(
	ctx context.Context,
	principal Principal,
	p Policy,
) (string, error) {
	request := Request{principal, PolicyActionWrite, POLICIES_PPATH}
	// Ensure resource starts with a slash
	for _, resource := range p.Resources {
		if !strings.HasPrefix(resource, "/") {
			return "", newValueError(fmt.Errorf("resources must start with a slash - '%s' is not a valid resource", resource))
		}
	}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", &ForbiddenError{request}
	}

	return vault.PolicyManager.CreatePolicy(ctx, p)
}

func (vault Vault) GetPolicy(
	ctx context.Context,
	principal Principal,
	policyId string,
) (Policy, error) {
	request := Request{principal, PolicyActionRead, fmt.Sprintf("%s/%s", POLICIES_PPATH, policyId)}
	allowed, err := vault.ValidateAction(ctx, request)
	if err != nil {
		return Policy{}, err
	}
	if !allowed {
		return Policy{}, &ForbiddenError{request}
	}

	return vault.PolicyManager.GetPolicy(ctx, policyId)
}

func (vault Vault) ValidateAction(
	ctx context.Context,
	request Request,
) (bool, error) {
	policies, err := vault.PolicyManager.GetPolicies(ctx, request.Principal.Policies)
	if err != nil {
		return false, err
	}

	allowed := EvaluateRequest(request, policies)
	if allowed {
		return true, nil
	}

	return false, nil
}
