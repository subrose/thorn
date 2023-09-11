package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

const COLLECTIONS_PREFIX = "collection:"
const RECORDS_PREFIX = "record:"
const FIELDS_PREFIX = "field:"
const PRINCIPAL_PREFIX = "principal:"
const POLICY_PREFIX = "policy:"
const INDEX_PREFIX = "idx:"
const TOKEN_PREFIX = "token:"

var (
	Prefix = map[string]string{
		"collection": COLLECTIONS_PREFIX,
		"record":     RECORDS_PREFIX,
	}
)

type RedisStore struct {
	Client *redis.Client
}

func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, fmt.Errorf("unable to connect to Redis: %w", err)
	}

	return &RedisStore{Client: client}, nil
}

func (rs RedisStore) Flush(ctx context.Context) error {
	_, err := rs.Client.FlushDB(ctx).Result()
	return err
}

func (rs RedisStore) GetCollections(ctx context.Context) ([]string, error) {
	members, err := rs.Client.SMembers(ctx, COLLECTIONS_PREFIX).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []string{}, nil
		}
		return []string{}, fmt.Errorf("failed to get collections: %w", err)
	}
	for i, member := range members {
		members[i] = member[len(COLLECTIONS_PREFIX):]
	}
	return members, nil
}

func (rs RedisStore) GetCollection(ctx context.Context, name string) (*Collection, error) {
	colId := fmt.Sprintf("%s%s", COLLECTIONS_PREFIX, name)
	dbCol := Collection{}
	col, err := rs.Client.HGetAll(ctx, colId).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get data from Redis with key %s: %w", colId, err)
	}
	if len(col) == 0 {
		return nil, &NotFoundError{colId}
	}
	pipe := rs.Client.Pipeline()
	for _, v := range col {
		pipe.HGetAll(ctx, v)
	}
	fields, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}
	dbCol.Fields = make(map[string]Field, len(fields))
	for _, field := range fields {
		dbCol.Fields[field.(*redis.MapStringStringCmd).Val()["name"]] = Field{
			Name:      field.(*redis.MapStringStringCmd).Val()["name"],
			Type:      field.(*redis.MapStringStringCmd).Val()["type"],
			IsIndexed: field.(*redis.MapStringStringCmd).Val()["is_indexed"] == "1",
		}
	}
	dbCol.Name = name
	return &dbCol, nil
}

func (rs RedisStore) CreateCollection(ctx context.Context, c Collection) (string, error) {
	colId := fmt.Sprintf("%s%s", COLLECTIONS_PREFIX, c.Name)

	exists, err := rs.Client.Exists(ctx, colId).Result()
	if err != nil {
		return c.Name, fmt.Errorf("failed to check collection existence: %w", err)
	}

	if exists == 1 {
		return c.Name, &ConflictError{colId}
	}

	pipe := rs.Client.Pipeline()
	pipe.SAdd(ctx, COLLECTIONS_PREFIX, colId)
	for fieldName, fieldValue := range c.Fields {
		fieldId := fmt.Sprintf("%s:%s%s", colId, FIELDS_PREFIX, fieldName)
		pipe.HSet(
			ctx,
			fieldId,
			"name", fieldName,
			"type", fieldValue.Type,
			"is_indexed", fieldValue.IsIndexed,
		)
		pipe.HSet(
			ctx,
			colId,
			fieldName,
			fieldId,
		)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return c.Name, fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}

	return c.Name, nil
}

func (rs RedisStore) DeleteCollection(ctx context.Context, name string) error {
	dbCollection, err := rs.GetCollection(ctx, name)
	if err != nil {
		return err
	}

	colId := fmt.Sprintf("%s%s", COLLECTIONS_PREFIX, name)
	recordIds, err := rs.Client.SMembers(ctx, fmt.Sprintf("%s:r", colId)).Result()
	if err != nil {
		return err
	}

	pipe := rs.Client.Pipeline()
	// Delete the collection
	pipe.Del(ctx, colId)
	pipe.SRem(ctx, COLLECTIONS_PREFIX, colId)
	// Delete all records and indexes for the collection
	for _, recordId := range recordIds {
		dbRecord, err := rs.GetRecords(ctx, name, []string{recordId})
		if err != nil {
			return err
		}

		redisKey := fmt.Sprintf("%s%s", RECORDS_PREFIX, recordId)
		pipe.Del(ctx, redisKey)
		pipe.SRem(ctx, fmt.Sprintf("%s:r", colId), recordId)
		for fieldName, fieldValue := range *dbRecord[recordId] {
			if dbCollection.Fields[fieldName].IsIndexed {
				pipe.SRem(ctx, formatIndex(fieldName, fieldValue), recordId)
			}
		}
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}

	return nil
}

func formatIndex(fieldName string, value string) string {
	// Given that the value is encrypted for now, this might not be needed.
	return fmt.Sprintf("%s%s_%s", INDEX_PREFIX, fieldName, strings.ToLower(value))
}

func (rs RedisStore) CreateRecords(ctx context.Context, collectionName string, records []Record) ([]string, error) {
	colId := fmt.Sprintf("%s%s", COLLECTIONS_PREFIX, collectionName)
	dbCol, err := rs.GetCollection(ctx, collectionName)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []string{}, &NotFoundError{colId}
		}
		return []string{}, err
	}

	recordIds := []string{}

	pipe := rs.Client.Pipeline()
	for _, record := range records {
		recordId := GenerateId()
		redisKey := fmt.Sprintf("%s%s", RECORDS_PREFIX, recordId)
		pipe.SAdd(ctx, fmt.Sprintf("%s:r", colId), recordId)
		for rFieldName, rFieldValue := range record {
			// TODO: Validate types and schema here
			field, ok := dbCol.Fields[rFieldName]
			if !ok {
				return []string{}, newValueError(fmt.Errorf("field %s does not exist in collection %s", rFieldName, collectionName))
			}
			pipe.HSet(
				ctx,
				redisKey,
				rFieldName,
				rFieldValue,
			)
			if field.IsIndexed {
				pipe.SAdd(ctx, formatIndex(rFieldName, rFieldValue), recordId)
			}
			// TODO: Add unique constraint here, removed for simplicity
		}

		recordIds = append(recordIds, recordId)
	}
	_, err = pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}
	return recordIds, nil
}

func (rs RedisStore) GetRecords(ctx context.Context, collectionName string, recordIds []string) (map[string]*Record, error) {
	_, err := rs.GetCollection(ctx, collectionName)
	if err != nil {
		return nil, err
	}
	records := map[string]*Record{}

	for _, recordId := range recordIds {
		redisKey := fmt.Sprintf("%s%s", RECORDS_PREFIX, recordId)
		recordMap, err := rs.Client.HGetAll(ctx, redisKey).Result()
		if len(recordMap) == 0 {
			return nil, &NotFoundError{redisKey}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get record with ID %s: %w", recordId, err)
		}

		record := &Record{}
		for key, value := range recordMap {
			(*record)[key] = value
		}

		records[recordId] = record
	}
	return records, nil
}

func (rs RedisStore) GetRecordsFilter(ctx context.Context, collectionName string, fieldName string, value string) ([]string, error) {
	dbCol, err := rs.GetCollection(ctx, collectionName)
	if err != nil {
		return []string{}, err
	}

	if !dbCol.Fields[fieldName].IsIndexed {
		return []string{}, ErrIndexError
	}

	data, err := rs.Client.SMembers(ctx, formatIndex(fieldName, value)).Result()
	if err != nil {
		return []string{}, err
	}
	return data, nil
}

func (rs RedisStore) UpdateRecord(ctx context.Context, collectionName string, recordId string, record Record) error {
	dbCol, err := rs.GetCollection(ctx, collectionName)
	if err != nil {
		return err
	}

	redisKey := fmt.Sprintf("%s%s", RECORDS_PREFIX, recordId)
	pipe := rs.Client.Pipeline()
	pipe.Del(ctx, redisKey)
	for rFieldName, rFieldValue := range record {
		field, ok := dbCol.Fields[rFieldName]
		if !ok {
			return newValueError(fmt.Errorf("field %s does not exist in collection %s", rFieldName, collectionName))
		}
		pipe.HSet(
			ctx,
			redisKey,
			rFieldName,
			rFieldValue,
		)
		if field.IsIndexed {
			pipe.SAdd(ctx, formatIndex(rFieldName, rFieldValue), recordId)
		}
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}
	return nil
}

func (rs RedisStore) DeleteRecord(ctx context.Context, collectionName string, recordId string) error {
	dbCol, err := rs.GetCollection(ctx, collectionName)
	if err != nil {
		return err
	}

	dbRecord, err := rs.GetRecords(ctx, collectionName, []string{recordId})
	if err != nil {
		return err
	}

	pipe := rs.Client.Pipeline()
	redisKey := fmt.Sprintf("%s%s", RECORDS_PREFIX, recordId)
	pipe.Del(ctx, redisKey)
	colId := fmt.Sprintf("%s%s", COLLECTIONS_PREFIX, collectionName)
	pipe.SRem(ctx, fmt.Sprintf("%s:r", colId), recordId)
	for fieldName, fieldValue := range *dbRecord[recordId] {
		if dbCol.Fields[fieldName].IsIndexed {
			pipe.SRem(ctx, formatIndex(fieldName, fieldValue), recordId)
		}
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}

	return nil
}

func (rs RedisStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	principalId := fmt.Sprintf("%s%s", PRINCIPAL_PREFIX, principal.Username)

	exists, err := rs.Client.Exists(ctx, principalId).Result()
	if err != nil {
		return fmt.Errorf("failed to check principal existence: %w", err)
	}

	if exists == 1 {
		return &ConflictError{principalId}
	}

	pipe := rs.Client.Pipeline()
	pipe.SAdd(ctx, PRINCIPAL_PREFIX, principalId)
	pipe.HSet(
		context.Background(),
		principalId,
		"username", principal.Username,
		"password", principal.Password,
		"created_at", principal.CreatedAt,
		"description", principal.Description,
	)

	for _, policy := range principal.Policies {
		// TODO: Is this a bad idea? The sets can get out of sync
		pipe.SAdd(ctx, fmt.Sprintf("%s:policies", principalId), policy)
		pipe.SAdd(ctx, fmt.Sprintf("%smembers:%s", POLICY_PREFIX, policy), principal.Username)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}
	return nil
}

func (rs RedisStore) GetPrincipal(ctx context.Context, username string) (*Principal, error) {
	principalId := fmt.Sprintf("%s%s", PRINCIPAL_PREFIX, username)
	var dbPrincipal Principal

	pipe := rs.Client.Pipeline()
	pipe.HGetAll(ctx, principalId)
	pipe.SMembers(ctx, fmt.Sprintf("%s:policies", principalId))
	pipeRes, err := pipe.Exec(ctx)
	if err != nil {
		if err == redis.Nil {
			return nil, &NotFoundError{principalId}
		}
		return nil, err
	}
	err = pipeRes[0].(*redis.MapStringStringCmd).Scan(&dbPrincipal)
	if err != nil {
		return nil, err
	}
	dbPrincipal.Policies = pipeRes[1].(*redis.StringSliceCmd).Val()
	if dbPrincipal.Username == "" || dbPrincipal.Password == "" {
		return nil, &NotFoundError{principalId}
	}
	return &dbPrincipal, nil
}

func (rs RedisStore) DeletePrincipal(ctx context.Context, username string) error {
	principalId := fmt.Sprintf("%s%s", PRINCIPAL_PREFIX, username)

	exists, err := rs.Client.Exists(ctx, principalId).Result()
	if err != nil {
		return fmt.Errorf("failed to check principal existence: %w", err)
	}

	if exists == 0 {
		return &NotFoundError{principalId}
	}

	pipe := rs.Client.Pipeline()
	pipe.Del(ctx, principalId)
	pipe.SRem(ctx, PRINCIPAL_PREFIX, principalId)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}
	return nil
}

type RawPolicy struct {
	PolicyId  string       `redis:"policy_id"`
	Effect    PolicyEffect `redis:"effect"`
	Actions   string       `redis:"actions"`
	Resources string       `redis:"resources"`
}

func (rawPolicy RawPolicy) toPolicy() *Policy {
	var actions []PolicyAction
	for _, action := range strings.Split(rawPolicy.Actions, ",") {
		actions = append(actions, PolicyAction(action))
	}
	policy := Policy{
		PolicyId:  rawPolicy.PolicyId,
		Effect:    rawPolicy.Effect,
		Actions:   actions,
		Resources: strings.Split(rawPolicy.Resources, ","),
	}

	return &policy
}

func (rs RedisStore) GetPolicy(ctx context.Context, policyId string) (*Policy, error) {
	polRedisId := fmt.Sprintf("%s%s", POLICY_PREFIX, policyId)
	cmd := rs.Client.HGetAll(ctx, polRedisId)
	if err := cmd.Err(); err != nil {
		return nil, err
	}

	result, err := cmd.Result()
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, &NotFoundError{polRedisId}
	}

	var rawPolicy RawPolicy
	if err := cmd.Scan(&rawPolicy); err != nil {
		return nil, err
	}

	return rawPolicy.toPolicy(), nil
}

func (rs RedisStore) GetPolicies(ctx context.Context, policyIds []string) ([]*Policy, error) {
	policies := []*Policy{}
	pipeline := rs.Client.Pipeline()

	// Prepare the commands
	cmds := make([]*redis.MapStringStringCmd, len(policyIds))
	for i, polId := range policyIds {
		polRedisId := fmt.Sprintf("%s%s", POLICY_PREFIX, polId)
		cmds[i] = pipeline.HGetAll(ctx, polRedisId)
	}

	// Execute the pipeline
	_, err := pipeline.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}

	// Process the results
	for _, cmd := range cmds {
		if err := cmd.Err(); err != nil {
			if err != redis.Nil {
				return nil, err
			}
			// Skip if not found
			continue
		}
		var rawPolicy RawPolicy
		if err := cmd.Scan(&rawPolicy); err != nil {
			return nil, err
		}
		policies = append(policies, rawPolicy.toPolicy())
	}
	return policies, nil
}

func (rs RedisStore) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	polRedisId := fmt.Sprintf("%s%s", POLICY_PREFIX, p.PolicyId)
	var actions []string
	for _, action := range p.Actions {
		actions = append(actions, string(action))
	}

	_, err := rs.Client.HSet(
		ctx,
		polRedisId,
		"policy_id", p.PolicyId,
		"effect", string(p.Effect),
		"actions", strings.Join(actions, ","),
		"resources", strings.Join(p.Resources, ","),
	).Result()

	if err != nil {
		return "", fmt.Errorf("failed to create policy: %w", err)
	}

	return p.PolicyId, nil
}

func (rs RedisStore) DeletePolicy(ctx context.Context, policyId string) error {
	_, err := rs.GetPolicy(ctx, policyId)
	if err != nil {
		return err
	}

	polRedisId := fmt.Sprintf("%s%s", POLICY_PREFIX, policyId)
	_, err = rs.Client.Del(ctx, polRedisId).Result()
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	return nil
}
