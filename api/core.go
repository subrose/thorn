package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	_logger "github.com/subrose/logger"
	_vault "github.com/subrose/vault"
)

// CoreConfig is used to parameterize a core
type CoreConfig struct {
	DATABASE_URL      string
	ENCRYPTION_SECRET string
	SIGNING_KEY       string
	ADMIN_USERNAME    string
	ADMIN_PASSWORD    string
	API_HOST          string
	API_PORT          int
	LOG_LEVEL         string
	LOG_FORMAT        string
	LOG_SINK          string
	DEV_MODE          bool
}

// Core is used as the central manager of Vault activity. It is the primary point of
// interface for API handlers and is responsible for managing the logical and physical
// backends, router, security barrier, and audit trails.
type Core struct {
	vault  _vault.Vault
	logger _logger.Logger
	conf   *CoreConfig
}

func ReadConfigs() (*CoreConfig, error) {
	conf := &CoreConfig{}
	var k = koanf.New("_")

	// Define config keys
	const (
		prefix              = "THORN_"
		apiHostKey          = prefix + "API_HOST"
		apiPortKey          = prefix + "API_PORT"
		logLevelKey         = prefix + "LOG_LEVEL"
		logSinkKey          = prefix + "LOG_SINK"
		logFormatKey        = prefix + "LOG_FORMAT"
		devModeKey          = prefix + "DEV_MODE"
		databaseURLKey      = prefix + "DATABASE_URL"
		encryptionKeyKey    = prefix + "ENCRYPTION_KEY"
		encryptionSecretKey = prefix + "ENCRYPTION_SECRET"
		signingKeyKey       = prefix + "SIGNING_KEY"
		adminUsernameKey    = prefix + "ADMIN_USERNAME"
		adminPasswordKey    = prefix + "ADMIN_PASSWORD"
	)

	// Set default values
	err := k.Load(confmap.Provider(map[string]interface{}{
		apiHostKey:   "0.0.0.0",
		apiPortKey:   3000,
		logLevelKey:  "info",
		logSinkKey:   "stdout",
		logFormatKey: "json",
		devModeKey:   false,
	}, "_"), nil)

	if err != nil {
		return nil, err
	}

	// Load from environment variables
	var provider = env.Provider(prefix, "_", nil) // only THORN_ prefixed env variables will be loaded
	err = k.Load(provider, nil)
	if err != nil {
		return nil, err
	}

	conf.DATABASE_URL = k.String(databaseURLKey)
	conf.ENCRYPTION_SECRET = k.String(encryptionSecretKey)
	conf.SIGNING_KEY = k.String(signingKeyKey)
	conf.ADMIN_USERNAME = k.String(adminUsernameKey)
	conf.ADMIN_PASSWORD = k.String(adminPasswordKey)
	conf.API_HOST = k.String(apiHostKey)
	conf.API_PORT = k.Int(apiPortKey)
	conf.LOG_LEVEL = k.String(logLevelKey)
	conf.LOG_FORMAT = k.String(logFormatKey)
	conf.LOG_SINK = k.String(logSinkKey)
	conf.DEV_MODE = k.Bool(devModeKey)

	return conf, nil
}

func ValidateCoreConfig(cc *CoreConfig) error {
	// Todo: Validate the configuration
	return nil
}

func CreateCore(conf *CoreConfig) (*Core, error) {
	c := &Core{}
	if err := ValidateCoreConfig(conf); err != nil {
		return nil, err
	}
	c.conf = conf

	apiLogger, err := _logger.NewLogger("API", conf.LOG_SINK, conf.LOG_FORMAT, conf.LOG_LEVEL, conf.DEV_MODE)
	if err != nil {
		return nil, err
	}

	c.logger = apiLogger
	db, err := _vault.NewSqlStore(conf.DATABASE_URL)
	if err != nil {
		panic(err)
	}

	priv, err := _vault.NewAESPrivatiser(conf.ENCRYPTION_SECRET)
	if err != nil {
		panic(err)
	}
	signer, err := _vault.NewHMACSigner([]byte(conf.SIGNING_KEY))
	if err != nil {
		panic(err)
	}

	vaultLogger, err := _logger.NewLogger("VAULT", conf.LOG_SINK, conf.LOG_FORMAT, conf.LOG_LEVEL, conf.DEV_MODE)
	vault := _vault.Vault{
		Db:        db,
		Priv:      priv,
		Logger:    vaultLogger,
		Signer:    signer,
		Validator: _vault.NewValidator(),
	}

	c.vault = vault

	return c, err
}

func (core *Core) Init() error {
	// TODO: This should be better controlled, probably a one time setup
	// TODO: update the admin password with environment variables
	ctx := context.Background()
	if core.conf.DEV_MODE {
		err := core.vault.Db.Flush(ctx)
		if err != nil {
			core.logger.Error("Error flushing db")
			panic(err)
		}
	}
	// TODO: Move this to a bootstrap function
	rootPolicyId := _vault.GenerateId("pol")
	err := core.vault.Db.CreatePolicy(ctx, &_vault.Policy{
		Id:        rootPolicyId,
		Name:      "root",
		Effect:    _vault.EffectAllow,
		Actions:   []_vault.PolicyAction{_vault.PolicyActionWrite, _vault.PolicyActionRead},
		Resources: []string{"*"},
	})
	if err != nil {
		// If error is of type conflict, ignore it
		var co *_vault.ConflictError
		if errors.As(err, &co) {
			core.logger.Debug("Root policy already exists, continuing")
		} else {
			panic(err)
		}
	}
	adminPrincipal := _vault.Principal{
		Username:    core.conf.ADMIN_USERNAME,
		Password:    core.conf.ADMIN_PASSWORD,
		Description: "admin",
		Policies:    []string{rootPolicyId}}
	err = core.vault.CreatePrincipal(ctx, adminPrincipal, &adminPrincipal) // The admin bootstraps himself

	var co *_vault.ConflictError
	if err != nil {
		if errors.As(err, &co) {
			core.logger.Debug("Admin principal already exists, continuing")
		} else {
			panic(err)
		}
	}

	return nil
}

func (core *Core) ParseJsonBody(data []byte, payload interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&payload)
	if err != nil {
		return err
	}
	return nil
}
