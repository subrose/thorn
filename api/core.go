package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	_logger "github.com/subrose/logger"
	_vault "github.com/subrose/vault"
)

// CoreConfig is used to parameterize a core
type CoreConfig struct {
	DB_HOST                 string
	DB_PORT                 int
	DB_PASSWORD             string
	DB_DB                   int
	VAULT_ENCRYPTION_KEY    string
	VAULT_ENCRYPTION_SECRET string
	VAULT_SIGNING_KEY       string
	VAULT_ADMIN_USERNAME    string
	VAULT_ADMIN_PASSWORD    string
	API_HOST                string
	API_PORT                int
	LOG_LEVEL               string
	LOG_HANDLER             string
	LOG_SINK                string
	DEV_MODE                bool
}

// Core is used as the central manager of Vault activity. It is the primary point of
// interface for API handlers and is responsible for managing the logical and physical
// backends, router, security barrier, and audit trails.
type Core struct {
	vault  _vault.Vault
	logger _logger.Logger
	conf   *CoreConfig
}

func ReadConfigs(configPath string) (*CoreConfig, error) {
	// Todo: Make this configurable
	conf := &CoreConfig{}
	var Config = koanf.New("_")
	err := Config.Load(file.Provider(configPath), toml.Parser())
	if err != nil {
		return nil, err
	}

	var envPrefix = Config.String("system_env_prefix")
	var provider = env.Provider(
		envPrefix,
		"_",
		func(s string) string {
			return strings.ToLower(strings.TrimPrefix(s, envPrefix))
		},
	)
	err = Config.Load(provider, nil)
	if err != nil {
		return nil, err
	}

	// Inject
	conf.DB_HOST = Config.String("db_host")
	conf.DB_PORT = Config.Int("db_port")
	conf.DB_PASSWORD = Config.String("db_password")
	conf.DB_DB = Config.Int("db_db")
	conf.VAULT_ENCRYPTION_KEY = Config.String("encryption_key")
	conf.VAULT_ENCRYPTION_SECRET = Config.String("encryption_secret")
	conf.VAULT_ADMIN_USERNAME = Config.String("admin_access_key")
	conf.VAULT_ADMIN_PASSWORD = Config.String("admin_access_secret")
	conf.API_HOST = Config.String("api_host")
	conf.API_PORT = Config.Int("api_port")
	conf.VAULT_SIGNING_KEY = Config.String("signing_key")
	conf.LOG_LEVEL = Config.String("log_level")
	conf.LOG_HANDLER = Config.String("log_handler")
	conf.LOG_SINK = Config.String("log_sink")
	conf.DEV_MODE = Config.Bool("system_dev_mode")

	return conf, nil
}

func ValidateCoreConfig(cc *CoreConfig) error {
	// Todo: Validate the configuration
	return nil
}

func CreateCore(conf *CoreConfig) (*Core, error) {
	c := &Core{}
	// confing
	if err := ValidateCoreConfig(conf); err != nil {
		return nil, err
	}
	c.conf = conf

	// Logger
	apiLogger, err := _logger.NewLogger("API", conf.LOG_SINK, conf.LOG_HANDLER, conf.LOG_LEVEL, conf.DEV_MODE)
	if err != nil {
		return nil, err
	}

	c.logger = apiLogger
	// Vault
	db, err := _vault.NewRedisStore(
		fmt.Sprintf("%v:%v", conf.DB_HOST, conf.DB_PORT),
		conf.DB_PASSWORD,
		conf.DB_DB,
	)
	if err != nil {
		panic(err)
	}

	priv := _vault.NewAESPrivatiser([]byte(conf.VAULT_ENCRYPTION_KEY), conf.VAULT_ENCRYPTION_SECRET)
	signer, err := _vault.NewHMACSigner([]byte(conf.VAULT_SIGNING_KEY))
	if err != nil {
		panic(err)
	}

	vaultLogger, err := _logger.NewLogger("VAULT", conf.LOG_SINK, conf.LOG_HANDLER, conf.LOG_LEVEL, conf.DEV_MODE)
	vault := _vault.Vault{
		Db:     db,
		Priv:   priv,
		Logger: vaultLogger,
		Signer: signer,
	}

	c.vault = vault

	return c, err
}

func (core *Core) Init() error {
	ctx := context.Background()
	if core.conf.DEV_MODE {
		_ = core.vault.Db.Flush(ctx)
	}
	_, _ = core.vault.Db.CreatePolicy(ctx, _vault.Policy{
		PolicyId:  "root",
		Effect:    _vault.EffectAllow,
		Actions:   []_vault.PolicyAction{_vault.PolicyActionWrite, _vault.PolicyActionRead},
		Resources: []string{"*"},
	})
	adminPrincipal := _vault.Principal{
		Username:    core.conf.VAULT_ADMIN_USERNAME,
		Password:    core.conf.VAULT_ADMIN_PASSWORD,
		Description: "admin",
		Policies:    []string{"root"}}
	err := core.vault.CreatePrincipal(ctx, adminPrincipal, adminPrincipal.Username, adminPrincipal.Password, adminPrincipal.Description, adminPrincipal.Policies)

	return err
}

func (core *Core) SendErrorResponse(c *fiber.Ctx, status int, message string, err error) error {
	return c.Status(status).JSON(ErrorResponse{status, message, nil})
}
