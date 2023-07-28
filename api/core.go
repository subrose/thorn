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
	DB_HOST                   string
	DB_PORT                   int
	DB_PASSWORD               string
	DB_DB                     int
	VAULT_ENCRYPTION_KEY      string
	VAULT_ENCRYPTION_SECRET   string
	VAULT_ADMIN_ACCESS_KEY    string
	VAULT_ADMIN_ACCESS_SECRET string
	API_HOST                  string
	API_PORT                  int
	API_JWT_SECRET            string
	LOG_LEVEL                 string
	LOG_OUTPUT                string
	DEV_MODE                  bool
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
	conf.VAULT_ADMIN_ACCESS_KEY = Config.String("admin_access_key")
	conf.VAULT_ADMIN_ACCESS_SECRET = Config.String("admin_access_secret")
	conf.API_HOST = Config.String("api_host")
	conf.API_PORT = Config.Int("api_port")
	conf.API_JWT_SECRET = Config.String("api_jwt_secret")
	conf.LOG_LEVEL = Config.String("log_level")
	conf.LOG_OUTPUT = Config.String("log_output")
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
	apiLogger, err := _logger.NewLogger("API", conf.LOG_OUTPUT, conf.LOG_LEVEL, conf.DEV_MODE)
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

	res := db.Client.Ping(context.Background())
	if res.Err() != nil {
		panic(res.Err())
	}

	priv := _vault.NewAESPrivatiser([]byte(conf.VAULT_ENCRYPTION_KEY), conf.VAULT_ENCRYPTION_SECRET)
	var policyManager _vault.PolicyManager = db
	var principalManager _vault.PrincipalManager = db
	vaultLogger, err := _logger.NewLogger("VAULT", conf.LOG_OUTPUT, conf.LOG_LEVEL, conf.DEV_MODE)
	vault := _vault.Vault{Db: db, Priv: priv, PrincipalManager: principalManager, PolicyManager: policyManager, Logger: vaultLogger}

	c.vault = vault

	return c, err
}

func (core *Core) Init() error {
	ctx := context.Background()
	if core.conf.DEV_MODE {
		_ = core.vault.Db.Flush(ctx)
	}
	_, _ = core.vault.PolicyManager.CreatePolicy(ctx, _vault.Policy{
		PolicyId: "admin-write",
		Effect:   _vault.EffectAllow,
		Action:   _vault.PolicyActionWrite,
		Resource: "*",
	})
	_, _ = core.vault.PolicyManager.CreatePolicy(ctx, _vault.Policy{
		PolicyId: "admin-read",
		Effect:   _vault.EffectAllow,
		Action:   _vault.PolicyActionRead,
		Resource: "*",
	})
	adminPrincipal := _vault.Principal{
		Username:    core.conf.VAULT_ADMIN_ACCESS_KEY,
		Password:    core.conf.VAULT_ADMIN_ACCESS_SECRET,
		Description: "admin",
		Policies:    []string{"admin-write", "admin-read"}} // TODO: Think about this, Admins shouldn't have read?
	err := core.vault.CreatePrincipal(ctx, adminPrincipal, adminPrincipal.Username, adminPrincipal.Password, adminPrincipal.Description, adminPrincipal.Policies)

	return err
}

func (core *Core) SendErrorResponse(c *fiber.Ctx, status int, message string, err error) error {
	if err != nil {
		core.logger.Error("", err)
	}
	return c.Status(status).JSON(ErrorResponse{status, message, nil})
}
