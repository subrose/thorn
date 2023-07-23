package main

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

// Common testing utils?
var testConfigPath = flag.String("testConfigFile", "../conf/test.conf.toml", "Path to config file")

func InitTestingVault(t *testing.T) (*fiber.App, _vault.Vault, *Core) {
	// Setup
	if *testConfigPath == "" {
		panic("Config path not specified")
	}

	coreConfig, err := ReadConfigs(*testConfigPath)

	if err != nil {
		t.Fatal("Failed to read config", err)
	}
	core, err := CreateCore(coreConfig)
	if err != nil {
		t.Fatal("Failed to create core", err)
	}
	app := SetupApi(core)
	// TODO: Use a mock db for unit testing
	db, _ := _vault.NewRedisStore(
		fmt.Sprintf("%s:%d", coreConfig.DB_HOST, coreConfig.DB_PORT),
		coreConfig.DB_PASSWORD,
		coreConfig.DB_DB,
	)

	priv := _vault.NewAESPrivatiser([]byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}, "abc&1*~#^2^#s0^=)^^7%b34")
	var pm _vault.PolicyManager = db
	vault := _vault.Vault{Db: db, Priv: priv, PrincipalManager: db, PolicyManager: pm}
	bootstrapContext := context.Background()
	_ = vault.Db.Flush(bootstrapContext)
	_, _ = pm.CreatePolicy(bootstrapContext, _vault.Policy{
		PolicyId: "admin-read",
		Effect:   _vault.EffectAllow,
		Action:   _vault.PolicyActionRead,
		Resource: "*",
	})
	_, _ = pm.CreatePolicy(bootstrapContext, _vault.Policy{
		PolicyId: "admin-write",
		Effect:   _vault.EffectAllow,
		Action:   _vault.PolicyActionWrite,
		Resource: "*",
	})
	adminPrincipal := _vault.Principal{Username: coreConfig.VAULT_ADMIN_ACCESS_KEY, Password: coreConfig.VAULT_ADMIN_ACCESS_SECRET, Policies: []string{"admin-write", "admin-read"}}
	principalErr := vault.CreatePrincipal(bootstrapContext, adminPrincipal, coreConfig.VAULT_ADMIN_ACCESS_KEY, coreConfig.VAULT_ADMIN_ACCESS_SECRET, "admin principal", []string{"admin-write", "admin-read"})
	if principalErr != nil {
		t.Fatal("Failed to create admin principal", principalErr)
	}
	return app, vault, core
}
