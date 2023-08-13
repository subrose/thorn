package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

const PRINCIPAL_CONTEXT_KEY = "principal"

func ApiLogger(core *Core) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		t1 := time.Now()
		_ = ctx.Next()
		t2 := time.Now()
		dt := float64(t2.Sub(t1))
		core.logger.WriteRequestLog(
			ctx.Method(),
			ctx.Path(),
			ctx.IP(),
			ctx.Get("User-Agent"),
			ctx.Get("X-Trace-Id"),
			dt,
			ctx.Response().StatusCode(),
		)

		return nil
	}
}

func GetSessionPrincipal(c *fiber.Ctx) _vault.Principal {
	return c.Locals(PRINCIPAL_CONTEXT_KEY).(_vault.Principal)
}

func authGuard(core *Core) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing Authorization header",
			})
		}

		const prefix = "Basic "
		if !strings.HasPrefix(authHeader, prefix) {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Authorization header",
			})
		}

		encodedCredentials := authHeader[len(prefix):]
		decoded, err := base64.StdEncoding.DecodeString(encodedCredentials)
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid base64 encoding",
			})
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Authorization value",
			})
		}

		username := credentials[0]
		password := credentials[1]

		principal, err := core.vault.Login(ctx.Context(), username, password)
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid username or password",
			})
		}

		// Set principal in context
		ctx.Locals(PRINCIPAL_CONTEXT_KEY, principal)
		// Continue stack
		_ = ctx.Next()

		return nil
	}
}

func SetupApi(core *Core) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Use(ApiLogger(core))

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("OK")
	})

	principalGroup := app.Group("/principals")
	principalGroup.Use(authGuard(core))
	principalGroup.Get(":username", core.GetPrincipal)
	principalGroup.Post("", core.CreatePrincipal)

	collectionsGroup := app.Group("/collections")
	collectionsGroup.Use(authGuard(core))
	collectionsGroup.Get("", core.GetCollections)
	collectionsGroup.Get("/:name", core.GetCollection)
	collectionsGroup.Post("", core.CreateCollection)
	collectionsGroup.Post("/:name/records", core.CreateRecords)
	collectionsGroup.Get("/:name/records/:id/:format", core.GetRecord)

	policiesGroup := app.Group("/policies")
	policiesGroup.Use(authGuard(core))
	policiesGroup.Get(":policyId", core.GetPolicyById)
	policiesGroup.Post("", core.CreatePolicy)

	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404) // => 404 "Not Found"
	})

	return app
}

func main() {
	configPath := flag.String("configFile", "", "Path to config file")
	flag.Parse()

	if *configPath == "" {
		panic("Config path not specified")
	}

	coreConfig, err := ReadConfigs(*configPath)
	if err != nil {
		panic(err)
	}
	core, err := CreateCore(coreConfig)
	if err != nil {
		panic(err)
	}
	initError := core.Init()
	if err != nil {
		panic(initError)
	}

	app := SetupApi(core)
	listenAddr := fmt.Sprintf("%s:%v", coreConfig.API_HOST, coreConfig.API_PORT)
	fmt.Println("Listening on", listenAddr)
	err = app.Listen(listenAddr)
	if err != nil {
		panic(err)
	}

}
