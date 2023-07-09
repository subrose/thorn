package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

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

func JwtGuard(core *Core) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Extract JWT from header
		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing Authorization header",
			})
		}
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Authorization header",
			})
		}
		tokenString := bearerToken[1]
		// Validate JWT
		principal, err := core.validateJWT(tokenString)
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid JWT",
			})
		}
		// Set principal in context
		ctx.Locals("principal", principal)
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

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("OK")
	})

	authGroup := app.Group("/auth")
	authGroup.Post("/token", core.GenerateBearerTokenFromCreds)

	principalGroup := app.Group("/principals")
	principalGroup.Use(JwtGuard(core))
	principalGroup.Get(":principalId", core.GetPrincipalById)
	principalGroup.Post("", core.CreatePrincipal)

	collectionsGroup := app.Group("/collections")
	collectionsGroup.Use(JwtGuard(core))
	collectionsGroup.Get("", core.GetCollections)
	collectionsGroup.Get("/:name", core.GetCollection)
	collectionsGroup.Post("", core.CreateCollection)
	collectionsGroup.Post("/:name/records", core.CreateRecords)
	collectionsGroup.Get("/:name/records/:id/:format", core.GetRecord)

	policiesGroup := app.Group("/policies")
	policiesGroup.Use(JwtGuard(core))
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
