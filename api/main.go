package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	_vault "github.com/subrose/vault"
)

const PRINCIPAL_CONTEXT_KEY = "principal"

func ApiLogger(core *Core) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		t1 := time.Now()
		err := ctx.Next()
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
		return err
	}
}

func GetSessionPrincipal(c *fiber.Ctx) _vault.Principal {
	return c.Locals(PRINCIPAL_CONTEXT_KEY).(_vault.Principal)
}

func authGuard(core *Core) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			return &AuthError{"Authorization header is required"}
		}

		const prefix = "Basic "
		if !strings.HasPrefix(authHeader, prefix) {
			return &AuthError{"Invalid authorisation header"}
		}

		encodedCredentials := authHeader[len(prefix):]
		decoded, err := base64.StdEncoding.DecodeString(encodedCredentials)
		if err != nil {
			return &AuthError{"Invalid base64 encoding"}
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			return &AuthError{"Invalid Authorization value"}
		}

		username := credentials[0]
		password := credentials[1]

		principal, err := core.vault.Login(ctx.Context(), username, password)
		if err != nil {
			return &AuthError{"Invalid username or password"}
		}

		ctx.Locals(PRINCIPAL_CONTEXT_KEY, principal)
		err = ctx.Next()

		return err
	}
}

func customErrorHandler(ctx *fiber.Ctx, err error) error {
	var e *fiber.Error
	if errors.As(err, &e) {
		code := e.Code
		return ctx.Status(code).SendString(err.Error())
	}

	// Handle custom errors from the vault package
	var ve *_vault.ValueError
	var fe *_vault.ForbiddenError
	var ne *_vault.NotFoundError
	var ae *AuthError
	switch {
	case errors.As(err, &ve):
		return ctx.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, ve.Error(), nil})
	case errors.As(err, &fe):
		return ctx.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, fe.Error(), nil})
	case errors.As(err, &ne):
		return ctx.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, ne.Error(), nil})
	case errors.As(err, &ae):
		return ctx.Status(http.StatusUnauthorized).JSON(ErrorResponse{http.StatusUnauthorized, ae.Error(), nil})
	default:
		// Handle other types of errors by returning a generic 500 - this should remain obscure as it can leak information
		return ctx.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Internal Server Error", nil})
	}
}

func SetupApi(core *Core) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler:          customErrorHandler,
	})
	app.Use(ApiLogger(core))
	app.Use(recover.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).SendString("OK")
	})

	principalGroup := app.Group("/principals")
	principalGroup.Use(authGuard(core))
	principalGroup.Get(":username", core.GetPrincipal)
	principalGroup.Post("", core.CreatePrincipal)
	principalGroup.Delete(":username", core.DeletePrincipal)

	collectionsGroup := app.Group("/collections")
	collectionsGroup.Use(authGuard(core))
	collectionsGroup.Get("", core.GetCollections)
	collectionsGroup.Get("/:name", core.GetCollection)
	collectionsGroup.Delete("/:name", core.DeleteCollection)
	collectionsGroup.Post("", core.CreateCollection)
	collectionsGroup.Post("/:name/records", core.CreateRecords)
	collectionsGroup.Get("/:name/records/:id", core.GetRecord)
	collectionsGroup.Put("/:name/records/:id", core.UpdateRecord)
	collectionsGroup.Delete("/:name/records/:id", core.DeleteRecord)

	policiesGroup := app.Group("/policies")
	policiesGroup.Use(authGuard(core))
	policiesGroup.Get(":policyId", core.GetPolicyById)
	policiesGroup.Post("", core.CreatePolicy)
	policiesGroup.Get("", core.GetPolicies)
	policiesGroup.Delete(":policyId", core.DeletePolicy)

	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404)
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
	core.logger.Info(fmt.Sprintf("Listening on %s", listenAddr))
	err = app.Listen(listenAddr)
	if err != nil {
		panic(err)
	}

}
