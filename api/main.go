package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/helmet"
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
			core.logger.Error(fmt.Sprintf("Error logging in: %s", err.Error()))
			return &AuthError{"Invalid username or password"}
		}

		// Set principal in context
		ctx.Locals(PRINCIPAL_CONTEXT_KEY, *principal)
		// Continue stack
		err = ctx.Next()

		return err
	}
}

func (core *Core) customErrorHandler(ctx *fiber.Ctx, err error) error {
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
	var co *_vault.ConflictError
	var va *_vault.ValidationErrors
	var ns *_vault.NotSupportedError

	switch {
	case errors.As(err, &ve):
		return ctx.Status(http.StatusBadRequest).JSON(ErrorResponse{ve.Error(), nil})
	case errors.As(err, &fe):
		return ctx.Status(http.StatusForbidden).JSON(ErrorResponse{fe.Error(), nil})
	case errors.As(err, &ne):
		return ctx.Status(http.StatusNotFound).JSON(ErrorResponse{ne.Error(), nil})
	case errors.As(err, &ae):
		return ctx.Status(http.StatusUnauthorized).JSON(ErrorResponse{ae.Error(), nil})
	case errors.As(err, &ns):
		return ctx.Status(http.StatusNotImplemented).JSON(ErrorResponse{err.Error(), nil})
	case errors.As(err, &co):
		return ctx.Status(http.StatusConflict).JSON(ErrorResponse{co.Error(), nil})
	case errors.As(err, &va):
		return ctx.Status(http.StatusBadRequest).JSON(ErrorResponse{va.Error(), nil})
	default:
		// Handle other types of errors by returning a generic 500 - this should remain obscure as it can leak information
		core.logger.Error(fmt.Sprintf("Unhandled error: %s", err.Error()))
		return ctx.Status(http.StatusInternalServerError).JSON(ErrorResponse{"Internal Server Error", nil})
	}
}

func JSONOnlyMiddleware(c *fiber.Ctx) error {
	// Allow blank content headers - assuming we default to json
	if c.Get("Content-Type") != "application/json" && c.Get("Content-Type") != "" {
		// If not application/json, send a 415 Unsupported Media Type response
		return c.Status(fiber.StatusUnsupportedMediaType).JSON(ErrorResponse{"Unsupported Media Type. Only application/json allowed. Got " + c.Get("Content-Type"), nil})
	}
	return c.Next()
}

func SetupApi(core *Core) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler:          core.customErrorHandler,
	})
	app.Use(helmet.New())
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
	collectionsGroup.Post("/:name/records", core.CreateRecord)
	collectionsGroup.Get("/:name/records", core.GetRecords)
	collectionsGroup.Get("/:name/records/:id", core.GetRecord)
	collectionsGroup.Post("/:name/records/search", core.SearchRecords)
	collectionsGroup.Put("/:name/records/:id", core.UpdateRecord)
	collectionsGroup.Delete("/:name/records/:id", core.DeleteRecord)

	policiesGroup := app.Group("/policies")
	policiesGroup.Use(authGuard(core))
	policiesGroup.Get(":policyId", core.GetPolicyById)
	policiesGroup.Post("", JSONOnlyMiddleware, core.CreatePolicy)
	policiesGroup.Get("", core.GetPolicies)
	policiesGroup.Delete(":policyId", core.DeletePolicy)

	tokensGroup := app.Group("/tokens")
	tokensGroup.Use(authGuard(core))
	tokensGroup.Get(":tokenId", core.GetTokenById)
	tokensGroup.Post("", core.CreateToken)

	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404)
	})

	return app
}

func main() {
	coreConfig, err := ReadConfigs()
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
