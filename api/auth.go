package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	_vault "github.com/subrose/vault"
)

type ClientToken struct {
	AccessToken string   `json:"access_token"`
	Principal   string   `json:"principal_username"`
	Policies    []string `json:"policies"`
	IssuedAt    int64    `json:"issued_at"`
	NotBefore   int64    `json:"not_before"`
	ExpiresAt   int64    `json:"expires_at"`
}

func GetSessionPrincipal(c *fiber.Ctx) _vault.Principal {
	return c.Locals("principal").(_vault.Principal)
}

func ExtractCredentials(c *fiber.Ctx) (username string, password string, err error) {
	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic".
	if len(auth) <= 6 || !utils.EqualFold(auth[:6], "basic ") {
		return "", "", errors.New("invalid credentials")
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", errors.New("invalid credentials")
	}

	// Get the credentials
	creds := utils.UnsafeString(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		return "", "", errors.New("invalid credentials")
	}

	// Get the username and password
	username = creds[:index]
	password = creds[index+1:]
	return username, password, nil
}

func (core *Core) GenerateBearerTokenFromCreds(c *fiber.Ctx) error {
	u, p, err := ExtractCredentials(c)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(ErrorResponse{http.StatusUnauthorized, "Invalid credentials", nil})
	}
	token, tokenMetadata, err := core.vault.Login(c.Context(), u, p)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(ErrorResponse{http.StatusUnauthorized, "Invalid credentials", nil})
	}

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
	}

	return c.Status(http.StatusOK).JSON(ClientToken{
		AccessToken: token,
		Principal:   tokenMetadata.PrincipalUsername,
		Policies:    tokenMetadata.Policies,
		IssuedAt:    tokenMetadata.IssuedAt,
		NotBefore:   tokenMetadata.NotBefore,
		ExpiresAt:   tokenMetadata.ExpiresAt,
	})
}
