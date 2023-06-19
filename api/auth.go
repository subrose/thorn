package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/golang-jwt/jwt/v5"
	_vault "github.com/subrose/vault"
)

type Token struct {
	AccessToken string `json:"access_token"`
	Type        string `json:"token_type"`
}

type CustomClaims struct {
	Policies []string `json:"policies"`
	jwt.RegisteredClaims
}

func GetSessionPrincipal(c *fiber.Ctx) _vault.Principal {
	return c.Locals("principal").(_vault.Principal)
}

func (core *Core) generateJWT(p _vault.Principal) (string, error) {

	// Create the claims
	claims := CustomClaims{
		p.Policies,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // TODO: Make this configurable
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()), // TODO: Make this configurable
			Issuer:    "subrose-vault",                // TODO: Vault namespace goes here or app name
			Subject:   p.AccessKey,
			ID:        _vault.GenerateId(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(core.conf.API_JWT_SECRET))
	if err != nil {
		return "", err
	}
	return ss, nil
}

func (core *Core) validateJWT(tokenString string) (_vault.Principal, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(core.conf.API_JWT_SECRET), nil
	})

	if err != nil {
		return _vault.Principal{}, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return _vault.Principal{AccessKey: claims.Subject, Policies: claims.Policies}, nil
	}
	return _vault.Principal{}, nil
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
	dbPrincipal, err := core.vault.AuthenticateUser(c.Context(), u, p)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(ErrorResponse{http.StatusUnauthorized, "Invalid credentials", nil})
	}

	token, err := core.generateJWT(dbPrincipal)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
	}

	return c.Status(http.StatusOK).JSON(Token{AccessToken: token, Type: "Bearer"})
}
