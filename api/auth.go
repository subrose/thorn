package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type LoginRequest struct {
	Username  string   `json:"username" validate:"required"`
	Password  string   `json:"password" validate:"required"`
	Policies  []string `json:"policies"`
	NotBefore int64    `json:"not_before" validate:"min=0"`
	ExpiresAt int64    `json:"expires_at"`
}

type LoginResponse struct {
	AccessToken string   `json:"access_token" validate:"required"`
	Principal   string   `json:"principal_username" validate:"required"`
	Policies    []string `json:"policies" validate:"required"`
	IssuedAt    int64    `json:"issued_at" validate:"required"`
	NotBefore   int64    `json:"not_before" validate:"required"`
	ExpiresAt   int64    `json:"expires_at" validate:"required"`
}

func (core *Core) Login(c *fiber.Ctx) error {
	request := LoginRequest{}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Invalid request format", nil})
	}

	if err := Validate(request); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	if request.NotBefore == 0 {
		// Default to the current time
		request.NotBefore = time.Now().Unix()
	}

	if request.ExpiresAt == 0 {
		// Default to an indefinite expiration time
		request.ExpiresAt = -1
	}
	token, tokenMetadata, err := core.vault.Login(c.Context(), request.Username, request.Password, request.Policies, request.NotBefore, request.ExpiresAt)
	if err != nil {
		var forbiddenErr *_vault.ForbiddenError
		var valueErr *_vault.ValueError
		if errors.As(err, &forbiddenErr) {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, "Invalid login", nil})
		}
		if errors.As(err, &valueErr) {
			return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, valueErr.Msg, nil})
		}
		return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
	}

	return c.Status(http.StatusOK).JSON(LoginResponse{
		AccessToken: token,
		Principal:   tokenMetadata.PrincipalUsername,
		Policies:    tokenMetadata.Policies,
		IssuedAt:    tokenMetadata.IssuedAt,
		NotBefore:   tokenMetadata.NotBefore,
		ExpiresAt:   tokenMetadata.ExpiresAt,
	})
}
