package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type PrincipalModel struct {
	Username    string   `json:"username" validate:"required,min=4,max=32"`
	Password    string   `json:"password" validate:"required,min=4"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
}

func (core *Core) CreatePrincipal(c *fiber.Ctx) error {
	var inputPrincipal PrincipalModel
	if err := c.BodyParser(&inputPrincipal); err != nil {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Invalid request body", nil})
	}

	errors := Validate(inputPrincipal)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errors)
	}

	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.CreatePrincipal(c.Context(), sessionPrincipal,
		inputPrincipal.Username,
		inputPrincipal.Password,
		inputPrincipal.Description,
		inputPrincipal.Policies,
	)
	if err != nil {
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.ConflictError:
			return c.Status(http.StatusConflict).JSON(ErrorResponse{http.StatusConflict, "Principal already exists", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusCreated).JSON(nil) // Return no content on purpose.
}

func (core *Core) GetPrincipal(c *fiber.Ctx) error {
	username := c.Params("username")
	sessionPrincipal := GetSessionPrincipal(c)
	principal, err := core.vault.GetPrincipal(c.Context(), sessionPrincipal, username)
	if err != nil {
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.NotFoundError:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Principal not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	// Note that we don't return the password hash.
	return c.Status(http.StatusOK).JSON(PrincipalModel{
		Username:    principal.Username,
		Description: principal.Description,
		Policies:    principal.Policies,
	})
}
