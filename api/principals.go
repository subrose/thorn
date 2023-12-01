package main

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type NewPrincipal struct {
	Username    string   `json:"username" validate:"required,min=1,max=32"`
	Password    string   `json:"password" validate:"required,min=4,max=32"` // This is to limit the size of the password hash.
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
}

type PrincipalResponse struct {
	Username    string   `json:"username"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
}

func (core *Core) CreatePrincipal(c *fiber.Ctx) error {
	var newPrincipal NewPrincipal
	if err := core.ParseJsonBody(c.Body(), &newPrincipal); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{fmt.Sprintf("Invalid body %v", err), nil})
	}

	if validationErrs := core.Validate(newPrincipal); validationErrs != nil {
		return c.Status(fiber.StatusBadRequest).JSON(validationErrs)
	}

	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.CreatePrincipal(c.Context(), sessionPrincipal,
		newPrincipal.Username,
		newPrincipal.Password,
		newPrincipal.Description,
		newPrincipal.Policies,
	)
	if err != nil {
		return err
	}
	return c.Status(http.StatusCreated).JSON(PrincipalResponse{
		Username:    newPrincipal.Username,
		Description: newPrincipal.Description,
		Policies:    newPrincipal.Policies,
	})
}

func (core *Core) GetPrincipal(c *fiber.Ctx) error {
	username := c.Params("username")
	sessionPrincipal := GetSessionPrincipal(c)
	principal, err := core.vault.GetPrincipal(c.Context(), sessionPrincipal, username)

	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(PrincipalResponse{
		Username:    principal.Username,
		Description: principal.Description,
		Policies:    principal.Policies,
	})
}

func (core *Core) DeletePrincipal(c *fiber.Ctx) error {
	username := c.Params("username")
	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.DeletePrincipal(c.Context(), sessionPrincipal, username)
	if err != nil {
		return err
	}
	return c.SendStatus(http.StatusNoContent)
}
