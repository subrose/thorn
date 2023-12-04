package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

// type NewPrincipal struct {
// 	Username    string   `json:"username" validate:"required,min=1,max=32"`
// 	Password    string   `json:"password" validate:"required,min=4,max=32"` // This is to limit the size of the password hash.
// 	Description string   `json:"description"`
// 	Policies    []string `json:"policies"`
// }

type PrincipalResponse struct {
	Id          string   `json:"id"`
	Username    string   `json:"username" validate:"required,min=3,max=32"`
	Description string   `json:"description"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	Policies    []string `json:"policies"`
}

func (core *Core) CreatePrincipal(c *fiber.Ctx) error {
	var principal _vault.Principal
	if err := core.ParseJsonBody(c.Body(), &principal); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", nil})
	}

	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.CreatePrincipal(c.Context(), sessionPrincipal, &principal)
	if err != nil {
		return err
	}
	return c.Status(http.StatusCreated).JSON(PrincipalResponse{Id: principal.Id, Username: principal.Username, Description: principal.Description, Policies: principal.Policies, CreatedAt: principal.CreatedAt, UpdatedAt: principal.UpdatedAt})
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
