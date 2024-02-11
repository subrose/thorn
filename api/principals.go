package main

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type PrincipalResponse struct {
	Id          string    `json:"id"`
	Username    string    `json:"username" validate:"required,min=3,max=32"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Policies    []string  `json:"policies"`
}

// CreatePrincipal godoc
// @Summary Create a Principal
// @Description Creates a Principal
// @Tags principals
// @Accept */*
// @Produce json
// @Success 201 {object} PrincipalResponse
// @Router /principals [post]
func (core *Core) CreatePrincipal(c *fiber.Ctx) error {
	var principal _vault.Principal
	if err := core.ParseJsonBody(c.Body(), &principal); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", []string{err.Error()}})
	}

	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.CreatePrincipal(c.Context(), sessionPrincipal, &principal)
	if err != nil {
		return err
	}
	return c.Status(http.StatusCreated).JSON(PrincipalResponse{Id: principal.Id,
		Username:    principal.Username,
		Description: principal.Description,
		Policies:    principal.Policies,
		CreatedAt:   principal.CreatedAt,
		UpdatedAt:   principal.UpdatedAt,
	})
}

// GetPrincipal godoc
// @Summary Get a Prinicipal by id
// @Description Returns a Principal given an id
// @Tags principals
// @Accept */*
// @Produce json
// @Success 200 {object} PrincipalResponse
// @Router /principals/{username} [get]
// @Param username path string true "Username"
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

// DeletePrincipal godoc
// @Summary Delete a Principal by id
// @Description Deletes a Principal given an id
// @Tags principals
// @Accept */*
// @Produce json
// @Success 204
// @Router /principals [delete]
// @Param username path string true "Username"
func (core *Core) DeletePrincipal(c *fiber.Ctx) error {
	username := c.Params("username")
	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.DeletePrincipal(c.Context(), sessionPrincipal, username)
	if err != nil {
		return err
	}
	return c.SendStatus(http.StatusNoContent)
}
