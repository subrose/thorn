package main

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type PrincipalModel struct {
	Name        string   `json:"name" validate:"required,alphanum,min=3,max=20,excludesall= "`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
}

type NewPrincipal struct {
	Name         string   `json:"name"`
	AccessKey    string   `json:"access_key"`
	AccessSecret string   `json:"access_secret"`
	Description  string   `json:"description"`
	Policies     []string `json:"policies"`
}

func (core *Core) GetPrincipalById(c *fiber.Ctx) error {
	principalId := c.Params("principalId")
	sessionPrincipal := GetSessionPrincipal(c)
	principal, err := core.vault.GetPrincipal(c.Context(), sessionPrincipal, principalId)
	if err != nil {
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); !ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, "Forbidden", nil})
		}
		switch err {
		case _vault.ErrNotFound:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Principal not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusOK).JSON(PrincipalModel{
		Name:        principal.Name,
		Description: principal.Description,
		Policies:    principal.Policies,
	})
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
	newPrincipal, err := core.vault.CreatePrincipal(c.Context(), sessionPrincipal,
		inputPrincipal.Name,
		fmt.Sprintf("%s-%s", inputPrincipal.Name, _vault.GenerateId()),
		_vault.GenerateId(), // TODO: Is this random enough?!
		inputPrincipal.Description,
		inputPrincipal.Policies,
	)
	if err != nil {
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); !ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, "Forbidden", nil})
		}
		switch err {
		case _vault.ErrConflict:
			return c.Status(http.StatusConflict).JSON(ErrorResponse{http.StatusConflict, "Principal already exists", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusCreated).JSON(NewPrincipal{
		Name:         newPrincipal.Name,
		AccessKey:    newPrincipal.AccessKey,
		AccessSecret: newPrincipal.AccessSecret,
		Description:  newPrincipal.Description,
		Policies:     newPrincipal.Policies,
	})
}
