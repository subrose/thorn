package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func (core *Core) GetPolicyById(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	policy, err := core.vault.GetPolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		// TODO: After replacing all other custom errors with types, the switch should work again using: switch t := err.(type) {}
		if _, ok := err.(_vault.ErrForbidden); !ok {
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, "Forbidden", nil})
		}
		switch err {
		case _vault.ErrNotFound:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Policy not found", nil})
		default:
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusOK).JSON(
		policy,
	)
}

func (core *Core) CreatePolicy(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	var policy _vault.Policy
	if err := c.BodyParser(&policy); err != nil {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Invalid request body", nil})
	}

	errors := Validate(policy)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errors)

	}
	_, err := core.vault.CreatePolicy(c.Context(), sessionPrincipal, policy)
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

	return c.Status(http.StatusCreated).JSON(policy)
}
