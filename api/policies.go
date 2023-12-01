package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func (core *Core) GetPolicies(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	policies, err := core.vault.GetPrincipalPolicies(c.Context(), sessionPrincipal)
	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(policies)
}

func (core *Core) GetPolicyById(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	policy, err := core.vault.GetPolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(policy)
}

func (core *Core) CreatePolicy(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	var policy _vault.Policy
	if err := c.BodyParser(&policy); err != nil {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{"Invalid request body", nil})
	}

	validation_errors := core.Validate(policy)
	if validation_errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(validation_errors)

	}
	_, err := core.vault.CreatePolicy(c.Context(), sessionPrincipal, policy)
	if err != nil {
		core.logger.Error("Error creating policy")
		return err
	}

	return c.Status(http.StatusCreated).JSON(policy)
}

func (core *Core) DeletePolicy(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.DeletePolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		return err
	}
	return c.SendStatus(http.StatusNoContent)
}

// Note: You cannot update a policy
