package main

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

// Note: You cannot update a policy

func (core *Core) GetPolicies(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	policies, err := core.vault.GetPrincipalPolicies(c.Context(), sessionPrincipal)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to get policies %v", err))
		return err
	}
	return c.Status(http.StatusOK).JSON(policies)
}

func (core *Core) GetPolicyById(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	policy, err := core.vault.GetPolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to get policy %v", err))
		return err
	}
	return c.Status(http.StatusOK).JSON(policy)
}

func (core *Core) CreatePolicy(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	var policy _vault.Policy
	if err := core.ParseJsonBody(c.Body(), &policy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{fmt.Sprintf("Invalid body: %v", err), nil})
	}

	if validationErrs := core.Validate(policy); validationErrs != nil {
		return c.Status(fiber.StatusBadRequest).JSON(validationErrs)
	}

	_, err := core.vault.CreatePolicy(c.Context(), sessionPrincipal, policy)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to create policy %v", err))
		return err
	}

	return c.Status(http.StatusCreated).JSON(policy)
}

func (core *Core) DeletePolicy(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.DeletePolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to delete policy %v", err))
		return err
	}
	return c.SendStatus(http.StatusNoContent)
}
