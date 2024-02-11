package main

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

// Note: You cannot update a policy

// GetPolicies godoc
// @Summary Get all Policies
// @Description Returns all Policies
// @Tags policies
// @Accept */*
// @Produce json
// @Success 200 {array} _vault.Policy
// @Router /policies [get]
func (core *Core) GetPolicies(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	policies, err := core.vault.GetPrincipalPolicies(c.Context(), sessionPrincipal)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to get policies %v", err))
		return err
	}
	return c.Status(http.StatusOK).JSON(policies)
}

// GetPolicyById godoc
// @Summary Get a Policy by id
// @Description Returns a Policy given an id
// @Tags policies
// @Accept */*
// @Produce json
// @Success 200 {object} _vault.Policy
// @Router /policies/{policyId} [get]
// @Param policyId path string true "Policy Id"
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

// CreatePolicy godoc
// @Summary Create a Policy
// @Description Creates a Policy
// @Tags policies
// @Accept */*
// @Produce json
// @Success 201 {object} _vault.Policy
// @Router /policies [post]
func (core *Core) CreatePolicy(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	var policy _vault.Policy
	if err := core.ParseJsonBody(c.Body(), &policy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", []string{err.Error()}})

	}

	err := core.vault.CreatePolicy(c.Context(), sessionPrincipal, &policy)
	if err != nil {
		core.logger.Error(fmt.Sprintf("Failed to create policy %v", err))
		return err
	}

	return c.Status(http.StatusCreated).JSON(policy)
}

// DeletePolicy godoc
// @Summary Delete a Policy by id
// @Description Deletes a Policy given an id
// @Tags policies
// @Accept */*
// @Produce json
// @Success 204
// @Router /policies/{policyId} [delete]
// @Param policyId path string true "Policy Id"
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
