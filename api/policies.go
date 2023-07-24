package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

type CompositePolicy struct {
	PolicyId  string                `json:"policy_id"`
	Effect    _vault.PolicyEffect   `json:"effect"`
	Actions   []_vault.PolicyAction `json:"actions"`
	Resources []string              `json:"resources"`
}

func (core *Core) GetPolicyById(c *fiber.Ctx) error {
	policyId := c.Params("policyId")
	sessionPrincipal := GetSessionPrincipal(c)
	policy, err := core.vault.GetPolicy(c.Context(), sessionPrincipal, policyId)
	if err != nil {
		switch err.(type) {
		case *_vault.ForbiddenError:
			return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
		case *_vault.NotFoundError:
			return c.Status(http.StatusNotFound).JSON(ErrorResponse{http.StatusNotFound, "Policy not found", nil})
		default:
			core.logger.Error("Error getting policy by id", err)
			return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
		}
	}
	return c.Status(http.StatusOK).JSON(policy)
}

func splitPolicies(policy CompositePolicy) []_vault.Policy {
	var policies []_vault.Policy
	for i, action := range policy.Actions {
		for _, resource := range policy.Resources {
			p := _vault.Policy{
				PolicyId: fmt.Sprintf("%s-%d", policy.PolicyId, i),
				Effect:   policy.Effect,
				Action:   action,
				Resource: resource,
			}

			policies = append(policies, p)
		}
	}
	return policies
}

func (core *Core) CreatePolicy(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	var compPolicy CompositePolicy
	if err := c.BodyParser(&compPolicy); err != nil {
		return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Invalid request body", nil})
	}

	validation_errors := Validate(compPolicy)
	if validation_errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(validation_errors)

	}
	policies := splitPolicies(compPolicy)
	for _, pol := range policies {
		_, err := core.vault.CreatePolicy(c.Context(), sessionPrincipal, pol)
		if err != nil {
			switch err.(type) {
			case *_vault.ForbiddenError:
				return c.Status(http.StatusForbidden).JSON(ErrorResponse{http.StatusForbidden, err.Error(), nil})
			case *_vault.ConflictError:
				return c.Status(http.StatusConflict).JSON(ErrorResponse{http.StatusConflict, "Principal already exists", nil})
			default:
				var valueErr *_vault.ValueError
				if errors.As(err, &valueErr) {
					core.logger.Error("Value error", valueErr)
					return c.Status(http.StatusBadRequest).JSON(ErrorResponse{http.StatusBadRequest, "Invalid request body", nil})
				}
				core.logger.Error("Error creating policy", err)
				return c.Status(http.StatusInternalServerError).JSON(ErrorResponse{http.StatusInternalServerError, "Something went wrong", nil})
			}
		}
	}

	return c.Status(http.StatusCreated).JSON(policies)
}
