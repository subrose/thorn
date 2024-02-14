package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type TokenRequest struct {
	Collection string `json:"collection" validate:"required"`
	RecordId   string `json:"recordId" validate:"required"`
	Field      string `json:"field" validate:"required"`
	Format     string `json:"format" validate:"required"`
}

// CreateToken godoc
// @Summary Create a Token
// @Description Creates a Token
// @Tags tokens
// @Accept */*
// @Produce json
// @Success 201 {string} string
// @Router /tokens [post]
func (core *Core) CreateToken(c *fiber.Ctx) error {
	tokenRequest := new(TokenRequest)

	if err := core.ParseJsonBody(c.Body(), &tokenRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{"Invalid body", []string{err.Error()}})
	}

	sessionPrincipal := GetSessionPrincipal(c)
	tokenId, err := core.vault.CreateToken(c.Context(), sessionPrincipal, tokenRequest.Collection, tokenRequest.RecordId, tokenRequest.Field, tokenRequest.Format)
	if err != nil {
		return err
	}

	return c.Status(http.StatusCreated).JSON(tokenId)
}

// GetTokenById godoc
// @Summary Get a Token by id
// @Description Returns a Token given an id
// @Tags tokens
// @Accept */*
// @Produce json
// @Success 200 {object} string
// @Router /tokens/{tokenId} [get]
// @Param tokenId path string true "Token Id"
func (core *Core) GetTokenById(c *fiber.Ctx) error {
	tokenId := c.Params("tokenId")
	sessionPrincipal := GetSessionPrincipal(c)
	token, err := core.vault.GetTokenValue(c.Context(), sessionPrincipal, tokenId)
	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(token)
}
