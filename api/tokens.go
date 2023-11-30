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

func (core *Core) CreateToken(c *fiber.Ctx) error {
	tokenRequest := new(TokenRequest)

	if err := c.BodyParser(tokenRequest); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	if err := Validate(tokenRequest); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err)
	}

	sessionPrincipal := GetSessionPrincipal(c)
	tokenId, err := core.vault.CreateToken(c.Context(), sessionPrincipal, tokenRequest.Collection, tokenRequest.RecordId, tokenRequest.Field, tokenRequest.Format)
	if err != nil {
		return err
	}

	return c.Status(http.StatusCreated).JSON(tokenId)
}

func (core *Core) GetTokenById(c *fiber.Ctx) error {
	tokenId := c.Params("tokenId")
	sessionPrincipal := GetSessionPrincipal(c)
	token, err := core.vault.GetTokenValue(c.Context(), sessionPrincipal, tokenId)
	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(token)
}
