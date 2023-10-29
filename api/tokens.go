package main

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func (core *Core) CreateToken(c *fiber.Ctx) error {
	sessionPrincipal := GetSessionPrincipal(c)
	tokenId, err := core.vault.CreateToken(c.Context(), sessionPrincipal, c.Query("collectionName"), c.Query("recordId"), c.Query("fieldName"), c.Query("returnFormat"))
	if err != nil {
		return err
	}

	return c.Status(http.StatusOK).JSON(tokenId)
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
