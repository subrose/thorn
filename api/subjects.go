package main

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	_vault "github.com/subrose/vault"
)

func (core *Core) CreateSubject(c *fiber.Ctx) error {
	subject := new(_vault.Subject)
	if err := core.ParseJsonBody(c.Body(), subject); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(err)
	}

	fmt.Println(subject)

	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.CreateSubject(c.Context(), sessionPrincipal, subject)
	if err != nil {
		return err
	}
	return c.Status(http.StatusCreated).JSON(subject)
}

func (core *Core) DeleteSubject(c *fiber.Ctx) error {
	sid := c.Params("subjectId")
	sessionPrincipal := GetSessionPrincipal(c)
	err := core.vault.DeleteSubject(c.Context(), sessionPrincipal, sid)
	if err != nil {
		return err
	}
	return c.SendStatus(http.StatusNoContent)
}

func (core *Core) GetSubject(c *fiber.Ctx) error {
	sid := c.Params("subjectId")
	sessionPrincipal := GetSessionPrincipal(c)
	subject, err := core.vault.GetSubject(c.Context(), sessionPrincipal, sid)

	if err != nil {
		return err
	}
	return c.Status(http.StatusOK).JSON(subject)
}
