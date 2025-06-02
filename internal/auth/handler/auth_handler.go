package handler

import (
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	userService *service.UserService
}

func NewAuthHandler(userService *service.UserService) *AuthHandler {
	return &AuthHandler{userService: userService}
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var input dto.RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid input",
		})
	}

	user, err := h.userService.Register(input)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":    user.ID,
		"email": user.Email,
	})
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var input dto.LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid input",
		})
	}

	// Capture metadata
	input.IPAddress = c.IP()
	input.UserAgent = string(c.Request().Header.UserAgent())
	input.Fingerprint = c.Get("X-Device-Fingerprint")

	tokenPair, err := h.userService.Login(input)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(tokenPair)
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var input dto.RefreshInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	input.Fingerprint = c.Get("X-Device-Fingerprint")
	input.IPAddress = c.IP()
	input.UserAgent = string(c.Request().Header.UserAgent())

	tokens, err := h.userService.Refresh(input)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(tokens)
}
