package handler

import (
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	"github.com/gofiber/fiber/v2"
)

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type AuthHandler struct {
	userService *service.UserService
}

func NewAuthHandler(userService *service.UserService) *AuthHandler {
	return &AuthHandler{userService: userService}
}

func sendError(c *fiber.Ctx, status int, err error) error {
	return c.Status(status).JSON(Response{
		Success: false,
		Error:   err.Error(),
	})
}

func sendSuccess(c *fiber.Ctx, status int, data interface{}) error {
	return c.Status(status).JSON(Response{
		Success: true,
		Data:    data,
	})
}

func (h *AuthHandler) parseInput(c *fiber.Ctx, input interface{}) error {
	if err := c.BodyParser(input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid input")
	}
	return nil
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var input dto.RegisterInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	user, err := h.userService.Register(input)
	if err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	return sendSuccess(c, fiber.StatusCreated, fiber.Map{
		"id":    user.ID,
		"email": user.Email,
	})
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var input dto.LoginInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	input.IPAddress = c.IP()
	input.UserAgent = string(c.Request().Header.UserAgent())
	input.Fingerprint = c.Get("X-Device-Fingerprint")

	tokenPair, err := h.userService.Login(input)
	if err != nil {
		return sendError(c, fiber.StatusUnauthorized, err)
	}

	return sendSuccess(c, fiber.StatusOK, tokenPair)
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var input dto.RefreshInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	input.Fingerprint = c.Get("X-Device-Fingerprint")
	input.IPAddress = c.IP()
	input.UserAgent = string(c.Request().Header.UserAgent())

	tokens, err := h.userService.Refresh(input)
	if err != nil {
		return sendError(c, fiber.StatusUnauthorized, err)
	}

	return sendSuccess(c, fiber.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	var input dto.LogoutInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	if err := h.userService.Logout(input.RefreshToken); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	return sendSuccess(c, fiber.StatusOK, fiber.Map{
		"message": "logged out successfully",
	})
}

func (h *AuthHandler) ForceLogout(c *fiber.Ctx) error {
	userID := c.Params("userID")
	if userID == "" {
		return sendError(c, fiber.StatusBadRequest, fiber.NewError(fiber.StatusBadRequest, "userID is required"))
	}

	if err := h.userService.ForceLogoutByUserID(userID); err != nil {
		return sendError(c, fiber.StatusInternalServerError, err)
	}

	return sendSuccess(c, fiber.StatusOK, fiber.Map{
		"message": "all sessions revoked for user",
	})
}
