package handler

import (
	"errors"
	"strings"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	autherror "github.com/AnthoniusHendriyanto/auth-service/internal/errors"
	"github.com/gofiber/fiber/v2"
)

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type AuthHandler struct {
	userService  *service.UserService
	tokenService service.TokenGenerator
}

func NewAuthHandler(userService *service.UserService, tokenService service.TokenGenerator) *AuthHandler {
	return &AuthHandler{
		userService:  userService,
		tokenService: tokenService,
	}
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

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var input dto.RegisterInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	user, err := h.userService.Register(c.Context(), input)
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

	tokenPair, err := h.userService.Login(c.Context(), input)
	if err != nil {
		if errors.Is(err, autherror.ErrTooManyLoginAttempts) {
			return sendError(c, fiber.StatusTooManyRequests, err)
		}

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

	tokens, err := h.userService.Refresh(c.Context(), input)
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

	if err := h.userService.Logout(c.Context(), input.RefreshToken); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	return sendSuccess(c, fiber.StatusOK, fiber.Map{
		"message": "logged out successfully",
	})
}

func (h *AuthHandler) ForceLogout(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return sendError(c, fiber.StatusBadRequest, fiber.NewError(fiber.StatusBadRequest, "userID is required"))
	}

	if err := h.userService.ForceLogoutByUserID(c.Context(), userID); err != nil {
		return sendError(c, fiber.StatusInternalServerError, err)
	}

	return sendSuccess(c, fiber.StatusOK, fiber.Map{
		"message": "all sessions revoked for user",
	})
}

func (h *AuthHandler) parseInput(c *fiber.Ctx, input interface{}) error {
	if err := c.BodyParser(input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid input")
	}

	return nil
}

// RequireRole is a middleware to enforce role-based access control.
func (h *AuthHandler) RequireRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return sendError(c, fiber.StatusUnauthorized, errors.New("authorization header is missing"))
		}

		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			return sendError(c, fiber.StatusUnauthorized, errors.New("invalid authorization header format"))
		}

		accessToken := tokenParts[1]
		claims, err := h.tokenService.VerifyAccessToken(accessToken)
		if err != nil {
			return sendError(c, fiber.StatusUnauthorized, errors.New("invalid or expired access token"))
		}

		if claims.Role != requiredRole {
			return sendError(c, fiber.StatusForbidden, errors.New("insufficient permissions"))
		}

		// Optionally, store user ID/role in Fiber context for later use in handler
		c.Locals("userID", claims.UserID)
		c.Locals("userEmail", claims.Email)
		c.Locals("userRole", claims.Role)

		return c.Next()
	}
}

func (h *AuthHandler) GetAllUsers(c *fiber.Ctx) error {
	users, err := h.userService.GetAllUsers(c.Context())
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, err)
	}

	return sendSuccess(c, fiber.StatusOK, users)
}

func (h *AuthHandler) UpdateUserRole(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return sendError(c, fiber.StatusBadRequest, errors.New("userID is required"))
	}

	var input dto.UpdateRoleInput
	if err := h.parseInput(c, &input); err != nil {
		return sendError(c, fiber.StatusBadRequest, err)
	}

	if err := h.userService.UpdateUserRole(c.Context(), userID, input.RoleID); err != nil {
		return sendError(c, fiber.StatusInternalServerError, err)
	}

	return sendSuccess(c, fiber.StatusOK, fiber.Map{
		"message": "user role updated successfully",
	})
}
