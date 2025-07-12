package handler

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App, h *AuthHandler) {
	app.Post("api/v1/register", h.Register)
	app.Post("api/v1/login", h.Login)
	app.Post("api/v1/refresh", h.Refresh)
	app.Delete("api/v1/session", h.Logout)

	// Admin-only endpoints
	admin := app.Group("/api/v1/admin", h.RequireRole("admin"))
	admin.Delete("/user/:id/sessions", h.ForceLogout)
	admin.Get("/users", h.GetAllUsers)
	admin.Patch("/user/:id/role", h.UpdateUserRole)
	admin.Get("/user/:id/sessions", h.GetUserSessions)
}
