package handler

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App, h *AuthHandler) {
	app.Post("api/v1/register", h.Register)
	app.Post("api/v1/login", h.Login)
	app.Post("api/v1/refresh", h.Refresh)
	app.Post("api/v1/logout", h.Logout)
}
