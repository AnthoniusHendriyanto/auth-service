package main

import (
	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/db"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/handler"
	repo "github.com/AnthoniusHendriyanto/auth-service/internal/auth/repository/postgres"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	"github.com/gofiber/fiber/v2"
)

func main() {
	cfg := config.Load()

	dbPool := db.NewPostgresPool(cfg.DBURL)
	userRepo := repo.NewPostgresUserRepository(dbPool)
	tokenService := service.NewTokenService(cfg.AccessTokenSecret, cfg.RefreshTokenSecret, cfg.AccessExpiryMin, cfg.RefreshExpiryMin)
	userService := service.NewUserService(userRepo, tokenService, cfg)
	authHandler := handler.NewAuthHandler(userService)

	app := fiber.New()
	handler.RegisterRoutes(app, authHandler)
	app.Listen(":" + cfg.Port)
}
