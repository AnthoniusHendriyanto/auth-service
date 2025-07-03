package main

import (
	"log"

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
	userRepo := repo.NewPostgresRepository(dbPool)
	tokenService := service.NewTokenService(cfg.AccessTokenSecret,
		cfg.RefreshTokenSecret, cfg.AccessExpiryMin, cfg.RefreshExpiryMin)
	userService := service.NewUserService(userRepo, tokenService, cfg)
	authHandler := handler.NewAuthHandler(userService)

	app := fiber.New()
	handler.RegisterRoutes(app, authHandler)
	err := app.Listen(":" + cfg.Port)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)

		return
	}
}
