package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/handler"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	autherror "github.com/AnthoniusHendriyanto/auth-service/internal/errors"
	"github.com/AnthoniusHendriyanto/auth-service/internal/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	userService := service.NewUserService(mockRepo, nil, &config.Config{})
	authHandler := handler.NewAuthHandler(userService, nil)

	app := fiber.New()
	app.Post("/register", authHandler.Register)

	t.Run("success", func(t *testing.T) {
		input := dto.RegisterInput{Email: "test@example.com", Password: "password"}
		// expectedUser := &domain.User{ID: "123", Email: "test@example.com"}

		mockRepo.EXPECT().GetByEmail(gomock.Any(), input.Email).Return(nil, nil)
		mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)
	})

	t.Run("bad request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/register", bytes.NewReader([]byte("")))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("registration failure", func(t *testing.T) {
		input := dto.RegisterInput{Email: "test@example.com", Password: "password"}
		mockRepo.EXPECT().GetByEmail(gomock.Any(), input.Email).Return(nil, nil)
		mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("registration failed"))

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create mocks for dependencies
	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)

	// Configure non-zero values to avoid default zero-value issues in logic
	cfg := &config.Config{
		LoginMaxAttempts:       5,
		MaxActiveRefreshTokens: 15,
	}

	// Instantiate the real services with mocked dependencies
	userService := service.NewUserService(mockRepo, mockTokenService, cfg)
	authHandler := handler.NewAuthHandler(userService, mockTokenService)

	// Setup Fiber app for testing
	app := fiber.New()
	app.Post("/login", authHandler.Login)

	t.Run("unauthorized - invalid password", func(t *testing.T) {
		input := dto.LoginInput{Email: "test@example.com", Password: "wrong-password"}
		hashedPassword := "$2a$10$3y.gq2hG7Fz.i7gY3hI0Aua/R/R1E.AgM1N9.i2fG5XlJ1gY2gGvO"
		user := &domain.User{Email: input.Email, PasswordHash: hashedPassword}
		expectedIP := "0.0.0.0"

		// Mock expectations for a failed password attempt
		mockRepo.EXPECT().CountRecentFailedAttempts(gomock.Any(), input.Email, expectedIP, cfg.MaxActiveRefreshTokens).Return(0, nil)
		mockRepo.EXPECT().GetByEmail(gomock.Any(), input.Email).Return(user, nil)
		// Since password fails, the next call is to record a failed attempt
		mockRepo.EXPECT().RecordLoginAttempt(gomock.Any(), input.Email, expectedIP, false).Return(nil)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("too many requests", func(t *testing.T) {
		input := dto.LoginInput{Email: "test@example.com", Password: "password"}
		expectedIP := "0.0.0.0"

		// Mock CountRecentFailedAttempts to return a value >= LoginMaxAttempts
		mockRepo.EXPECT().CountRecentFailedAttempts(gomock.Any(), input.Email, expectedIP,
			cfg.MaxActiveRefreshTokens).Return(cfg.LoginMaxAttempts, nil)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
	})

	t.Run("bad request - invalid json", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/login", bytes.NewReader([]byte("{invalid-json")))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}

func TestRefresh(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	userService := service.NewUserService(mockRepo, mockTokenService, &config.Config{})
	authHandler := handler.NewAuthHandler(userService, mockTokenService)

	app := fiber.New()
	app.Post("/refresh", authHandler.Refresh)

	t.Run("success", func(t *testing.T) {
		input := dto.RefreshInput{RefreshToken: "valid-token"}
		// Initialize with a non-expired time
		refreshToken := &domain.RefreshToken{DeviceFingerprint: "", ExpiresAt: time.Now().Add(time.Hour)}

		// Expectations
		mockRepo.EXPECT().GetRefreshToken(gomock.Any(), input.RefreshToken).Return(refreshToken, nil)
		mockRepo.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(nil)
		mockRepo.EXPECT().GetByIDWithRole(gomock.Any(), gomock.Any()).Return(&domain.User{}, nil)
		mockTokenService.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("new-access", "new-refresh", time.Now(), nil)
		mockTokenService.EXPECT().GetAccessTokenExpiry().Return(time.Minute * 15)
		mockRepo.EXPECT().StoreRefreshToken(gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("unauthorized", func(t *testing.T) {
		input := dto.RefreshInput{RefreshToken: "invalid-token"}
		// To test this path correctly, the GetRefreshToken should return an error.
		mockRepo.EXPECT().GetRefreshToken(gomock.Any(), input.RefreshToken).Return(nil, autherror.ErrRefreshTokenNotFound)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

func TestLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	userService := service.NewUserService(mockRepo, nil, &config.Config{})
	authHandler := handler.NewAuthHandler(userService, nil)

	app := fiber.New()
	app.Delete("/logout", authHandler.Logout)

	t.Run("success", func(t *testing.T) {
		input := dto.LogoutInput{RefreshToken: "valid-token"}
		mockRepo.EXPECT().GetRefreshToken(gomock.Any(), input.RefreshToken).Return(&domain.RefreshToken{}, nil)
		mockRepo.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("DELETE", "/logout", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("bad request", func(t *testing.T) {
		input := dto.LogoutInput{RefreshToken: "invalid-token"}
		mockRepo.EXPECT().GetRefreshToken(gomock.Any(), input.RefreshToken).Return(nil, errors.New("some error"))

		body, _ := json.Marshal(input)
		req := httptest.NewRequest("DELETE", "/logout", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}

func TestForceLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	userService := service.NewUserService(mockRepo, nil, &config.Config{})
	authHandler := handler.NewAuthHandler(userService, nil)

	app := fiber.New()
	app.Delete("/user/:id/sessions", authHandler.ForceLogout)

	t.Run("success", func(t *testing.T) {
		userID := "user-123"
		mockRepo.EXPECT().RevokeAllRefreshTokensByUserID(gomock.Any(), userID).Return(nil)

		req := httptest.NewRequest("DELETE", "/user/user-123/sessions", nil)

		resp, _ := app.Test(req, -1)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("internal server error", func(t *testing.T) {
		userID := "user-123"
		mockRepo.EXPECT().RevokeAllRefreshTokensByUserID(gomock.Any(), userID).Return(errors.New("some error"))

		req := httptest.NewRequest("DELETE", "/user/user-123/sessions", nil)

		resp, _ := app.Test(req, -1)
		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	})
}
