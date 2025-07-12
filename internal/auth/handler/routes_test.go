package handler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/handler"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/service"
	"github.com/AnthoniusHendriyanto/auth-service/internal/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterRoutes verifies that all non-protected routes are mounted correctly.
func TestRegisterRoutes(t *testing.T) {
	// --- Setup ---
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}
	userService := service.NewUserService(mockRepo, mockTokenService, cfg)
	authHandler := handler.NewAuthHandler(userService, mockTokenService)

	app := fiber.New()
	handler.RegisterRoutes(app, authHandler)

	testCases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/register"},
		{http.MethodPost, "/api/v1/login"},
		{http.MethodPost, "/api/v1/refresh"},
		{http.MethodDelete, "/api/v1/session"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_%s_exists", tc.method, tc.path), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			// We only care that the route exists. A 404 means it doesn't.
			// The actual handlers will return other codes (e.g., 400 Bad Request
			// for missing body), which is fine for this existence check.
			assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

// TestRequireRoleMiddleware provides focused testing for the admin-only endpoint.
func TestRequireRoleMiddleware(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}
	userService := service.NewUserService(mockRepo, mockTokenService, cfg)
	authHandler := handler.NewAuthHandler(userService, mockTokenService)

	app := fiber.New()
	// Register the routes to apply the middleware
	handler.RegisterRoutes(app, authHandler)

	adminRoute := "/api/v1/user/admin-test-id/sessions"

	// --- Test Cases for Middleware Logic ---
	t.Run("fails without auth header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, adminRoute, nil)
		resp, _ := app.Test(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("fails with malformed token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, adminRoute, nil)
		req.Header.Set("Authorization", "BearerInvalidToken") // No space
		resp, _ := app.Test(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("fails for non-admin user", func(t *testing.T) {
		// Mock the token service to return a valid "user" role token
		claims := &service.JWTCustomClaims{UserID: "user-123", Role: "user"}
		mockTokenService.EXPECT().VerifyAccessToken("user-token").Return(claims, nil)

		req := httptest.NewRequest(http.MethodDelete, adminRoute, nil)
		req.Header.Set("Authorization", "Bearer user-token")
		resp, _ := app.Test(req)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("succeeds for admin user", func(t *testing.T) {
		userID := "admin-test-id"
		adminClaims := &service.JWTCustomClaims{
			UserID: "admin-456",
			Role:   "admin", // The correct role
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		// 1. Middleware checks the token
		mockTokenService.EXPECT().VerifyAccessToken("admin-token").Return(adminClaims, nil)
		// 2. Middleware passes, handler is called, which calls the repo
		mockRepo.EXPECT().RevokeAllRefreshTokensByUserID(gomock.Any(), userID).Return(nil)

		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/user/%s/sessions", userID), nil)
		req.Header.Set("Authorization", "Bearer admin-token")

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
