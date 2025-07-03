package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenService(t *testing.T) {
	tests := []struct {
		name           string
		accessSecret   string
		refreshSecret  string
		accessMinutes  int
		refreshMinutes int
	}{
		{
			name:           "valid parameters",
			accessSecret:   "access-secret-key",
			refreshSecret:  "refresh-secret-key",
			accessMinutes:  15,
			refreshMinutes: 1440,
		},
		{
			name:           "empty secrets",
			accessSecret:   "",
			refreshSecret:  "",
			accessMinutes:  30,
			refreshMinutes: 2880,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := NewTokenService(tt.accessSecret, tt.refreshSecret, tt.accessMinutes, tt.refreshMinutes)

			assert.NotNil(t, ts)
			assert.Equal(t, tt.accessSecret, ts.AccessTokenSecret)
			assert.Equal(t, tt.refreshSecret, ts.RefreshTokenSecret)
			assert.Equal(t, time.Duration(tt.accessMinutes)*time.Minute, ts.AccessTokenExpiry)
			assert.Equal(t, time.Duration(tt.refreshMinutes)*time.Minute, ts.RefreshTokenExpiry)
		})
	}
}

func TestTokenService_Generate(t *testing.T) {
	tests := []struct {
		name           string
		accessSecret   string
		refreshSecret  string
		accessMinutes  int
		refreshMinutes int
		userID         string
		email          string
		role           string
		expectError    bool
	}{
		{
			name:           "successful token generation",
			accessSecret:   "test-access-secret-key-123",
			refreshSecret:  "test-refresh-secret-key-456",
			accessMinutes:  15,
			refreshMinutes: 1440,
			userID:         "user-123",
			email:          "test@example.com",
			role:           "user",
			expectError:    false,
		},
		{
			name:           "successful token generation with admin role",
			accessSecret:   "test-access-secret-key-123",
			refreshSecret:  "test-refresh-secret-key-456",
			accessMinutes:  30,
			refreshMinutes: 2880,
			userID:         "admin-456",
			email:          "admin@example.com",
			role:           "admin",
			expectError:    false,
		},
		{
			name:           "empty user data",
			accessSecret:   "test-access-secret-key-123",
			refreshSecret:  "test-refresh-secret-key-456",
			accessMinutes:  15,
			refreshMinutes: 1440,
			userID:         "",
			email:          "",
			role:           "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := NewTokenService(tt.accessSecret, tt.refreshSecret, tt.accessMinutes, tt.refreshMinutes)

			beforeGenerate := time.Now()
			accessToken, refreshToken, expiryTime, err := ts.Generate(tt.userID, tt.email, tt.role)
			afterGenerate := time.Now()

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, accessToken)
				assert.Empty(t, refreshToken)
				assert.True(t, expiryTime.IsZero())
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, accessToken)
				assert.NotEmpty(t, refreshToken)
				assert.False(t, expiryTime.IsZero())

				// Verify expiry time is within expected range
				expectedExpiry := beforeGenerate.Add(ts.AccessTokenExpiry)
				assert.True(t, expiryTime.After(expectedExpiry.Add(-time.Second)))
				assert.True(t, expiryTime.Before(afterGenerate.Add(ts.AccessTokenExpiry).Add(time.Second)))

				// Verify access token claims
				accessClaims := &JWTCustomClaims{}
				accessTokenParsed, err := jwt.ParseWithClaims(accessToken, accessClaims, func(token *jwt.Token) (interface{}, error) {
					return []byte(tt.accessSecret), nil
				})
				require.NoError(t, err)
				assert.True(t, accessTokenParsed.Valid)
				assert.Equal(t, tt.userID, accessClaims.UserID)
				assert.Equal(t, tt.email, accessClaims.Email)
				assert.Equal(t, tt.role, accessClaims.Role)

				// Verify refresh token claims
				refreshClaims := &JWTCustomClaims{}
				refreshTokenParsed, err := jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
					return []byte(tt.refreshSecret), nil
				})
				require.NoError(t, err)
				assert.True(t, refreshTokenParsed.Valid)
				assert.Equal(t, tt.userID, refreshClaims.UserID)
				assert.Equal(t, tt.email, refreshClaims.Email)
				// Note: refresh token doesn't include role in the original implementation
				assert.Empty(t, refreshClaims.Role)

				// Verify token expiry times
				assert.True(t, accessClaims.ExpiresAt.Time.After(beforeGenerate))
				assert.True(t, refreshClaims.ExpiresAt.Time.After(beforeGenerate))
				assert.True(t, refreshClaims.ExpiresAt.Time.After(accessClaims.ExpiresAt.Time))
			}
		})
	}
}

func TestTokenService_Generate_InvalidSecret(t *testing.T) {
	// Test with very short secret that might cause signing issues
	ts := NewTokenService("x", "y", 15, 1440)

	accessToken, refreshToken, expiryTime, err := ts.Generate("user-123", "test@example.com", "user")

	// Even with short secrets, JWT signing should still work
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	assert.False(t, expiryTime.IsZero())
}

func TestTokenService_Generate_TokenValidation(t *testing.T) {
	ts := NewTokenService("test-access-secret", "test-refresh-secret", 15, 1440)

	userID := "test-user-123"
	email := "test@example.com"
	role := "admin"

	accessToken, refreshToken, _, err := ts.Generate(userID, email, role)
	require.NoError(t, err)

	// Test access token with wrong secret should fail
	wrongClaims := &JWTCustomClaims{}
	_, err = jwt.ParseWithClaims(accessToken, wrongClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte("wrong-secret"), nil
	})
	assert.Error(t, err)

	// Test refresh token with wrong secret should fail
	_, err = jwt.ParseWithClaims(refreshToken, wrongClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte("wrong-secret"), nil
	})
	assert.Error(t, err)
}

func TestTokenService_Generate_TimeConsistency(t *testing.T) {
	ts := NewTokenService("test-access-secret", "test-refresh-secret", 30, 1440)

	// Generate multiple tokens and ensure time consistency
	for i := 0; i < 5; i++ {
		beforeTime := time.Now()
		_, _, expiryTime, err := ts.Generate("user", "user@test.com", "user")
		afterTime := time.Now()

		require.NoError(t, err)

		expectedMinExpiry := beforeTime.Add(30 * time.Minute)
		expectedMaxExpiry := afterTime.Add(30 * time.Minute)

		assert.True(t, expiryTime.After(expectedMinExpiry.Add(-time.Second)))
		assert.True(t, expiryTime.Before(expectedMaxExpiry.Add(time.Second)))

		// Small delay to ensure different timestamps
		time.Sleep(time.Millisecond)
	}
}
