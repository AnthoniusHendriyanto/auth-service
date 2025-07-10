package service

//go:generate mockgen -destination=../../mocks/mock_token_generator.go -package=mocks github.com/AnthoniusHendriyanto/auth-service/internal/auth/service TokenGenerator

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenGenerator interface {
	Generate(userID, email, role string) (string, string, time.Time, error)
	GetAccessTokenExpiry() time.Duration
	GetRefreshTokenExpiry() time.Duration
	VerifyAccessToken(tokenString string) (*JWTCustomClaims, error)
}

type TokenService struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

type JWTCustomClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

func NewTokenService(accessSecret, refreshSecret string, accessMinutes, refreshMinutes int) *TokenService {
	return &TokenService{
		AccessTokenSecret:  accessSecret,
		RefreshTokenSecret: refreshSecret,
		AccessTokenExpiry:  time.Duration(accessMinutes) * time.Minute,
		RefreshTokenExpiry: time.Duration(refreshMinutes) * time.Minute,
	}
}

func (ts *TokenService) Generate(userID, email, role string) (string, string, time.Time, error) {
	now := time.Now()

	accessClaims := JWTCustomClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	refreshClaims := JWTCustomClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(ts.AccessTokenSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
		refreshClaims).SignedString([]byte(ts.RefreshTokenSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, now.Add(ts.AccessTokenExpiry), nil
}

func (ts *TokenService) GetAccessTokenExpiry() time.Duration {
	return ts.AccessTokenExpiry
}

func (ts *TokenService) GetRefreshTokenExpiry() time.Duration {
	return ts.RefreshTokenExpiry
}

// VerifyAccessToken parses and validates the given access token string.
func (ts *TokenService) VerifyAccessToken(tokenString string) (*JWTCustomClaims, error) {
	claims := &JWTCustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method is HMAC.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ts.AccessTokenSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
