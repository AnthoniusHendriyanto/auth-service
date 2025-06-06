package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo                   domain.UserRepository
	tokenService           *TokenService
	maxActiveTokensPerUser int
}

func NewUserService(repo domain.UserRepository, tokenService *TokenService, maxTokens int) *UserService {
	return &UserService{
		repo:                   repo,
		tokenService:           tokenService,
		maxActiveTokensPerUser: maxTokens,
	}
}

func (s *UserService) Register(input dto.RegisterInput) (*domain.User, error) {
	existingUser, err := s.repo.GetByEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("email already in use")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: string(hashedPassword),
		RoleID:       1, // Default User Role, Later we can change
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	err = s.repo.Create(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) Login(input dto.LoginInput) (*dto.TokenResponse, error) {
	user, err := s.repo.GetByEmail(input.Email)
	if err != nil {
		return nil, err
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		_ = s.repo.RecordLoginAttempt(input.Email, input.IPAddress, false)
		return nil, errors.New("invalid credentials")
	}

	accessToken, refreshToken, _, err := s.tokenService.Generate(user.ID, user.Email, user.RoleName)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	refreshTokenObj := &domain.RefreshToken{
		ID:                uuid.New().String(),
		UserID:            user.ID,
		Token:             refreshToken,
		DeviceFingerprint: input.Fingerprint,
		IPAddress:         input.IPAddress,
		UserAgent:         input.UserAgent,
		ExpiresAt:         now.Add(s.tokenService.RefreshTokenExpiry * time.Minute),
		CreatedAt:         now,
		Revoked:           false,
	}

	if err := s.repo.StoreRefreshToken(refreshTokenObj); err != nil {
		return nil, err
	}

	if err := s.repo.UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress); err != nil {
		return nil, err
	}

	if err := s.repo.RecordLoginAttempt(input.Email, input.IPAddress, true); err != nil {
		return nil, err
	}

	// Delete oldest if token count exceeds limit
	if err := s.repo.DeleteOldestByUserID(user.ID); err != nil {
		log.Printf("warn: failed to delete oldest refresh token for user %s: %v", user.ID, err)
	}

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *UserService) Refresh(input dto.RefreshInput) (*dto.TokenResponse, error) {
	// Step 1: Validate existing refresh token
	token, err := s.repo.GetRefreshToken(input.RefreshToken)
	if err != nil || token == nil {
		return nil, errors.New("refresh token not found")
	}

	if token.Revoked {
		return nil, errors.New("refresh token revoked")
	}

	if token.DeviceFingerprint != input.Fingerprint {
		return nil, errors.New("device fingerprint mismatch")
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	// Step 2: Revoke the old token
	if err := s.repo.RevokeRefreshToken(token.ID); err != nil {
		return nil, fmt.Errorf("failed to revoke token: %w", err)
	}

	// Step 3: Check and delete if too many active tokens
	activeCount, err := s.repo.GetActiveCountByUserID(token.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to count active tokens: %w", err)
	}
	if activeCount >= s.maxActiveTokensPerUser {
		if err := s.repo.DeleteOldestByUserID(token.UserID); err != nil {
			log.Printf("warn: failed to delete oldest token for user %s: %v", token.UserID, err)
		}
	}

	// Step 4: Re-fetch user (with role info) to embed role into access token
	user, err := s.repo.GetByIDWithRole(token.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found for token refresh")
	}

	accessToken, newRefreshToken, expiresAt, err := s.tokenService.Generate(user.ID, user.Email, user.RoleName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Step 5: Store the new refresh token
	newToken := &domain.RefreshToken{
		ID:                uuid.NewString(),
		UserID:            token.UserID,
		Token:             newRefreshToken,
		DeviceFingerprint: input.Fingerprint,
		IPAddress:         input.IPAddress,
		UserAgent:         input.UserAgent,
		ExpiresAt:         expiresAt,
		CreatedAt:         time.Now(),
		Revoked:           false,
	}
	if err := s.repo.StoreRefreshToken(newToken); err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// Step 6: Return token pair
	return &dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
