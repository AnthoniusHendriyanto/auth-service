package service

import (
	"fmt"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	autherror "github.com/AnthoniusHendriyanto/auth-service/internal/errors"
	authconstant "github.com/AnthoniusHendriyanto/auth-service/pkg/constant"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo         domain.UserRepository
	tokenService TokenGenerator
	cfg          *config.Config
}

func NewUserService(repo domain.UserRepository, tokenService TokenGenerator, cfg *config.Config) *UserService {
	return &UserService{
		repo:         repo,
		tokenService: tokenService,
		cfg:          cfg,
	}
}

func (s *UserService) Register(input dto.RegisterInput) (*domain.User, error) {
	existingUser, err := s.repo.GetByEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, autherror.ErrEmailAlreadyInUse
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
		RoleID:       authconstant.DefaultUserRoleID, // Default User Role, Later we can change
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
	// 1. Brute-force check
	failedAttempts, err := s.repo.CountRecentFailedAttempts(input.Email, input.IPAddress, s.cfg.MaxActiveRefreshTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to check login attempts: %w", err)
	}

	if failedAttempts >= s.cfg.LoginMaxAttempts {
		return nil, autherror.ErrTooManyLoginAttempts
	}

	// 2. Check user credentials
	user, err := s.repo.GetByEmail(input.Email)
	if err != nil {
		return nil, err
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		_ = s.repo.RecordLoginAttempt(input.Email, input.IPAddress, false)

		return nil, autherror.ErrInvalidCredentials
	}

	// 3. Generate tokens
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
		ExpiresAt:         now.Add(s.tokenService.GetRefreshTokenExpiry()),
		CreatedAt:         now,
		Revoked:           false,
	}

	if err := s.repo.StoreRefreshToken(refreshTokenObj); err != nil {
		return nil, err
	}

	if err = s.repo.UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress); err != nil {
		return nil, err
	}

	if err = s.repo.RecordLoginAttempt(input.Email, input.IPAddress, true); err != nil {
		return nil, err
	}

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    authconstant.DefaultTokenType,
		ExpiresIn:    int(s.tokenService.GetAccessTokenExpiry().Seconds()),
	}, nil
}

func (s *UserService) Refresh(input dto.RefreshInput) (*dto.TokenResponse, error) {
	token, err := s.ValidateRefreshToken(input)
	if err != nil {
		return nil, err
	}

	if err := s.repo.RevokeRefreshToken(token.ID); err != nil {
		return nil, fmt.Errorf("failed to revoke token: %w", err)
	}

	return s.GenerateAndStoreNewTokens(token, input)
}

func (s *UserService) Logout(refreshToken string) error {
	token, err := s.repo.GetRefreshToken(refreshToken)
	if err != nil || token == nil {
		return autherror.ErrRefreshTokenNotFound
	}

	if token.Revoked {
		return autherror.ErrRefreshTokenRevoked
	}

	return s.repo.RevokeRefreshToken(token.ID)
}

func (s *UserService) ForceLogoutByUserID(userID string) error {
	return s.repo.RevokeAllRefreshTokensByUserID(userID)
}

func (s *UserService) ValidateRefreshToken(input dto.RefreshInput) (*domain.RefreshToken, error) {
	token, err := s.repo.GetRefreshToken(input.RefreshToken)
	if err != nil || token == nil {
		return nil, autherror.ErrRefreshTokenNotFound
	}

	if token.Revoked {
		return nil, autherror.ErrRefreshTokenRevoked
	}

	if token.DeviceFingerprint != input.Fingerprint {
		return nil, autherror.ErrDeviceFingerprintMismatch
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, autherror.ErrRefreshTokenExpired
	}

	return token, nil
}

func (s *UserService) GenerateAndStoreNewTokens(oldToken *domain.RefreshToken,
	input dto.RefreshInput) (*dto.TokenResponse, error) {
	user, err := s.repo.GetByIDWithRole(oldToken.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found for token refresh")
	}

	accessToken, newRefreshToken, expiresAt, err := s.tokenService.Generate(user.ID, user.Email, user.RoleName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	newToken := &domain.RefreshToken{
		ID:                uuid.NewString(),
		UserID:            oldToken.UserID,
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

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    authconstant.DefaultTokenType,
		ExpiresIn:    int(s.tokenService.GetAccessTokenExpiry().Seconds()),
	}, nil
}
