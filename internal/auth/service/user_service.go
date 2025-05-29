package service

import (
	"errors"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo         domain.UserRepository
	cfg          config.Config
	tokenService *TokenService
}

func NewUserService(repo domain.UserRepository, tokenService *TokenService) *UserService {
	return &UserService{
		repo:         repo,
		tokenService: tokenService,
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

	accessToken, refreshToken, _, err := s.tokenService.Generate(user.ID, user.Email)
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

	_ = s.repo.UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress)
	_ = s.repo.RecordLoginAttempt(user.Email, input.IPAddress, true)

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
