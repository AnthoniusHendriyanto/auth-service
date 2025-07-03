package service

import (
	"errors"
	"testing"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/config"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	autherror "github.com/AnthoniusHendriyanto/auth-service/internal/errors"
	"github.com/AnthoniusHendriyanto/auth-service/internal/mocks"
	authconstant "github.com/AnthoniusHendriyanto/auth-service/pkg/constant"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestNewUserService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	assert.NotNil(t, service)
	assert.Equal(t, mockRepo, service.repo)
	assert.Equal(t, mockTokenService, service.tokenService)
	assert.Equal(t, cfg, service.cfg)
}

func TestUserService_Register_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Mock expectations
	mockRepo.EXPECT().GetByEmail(input.Email).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(nil)

	user, err := service.Register(input)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, input.Email, user.Email)
	assert.NotEmpty(t, user.ID)
	assert.NotEmpty(t, user.PasswordHash)
	assert.Equal(t, authconstant.DefaultUserRoleID, user.RoleID)
	assert.NotZero(t, user.CreatedAt)
	assert.NotZero(t, user.UpdatedAt)
}

func TestUserService_Register_EmailAlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	}

	existingUser := &domain.User{
		ID:    "existing-id",
		Email: input.Email,
	}

	// Mock expectations
	mockRepo.EXPECT().GetByEmail(input.Email).Return(existingUser, nil)

	user, err := service.Register(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrEmailAlreadyInUse, err)
	assert.Nil(t, user)
}

func TestUserService_Register_GetByEmailError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	}

	expectedError := errors.New("database error")

	// Mock expectations
	mockRepo.EXPECT().GetByEmail(input.Email).Return(nil, expectedError)

	user, err := service.Register(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, user)
}

func TestUserService_Register_CreateError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	}

	expectedError := errors.New("create error")

	// Mock expectations
	mockRepo.EXPECT().GetByEmail(input.Email).Return(nil, nil)
	mockRepo.EXPECT().Create(gomock.Any()).Return(expectedError)

	user, err := service.Register(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, user)
}

func TestUserService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		RoleName:     "user",
	}

	input := dto.LoginInput{
		Email:       user.Email,
		Password:    password,
		IPAddress:   "192.168.1.1",
		Fingerprint: "device-fingerprint",
		UserAgent:   "test-agent",
	}

	accessToken := "access-token"
	refreshToken := "refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	accessTokenExpiry := 15 * time.Minute

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, refreshToken, expiresAt, nil)
	mockTokenService.EXPECT().GetRefreshTokenExpiry().Return(7 * 24 * time.Hour)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(nil)
	mockRepo.EXPECT().UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress).Return(nil)
	mockRepo.EXPECT().RecordLoginAttempt(input.Email, input.IPAddress, true).Return(nil)
	mockTokenService.EXPECT().GetAccessTokenExpiry().Return(accessTokenExpiry)

	response, err := service.Login(input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, accessToken, response.AccessToken)
	assert.Equal(t, refreshToken, response.RefreshToken)
	assert.Equal(t, authconstant.DefaultTokenType, response.TokenType)
	assert.Equal(t, int(accessTokenExpiry.Seconds()), response.ExpiresIn)
}

func TestUserService_Login_TooManyAttempts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.LoginInput{
		Email:     "test@example.com",
		Password:  "password123",
		IPAddress: "192.168.1.1",
	}

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(6, nil)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrTooManyLoginAttempts, err)
	assert.Nil(t, response)
}

func TestUserService_Login_CountFailedAttemptsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.LoginInput{
		Email:     "test@example.com",
		Password:  "password123",
		IPAddress: "192.168.1.1",
	}

	expectedError := errors.New("database error")

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress,
		cfg.MaxActiveRefreshTokens).Return(0, expectedError)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check login attempts")
	assert.Nil(t, response)
}

func TestUserService_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.LoginInput{
		Email:     "test@example.com",
		Password:  "password123",
		IPAddress: "192.168.1.1",
	}

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(nil, nil)
	mockRepo.EXPECT().RecordLoginAttempt(input.Email, input.IPAddress, false).Return(nil)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrInvalidCredentials, err)
	assert.Nil(t, response)
}

func TestUserService_Login_InvalidPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
	}

	input := dto.LoginInput{
		Email:     user.Email,
		Password:  "wrong-password",
		IPAddress: "192.168.1.1",
	}

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockRepo.EXPECT().RecordLoginAttempt(input.Email, input.IPAddress, false).Return(nil)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrInvalidCredentials, err)
	assert.Nil(t, response)
}

func TestUserService_Login_TokenGenerationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		RoleName:     "user",
	}

	input := dto.LoginInput{
		Email:     user.Email,
		Password:  password,
		IPAddress: "192.168.1.1",
	}

	expectedError := errors.New("token generation error")

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).Return("", "", time.Time{}, expectedError)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, response)
}

func TestUserService_Refresh_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "device-fingerprint",
		ExpiresAt:         time.Now().Add(time.Hour),
		Revoked:           false,
	}

	user := &domain.User{
		ID:       "user-id",
		Email:    "test@example.com",
		RoleName: "user",
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
		IPAddress:    "192.168.1.1",
		UserAgent:    "test-agent",
	}

	accessToken := "new-access-token"
	newRefreshToken := "new-refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	accessTokenExpiry := 15 * time.Minute

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)
	mockRepo.EXPECT().RevokeRefreshToken(refreshToken.ID).Return(nil)
	mockRepo.EXPECT().GetByIDWithRole(refreshToken.UserID).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, newRefreshToken, expiresAt, nil)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(nil)
	mockTokenService.EXPECT().GetAccessTokenExpiry().Return(accessTokenExpiry)

	response, err := service.Refresh(input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, accessToken, response.AccessToken)
	assert.Equal(t, newRefreshToken, response.RefreshToken)
	assert.Equal(t, authconstant.DefaultTokenType, response.TokenType)
	assert.Equal(t, int(accessTokenExpiry.Seconds()), response.ExpiresIn)
}

func TestUserService_Refresh_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	input := dto.RefreshInput{
		RefreshToken: "invalid-token",
		Fingerprint:  "device-fingerprint",
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(nil, nil)

	response, err := service.Refresh(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenNotFound, err)
	assert.Nil(t, response)
}

func TestUserService_Refresh_RevokedToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "device-fingerprint",
		ExpiresAt:         time.Now().Add(time.Hour),
		Revoked:           true,
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)

	response, err := service.Refresh(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenRevoked, err)
	assert.Nil(t, response)
}

func TestUserService_Refresh_FingerprintMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "different-fingerprint",
		ExpiresAt:         time.Now().Add(time.Hour),
		Revoked:           false,
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)

	response, err := service.Refresh(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrDeviceFingerprintMismatch, err)
	assert.Nil(t, response)
}

func TestUserService_Refresh_ExpiredToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "device-fingerprint",
		ExpiresAt:         time.Now().Add(-time.Hour), // Expired
		Revoked:           false,
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)

	response, err := service.Refresh(input)

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenExpired, err)
	assert.Nil(t, response)
}

func TestUserService_Logout_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:      "token-id",
		Token:   "refresh-token",
		Revoked: false,
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken("refresh-token").Return(refreshToken, nil)
	mockRepo.EXPECT().RevokeRefreshToken(refreshToken.ID).Return(nil)

	err := service.Logout("refresh-token")

	assert.NoError(t, err)
}

func TestUserService_Logout_TokenNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken("invalid-token").Return(nil, nil)

	err := service.Logout("invalid-token")

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenNotFound, err)
}

func TestUserService_Logout_AlreadyRevoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:      "token-id",
		Token:   "refresh-token",
		Revoked: true,
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken("refresh-token").Return(refreshToken, nil)

	err := service.Logout("refresh-token")

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenRevoked, err)
}

func TestUserService_ForceLogoutByUserID_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	userID := "user-id"

	// Mock expectations
	mockRepo.EXPECT().RevokeAllRefreshTokensByUserID(userID).Return(nil)

	err := service.ForceLogoutByUserID(userID)

	assert.NoError(t, err)
}

func TestUserService_ForceLogoutByUserID_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	userID := "user-id"
	expectedError := errors.New("database error")

	// Mock expectations
	mockRepo.EXPECT().RevokeAllRefreshTokensByUserID(userID).Return(expectedError)

	err := service.ForceLogoutByUserID(userID)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestUserService_validateRefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "device-fingerprint",
		ExpiresAt:         time.Now().Add(time.Hour),
		Revoked:           false,
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
	}

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)

	result, err := service.validateRefreshToken(input)

	assert.NoError(t, err)
	assert.Equal(t, refreshToken, result)
}

func TestUserService_generateAndStoreNewTokens_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	oldToken := &domain.RefreshToken{
		ID:     "old-token-id",
		UserID: "user-id",
	}

	user := &domain.User{
		ID:       "user-id",
		Email:    "test@example.com",
		RoleName: "user",
	}

	input := dto.RefreshInput{
		Fingerprint: "device-fingerprint",
		IPAddress:   "192.168.1.1",
		UserAgent:   "test-agent",
	}

	accessToken := "new-access-token"
	newRefreshToken := "new-refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	accessTokenExpiry := 15 * time.Minute

	// Mock expectations
	mockRepo.EXPECT().GetByIDWithRole(oldToken.UserID).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, newRefreshToken, expiresAt, nil)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(nil)
	mockTokenService.EXPECT().GetAccessTokenExpiry().Return(accessTokenExpiry)

	response, err := service.generateAndStoreNewTokens(oldToken, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, accessToken, response.AccessToken)
	assert.Equal(t, newRefreshToken, response.RefreshToken)
	assert.Equal(t, authconstant.DefaultTokenType, response.TokenType)
	assert.Equal(t, int(accessTokenExpiry.Seconds()), response.ExpiresIn)
}

func TestUserService_generateAndStoreNewTokens_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	oldToken := &domain.RefreshToken{
		ID:     "old-token-id",
		UserID: "user-id",
	}

	input := dto.RefreshInput{
		Fingerprint: "device-fingerprint",
		IPAddress:   "192.168.1.1",
		UserAgent:   "test-agent",
	}

	// Mock expectations
	mockRepo.EXPECT().GetByIDWithRole(oldToken.UserID).Return(nil, nil)

	response, err := service.generateAndStoreNewTokens(oldToken, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found for token refresh")
	assert.Nil(t, response)
}

func TestUserService_generateAndStoreNewTokens_TokenGenerationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	oldToken := &domain.RefreshToken{
		ID:     "old-token-id",
		UserID: "user-id",
	}

	user := &domain.User{
		ID:       "user-id",
		Email:    "test@example.com",
		RoleName: "user",
	}

	input := dto.RefreshInput{
		Fingerprint: "device-fingerprint",
		IPAddress:   "192.168.1.1",
		UserAgent:   "test-agent",
	}

	expectedError := errors.New("token generation error")

	// Mock expectations
	mockRepo.EXPECT().GetByIDWithRole(oldToken.UserID).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).Return("", "", time.Time{}, expectedError)

	response, err := service.generateAndStoreNewTokens(oldToken, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate new tokens")
	assert.Nil(t, response)
}

func TestUserService_generateAndStoreNewTokens_StoreError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	oldToken := &domain.RefreshToken{
		ID:     "old-token-id",
		UserID: "user-id",
	}

	user := &domain.User{
		ID:       "user-id",
		Email:    "test@example.com",
		RoleName: "user",
	}

	input := dto.RefreshInput{
		Fingerprint: "device-fingerprint",
		IPAddress:   "192.168.1.1",
		UserAgent:   "test-agent",
	}

	accessToken := "new-access-token"
	newRefreshToken := "new-refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	expectedError := errors.New("store error")

	// Mock expectations
	mockRepo.EXPECT().GetByIDWithRole(oldToken.UserID).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, newRefreshToken, expiresAt, nil)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(expectedError)

	response, err := service.generateAndStoreNewTokens(oldToken, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store new refresh token")
	assert.Nil(t, response)
}

func TestUserService_Login_StoreRefreshTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		RoleName:     "user",
	}

	input := dto.LoginInput{
		Email:       user.Email,
		Password:    password,
		IPAddress:   "192.168.1.1",
		Fingerprint: "device-fingerprint",
		UserAgent:   "test-agent",
	}

	accessToken := "access-token"
	refreshToken := "refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	expectedError := errors.New("store error")

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, refreshToken, expiresAt, nil)
	mockTokenService.EXPECT().GetRefreshTokenExpiry().Return(7 * 24 * time.Hour)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(expectedError)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, response)
}

func TestUserService_Login_UpsertTrustedDeviceError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		RoleName:     "user",
	}

	input := dto.LoginInput{
		Email:       user.Email,
		Password:    password,
		IPAddress:   "192.168.1.1",
		Fingerprint: "device-fingerprint",
		UserAgent:   "test-agent",
	}

	accessToken := "access-token"
	refreshToken := "refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	expectedError := errors.New("upsert error")

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).
		Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, refreshToken, expiresAt, nil)
	mockTokenService.EXPECT().GetRefreshTokenExpiry().Return(7 * 24 * time.Hour)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(nil)
	mockRepo.EXPECT().UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress).
		Return(expectedError)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, response)
}

func TestUserService_Login_RecordLoginAttemptError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{
		MaxActiveRefreshTokens: 5,
		LoginMaxAttempts:       5,
	}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		RoleName:     "user",
	}

	input := dto.LoginInput{
		Email:       user.Email,
		Password:    password,
		IPAddress:   "192.168.1.1",
		Fingerprint: "device-fingerprint",
		UserAgent:   "test-agent",
	}

	accessToken := "access-token"
	refreshToken := "refresh-token"
	expiresAt := time.Now().Add(15 * time.Minute)
	expectedError := errors.New("record error")

	// Mock expectations
	mockRepo.EXPECT().CountRecentFailedAttempts(input.Email, input.IPAddress, cfg.MaxActiveRefreshTokens).Return(0, nil)
	mockRepo.EXPECT().GetByEmail(input.Email).Return(user, nil)
	mockTokenService.EXPECT().Generate(user.ID, user.Email, user.RoleName).
		Return(accessToken, refreshToken, expiresAt, nil)
	mockTokenService.EXPECT().GetRefreshTokenExpiry().Return(7 * 24 * time.Hour)
	mockRepo.EXPECT().StoreRefreshToken(gomock.Any()).Return(nil)
	mockRepo.EXPECT().UpsertTrustedDevice(user.ID, input.Fingerprint, input.UserAgent, input.IPAddress).Return(nil)
	mockRepo.EXPECT().RecordLoginAttempt(input.Email, input.IPAddress, true).Return(expectedError)

	response, err := service.Login(input)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, response)
}

func TestUserService_Refresh_RevokeTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	refreshToken := &domain.RefreshToken{
		ID:                "token-id",
		UserID:            "user-id",
		Token:             "refresh-token",
		DeviceFingerprint: "device-fingerprint",
		ExpiresAt:         time.Now().Add(time.Hour),
		Revoked:           false,
	}

	input := dto.RefreshInput{
		RefreshToken: "refresh-token",
		Fingerprint:  "device-fingerprint",
	}

	expectedError := errors.New("revoke error")

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken(input.RefreshToken).Return(refreshToken, nil)
	mockRepo.EXPECT().RevokeRefreshToken(refreshToken.ID).Return(expectedError)

	response, err := service.Refresh(input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke token")
	assert.Nil(t, response)
}

func TestUserService_Logout_GetTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenService := mocks.NewMockTokenGenerator(ctrl)
	cfg := &config.Config{}

	service := NewUserService(mockRepo, mockTokenService, cfg)

	expectedError := errors.New("database error")

	// Mock expectations
	mockRepo.EXPECT().GetRefreshToken("refresh-token").Return(nil, expectedError)

	err := service.Logout("refresh-token")

	assert.Error(t, err)
	assert.Equal(t, autherror.ErrRefreshTokenNotFound, err)
}

func TestTokenService_Getters(t *testing.T) {
	mockAccessTokenExpiry := 15 * time.Minute
	mockRefreshTokenExpiry := 24 * time.Hour * 7 // 7 days

	ts := &TokenService{
		AccessTokenExpiry:  mockAccessTokenExpiry,
		RefreshTokenExpiry: mockRefreshTokenExpiry,
	}

	t.Run("GetAccessTokenExpiry", func(t *testing.T) {
		expiry := ts.GetAccessTokenExpiry()

		if expiry != mockAccessTokenExpiry {
			t.Errorf("expected access token expiry %v, but got %v", mockAccessTokenExpiry, expiry)
		}
	})

	t.Run("GetRefreshTokenExpiry", func(t *testing.T) {
		expiry := ts.GetRefreshTokenExpiry()

		if expiry != mockRefreshTokenExpiry {
			t.Errorf("expected refresh token expiry %v, but got %v", mockRefreshTokenExpiry, expiry)
		}
	})
}
