package domain

import (
	"context"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
)

//go:generate mockgen -destination=../../mocks/mock_user_repository.go -package=mocks github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain UserRepository

// UserManager handles user CRUD operations
type UserManager interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByIDWithRole(ctx context.Context, userID string) (*User, error)
	Create(ctx context.Context, user *User) error
	GetAllUsers(ctx context.Context) ([]dto.UserOutput, error)
	UpdateUserRole(ctx context.Context, userID string, roleID int) error
}

// RefreshTokenManager handles refresh token operations
type RefreshTokenManager interface {
	StoreRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string) error
	GetActiveCountByUserID(ctx context.Context, userID string) (int, error)
	DeleteOldestByUserID(ctx context.Context, userID string) error
	RevokeAllRefreshTokensByUserID(ctx context.Context, userID string) error
	GetActiveSessionsByUserID(ctx context.Context, userID string) ([]RefreshToken, error)
}

// SecurityAuditor handles security-related operations
type SecurityAuditor interface {
	RecordLoginAttempt(ctx context.Context, email, ip string, success bool) error
	UpsertTrustedDevice(ctx context.Context, userID, fingerprint, userAgent, ip string) error
	CountRecentFailedAttempts(ctx context.Context, email, ip string, withinMinutes int) (int, error)
}

// UserRepository combines all repository interfaces for backward compatibility
type UserRepository interface {
	UserManager
	RefreshTokenManager
	SecurityAuditor
}
