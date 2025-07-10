package domain

//go:generate mockgen -destination=../../mocks/mock_user_repository.go -package=mocks github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain UserRepository

// UserManager handles user CRUD operations
type UserManager interface {
	GetByEmail(email string) (*User, error)
	GetByIDWithRole(userID string) (*User, error)
	Create(user *User) error
}

// RefreshTokenManager handles refresh token operations
type RefreshTokenManager interface {
	StoreRefreshToken(rt *RefreshToken) error
	GetRefreshToken(token string) (*RefreshToken, error)
	RevokeRefreshToken(id string) error
	GetActiveCountByUserID(userID string) (int, error)
	DeleteOldestByUserID(userID string) error
	RevokeAllRefreshTokensByUserID(userID string) error
}

// SecurityAuditor handles security-related operations
type SecurityAuditor interface {
	RecordLoginAttempt(email, ip string, success bool) error
	UpsertTrustedDevice(userID, fingerprint, userAgent, ip string) error
	CountRecentFailedAttempts(email, ip string, withinMinutes int) (int, error)
}

// UserRepository combines all repository interfaces for backward compatibility
type UserRepository interface {
	UserManager
	RefreshTokenManager
	SecurityAuditor
}
