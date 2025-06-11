package domain

type UserRepository interface {
	GetByEmail(email string) (*User, error)
	GetByIDWithRole(userID string) (*User, error)
	Create(user *User) error
	StoreRefreshToken(rt *RefreshToken) error
	RecordLoginAttempt(email, ip string, success bool) error
	UpsertTrustedDevice(userID, fingerprint, userAgent, ip string) error
	GetRefreshToken(token string) (*RefreshToken, error)
	RevokeRefreshToken(id string) error
	GetActiveCountByUserID(userID string) (int, error)
	DeleteOldestByUserID(userID string) error
	RevokeAllRefreshTokensByUserID(userID string) error
	CountRecentFailedAttempts(email, ip string, withinMinutes int) (int, error)
}
