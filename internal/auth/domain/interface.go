package domain

type UserRepository interface {
	GetByEmail(email string) (*User, error)
	Create(user *User) error
	StoreRefreshToken(rt *RefreshToken) error
	RecordLoginAttempt(email, ip string, success bool) error
	UpsertTrustedDevice(userID, fingerprint, userAgent, ip string) error
}
