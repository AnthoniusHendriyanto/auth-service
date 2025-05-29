package domain

import "time"

type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshToken struct {
	ID                string
	UserID            string
	Token             string
	DeviceFingerprint string
	IPAddress         string
	UserAgent         string
	ExpiresAt         time.Time
	CreatedAt         time.Time
	Revoked           bool
}

type LoginAttempt struct {
	ID          string
	Email       string
	IPAddress   string
	AttemptTime time.Time
	Successful  bool
}
