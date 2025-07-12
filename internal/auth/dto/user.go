package dto

import (
	"time"
)

type UserOutput struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	RoleID    int       `json:"role_id"`
	RoleName  string    `json:"role_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UpdateRoleInput struct {
	RoleID int `json:"role_id"`
}

type SessionOutput struct {
	ID                string    `json:"id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}
