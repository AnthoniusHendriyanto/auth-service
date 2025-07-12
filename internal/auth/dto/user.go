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
