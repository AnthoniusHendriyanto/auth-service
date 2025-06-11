package errors

import (
	"errors"
)

var (
	ErrTooManyLoginAttempts      = errors.New("too many failed login attempts")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrEmailAlreadyInUse         = errors.New("email already in use")
	ErrRefreshTokenNotFound      = errors.New("refresh token not found")
	ErrRefreshTokenRevoked       = errors.New("refresh token revoked")
	ErrRefreshTokenExpired       = errors.New("refresh token expired")
	ErrDeviceFingerprintMismatch = errors.New("device fingerprint mismatch")
)
