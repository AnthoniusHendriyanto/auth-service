package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	db *pgxpool.Pool
}

func NewPostgresUserRepository(db *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetByEmail(email string) (*domain.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.role_id, r.name as role_name, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON u.role_id = r.id
		WHERE u.email = $1
		LIMIT 1;
	`
	row := r.db.QueryRow(context.Background(), query, email)

	var user domain.User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.RoleID,
		&user.RoleName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

func (r *PostgresRepository) GetByIDWithRole(userID string) (*domain.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.role_id, r.name AS role_name, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON u.role_id = r.id
		WHERE u.id = $1
		LIMIT 1;
	`
	row := r.db.QueryRow(context.Background(), query, userID)

	var user domain.User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.RoleID,
		&user.RoleName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID with role: %w", err)
	}

	return &user, nil
}

func (r *PostgresRepository) Create(user *domain.User) error {
	_, err := r.db.Exec(context.Background(), `
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
    `, user.ID, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt)

	return err
}

func (r *PostgresRepository) StoreRefreshToken(rt *domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, user_id, token, device_fingerprint, ip_address, user_agent, expires_at, created_at, revoked)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.db.Exec(context.Background(), query,
		rt.ID, rt.UserID, rt.Token, rt.DeviceFingerprint, rt.IPAddress,
		rt.UserAgent, rt.ExpiresAt, rt.CreatedAt, rt.Revoked)
	return err
}

func (r *PostgresRepository) RecordLoginAttempt(email, ip string, success bool) error {
	_, err := r.db.Exec(context.Background(), `
		INSERT INTO login_attempts (id, email, ip_address, attempt_time, successful)
		VALUES (gen_random_uuid(), $1, $2, now(), $3)
	`, email, ip, success)
	return err
}

func (r *PostgresRepository) UpsertTrustedDevice(userID, fingerprint, userAgent, ip string) error {
	_, err := r.db.Exec(context.Background(), `
		INSERT INTO trusted_devices (
			id, user_id, device_fingerprint, user_agent, ip_address, last_seen, created_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4, now(), now()
		)
		ON CONFLICT (user_id, device_fingerprint)
		DO UPDATE SET
			last_seen = now(),
			ip_address = EXCLUDED.ip_address,
			user_agent = EXCLUDED.user_agent
	`, userID, fingerprint, userAgent, ip)
	return err
}

func (r *PostgresRepository) GetRefreshToken(token string) (*domain.RefreshToken, error) {
	row := r.db.QueryRow(context.Background(), `
		SELECT id, user_id, token, device_fingerprint, ip_address, user_agent, expires_at, created_at, revoked
		FROM refresh_tokens
		WHERE token = $1
	`, token)

	var rt domain.RefreshToken
	err := row.Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.DeviceFingerprint,
		&rt.IPAddress,
		&rt.UserAgent,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&rt.Revoked,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *PostgresRepository) RevokeRefreshToken(id string) error {
	_, err := r.db.Exec(context.Background(),
		`UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`, id)
	return err
}

func (r *PostgresRepository) GetActiveCountByUserID(userID string) (int, error) {
	query := `
		SELECT COUNT(id)
		FROM refresh_tokens
		WHERE user_id = $1
		  AND revoked = FALSE
		  AND expires_at > NOW()
	`
	var count int
	err := r.db.QueryRow(context.Background(), query, userID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *PostgresRepository) DeleteOldestByUserID(userID string) error {
	query := `
		DELETE FROM refresh_tokens
		WHERE id = (
			SELECT id FROM refresh_tokens
			WHERE user_id = $1 AND revoked = FALSE
			ORDER BY created_at ASC
			LIMIT 1
		)
	`
	_, err := r.db.Exec(context.Background(), query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete oldest refresh token for user %s: %w", userID, err)
	}
	return nil
}

func (r *PostgresRepository) RevokeAllRefreshTokensByUserID(userID string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.db.Exec(context.Background(), query, userID)
	return err
}
