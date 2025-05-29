package postgres

import (
	"context"
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
		SELECT id, email, password_hash, created_at, updated_at
		FROM users
		WHERE email = $1
		LIMIT 1;
	`
	row := r.db.QueryRow(context.Background(), query, email)

	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user with email %s not found", email)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
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
