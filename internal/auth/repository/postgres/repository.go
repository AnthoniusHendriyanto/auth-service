package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Repository struct {
	db DBPool
}

type DBPool interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

func NewPostgresRepository(db DBPool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.role_id, r.name as role_name, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON u.role_id = r.id
		WHERE u.email = $1
		LIMIT 1;
	`
	row := r.db.QueryRow(ctx, query, email)

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

func (r *Repository) GetByIDWithRole(ctx context.Context, userID string) (*domain.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.role_id, r.name AS role_name, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON u.role_id = r.id
		WHERE u.id = $1
		LIMIT 1;
	`
	row := r.db.QueryRow(ctx, query, userID)

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

func (r *Repository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.db.Exec(ctx, `
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
    `, user.ID, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt)

	return err
}

func (r *Repository) StoreRefreshToken(ctx context.Context, rt *domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, user_id, token, device_fingerprint, ip_address, user_agent, 
                            expires_at, created_at, revoked)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.db.Exec(ctx, query,
		rt.ID, rt.UserID, rt.Token, rt.DeviceFingerprint, rt.IPAddress,
		rt.UserAgent, rt.ExpiresAt, rt.CreatedAt, rt.Revoked)

	return err
}

func (r *Repository) RecordLoginAttempt(ctx context.Context, email, ip string, success bool) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO login_attempts (id, email, ip_address, attempt_time, successful)
		VALUES (gen_random_uuid(), $1, $2, now(), $3)
	`, email, ip, success)

	return err
}

func (r *Repository) UpsertTrustedDevice(ctx context.Context, userID, fingerprint, userAgent, ip string) error {
	_, err := r.db.Exec(ctx, `
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

func (r *Repository) GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	row := r.db.QueryRow(ctx, `
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
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &rt, nil
}

func (r *Repository) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`, id)

	return err
}

func (r *Repository) GetActiveCountByUserID(ctx context.Context, userID string) (int, error) {
	query := `
		SELECT COUNT(id)
		FROM refresh_tokens
		WHERE user_id = $1
		  AND revoked = FALSE
		  AND expires_at > NOW()
	`
	var count int
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *Repository) DeleteOldestByUserID(ctx context.Context, userID string) error {
	query := `
		DELETE FROM refresh_tokens
		WHERE id = (
			SELECT id FROM refresh_tokens
			WHERE user_id = $1 AND revoked = FALSE
			ORDER BY created_at ASC
			LIMIT 1
		)
	`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete oldest refresh token for user %s: %w", userID, err)
	}

	return nil
}

func (r *Repository) RevokeAllRefreshTokensByUserID(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.db.Exec(ctx, query, userID)

	return err
}

func (r *Repository) CountRecentFailedAttempts(ctx context.Context, email, ip string, withinMinutes int) (int, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM login_attempts
		WHERE email = $1
		  AND ip_address = $2
		  AND successful = FALSE
		  AND attempt_time > NOW() - INTERVAL '%d minutes'
	`, withinMinutes)

	var count int
	err := r.db.QueryRow(ctx, query, email, ip).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count recent failed attempts: %w", err)
	}

	return count, nil
}

func (r *Repository) GetAllUsers(ctx context.Context) ([]dto.UserOutput, error) {
	query := `
		SELECT u.id, u.email, u.role_id, r.name as role_name, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON u.role_id = r.id
		ORDER BY u.created_at DESC;
	`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}
	defer rows.Close()

	var users []dto.UserOutput
	for rows.Next() {
		var user dto.UserOutput
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.RoleID,
			&user.RoleName,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over user rows: %w", err)
	}

	return users, nil
}

func (r *Repository) UpdateUserRole(ctx context.Context, userID string, roleID int) error {
	query := `UPDATE users SET role_id = $1, updated_at = now() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, roleID, userID)
	return err
}

func (r *Repository) GetActiveSessionsByUserID(ctx context.Context, userID string) ([]domain.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, device_fingerprint, ip_address, user_agent, expires_at, created_at, revoked
		FROM refresh_tokens
		WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []domain.RefreshToken
	for rows.Next() {
		var rt domain.RefreshToken
		err := rows.Scan(
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
		if err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}
		sessions = append(sessions, rt)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over session rows: %w", err)
	}

	return sessions, nil
}
