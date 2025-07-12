package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/domain"
	"github.com/AnthoniusHendriyanto/auth-service/internal/auth/dto"
	repo "github.com/AnthoniusHendriyanto/auth-service/internal/auth/repository/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetByEmail covers the GetByEmail repository method.
func TestGetByEmail(t *testing.T) {
	// --- Setup ---
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	r := repo.NewPostgresRepository(mock)
	columns := []string{"id", "email", "password_hash", "role_id", "role_name", "created_at", "updated_at"}
	userEmail := "test@example.com"
	expectedUser := &domain.User{ID: "user-123", Email: userEmail}

	// Define a context to use in the tests
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userEmail).
			WillReturnRows(pgxmock.NewRows(columns).
				AddRow(expectedUser.ID, expectedUser.Email, "hash", 1, "user", time.Now(), time.Now()))

		user, err := r.GetByEmail(ctx, userEmail)
		require.NoError(t, err)
		assert.Equal(t, expectedUser.ID, user.ID)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userEmail).
			WillReturnError(pgx.ErrNoRows)

		user, err := r.GetByEmail(ctx, userEmail)
		require.NoError(t, err) // Should return nil user, nil error
		assert.Nil(t, user)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userEmail).
			WillReturnError(fmt.Errorf("db error"))

		_, err := r.GetByEmail(ctx, userEmail)
		assert.Error(t, err)
	})
}

// TestCreate covers the Create repository method.
func TestCreate(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	userToCreate := &domain.User{
		ID:           "user-123",
		Email:        "new@example.com",
		PasswordHash: "new-hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO users").
			WithArgs(userToCreate.ID, userToCreate.Email, userToCreate.PasswordHash, userToCreate.CreatedAt, userToCreate.UpdatedAt).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := r.Create(ctx, userToCreate)
		assert.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO users").
			WithArgs(userToCreate.ID, userToCreate.Email, userToCreate.PasswordHash, userToCreate.CreatedAt, userToCreate.UpdatedAt).
			WillReturnError(fmt.Errorf("db error"))

		err := r.Create(ctx, userToCreate)
		assert.Error(t, err)
	})
}

// TestStoreRefreshToken covers the StoreRefreshToken method.
func TestStoreRefreshToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	rt := &domain.RefreshToken{ID: "rt-123", UserID: "user-123", Token: "token"}

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(rt.ID, rt.UserID, rt.Token, rt.DeviceFingerprint, rt.IPAddress, rt.UserAgent, rt.ExpiresAt, rt.CreatedAt, rt.Revoked).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := r.StoreRefreshToken(ctx, rt)
		assert.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(rt.ID, rt.UserID, rt.Token, rt.DeviceFingerprint, rt.IPAddress, rt.UserAgent, rt.ExpiresAt, rt.CreatedAt, rt.Revoked).
			WillReturnError(fmt.Errorf("db error"))

		err := r.StoreRefreshToken(ctx, rt)
		assert.Error(t, err)
	})
}

// TestGetRefreshToken covers the GetRefreshToken method.
func TestGetRefreshToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	columns := []string{"id", "user_id", "token", "device_fingerprint", "ip_address", "user_agent", "expires_at", "created_at", "revoked"}
	tokenString := "test-token"
	expectedRT := &domain.RefreshToken{ID: "rt-123", Token: tokenString}

	t.Run("success", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, user_id").
			WithArgs(tokenString).
			WillReturnRows(pgxmock.NewRows(columns).
				AddRow(expectedRT.ID, "uid", expectedRT.Token, "", "", "", time.Now(), time.Now(), false))

		rt, err := r.GetRefreshToken(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, expectedRT.ID, rt.ID)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, user_id").
			WithArgs(tokenString).
			WillReturnError(pgx.ErrNoRows)

		rt, err := r.GetRefreshToken(ctx, tokenString)
		require.NoError(t, err)
		assert.Nil(t, rt)
	})
	t.Run("database scan error", func(t *testing.T) {
		// --- This is the new test case ---
		// Here, we simulate a generic database error during the scan.
		dbError := fmt.Errorf("db scan error")
		mock.ExpectQuery("SELECT id, user_id").
			WithArgs(tokenString).
			WillReturnError(dbError) // Simulate the error

		rt, err := r.GetRefreshToken(ctx, tokenString)

		// Assert that the error is the one we simulated and the token is nil
		require.Error(t, err)
		assert.Equal(t, dbError, err)
		assert.Nil(t, rt)
	})
}

// TestRevokeRefreshToken covers the RevokeRefreshToken method.
func TestRevokeRefreshToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	tokenID := "token-to-revoke"

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := r.RevokeRefreshToken(ctx, tokenID)
		assert.NoError(t, err)
	})
}

// TestCountRecentFailedAttempts covers the CountRecentFailedAttempts method.
func TestCountRecentFailedAttempts(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	r := repo.NewPostgresRepository(mock)
	email := "test@example.com"
	ip := "127.0.0.1"
	minutes := 15

	// Define a context to use in the tests
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		expectedCount := 5
		mock.ExpectQuery("SELECT COUNT").
			WithArgs(email, ip).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(expectedCount))

		count, err := r.CountRecentFailedAttempts(ctx, email, ip, minutes)
		require.NoError(t, err)
		assert.Equal(t, expectedCount, count)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT").
			WithArgs(email, ip).
			WillReturnError(fmt.Errorf("db error"))

		_, err := r.CountRecentFailedAttempts(ctx, email, ip, minutes)
		assert.Error(t, err)
	})
}

// TestRevokeAllRefreshTokensByUserID tests the RevokeAllRefreshTokensByUserID method.
func TestRevokeAllRefreshTokensByUserID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repository := repo.NewPostgresRepository(mock)
	userID := "user-to-logout"

	// Define a context to use in the tests
	ctx := context.Background()

	mock.ExpectExec("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = \\$1 AND revoked = FALSE").
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 5)) // Assume 5 tokens were revoked

	err = repository.RevokeAllRefreshTokensByUserID(ctx, userID)
	require.NoError(t, err)

	// You can also test the error case
	mock.ExpectExec("UPDATE refresh_tokens").
		WithArgs(userID).
		WillReturnError(fmt.Errorf("db error"))

	err = repository.RevokeAllRefreshTokensByUserID(ctx, userID)
	require.Error(t, err)
}

// TestGetByIDWithRole covers the GetByIDWithRole repository method.
func TestGetByIDWithRole(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	columns := []string{"id", "email", "password_hash", "role_id", "role_name", "created_at", "updated_at"}
	userID := "user-123"
	expectedUser := &domain.User{ID: userID, RoleName: "admin"}

	t.Run("success", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows(columns).
				AddRow(expectedUser.ID, "admin@example.com", "hash", 2, "admin", time.Now(), time.Now()))

		user, err := r.GetByIDWithRole(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, expectedUser.ID, user.ID)
		assert.Equal(t, "admin", user.RoleName)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userID).
			WillReturnError(pgx.ErrNoRows)

		user, err := r.GetByIDWithRole(ctx, userID)
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery("SELECT u.id, u.email").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		_, err := r.GetByIDWithRole(ctx, userID)
		assert.Error(t, err)
	})
}

// TestRecordLoginAttempt covers the RecordLoginAttempt method.
func TestRecordLoginAttempt(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	email := "test@example.com"
	ip := "127.0.0.1"

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO login_attempts").
			WithArgs(email, ip, true).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := r.RecordLoginAttempt(ctx, email, ip, true)
		assert.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO login_attempts").
			WithArgs(email, ip, false).
			WillReturnError(fmt.Errorf("db error"))

		err := r.RecordLoginAttempt(ctx, email, ip, false)
		assert.Error(t, err)
	})
}

// TestUpsertTrustedDevice covers the UpsertTrustedDevice method.
func TestUpsertTrustedDevice(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	userID := "user-123"
	fingerprint := "fingerprint-abc"
	userAgent := "Go-http-client/1.1"
	ip := "127.0.0.1"

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO trusted_devices").
			WithArgs(userID, fingerprint, userAgent, ip).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := r.UpsertTrustedDevice(ctx, userID, fingerprint, userAgent, ip)
		assert.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO trusted_devices").
			WithArgs(userID, fingerprint, userAgent, ip).
			WillReturnError(fmt.Errorf("db error"))

		err := r.UpsertTrustedDevice(ctx, userID, fingerprint, userAgent, ip)
		assert.Error(t, err)
	})
}

// TestGetActiveCountByUserID covers the GetActiveCountByUserID method.
func TestGetActiveCountByUserID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	userID := "user-123"

	t.Run("success", func(t *testing.T) {
		expectedCount := 3
		mock.ExpectQuery("SELECT COUNT\\(id\\)").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(expectedCount))

		count, err := r.GetActiveCountByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, expectedCount, count)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(id\\)").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		_, err := r.GetActiveCountByUserID(ctx, userID)
		assert.Error(t, err)
	})
}

// TestDeleteOldestByUserID covers the DeleteOldestByUserID method.
func TestDeleteOldestByUserID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Define a context to use in the tests
	ctx := context.Background()

	r := repo.NewPostgresRepository(mock)
	userID := "user-123"

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec("DELETE FROM refresh_tokens").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := r.DeleteOldestByUserID(ctx, userID)
		assert.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec("DELETE FROM refresh_tokens").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		err := r.DeleteOldestByUserID(ctx, userID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete oldest refresh token")
	})
}

// TestGetAllUsers covers the GetAllUsers repository method.
func TestGetAllUsers(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	r := repo.NewPostgresRepository(mock)
	ctx := context.Background()
	columns := []string{"id", "email", "role_id", "role_name", "created_at", "updated_at"}

	t.Run("success", func(t *testing.T) {
		// Expected user data
		now := time.Now()
		expectedUsers := []dto.UserOutput{
			{ID: "user-1", Email: "user1@example.com", RoleID: 1, RoleName: "user", CreatedAt: now, UpdatedAt: now},
			{ID: "user-2", Email: "user2@example.com", RoleID: 2, RoleName: "admin", CreatedAt: now, UpdatedAt: now},
		}

		// Mock the query to return rows
		rows := pgxmock.NewRows(columns).
			AddRow(expectedUsers[0].ID, expectedUsers[0].Email, expectedUsers[0].RoleID, expectedUsers[0].RoleName, expectedUsers[0].CreatedAt, expectedUsers[0].UpdatedAt).
			AddRow(expectedUsers[1].ID, expectedUsers[1].Email, expectedUsers[1].RoleID, expectedUsers[1].RoleName, expectedUsers[1].CreatedAt, expectedUsers[1].UpdatedAt)

		mock.ExpectQuery("SELECT u.id, u.email, u.role_id").
			WillReturnRows(rows)

		users, err := r.GetAllUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, expectedUsers[0].Email, users[0].Email)
		assert.Equal(t, expectedUsers[1].RoleName, users[1].RoleName)
	})

	t.Run("database error on query", func(t *testing.T) {
		dbErr := fmt.Errorf("db error")
		mock.ExpectQuery("SELECT u.id, u.email, u.role_id").
			WillReturnError(dbErr)

		users, err := r.GetAllUsers(ctx)
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), dbErr.Error())
	})

	t.Run("database error on row scan", func(t *testing.T) {
		// Mock rows with a type mismatch to cause a scan error
		rows := pgxmock.NewRows(columns).
			AddRow("user-1", "user1@example.com", "not-an-int", "user", time.Now(), time.Now())

		mock.ExpectQuery("SELECT u.id, u.email, u.role_id").
			WillReturnRows(rows)

		users, err := r.GetAllUsers(ctx)
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "failed to scan user row")
	})
}
