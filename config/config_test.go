package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestEnv creates a temporary directory for config files and changes the working directory to it.
// It returns a cleanup function that should be deferred by the caller.
func setupTestEnv(t *testing.T) func() {
	t.Helper()

	// Create a temporary directory for the test
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "config")
	err := os.Mkdir(configDir, 0755)
	require.NoError(t, err)

	// Save the original working directory
	originalWD, err := os.Getwd()
	require.NoError(t, err)

	// Change to the temporary directory
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// Return a cleanup function to restore the original working directory
	return func() {
		_ = os.Chdir(originalWD)
	}
}

// createTempConfigFile creates a temporary .env file with the given content.
func createTempConfigFile(t *testing.T, filename, content string) {
	t.Helper()
	// Assumes we are in the temp directory created by setupTestEnv
	filePath := filepath.Join("config", filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)
}

func TestLoad(t *testing.T) {
	// Common required variables for most tests
	setRequiredEnvVars := func(t *testing.T) {
		t.Setenv("DB_URL", "postgres://user:pass@localhost:5432/testdb")
		t.Setenv("ACCESS_TOKEN_SECRET", "access_secret")
		t.Setenv("REFRESH_TOKEN_SECRET", "refresh_secret")
	}

	t.Run("loads configuration from dev file", func(t *testing.T) {
		cleanup := setupTestEnv(t)
		defer cleanup()

		// No ENV set, should default to 'development'
		devConfigContent := `
PORT=3000
DB_URL=postgres://user:pass@localhost:5432/devdb
ACCESS_TOKEN_SECRET=dev_access_secret
REFRESH_TOKEN_SECRET=dev_refresh_secret
ACCESS_TOKEN_EXPIRY=10
`
		createTempConfigFile(t, ".env.dev", devConfigContent)

		cfg := Load()

		assert.Equal(t, "development", cfg.Env)
		assert.Equal(t, "3000", cfg.Port)
		assert.Equal(t, "postgres://user:pass@localhost:5432/devdb", cfg.DBURL)
		assert.Equal(t, "dev_access_secret", cfg.AccessTokenSecret)
		assert.Equal(t, "dev_refresh_secret", cfg.RefreshTokenSecret)
		assert.Equal(t, 10, cfg.AccessExpiryMin)
		// This value was not in the file, so it should use the default
		assert.Equal(t, DefaultRefreshTokenExpiryMin, cfg.RefreshExpiryMin)
	})

	t.Run("loads configuration from prod file", func(t *testing.T) {
		cleanup := setupTestEnv(t)
		defer cleanup()

		t.Setenv("ENV", "production")

		prodConfigContent := `
PORT=8000
DB_URL=postgres://user:pass@localhost:5432/proddb
ACCESS_TOKEN_SECRET=prod_access_secret
REFRESH_TOKEN_SECRET=prod_refresh_secret
`
		createTempConfigFile(t, ".env.prod", prodConfigContent)

		cfg := Load()

		assert.Equal(t, "production", cfg.Env)
		assert.Equal(t, "8000", cfg.Port)
		assert.Equal(t, "postgres://user:pass@localhost:5432/proddb", cfg.DBURL)
		assert.Equal(t, "prod_access_secret", cfg.AccessTokenSecret)
		assert.Equal(t, "prod_refresh_secret", cfg.RefreshTokenSecret)
		assert.Equal(t, DefaultAccessTokenExpiryMin, cfg.AccessExpiryMin)
	})

	t.Run("uses default values when not set in file or env", func(t *testing.T) {
		cleanup := setupTestEnv(t)
		defer cleanup()

		// Set only the required variables
		setRequiredEnvVars(t)

		cfg := Load()

		assert.Equal(t, "development", cfg.Env)
		assert.Equal(t, DefaultPort, cfg.Port)
		assert.Equal(t, DefaultAccessTokenExpiryMin, cfg.AccessExpiryMin)
		assert.Equal(t, DefaultRefreshTokenExpiryMin, cfg.RefreshExpiryMin)
		assert.Equal(t, DefaultMaxActiveRefreshTokens, cfg.MaxActiveRefreshTokens)
		assert.Equal(t, DefaultLoginMaxAttempts, cfg.LoginMaxAttempts)
		assert.Equal(t, DefaultLoginWindowMinutes, cfg.LoginWindowMinutes)
	})

	t.Run("environment variables override file configuration", func(t *testing.T) {
		cleanup := setupTestEnv(t)
		defer cleanup()

		// Set file values
		devConfigContent := `
PORT=3000
DB_URL=file_db_url
ACCESS_TOKEN_SECRET=file_access_secret
REFRESH_TOKEN_SECRET=file_refresh_secret
`
		createTempConfigFile(t, ".env.dev", devConfigContent)

		// Set environment variables that should take precedence
		t.Setenv("PORT", "9090")
		t.Setenv("DB_URL", "env_db_url")
		t.Setenv("ACCESS_TOKEN_EXPIRY", "99")

		cfg := Load()

		assert.Equal(t, "9090", cfg.Port)
		assert.Equal(t, "env_db_url", cfg.DBURL)
		assert.Equal(t, "file_access_secret", cfg.AccessTokenSecret) // This was not overridden by env
		assert.Equal(t, 99, cfg.AccessExpiryMin)
	})
}

// TestLoad_FatalOnMissingKeys tests the fatal error handling when required keys are missing.
// It works by re-running the test in a separate process.
func TestLoad_FatalOnMissingKeys(t *testing.T) {
	// This map defines test cases for each required key.
	// The key is the missing environment variable, and the value is the expected error message.
	testCases := map[string]string{
		"DB_URL":               "Missing required config: DB_URL",
		"ACCESS_TOKEN_SECRET":  "Missing required config: ACCESS_TOKEN_SECRET",
		"REFRESH_TOKEN_SECRET": "Missing required config: REFRESH_TOKEN_SECRET",
	}

	for missingKey, expectedErr := range testCases {
		t.Run(fmt.Sprintf("missing_%s", missingKey), func(t *testing.T) {
			// This is the sub-process that will actually run the code and crash.
			if os.Getenv("GO_TEST_FATAL") == "1" {
				Load()
				return // Should not be reached
			}

			// This is the main test process. It executes the sub-process.
			cmd := exec.Command(os.Args[0], "-test.run", t.Name())
			cmd.Env = append(os.Environ(), "GO_TEST_FATAL=1")

			// Set all required keys EXCEPT the one we're testing for.
			for key := range testCases {
				if key != missingKey {
					cmd.Env = append(cmd.Env, fmt.Sprintf("%s=some_value", key))
				}
			}

			// Run the command and capture the output.
			// We expect it to exit with a non-zero status code.
			output, err := cmd.CombinedOutput()

			// Check that the process exited as expected.
			exitErr, ok := err.(*exec.ExitError)
			require.True(t, ok, "Expected command to exit with an error")
			assert.False(t, exitErr.Success(), "Expected command to fail")

			// Check that the output contains our expected fatal error message.
			assert.True(t, strings.Contains(string(output), expectedErr), "Expected output to contain '%s', got '%s'", expectedErr, string(output))
		})
	}
}

func Test_getEnv(t *testing.T) {
	t.Run("returns value if env var is set", func(t *testing.T) {
		key := "TEST_GETENV_KEY"
		expectedValue := "my-test-value"
		t.Setenv(key, expectedValue)

		val := getEnv(key, "fallback")
		assert.Equal(t, expectedValue, val)
	})

	t.Run("returns fallback if env var is not set", func(t *testing.T) {
		key := "TEST_GETENV_UNSET_KEY"
		fallbackValue := "my-fallback-value"

		val := getEnv(key, fallbackValue)
		assert.Equal(t, fallbackValue, val)
	})

	t.Run("returns fallback if env var is set but empty", func(t *testing.T) {
		key := "TEST_GETENV_EMPTY_KEY"
		fallbackValue := "my-fallback-value"
		t.Setenv(key, "")

		val := getEnv(key, fallbackValue)
		assert.Equal(t, fallbackValue, val)
	})
}
