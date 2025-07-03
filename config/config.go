package config

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"
)

// Default configuration constants
const (
	DefaultPort                   = "8080"
	DefaultAccessTokenExpiryMin   = 15
	DefaultRefreshTokenExpiryMin  = 10080 // 7 days in minutes
	DefaultMaxActiveRefreshTokens = 5
	DefaultLoginMaxAttempts       = 5
	DefaultLoginWindowMinutes     = 15
)

type Config struct {
	Env                    string
	Port                   string
	DBURL                  string
	AccessTokenSecret      string
	RefreshTokenSecret     string
	AccessExpiryMin        int
	RefreshExpiryMin       int
	MaxActiveRefreshTokens int
	LoginMaxAttempts       int
	LoginWindowMinutes     int
}

func Load() *Config {
	v := viper.New()

	// Default to "development" if ENV is not set
	env := getEnv("ENV", "development")

	// Automatically read env vars
	v.AutomaticEnv()

	// Load appropriate file based on ENV
	switch env {
	case "production":
		v.SetConfigFile("config/.env.prod")
	default:
		v.SetConfigFile("config/.env.dev")
	}

	v.SetConfigType("env")
	v.AddConfigPath(".")

	// Attempt to load config file
	if err := v.ReadInConfig(); err != nil {
		fmt.Printf("No config file found, fallback to ENV vars: %v\n", err)
	}

	// Set fallback defaults
	v.SetDefault("PORT", DefaultPort)
	v.SetDefault("ACCESS_TOKEN_EXPIRY", DefaultAccessTokenExpiryMin)
	v.SetDefault("REFRESH_TOKEN_EXPIRY", DefaultRefreshTokenExpiryMin)
	v.SetDefault("MAX_ACTIVE_REFRESH_TOKENS", DefaultMaxActiveRefreshTokens)
	v.SetDefault("LOGIN_MAX_ATTEMPTS", DefaultLoginMaxAttempts)
	v.SetDefault("LOGIN_WINDOW_MINUTES", DefaultLoginWindowMinutes)

	// Validate required keys
	requiredKeys := []string{
		"DB_URL",
		"ACCESS_TOKEN_SECRET",
		"REFRESH_TOKEN_SECRET",
	}

	for _, key := range requiredKeys {
		if !v.IsSet(key) || v.GetString(key) == "" {
			log.Fatalf("Missing required config: %s", key)
		}
	}

	return &Config{
		Env:                    env,
		Port:                   v.GetString("PORT"),
		DBURL:                  v.GetString("DB_URL"),
		AccessTokenSecret:      v.GetString("ACCESS_TOKEN_SECRET"),
		RefreshTokenSecret:     v.GetString("REFRESH_TOKEN_SECRET"),
		AccessExpiryMin:        v.GetInt("ACCESS_TOKEN_EXPIRY"),
		RefreshExpiryMin:       v.GetInt("REFRESH_TOKEN_EXPIRY"),
		MaxActiveRefreshTokens: v.GetInt("MAX_ACTIVE_REFRESH_TOKENS"),
		LoginMaxAttempts:       v.GetInt("LOGIN_MAX_ATTEMPTS"),
		LoginWindowMinutes:     v.GetInt("LOGIN_WINDOW_MINUTES"),
	}
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	return val
}
