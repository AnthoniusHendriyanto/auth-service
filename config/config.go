package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	Env                string
	Port               string
	DBURL              string
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessExpiryMin    int
	RefreshExpiryMin   int
}

func Load() *Config {
	return &Config{
		Env:                getEnv("ENV", "development"),
		Port:               getEnv("PORT", "8080"),
		DBURL:              mustGetEnv("DB_URL"),
		AccessTokenSecret:  mustGetEnv("ACCESS_TOKEN_SECRET"),
		RefreshTokenSecret: mustGetEnv("REFRESH_TOKEN_SECRET"),
		AccessExpiryMin:    getEnvAsInt("ACCESS_TOKEN_EXPIRY", 15),
		RefreshExpiryMin:   getEnvAsInt("REFRESH_TOKEN_EXPIRY", 10080),
	}
}

func getEnv(key string, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func mustGetEnv(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	log.Fatalf("Missing required environment variable: %s", key)
	return ""
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		log.Printf("Invalid value for %s, using default %d", key, defaultVal)
		return defaultVal
	}
	return val
}
