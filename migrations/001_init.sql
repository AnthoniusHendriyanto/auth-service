-- 1. Create a database
CREATE DATABASE porto_auth;

-- 2. Enable pgcrypto for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 3. Create tables
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
  device_fingerprint TEXT,
  ip_address TEXT,
  user_agent TEXT,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE trusted_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_fingerprint TEXT NOT NULL,
  user_agent TEXT,
  ip_address TEXT,
  last_seen TIMESTAMP DEFAULT NOW(),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE login_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  ip_address TEXT,
  attempt_time TIMESTAMP DEFAULT NOW(),
  successful BOOLEAN
);

-- 4. Indexes
-- For fast login lookup and enforcement
CREATE INDEX idx_users_email ON users(email);

-- For revoking tokens and fast lookup
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- For identifying device sessions per user
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_fingerprint ON trusted_devices(device_fingerprint);

-- For monitoring login activity or brute-force protection
CREATE INDEX idx_login_attempts_email_time ON login_attempts(email, attempt_time);

-- make sure trusted_devices table has a unique constraint
ALTER TABLE trusted_devices
ADD CONSTRAINT unique_user_device UNIQUE (user_id, device_fingerprint);

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- Seed basic roles
INSERT INTO roles (name) VALUES ('user'), ('admin');

-- Update users table to use role_id
ALTER TABLE users
ADD COLUMN role_id INTEGER NOT NULL DEFAULT 1,
ADD CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(id);
