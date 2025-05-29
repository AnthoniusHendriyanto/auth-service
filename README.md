# Auth Service

This is an authentication microservice written in Go using the Fiber framework and PostgreSQL (via pgx). It implements:

* User registration and login
* Access/refresh token generation using JWT
* Token expiration and storage in DB
* Metadata logging: device fingerprint, IP address, user-agent
* Trusted device tracking
* Login attempt history

---

## ✅ Features Implemented

* [x] User registration (`/register`)
* [x] User login (`/login`)
* [x] JWT token generation
* [x] Refresh token storage in DB
* [x] Device & session metadata capture (fingerprint, IP, user-agent)
* [x] Login attempt recording
* [x] Trusted device upsert
* [x] Clean Architecture

## 🛠 Tech Stack

* **Go** (1.20+)
* **Fiber** (HTTP framework)
* **pgx** (PostgreSQL driver)
* **uuid**, **bcrypt**, **jwt-go**
* PostgreSQL

## 📦 Folder Structure

```
auth-service/
├── cmd/                     # Entry point (main.go)
│   └── main.go
├── config/                  # Environment loading (config.go)
│   └── config.go
├── db/                      # DB connection helper
│   └── db.go
├── internal/
│   ├── auth/
│   │   ├── domain/          # Interfaces, core structs
│   │   ├── dto/             # Request/response DTOs
│   │   ├── handler/         # HTTP handler functions
│   │   ├── repository/      # Interfaces + Postgres implementation
│   │   └── service/         # Business logic (UserService, TokenService)
├── migrations/              # SQL migration scripts
│   └── 001_init.sql
├── pkg/
│   ├── middleware/          # Middleware (future use)
│   └── utils/               # Shared helpers (optional)
├── .env.dev
├── .env.prod
├── go.mod
├── LICENSE
└── README.md
```

## 🔐 API Endpoints

### `POST /api/v1/register`

Registers a new user

#### Request

```json
{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

#### Response

```json
{
  "id": "uuid",
  "email": "user@example.com"
}
```

---

### `POST /api/v1/login`

Authenticates user and returns access & refresh tokens

#### Headers

```
X-Device-Fingerprint: your-device-id
Content-Type: application/json
```

#### Body

```json
{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

#### Response

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

---

## 🧪 Example cURL Requests

### Register

```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"123456"}'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -H "X-Device-Fingerprint: abc123" \
  -d '{"email":"user@example.com","password":"123456"}'
```

---

## 📋 PostgreSQL Schema

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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
```

---

## ✅ Environment Variables

```
PORT=8080
DATABASE_URL=postgres://postgres:password@localhost:5432/auth?sslmode=disable
ACCESS_TOKEN_SECRET=youraccesstokensecret
REFRESH_TOKEN_SECRET=yourrefreshtokensecret
ACCESS_TOKEN_EXPIRY=15 # minutes
REFRESH_TOKEN_EXPIRY=10080 # 7 days (in minutes)
```

---

## 🔄 Token Behavior

* **Access token**: short-lived (15m)
* **Refresh token**: long-lived (7d), stored in DB
* On login:

  * Access and refresh tokens are returned
  * Refresh token stored with metadata
  * Login attempt logged
  * Trusted device upserted

---

## 🔧 Run Locally

```bash
# Clone the repository
git clone https://github.com/AnthoniusHendriyanto/auth-service.git
cd auth-service

# Start PostgreSQL (example using Docker)
docker run --name porto-auth-db \
  -e POSTGRES_PASSWORD=yourpassword \
  -p 5432:5432 \
  -d postgres

# Apply database schema (using psql)
psql -h localhost -U postgres -d porto_auth -f migrations/001_init.sql

# Copy or configure environment variables
cp .env.dev .env

# Run the application
go run cmd/main.go
```

---

## 📌 Notes

* Make sure to include header `X-Device-Fingerprint` on login
* Timezone is handled in `Asia/Jakarta` in code layer (not PostgreSQL)
* DTOs are placed in `internal/auth/dto` for clarity

---

Feel free to improve or PR more endpoints (logout, refresh, revoke, etc)!
