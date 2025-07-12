# Porto Auth Service
[![codecov](https://codecov.io/github/AnthoniusHendriyanto/auth-service/graph/badge.svg?token=VV3CFWZG5G)](https://codecov.io/github/AnthoniusHendriyanto/auth-service)
[![Go Report Card](https://goreportcard.com/badge/github.com/AnthoniusHendriyanto/auth-service)](https://goreportcard.com/report/github.com/AnthoniusHendriyanto/auth-service)

A robust, modular authentication service for the Porto application ecosystem, built in Go using Fiber. This service handles user registration, login, refresh token rotation, secure device tracking, session metadata logging, and role-based access control.

---
## Features

- ✅ JWT-based authentication (access + refresh tokens)
- 🔁 Refresh token rotation with metadata validation
- 👤 Role-based access control (admin, user via `roles` table)
- 🧠 Trusted device tracking and upsert logic
- 🕵️‍♂️ Login attempt logging
- 🔐 Token revocation on refresh, logout, and force logout
- 🌍 Environment-based config via Viper
- 🗃️ PostgreSQL database using `pgx`
- 🧪 Clean Architecture
- 🛡️ Role-Based Access Control: Middleware to enforce role-based access for specific endpoints.
- 🔒 Brute-Force Protection: Limits login attempts from a single IP address to prevent brute-force attacks.
- 🔄 CI Pipeline: Continuous integration pipeline to build, test, and scan the code for vulnerabilities and quality issues.
- 📋 **Admin User Listing**: Admins can retrieve a list of all registered users.

---
## Architecture

This project follows **Clean Architecture** principles to maintain a separation of concerns, making the application more scalable, testable, and maintainable.

- `cmd/` - Main application entry point.
- `config/` - Handles application configuration using Viper.
- `db/` - Database connection and initialization.
- `domain/` - Contains the core business entities and repository interfaces (e.g., `User`, `UserRepository`).
- `dto/` - Data Transfer Objects (DTOs) for handling request and response data.
- `handler/` - The HTTP delivery layer, built using the Fiber framework.
- `internal/errors` - Defines custom error types for the application.
- `internal/mocks` - Contains generated mocks for testing.
- `migrations/` - Database migration files.
- `repository/` - The infrastructure layer, with a PostgreSQL-specific implementation.
- `service/` - Implements the application's business logic (use cases).

---

## Installation & Running

1. **Clone the repository**

```bash
git clone https://github.com/AnthoniusHendriyanto/auth-service.git
cd auth-service
```

2. **Set up the database**

- Create a PostgreSQL database named `porto_auth`.
- Run the migrations in `/migrations`.

3. **Create a file** inside the `config/` directory:

```env
PORT=8080
DB_URL=postgres://user:pass@localhost:5432/porto_auth
ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_EXPIRY=15
REFRESH_TOKEN_EXPIRY=10080
```

4. **Run the app**

```bash
go mod tidy
go run cmd/main.go
```

> Visit: `http://localhost:8080`

---

## API Endpoints

### `POST /api/v1/register`

Registers a new user.

**Example Request:**

```bash
curl -X POST http://localhost:8080/api/v1/register \
-H "Content-Type: application/json" \
-d '{
  "email": "test@example.com",
  "password": "password123"
}'
```

---

### `POST /api/v1/login`

Authenticates a user and returns access & refresh tokens.

**Example Request:**

```bash
curl -X POST http://localhost:8080/api/v1/login \
-H "Content-Type: application/json" \
-d '{
  "email": "test@example.com",
  "password": "password123"
}'
```

---

### `POST /api/v1/refresh`

Rotates the refresh token.

**Example Request:**

```bash
curl -X POST http://localhost:8080/api/v1/refresh \
-H "Content-Type: application/json" \
-d '{
  "refresh_token": "your_refresh_token"
}'
```

---

### `DELETE /api/v1/session`

Revokes the provided refresh token.

**Example Request:**

```bash
curl -X DELETE http://localhost:8080/api/v1/session \
-H "Content-Type: application/json" \
-d '{
  "refresh_token": "your_refresh_token"
}'
```

---

### `GET /api/v1/admin/users`

Retrieves a list of all registered users **(Admin only)**.

**Example Request:**

```bash
curl -X GET http://localhost:8080/api/v1/admin/users \
-H "Authorization: Bearer your_admin_access_token"
```

---

### `DELETE /api/v1/admin/user/:id/sessions`

Revokes all active refresh tokens for a specific user **(Admin only)**.

**Example Request:**

```bash
curl -X DELETE http://localhost:8080/api/v1/user/user-id/sessions \
-H "Authorization: Bearer your_admin_access_token"
```

---
### `PATCH /api/v1/admin/user/:id/role`

Updates the role for a specific user **(Admin only)**.

**Example Request:**

```bash
# To update a user to be an admin (role_id = 2)
curl -X PATCH http://localhost:8080/api/v1/admin/user/user-id/role \
-H "Authorization: Bearer your_admin_access_token" \
-H "Content-Type: application/json" \
-d '{
  "role_id": 2
}'
```

---

## Running Tests

Run all tests:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test ./... -coverprofile=coverage.out -covermode=atomic
```

---

## Tech Stack
- **Language:** Go
- **Framework:** Fiber
- **Database:** PostgreSQL (`pgx`)
- **Testing:** Testify, GoMock
- **Migrations:** Manual SQL
- **Config:** Viper

---

## Security Features
- Device fingerprinting, IP, and user-agent tracking
- Refresh token rotation & revocation
- RBAC (user/admin)
- Admin force logout
- Brute-force protection (login rate limiting)


---

## Database Tables
- `users` - Stores user information, including a `role_id` as a foreign key to the `roles` table.
- `roles` - Defines the available user roles, such as `user` and `admin`.
- `refresh_tokens` - Tracks refresh tokens, including device metadata and the token's revocation status.
- `trusted_devices` - Stores information about devices that have been used to log in.
- `login_attempts` - Logs all login attempts for security monitoring.

---

## Upcoming Improvements
1. More admin dashboard features (e.g., viewing specific user sessions).
2. Deployment to a cloud provider like GCP (e.g., Cloud Run, Cloud SQL, Secret Manager).
3. A scheduled job (e.g., Cloud Scheduler) for cleaning up expired tokens from the database.

---

## License
MIT License
