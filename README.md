# Porto Auth Service

A robust, modular authentication service for the Porto application ecosystem, built in Go using Fiber. This service handles user registration, login, refresh token rotation, secure device tracking, session metadata logging, and role-based access control.

---

## Features

- ✅ JWT-based authentication (access + refresh tokens)
- 🔁 Refresh token rotation with metadata validation
- 👤 Role-based access control (admin, user via `roles` table)
- 🧠 Trusted device tracking and upsert logic
- 🕵️‍♂️ Login attempt logging
- 🔐 Token revocation on refresh (logout coming soon)
- 🌍 Environment-based config via Viper
- 🗃️ PostgreSQL database using `pgx`
- 🧪 Test-driven development (TDD) and Clean Architecture

---

## API Endpoints

### `POST /api/v1/register`
Registers a new user with role `user`.

### `POST /api/v1/login`
Authenticates a user and returns access & refresh tokens.
- Access token includes `user_id`, `email`, and `role`

### `POST /api/v1/refresh`
Rotates the refresh token after validating metadata.
- Re-fetches user role for new access token

---

## Tech Stack
- **Language:** Go
- **Framework:** Fiber
- **Database:** PostgreSQL (accessed via `pgx`)
- **Migration Tool:** Manual SQL
- **Config:** Viper

---

## Security Features
- Device fingerprint, IP address, and user agent tracking
- Enforced refresh token expiry and active token limit
- Role-based access control using `roles` table (`user`, `admin`)
- Refresh token revocation and re-issuance with fingerprint match

---

## Environment Variables
```
PORT=8080
DB_URL=postgres://user:pass@localhost:5432/porto_auth
ACCESS_TOKEN_SECRET=...
REFRESH_TOKEN_SECRET=...
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_MINUTES=10080  # 7 days
```

---

## Database Tables
- `users` – includes `role_id` (FK to `roles`)
- `roles` – defines available roles like `user`, `admin`
- `refresh_tokens` – tracks device metadata + token state
- `trusted_devices`
- `login_attempts`

---

## Upcoming Improvements
1. Implement `/api/v1/logout` endpoint to revoke refresh tokens securely
2. Add `RequireRole()` middleware for protected admin routes
3. Brute-force protection per IP/user (via middleware and login attempt tracking)
4. Admin endpoints for user/session management (e.g. list users, revoke sessions)
5. Integration test suite and CI pipeline
6. Deployment to GCP (Cloud Run / Cloud SQL / Secret Manager etc.)

---

## Architecture Notes

This project follows Clean Architecture principles adapted for Go. Folder structure is organized as:

- `domain/` — Core business entities and interfaces (e.g. `User`, `UserRepository`)
- `service/` — Application logic (use cases)
- `repository/` — Infrastructure layer, with PostgreSQL-specific implementation
- `handler/` — HTTP delivery layer, built using Fiber
- `dto/` — Data Transfer Objects for request/response (kept separate to avoid leaking transport logic into domain)

This separation ensures that business logic remains framework-agnostic and testable. DTOs are intentionally **not** placed inside the domain layer.

---

## License
MIT License
