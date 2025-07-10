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

---

## API Endpoints

### `POST /api/v1/register`
Registers a new user with role `user`. Returns user ID and email.

### `POST /api/v1/login`
Authenticates a user and returns access & refresh tokens.
- The access token payload includes the user_id, email, and role. 
- This endpoint automatically logs the login attempt and upserts the device as a trusted device.

### `POST /api/v1/refresh`
Rotates the refresh token after validating metadata.
- The process includes validation of the device fingerprint, IP address, and token expiration.
- It revokes the old token and issues a new pair of access and refresh tokens.

### `DELETE /api/v1/session`
Revokes the provided refresh token, effectively logging the user out from that session.

### `DELETE /api/v1/user/:id/sessions`
This is an ***admin-only*** endpoint that revokes all active refresh tokens for a specific user, logging them out of all devices.

---

## Tech Stack
- **Language:** Go
- **Framework:** Fiber
- **Database:** PostgreSQL (accessed via `pgx`)
- **Testing:** Testify, Gomock
- **Migration Tool:** Manual SQL
- **Config:** Viper

---

## Security Features
- Device Fingerprint and Metadata Tracking: The service tracks the device fingerprint, IP address, and user agent for each session.
- Token Expiry and Revocation: Enforces refresh token expiry and ensures that tokens are revoked upon refresh and logout.
- Role-Based Access Control: Utilizes a roles table (user, admin) to manage user permissions.
- Secure Token Re-issuance: Matches the device fingerprint to prevent unauthorized token re-issuance.
- Session Invalidation: Provides a mechanism for admins to forcefully log out a user from all active sessions.

---

## Environment Variables
```env
PORT=8080
DB_URL=postgres://user:pass@localhost:5432/porto_auth
ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_EXPIRY=15
REFRESH_TOKEN_EXPIRY=10080  # 7 days
```

---

## Database Tables
- `users` – Stores user information, including a `role_id` as a foreign key to the `roles` table.
- `roles` – Defines the available user roles, such as `user` and `admin`.
- `refresh_tokens` – Tracks refresh tokens, including device metadata and the token's revocation status.
- `trusted_devices` - Stores information about devices that have been used to log in.
- `login_attempts` - Logs all login attempts for security monitoring.

---

## Upcoming Improvements
1. Admin endpoints for user/session management (e.g. list users, revoke sessions)
2. Deployment to a cloud provider like GCP (e.g., Cloud Run, Cloud SQL, Secret Manager).
3. A scheduled job (e.g., Cloud Scheduler) for cleaning up expired tokens from the database.

---

## Architecture Notes

This project follows Clean Architecture principles adapted for Go. The folder structure is organized as follows:

- `domain/` — Contains the core business entities and interfaces (e.g., `User`, `UserRepository`).
- `service/` — Implements the application's business logic (use cases).
- `repository/` — The infrastructure layer, with a PostgreSQL-specific implementation.
- `handler/` — The HTTP delivery layer, built using the Fiber framework.
- `dto/` — Data Transfer Objects (DTOs) for handling request and response data, keeping the transport layer separate from the domain.

This separation ensures that business logic remains framework-agnostic and testable. DTOs are intentionally **not** placed inside the domain layer.

---

## License
MIT License
