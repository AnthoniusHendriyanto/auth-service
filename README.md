# Porto Auth Service
[![codecov](https://codecov.io/github/AnthoniusHendriyanto/auth-service/graph/badge.svg?token=VV3CFWZG5G)](https://codecov.io/github/AnthoniusHendriyanto/auth-service)

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

---

## API Endpoints

### `POST /api/v1/register`
Registers a new user with role `user`. Returns user ID and email.

### `POST /api/v1/login`
Authenticates a user and returns access & refresh tokens.
- Access token includes `user_id`, `email`, and `role`
- Automatically logs login attempt and upserts trusted device

### `POST /api/v1/refresh`
Rotates the refresh token after validating metadata.
- Validates fingerprint, IP, and expiry
- Revokes old token and issues new pair
- Cleans up old tokens if exceeding active limit

### `DELETE /api/v1/session`
Revokes the current refresh token. Useful for user-initiated logout from a device/session.

### `DELETE /api/v1/user/:id/sessions`
Admin-only endpoint to revoke **all refresh tokens** for a given user.
- Used to log out user from all devices

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
- Device fingerprint, IP address, and user agent tracking
- Enforced refresh token expiry and active token limit
- Role-based access control using `roles` table (`user`, `admin`)
- Refresh token revocation and re-issuance with fingerprint match
- Full session wipe via force logout

---

## Environment Variables
```env
PORT=8080
DB_URL=postgres://user:pass@localhost:5432/porto_auth
ACCESS_TOKEN_SECRET=...
REFRESH_TOKEN_SECRET=...
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_MINUTES=10080  # 7 days