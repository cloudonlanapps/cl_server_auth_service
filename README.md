# CL Server Authentication Service

A lightweight JWT-based authentication microservice built with FastAPI. This service handles user authentication, token generation, and role-based access control for the CL Server ecosystem.

**Server Port:** 8000 (default, configurable)
**Authentication Method:** JWT with ES256 (ECDSA) signature
**Package Manager:** uv
**Database:** SQLite with WAL mode

> **For Developers:** See [INTERNALS.md](INTERNALS.md) for package structure, development workflow, and contribution guidelines.
>
> **For Testing:** See [tests/README.md](tests/README.md) for comprehensive testing guide, test organization, and coverage requirements.

## Quick Start

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- Set `CL_SERVER_DIR` environment variable

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Set required environment variable
export CL_SERVER_DIR=~/.data/cl_server_data
```

### Installation

**Individual Package Installation:**

```bash
# Navigate to the auth service directory
cd services/auth

# Install dependencies (uv will create .venv automatically)
uv sync

# Run database migrations
uv run alembic upgrade head
```

**Workspace Installation (All Packages):**

See root [README.md](../../README.md) for installing all packages using `./install.sh`.

### Starting the Server

```bash
# Development mode (with auto-reload)
uv run auth-server --reload

# Production mode
uv run auth-server --port 8000

# Custom configuration
uv run auth-server --host 0.0.0.0 --port 8080 --log-level debug
```

The service will:
1. Create default admin user on first startup (credentials from env vars)
2. Start the FastAPI server
3. Be accessible at `http://localhost:8000`

### Available Commands

```bash
uv run auth-server --help      # Show all options
uv run pytest                  # Run tests
uv run alembic upgrade head    # Run migrations
uv run alembic revision --autogenerate -m "description"  # Create migration
```

## CLI Commands & Usage

The service provides one CLI command for starting the authentication server.

**Note:** `CL_SERVER_DIR` environment variable is required for database and key storage location.

### Command: auth-server

Starts the FastAPI server for JWT authentication and user management.

```bash
# Basic usage (development mode with auto-reload)
uv run auth-server --reload

# Production mode
uv run auth-server

# Custom configuration
uv run auth-server --host 0.0.0.0 --port 8080 --log-level debug --admin-username admin --admin-password secretpass
```

**Available Options:**
- `--host HOST` - Host to bind to (default: `0.0.0.0`)
- `--port PORT` - Port to bind to (default: `8000`)
- `--reload` - Enable auto-reload for development
- `--log-level LEVEL` - Log level: critical, error, warning, info, debug, trace (default: `info`)
- `--private-key-path PATH` - Path to ECDSA private key for signing tokens
- `--public-key-path PATH` - Path to ECDSA public key for verifying tokens
- `--admin-username USERNAME` - Default admin username (default: `admin`)
- `--admin-password PASSWORD` - Default admin password (default: `admin`)
- `--token-expire-minutes MINUTES` - JWT token lifetime in minutes (default: `30`)

**Example:**
```bash
uv run auth-server --host 0.0.0.0 --port 8000 --reload --log-level info
```

**Startup Behavior:**
1. Creates `$CL_SERVER_DIR` if it doesn't exist
2. Generates ECDSA key pair (`private_key.pem`, `public_key.pem`) if not present in `$CL_SERVER_DIR`
3. Runs database migrations automatically
4. Creates default admin user on first startup (credentials from CLI arguments or defaults)
5. Starts the FastAPI server

## API Endpoints

All endpoints return JSON responses. The service runs on port 8000.

### Public Endpoints (No Authentication Required)

#### 1. Health Check
```
GET /
```

**Response:**
```json
{
  "message": "authentication service is running"
}
```

**Example:**
```bash
curl http://localhost:8000/
```

---

#### 2. Generate Token (Login)
```
POST /auth/token
```

**Request Body (form data):**
```
username: string
password: string
```

**Response (201):**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Status Codes:**
- `200 OK` - Token generated successfully
- `401 Unauthorized` - Invalid username or password
- `422 Unprocessable Entity` - Missing or invalid request format

**Example:**
```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"
```

---

#### 2.1 Refresh Token
```
POST /auth/token/refresh
```

Refreshes the access token for the current authenticated user.

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Status Codes:**
- `200 OK` - Token refreshed successfully
- `401 Unauthorized` - Missing or invalid token

**Example:**
```bash
curl -X POST http://localhost:8000/auth/token/refresh \
  -H "Authorization: Bearer $TOKEN"
```

---

#### 3. Get Public Key
```
GET /auth/public-key
```

Returns the public key for verifying tokens issued by this service. Used by other services to validate JWT tokens.

**Response (200):**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
  "algorithm": "ES256"
}
```

**Example:**
```bash
curl http://localhost:8000/auth/public-key
```

---

### Protected Endpoints (Require Valid JWT Token)

Include the token in the `Authorization` header:
```
Authorization: Bearer <token>
```

#### 4. Get Current User Info
```
GET /users/me
```

**Response (200):**
```json
{
  "id": 1,
  "username": "admin",
  "is_admin": true,
  "is_active": true,
  "created_at": "2024-01-15T10:30:00",
  "permissions": ["*"]
}
```

**Status Codes:**
- `200 OK` - User info retrieved
- `401 Unauthorized` - Missing or invalid token

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/users/me
```

---

### Admin Endpoints (Require Valid Token + Admin Privilege)

#### 5. Create User
```
POST /users/
```

**Request Body (form data):**
```
username=newuser
password=securepassword
permissions=[read:posts, write:posts]
```

**Or via curl:**
```bash
curl -X POST http://localhost:8000/users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=newuser&password=securepassword&permissions=[read:posts, write:posts]"
```

**Response (201):**
```json
{
  "id": 2,
  "username": "newuser",
  "is_admin": false,
  "is_active": true,
  "created_at": "2024-01-15T10:35:00",
  "permissions": ["read:posts", "write:posts"]
}
```

**Status Codes:**
- `201 Created` - User created successfully
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - User lacks admin privilege
- `422 Unprocessable Entity` - Invalid request format

**Note:** The endpoint expects form data, not JSON.

---

#### 6. List Users
```
GET /users/?skip=0&limit=100
```

**Query Parameters:**
- `skip` (optional, default: 0) - Number of users to skip
- `limit` (optional, default: 100) - Max users to return

**Response (200):**
```json
[
  {
    "id": 1,
    "username": "admin",
    "is_admin": true,
    "is_active": true,
    "created_at": "2024-01-15T10:30:00",
    "permissions": ["*"]
  },
  {
    "id": 2,
    "username": "newuser",
    "is_admin": false,
    "is_active": true,
    "created_at": "2024-01-15T10:35:00",
    "permissions": ["read:posts"]
  }
]
```

**Status Codes:**
- `200 OK` - Users retrieved
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - User lacks admin privilege

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/users/?skip=0&limit=50"
```

---

#### 7. Get User by ID
```
GET /users/{user_id}
```

**Response (200):**
```json
{
  "id": 2,
  "username": "newuser",
  "is_admin": false,
  "is_active": true,
  "created_at": "2024-01-15T10:35:00",
  "permissions": ["read:posts"]
}
```

**Status Codes:**
- `200 OK` - User found
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - User lacks admin privilege
- `404 Not Found` - User does not exist

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/users/2
```

---

#### 8. Update User
```
PUT /users/{user_id}
```

**Request Body (form data, all fields optional):**
- `password`: string
- `permissions`: string (comma-separated, e.g., "read:posts,write:posts")
- `is_active`: boolean
- `is_admin`: boolean

**Response (200):**
```json
{
  "id": 2,
  "username": "newuser",
  "is_admin": false,
  "is_active": true,
  "created_at": "2024-01-15T10:35:00",
  "permissions": ["read:posts", "write:posts"]
}
```

**Status Codes:**
- `200 OK` - User updated
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - User lacks admin privilege
- `404 Not Found` - User does not exist

**Example:**
```bash
curl -X PUT http://localhost:8000/users/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "permissions=read:posts,write:posts,admin:users"
```

---

#### 9. Delete User
```
DELETE /users/{user_id}
```

**Response (204):**
No content returned on success

**Status Codes:**
- `204 No Content` - User deleted
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - User lacks admin privilege
- `404 Not Found` - User does not exist

**Example:**
```bash
curl -X DELETE http://localhost:8000/users/2 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Authentication Flow

### Step 1: Obtain a Token

Send credentials to the login endpoint:

```bash
TOKEN=$(curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  | jq -r '.access_token')

echo $TOKEN
```

### Step 2: Use Token for Authenticated Requests

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/users/me
```

### Step 3: Token Verification (For Other Services)

Other services can verify tokens using the public key:

```bash
curl http://localhost:8000/auth/public-key > public_key.pem
```

Then use the public key to verify JWT signatures with ES256 algorithm.

### Token Details

- **Format:** JWT (JSON Web Token)
- **Algorithm:** ES256 (ECDSA with SHA-256)
- **Lifetime:** Configurable via `ACCESS_TOKEN_EXPIRE_MINUTES` (default: 30 minutes)
- **Expiration:** Get a new token by re-authenticating when expired

## Error Handling

All error responses include a JSON body with error details.

### HTTP Status Codes

| Status | Meaning | When It Occurs |
|--------|---------|-----------------|
| `400 Bad Request` | Invalid request format | Malformed JSON or missing required fields |
| `401 Unauthorized` | Missing or invalid authentication | No token provided, expired token, invalid credentials |
| `403 Forbidden` | Valid token but insufficient permissions | User lacks admin privilege for admin endpoints |
| `404 Not Found` | Resource does not exist | User ID doesn't exist, invalid endpoint |
| `422 Unprocessable Entity` | Invalid request data | Invalid field values, constraint violations |
| `500 Internal Server Error` | Server-side error | Unexpected server error |

### Example Error Responses

**Missing Authentication (401):**
```json
{
  "detail": "Not authenticated"
}
```

**Insufficient Permissions (403):**
```json
{
  "detail": "Not enough permissions"
}
```

**User Not Found (404):**
```json
{
  "detail": "User not found"
}
```

**Invalid Request (422):**
```json
{
  "detail": [
    {
      "loc": ["body", "username"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

### Client Error Handling

Implement these checks in your client:

1. **Check for 401 errors** - Token may have expired. Re-authenticate and obtain a new token.
2. **Check for 403 errors** - User doesn't have required permissions. Verify user role and permissions.
3. **Check for 404 errors** - Resource doesn't exist. Verify user ID or resource exists before operating on it.
4. **Handle 422 errors** - Validate request format and required fields match the documentation.
5. **Retry on 500 errors** - Implement exponential backoff for temporary server errors.

## Troubleshooting

### Port Already in Use

If you see "Address already in use":

```bash
# Find process using the port
lsof -i :8000

# Kill the process (if safe to do so)
kill -9 <PID>

# Or start on a different port
uv run auth-server --port 8080
```

### Missing CL_SERVER_DIR

If the service fails to start:

```bash
# Check if CL_SERVER_DIR is set
echo $CL_SERVER_DIR

# Set it if missing
export CL_SERVER_DIR=~/.data/cl_server_data

# Ensure directory exists
mkdir -p $CL_SERVER_DIR

# Then run the server again
uv run auth-server --reload
```

### Import Errors

If you see import errors:

```bash
# Reinstall dependencies
uv sync

# Or reinstall in editable mode
uv pip install -e .
```

### Test Failures

If tests fail:

```bash
# Ensure database migrations are current
uv run alembic upgrade head

# Run tests with verbose output
uv run pytest -v

# Check if any files are missing from folder restructure
# Ensure all imports use: from auth.* (not from src.*)
```

### Authentication Failures (401/403)

**Issue:** Getting "Not authenticated" errors

**Solutions:**
- Verify token is included in `Authorization: Bearer <token>` header
- Check that token hasn't expired (default 30 min lifetime)
- Get a new token by logging in again
- Verify credentials are correct

**Issue:** Getting "Not enough permissions" (403)

**Solutions:**
- Verify user has admin privilege for admin-only endpoints
- Check user permissions using `GET /users/me`
- Ask an admin to update user permissions

### Token Expiration

Tokens expire after `ACCESS_TOKEN_EXPIRE_MINUTES` (default: 30 minutes).

**To handle expiration:**
1. Cache the token expiration time from the JWT
2. When near expiration, proactively get a new token
3. If you get a 401 error, assume token expired and re-authenticate
4. Implement token refresh in your client startup

### Database Errors

If you see SQLite errors:

```bash
# Check if another instance is running
ps aux | grep auth-server

# Run migrations
uv run alembic upgrade head

# Or delete database to recreate (⚠️ loses all data)
rm $CL_SERVER_DIR/user_auth.db
uv run alembic upgrade head
uv run auth-server --reload
```

### uv Command Not Found

If `uv` is not found:

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or use pip
pip install uv

# Verify installation
uv --version
```

### Keys Not Found

If you see errors about missing `private_key.pem` or `public_key.pem`:

These files are automatically generated on first startup in `$CL_SERVER_DIR`. If missing:

1. Verify `CL_SERVER_DIR` is set and directory exists
2. Ensure directory has write permissions
3. Check logs in `$CL_SERVER_DIR/run_logs`
4. Delete existing keys to regenerate: `rm $CL_SERVER_DIR/*.pem`
5. Restart the server: `uv run auth-server --reload`

## Documentation

- **[INTERNALS.md](./INTERNALS.md)** - Developer documentation, architecture, contributing guide
- **[tests/README.md](./tests/README.md)** - Testing guide with fixtures and patterns
- **[Architecture Overview](../../docs/ARCHITECTURE.md)** - System-wide architecture and inter-service communication

## Integration Example

Here's a complete example of a Python client integrating with this service:

```python
import requests
import json

# Configuration
AUTH_SERVER = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "admin"

# Step 1: Get token
response = requests.post(
    f"{AUTH_SERVER}/auth/token",
    data={"username": USERNAME, "password": PASSWORD}
)
response.raise_for_status()
token = response.json()["access_token"]

# Step 2: Use token for authenticated requests
headers = {"Authorization": f"Bearer {token}"}

# Get current user
user_response = requests.get(
    f"{AUTH_SERVER}/users/me",
    headers=headers
)
print("Current user:", user_response.json())

# Create new user (admin only)
new_user = {
    "username": "testuser",
    "password": "testpass123",
    "is_admin": False,
    "permissions": ["read:data"]
}
create_response = requests.post(
    f"{AUTH_SERVER}/users/",
    json=new_user,
    headers=headers
)
print("Created user:", create_response.json())

# Handle token expiration
try:
    response = requests.get(f"{AUTH_SERVER}/users/me", headers=headers)
    response.raise_for_status()
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 401:
        # Token expired, get new one
        print("Token expired, re-authenticating...")
        response = requests.post(
            f"{AUTH_SERVER}/auth/token",
            data={"username": USERNAME, "password": PASSWORD}
        )
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
```

## License

MIT License - see [LICENSE](./LICENSE) file for details.

