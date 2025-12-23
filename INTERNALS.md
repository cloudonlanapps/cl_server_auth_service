# Authentication Service - Internal Documentation

This document contains development-related information for contributors working on the authentication service.

## Package Structure

```
services/auth/
├── src/auth/              # Main application package
│   ├── __init__.py        # FastAPI app with lifespan
│   ├── main.py            # CLI entry point (auth-server command)
│   ├── models.py          # SQLAlchemy models (uses shared Base)
│   ├── schemas.py         # Pydantic schemas
│   ├── routes.py          # API endpoints
│   ├── service.py         # Business logic
│   ├── auth_utils.py      # JWT utilities
│   └── database.py        # Database configuration
├── tests/                 # Test suite
│   ├── conftest.py        # Pytest fixtures
│   ├── test_auth.py       # Authentication tests
│   ├── test_users.py      # User management tests
│   ├── test_rbac.py       # RBAC tests
│   └── test_integration.py # Integration tests
├── alembic/               # Database migrations
│   ├── versions/          # Migration scripts
│   └── env.py            # Alembic configuration
├── pyproject.toml         # Package configuration
└── README.md             # User documentation
```

**Key Design:**
- Uses shared `Base` class from `cl-server-shared.models`
- Single worker (SQLite with WAL mode)
- ES256 JWT tokens with auto-generated keys
- Alembic for database migrations

## Development

### Running Tests

See [tests/README.md](tests/README.md) for detailed information on running tests, coverage options, and test structure.

**Quick commands:**
```bash
# Run all tests (coverage automatic: HTML + terminal reports, 90% required)
uv run pytest

# Run specific test file
uv run pytest tests/test_auth.py -v

# Skip coverage for quick testing
uv run pytest --no-cov
```

**Coverage:** Automatically enabled via `pyproject.toml` - generates `htmlcov/` directory + terminal report, requires ≥90%

### Database Migrations

```bash
# Create a new migration
uv run alembic revision --autogenerate -m "Add user permissions"

# Apply migrations
uv run alembic upgrade head

# Rollback one migration
uv run alembic downgrade -1

# Check current version
uv run alembic current
```

### Code Quality

```bash
# Format code
uv run ruff format src/

# Lint code
uv run ruff check src/

# Fix linting issues
uv run ruff check --fix src/
```

### Development Workflow

1. **Make changes** to code in `src/auth/`
2. **Run tests** to ensure everything works: `uv run pytest`
3. **Create migration** if models changed: `uv run alembic revision --autogenerate -m "description"`
4. **Test the server** with auto-reload: `uv run auth-server --reload`
5. **Commit** your changes

### Adding Dependencies

```bash
# Add a new dependency
uv add package-name

# Add a development dependency
uv add --dev package-name

# Update all dependencies
uv sync --upgrade
```

## Future Enhancements

### Account State & Access Control
- The `is_active` flag is currently not used during the login flow (`login_for_access_token`) or anywhere else. Determine whether this field should restrict authentication attempts. Client applications may require APIs to modify this flag, though it currently has no functional effect.

### Security & Token Management
- Assess whether the `GET /auth/public-key` endpoint can be removed. Ideally, clients should not need to extract or inspect bearer tokens, improving overall security posture.

### User Self-Service Features
- Implement an endpoint that allows users to change their own passwords securely.

### Permissions System
- Permissions such as `["read:posts", "write:posts"]` need standardized definitions from upstream services. The authentication service should treat permissions as opaque strings—store and retrieve only, without validation.
- Verify if there is an existing endpoint that allows users to retrieve their own permissions. Add one if missing.

### Login Security & Abuse Prevention
- Introduce rate limiting for failed login attempts. Track failed attempts per user and, after *N* consecutive failures, temporarily lock the account (e.g., for 24 hours) or require an admin-initiated password reset.

### Administrative Capabilities
 - Add admin-focused APIs or a simple dashboard for managing users, roles, and permissions.

### Password Policy
- Enforce a minimal password policy (minimum length and basic complexity).

### Audit Logging
- Record key authentication and account events and provide a secure way to retrieve audit logs.

## Architecture Notes

### Database Design
- Uses SQLite with WAL mode for concurrent read access
- Shared `Base` class from `cl-server-shared` package ensures consistency across services
- Alembic migrations track schema changes

### JWT Token Strategy
- ES256 (ECDSA with SHA-256) provides better security than HS256
- Private key stays on auth service, public key shared with other services
- Keys auto-generated on first startup if not present

### Service Integration
- Auth service runs independently on port 8000
- Other services fetch public key from `/auth/public-key` endpoint
- Tokens are stateless - no session storage required
- Token expiration handled client-side with re-authentication

## Testing Strategy

Tests are organized by functionality:
- `test_auth.py` - Token generation and validation
- `test_users.py` - User CRUD operations
- `test_rbac.py` - Role-based access control
- `test_anonymous.py` - Unauthenticated access protection
- `test_integration.py` - End-to-end workflows

All tests use in-memory SQLite databases and isolated test clients.

## Contributing

When contributing to this service:
1. Maintain 90%+ test coverage
2. Run linter and formatter before committing
3. Create migrations for any model changes
4. Update API documentation in README.md for user-facing changes
5. Add entries to Future Enhancements section for planned features
