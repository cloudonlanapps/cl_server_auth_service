# Tests for CL Server Authentication Service

This directory contains the test suite for the authentication microservice. The tests are written using `pytest` and cover authentication flows, user management, and role-based access control (RBAC).

## Overview & Structure

The test suite is organized into two categories:

- **Unit tests** (`test_*.py`) — Test individual components with in-memory SQLite databases and mocked dependencies
- **Integration tests** (`test_integration.py`) — Test end-to-end workflows with full service integration

## Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- Dependencies installed via `uv sync`

**Note:** With uv, you don't need to manually create or activate virtual environments. Use `uv run` to execute commands in the automatically managed environment.

## Running Tests

### Run All Tests

To run the entire test suite with coverage:

```bash
uv run pytest
```

**Coverage requirement:** 90% (configured in `pyproject.toml`)

### Run Specific Test Files

To run tests from a specific file:

```bash
uv run pytest tests/test_auth.py -v
uv run pytest tests/test_users.py -v
uv run pytest tests/test_rbac.py -v
```

### Run Individual Tests

To run a specific test function:

```bash
uv run pytest tests/test_users.py::test_create_user_as_admin -v
```

### Coverage Options

**Default behavior:** Coverage is automatically collected with HTML + terminal reports and requires ≥90% coverage.

```bash
# Run tests with coverage (generates htmlcov/ directory + terminal report)
uv run pytest

# Skip coverage for quick testing
uv run pytest --no-cov

# Override coverage threshold (e.g., for debugging)
uv run pytest --cov-fail-under=0
```

Coverage reports are saved to `htmlcov/index.html` - open this file in a browser to view detailed coverage.

## Test Structure

The tests are organized into the following files:

| File | Description |
|------|-------------|
| `tests/test_auth.py` | Tests for authentication endpoints (login, public key, root) and token validation. |
| `tests/test_users.py` | Tests for user management (CRUD operations) and basic permissions. |
| `tests/test_rbac.py` | Tests for Role-Based Access Control, ensuring regular users cannot access admin endpoints. |
| `tests/test_anonymous.py` | Tests for anonymous access, ensuring unauthenticated users cannot access protected endpoints. |
| `tests/conftest.py` | Pytest fixtures for database sessions, test client, and user creation. |

## Configuration

The test configuration is defined in `pyproject.toml` under `[tool.pytest.ini_options]`:
- **Test Paths**: `tests`
- **Coverage**: Automatically enabled with HTML + terminal reports
- **Coverage Threshold**: 90% minimum (tests fail if below)
- **Verbose Output**: Enabled by default

## Quick Reference

For a quick command reference, see [QUICK.md](QUICK.md)
