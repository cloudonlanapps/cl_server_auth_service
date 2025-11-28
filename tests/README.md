# Tests for CL Server Authentication Service

This directory contains the test suite for the authentication microservice. The tests are written using `pytest` and cover authentication flows, user management, and role-based access control (RBAC).

## Prerequisites

Ensure you have Python 3.9+ installed.

### Setting up the Environment

If you don't have a virtual environment set up yet, follow these steps:

1.  **Create a virtual environment:**
    ```bash
    python3 -m venv venv
    ```

2.  **Activate the virtual environment:**
    - On macOS/Linux:
        ```bash
        source venv/bin/activate
        ```
    - On Windows:
        ```bash
        .\venv\Scripts\activate
        ```

3.  **Install dependencies and the package in editable mode:**
    This ensures that the `src` package is available to the tests.
    ```bash
    pip install -e .
    ```
    This command installs the dependencies listed in `pyproject.toml` (including `pytest`, `httpx`, etc.) and installs the current package in editable mode.

## Running Tests

Make sure your virtual environment is activated.

### Run All Tests

To run the entire test suite:

```bash
pytest
```

### Run Specific Test Files

To run tests from a specific file:

```bash
pytest tests/test_auth.py
pytest tests/test_users.py
pytest tests/test_rbac.py
```

### Run Individual Tests

To run a specific test function:

```bash
pytest tests/test_users.py::test_create_user_as_admin
```

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

The test configuration is defined in `pyproject.toml` under `[tool.pytest.ini_options]`.
- **Test Paths**: `tests`
- **Addopts**: `-v --tb=short` (Verbose output, short traceback)
