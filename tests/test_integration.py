"""Integration tests that verify FastAPI dependency injection works correctly.

These tests use the REAL get_db() function without overrides to ensure
the production dependency injection path works correctly.

Key difference from other tests:
- Other tests override get_db() with a test implementation
- These tests configure the database via environment variables
- This ensures the ACTUAL get_db() function is tested
"""
import os
import sys
from collections.abc import Generator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from auth.schemas import Token, UserResponse


class PublicKeyResponse(BaseModel):
    """Schema for public key endpoint response."""

    public_key: str
    algorithm: str


class RootResponse(BaseModel):
    """Schema for root endpoint response."""

    message: str


class ErrorResponse(BaseModel):
    """Schema for error response."""

    detail: str


@pytest.fixture(scope="function")
def integration_app() -> Generator[FastAPI, None, None]:
    """Create app with in-memory database but WITHOUT overriding get_db().

    This ensures we test the real dependency injection path.
    We patch the engine to use a test database, but don't override get_db().
    """
    from unittest.mock import patch

    from auth.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from auth import app, database, auth_utils
    from auth.config import AuthConfig

    artifact_dir = Path(os.getenv("TEST_ARTIFACT_DIR", "/tmp/cl_server_test_artifacts"))
    cl_server_dir = artifact_dir / "auth_integration"
    cl_server_dir.mkdir(parents=True, exist_ok=True)
    
    keys_dir = cl_server_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Mock config and keys
    config = AuthConfig(
        cl_server_dir=cl_server_dir,
        database_url="sqlite:///:memory:",
        private_key_path=keys_dir / "private.pem",
        public_key_path=keys_dir / "public_key.pem",
        admin_username="admin",
        admin_password="admin",
        access_token_expire_minutes=30,
        algorithm="ES256"
    )
    
    # Generate keys for testing
    if auth_utils.PRIVATE_KEY is None:
        auth_utils.PRIVATE_KEY, auth_utils.PUBLIC_KEY = auth_utils._generate_keys(
            config.private_key_path, 
            config.public_key_path
        )
    
    app.state.config = config

    # Create test engine
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Create tables in test database
    Base.metadata.create_all(bind=test_engine)

    # Patch the SessionLocal in database module
    with patch.object(database, "SessionLocal", TestSessionLocal):
        yield app

    # Cleanup
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def integration_client(integration_app: FastAPI) -> Generator[TestClient, None, None]:
    """Test client with NO dependency overrides.

    This is the key to testing the real dependency injection.
    Unlike the standard test client, we don't override get_db().
    """
    with TestClient(integration_app) as client:
        yield client


class TestDependencyInjection:
    """Tests that verify get_db() properly yields a database session."""

    def test_get_db_yields_session_not_generator(self, integration_client: TestClient) -> None:
        """Critical: Verify get_db() yields a Session, not a generator object."""
        # Create admin user first (directly via database to bootstrap)
        from auth.auth_utils import get_password_hash
        from auth import database
        from auth.models import User

        db = database.SessionLocal() # type: ignore
        assert db is not None
        admin = User(
            username="testadmin",
            hashed_password=get_password_hash("testpass"),
            is_admin=True,
            is_active=True,
            permissions="",
        )
        db.add(admin)
        db.commit()
        db.close()

        # Now test login endpoint
        response = integration_client.post(
            "/auth/token", data={"username": "testadmin", "password": "testpass"}
        )

        assert response.status_code == 200, f"Login failed: {response.text}"
        try:
            token = Token.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as Token: {e}") from e
        assert token.access_token
        assert token.token_type == "bearer"

    def test_root_endpoint_works(self, integration_client: TestClient) -> None:
        """Test root endpoint with real dependency injection."""
        response = integration_client.get("/")
        assert response.status_code == 200
        try:
            data = RootResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as RootResponse: {e}") from e
        assert data.message == "authentication service is running"

    def test_public_key_endpoint_works(self, integration_client: TestClient) -> None:
        """Test public key endpoint with real dependency injection."""
        response = integration_client.get("/auth/public-key")
        assert response.status_code == 200
        try:
            data = PublicKeyResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as PublicKeyResponse: {e}") from e
        assert data.public_key
        assert len(data.public_key) > 0


class TestAuthenticatedEndpoints:
    """Tests for endpoints that require authentication."""

    def test_authenticated_endpoint_with_real_dependency(self, integration_client: TestClient) -> None:
        """Test authenticated endpoints use real get_db() dependency."""
        # Create and login as admin
        from auth.auth_utils import get_password_hash
        from auth import database
        from auth.models import User

        db = database.SessionLocal() # type: ignore
        assert db is not None
        admin = User(
            username="admin2",
            hashed_password=get_password_hash("adminpass"),
            is_admin=True,
            is_active=True,
            permissions="",
        )
        db.add(admin)
        db.commit()
        db.close()

        # Login
        response = integration_client.post(
            "/auth/token", data={"username": "admin2", "password": "adminpass"}
        )
        assert response.status_code == 200
        try:
            token_data = Token.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as Token: {e}") from e

        # Use authenticated endpoint - will fail if get_db() broken
        response = integration_client.get(
            "/users/me", headers={"Authorization": f"Bearer {token_data.access_token}"}
        )
        assert response.status_code == 200
        try:
            user = UserResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
        assert user.username == "admin2"
        assert user.is_admin is True

    def test_user_creation_with_real_dependency(self, integration_client: TestClient) -> None:
        """Test user creation endpoint with real get_db()."""
        # Create admin user
        from auth.auth_utils import get_password_hash
        from auth import database
        from auth.models import User

        db = database.SessionLocal() # type: ignore
        assert db is not None
        admin = User(
            username="admin3",
            hashed_password=get_password_hash("adminpass"),
            is_admin=True,
            is_active=True,
            permissions="",
        )
        db.add(admin)
        db.commit()
        db.close()

        # Login as admin
        response = integration_client.post(
            "/auth/token", data={"username": "admin3", "password": "adminpass"}
        )
        try:
            token_data = Token.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as Token: {e}") from e

        # Create new user via API
        response = integration_client.post(
            "/users/",
            headers={"Authorization": f"Bearer {token_data.access_token}"},
            data={
                "username": "newuser",
                "password": "newpass",
                "permissions": "[]",  # Form data expects string
            },
        )
        assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
        try:
            user = UserResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
        assert user.username == "newuser"

    def test_invalid_credentials_handled_correctly(self, integration_client: TestClient) -> None:
        """Test that invalid credentials are rejected properly."""
        response = integration_client.post(
            "/auth/token", data={"username": "nonexistent", "password": "wrongpass"}
        )
        assert response.status_code == 401
        try:
            error = ErrorResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise AssertionError(f"Failed to parse response as ErrorResponse: {e}") from e
        assert error.detail


class TestMultipleSequentialRequests:
    """Test that database sessions are properly managed across requests."""

    def test_multiple_login_requests_work(self, integration_client: TestClient) -> None:
        """Verify sessions are properly created and cleaned up."""
        # Create test user
        from auth.auth_utils import get_password_hash
        from auth import database
        from auth.models import User

        db = database.SessionLocal() # type: ignore
        assert db is not None
        user = User(
            username="multitest",
            hashed_password=get_password_hash("testpass"),
            is_admin=False,
            is_active=True,
            permissions="",
        )
        db.add(user)
        db.commit()
        db.close()

        # Make multiple requests
        for _i in range(5):
            response = integration_client.post(
                "/auth/token", data={"username": "multitest", "password": "testpass"}
            )
            assert response.status_code == 200
            try:
                token = Token.model_validate_json(response.text)
            except ValidationError as e:
                raise AssertionError(f"Failed to parse response as Token: {e}") from e
            assert token.access_token
