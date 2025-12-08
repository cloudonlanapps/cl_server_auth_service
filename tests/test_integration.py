"""Integration tests that verify FastAPI dependency injection works correctly.

These tests use the REAL get_db() function without overrides to ensure
the production dependency injection path works correctly.

Key difference from other tests:
- Other tests override get_db() with a test implementation
- These tests configure the database via environment variables
- This ensures the ACTUAL get_db() function is tested
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import os
from fastapi.testclient import TestClient


@pytest.fixture(scope="function")
def integration_app():
    """Create app with in-memory database but WITHOUT overriding get_db().

    This ensures we test the real dependency injection path.
    The critical difference: we set DATABASE_URL before importing,
    rather than overriding dependencies after import.
    """
    # Set database URL BEFORE importing app
    # This is critical - the app must be configured before import
    os.environ["AUTH_DATABASE_URL"] = "sqlite:///:memory:"

    # Import app AFTER setting environment variable
    # This ensures the app uses our in-memory database
    from src import app
    from src.database import engine, Base

    # Create tables
    Base.metadata.create_all(bind=engine)

    yield app

    # Cleanup
    Base.metadata.drop_all(bind=engine)
    # Clean up environment
    if "AUTH_DATABASE_URL" in os.environ:
        del os.environ["AUTH_DATABASE_URL"]


@pytest.fixture(scope="function")
def integration_client(integration_app):
    """Test client with NO dependency overrides.

    This is the key to testing the real dependency injection.
    Unlike the standard test client, we don't override get_db().
    """
    with TestClient(integration_app) as client:
        yield client


class TestDependencyInjection:
    """Tests that verify get_db() properly yields a database session."""

    def test_get_db_yields_session_not_generator(self, integration_client):
        """Critical: Verify get_db() yields a Session, not a generator object.

        This test would FAIL with the broken 'return get_db_session()' code
        because FastAPI would inject a generator object instead of a Session.

        With the fixed 'yield from get_db_session()' code, FastAPI properly
        recognizes the generator and injects the yielded Session object.

        If get_db() is broken, this will return 500 with:
        AttributeError: 'generator' object has no attribute 'query'
        """
        # Create admin user first (directly via database to bootstrap)
        from src.database import SessionLocal
        from src.models import User
        from src.auth_utils import get_password_hash

        db = SessionLocal()
        admin = User(
            username="testadmin",
            hashed_password=get_password_hash("testpass"),
            is_admin=True,
            is_active=True
        )
        db.add(admin)
        db.commit()
        db.close()

        # Now test login endpoint
        # This will fail if get_db() returns generator object
        response = integration_client.post(
            "/auth/token",
            data={"username": "testadmin", "password": "testpass"}
        )

        # If get_db() is broken, this will return 500
        assert response.status_code == 200, f"Login failed: {response.json()}"
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"

    def test_root_endpoint_works(self, integration_client):
        """Test root endpoint with real dependency injection."""
        response = integration_client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "authentication service is running"}

    def test_public_key_endpoint_works(self, integration_client):
        """Test public key endpoint with real dependency injection."""
        response = integration_client.get("/auth/public-key")
        assert response.status_code == 200
        assert "public_key" in response.json()
        assert isinstance(response.json()["public_key"], str)
        assert len(response.json()["public_key"]) > 0


class TestAuthenticatedEndpoints:
    """Tests for endpoints that require authentication."""

    def test_authenticated_endpoint_with_real_dependency(self, integration_client):
        """Test authenticated endpoints use real get_db() dependency.

        This test creates a user, logs in, and then accesses an
        authenticated endpoint. All of these operations go through
        the real get_db() function.
        """
        # Create and login as admin
        from src.database import SessionLocal
        from src.models import User
        from src.auth_utils import get_password_hash

        db = SessionLocal()
        admin = User(
            username="admin2",
            hashed_password=get_password_hash("adminpass"),
            is_admin=True,
            is_active=True
        )
        db.add(admin)
        db.commit()
        db.close()

        # Login
        response = integration_client.post(
            "/auth/token",
            data={"username": "admin2", "password": "adminpass"}
        )
        assert response.status_code == 200
        token = response.json()["access_token"]

        # Use authenticated endpoint - will fail if get_db() broken
        response = integration_client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == "admin2"
        assert response.json()["is_admin"] is True

    def test_user_creation_with_real_dependency(self, integration_client):
        """Test user creation endpoint with real get_db()."""
        # Create admin user
        from src.database import SessionLocal
        from src.models import User
        from src.auth_utils import get_password_hash

        db = SessionLocal()
        admin = User(
            username="admin3",
            hashed_password=get_password_hash("adminpass"),
            is_admin=True,
            is_active=True
        )
        db.add(admin)
        db.commit()
        db.close()

        # Login as admin
        response = integration_client.post(
            "/auth/token",
            data={"username": "admin3", "password": "adminpass"}
        )
        token = response.json()["access_token"]

        # Create new user via API
        response = integration_client.post(
            "/users/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "newuser",
                "password": "newpass",
                "is_admin": False,
                "is_active": True
            }
        )
        assert response.status_code == 201  # 201 Created is correct for POST
        assert response.json()["username"] == "newuser"

    def test_invalid_credentials_handled_correctly(self, integration_client):
        """Test that invalid credentials are rejected properly."""
        response = integration_client.post(
            "/auth/token",
            data={"username": "nonexistent", "password": "wrongpass"}
        )
        assert response.status_code == 401
        assert "detail" in response.json()


class TestMultipleSequentialRequests:
    """Test that database sessions are properly managed across requests."""

    def test_multiple_login_requests_work(self, integration_client):
        """Verify sessions are properly created and cleaned up."""
        # Create test user
        from src.database import SessionLocal
        from src.models import User
        from src.auth_utils import get_password_hash

        db = SessionLocal()
        user = User(
            username="multitest",
            hashed_password=get_password_hash("testpass"),
            is_admin=False,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.close()

        # Make multiple requests
        for i in range(5):
            response = integration_client.post(
                "/auth/token",
                data={"username": "multitest", "password": "testpass"}
            )
            assert response.status_code == 200
            assert "access_token" in response.json()
