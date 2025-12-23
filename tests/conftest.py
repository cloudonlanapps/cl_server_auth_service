import sys
from collections.abc import Generator
from pathlib import Path

# Add project root to python path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cl_server_shared.models import Base
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Import models to register them with Base.metadata
from auth import app
from auth.auth_utils import get_password_hash
from auth.database import get_db
from auth.models import User

# Use in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Create a fresh database session for each test."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with overridden database dependency."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(db_session: Session) -> User:
    """Create an admin user."""
    user = User(
        username="admin",
        hashed_password=get_password_hash("admin"),
        is_admin=True,
        is_active=True,
        permissions="",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def regular_user(db_session: Session) -> User:
    """Create a regular user."""
    user = User(
        username="user",
        hashed_password=get_password_hash("password"),
        is_admin=False,
        is_active=True,
        permissions="",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def admin_token(client: TestClient, admin_user: User) -> str:
    """Get access token for admin user."""
    from auth.schemas import Token

    _ = admin_user
    response = client.post("/auth/token", data={"username": "admin", "password": "admin"})
    token = Token.model_validate_json(response.text)
    return token.access_token


@pytest.fixture
def user_token(client: TestClient, regular_user: User) -> str:
    """Get access token for regular user."""
    from auth.schemas import Token

    _ = regular_user
    response = client.post("/auth/token", data={"username": "user", "password": "password"})
    token = Token.model_validate_json(response.text)
    return token.access_token
