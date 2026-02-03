import os
from collections.abc import Generator
from pathlib import Path

import pytest
from auth.models import Base
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Import models to register them with Base.metadata
from auth import app
from auth.auth_utils import get_password_hash
from auth.database import get_db
from auth.models import User

@pytest.fixture(scope="session")
def test_engine():
    """Create a session-scoped test database engine."""
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def testing_session_local(test_engine):
    """Create sessionmaker bound to test engine."""
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session(test_engine, testing_session_local) -> Generator[Session, None, None]:
    """Create a fresh database session for each test."""
    Base.metadata.create_all(bind=test_engine)
    session = testing_session_local()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True, scope="function")
def reset_auth_utils():
    """Reset auth_utils module state between tests."""
    from auth import auth_utils
    yield
    # Clear keys after each test
    auth_utils.PRIVATE_KEY = None
    auth_utils.PUBLIC_KEY = None


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with overridden database dependency."""
    from auth.config import AuthConfig
    from auth import auth_utils
    
    # Setup mock config and keys
    artifact_dir = os.getenv("TEST_ARTIFACT_DIR", "/tmp/cl_server_test_artifacts")
    cl_server_dir = Path(artifact_dir) / "auth"
    cl_server_dir.mkdir(parents=True, exist_ok=True)
    
    keys_dir = cl_server_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    config = AuthConfig(
        cl_server_dir=cl_server_dir,
        database_url="sqlite:///:memory:",
        private_key_path=keys_dir / "private.pem",
        public_key_path=keys_dir / "public.pem",
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

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    # Enhanced cleanup
    app.dependency_overrides.clear()
    if hasattr(app, 'state') and hasattr(app.state, 'config'):
        delattr(app.state, 'config')


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
