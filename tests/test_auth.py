from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from auth import auth_utils
from auth.models import User
from auth.schemas import Token


class PublicKeyResponse(BaseModel):
    """Schema for public key endpoint response."""

    public_key: str
    algorithm: str


class RootResponse(BaseModel):
    """Schema for root endpoint response."""

    message: str


def test_login_success(client: TestClient, regular_user: User) -> None:
    _ = regular_user
    response = client.post("/auth/token", data={"username": "user", "password": "password"})
    assert response.status_code == 200
    try:
        data = Token.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as Token: {e}") from e
    assert data.access_token
    assert data.token_type == "bearer"


def test_login_failure(client: TestClient) -> None:
    response = client.post("/auth/token", data={"username": "wrong", "password": "wrong"})
    assert response.status_code == 401


def test_get_public_key(client: TestClient) -> None:
    response = client.get("/auth/public-key")
    assert response.status_code == 200
    try:
        data = PublicKeyResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as PublicKeyResponse: {e}") from e
    assert data.public_key
    assert data.algorithm == "ES256"


def test_token_contains_permissions(client: TestClient, db_session: Session, regular_user: User) -> None:
    # Add permission to user using set_permissions_list
    regular_user.set_permissions_list(["read", "write"])
    db_session.commit()

    # Login
    response = client.post("/auth/token", data={"username": "user", "password": "password"})
    try:
        token_data = Token.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as Token: {e}") from e

    # Decode token
    payload = auth_utils.decode_token(token_data.access_token, algorithm="ES256")
    assert "permissions" in payload
    permissions = payload["permissions"]
    assert isinstance(permissions, list)
    assert "read" in permissions
    assert "write" in permissions


def test_root(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    try:
        data = RootResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as RootResponse: {e}") from e
    assert data.message == "authentication service is running"
