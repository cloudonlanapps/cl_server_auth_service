from fastapi.testclient import TestClient
from pydantic import BaseModel, TypeAdapter, ValidationError

from auth.models import User
from auth.schemas import UserResponse


class ErrorResponse(BaseModel):
    """Schema for error response."""

    detail: str


def test_create_user_as_admin(client: TestClient, admin_token: str) -> None:
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "username": "newuser",
            "password": "newpassword",
            "permissions": "read, write",  # Comma-separated for Form parsing
        },
    )
    assert response.status_code == 201
    try:
        data = UserResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
    assert data.username == "newuser"
    assert "read" in data.permissions
    assert "write" in data.permissions


def test_create_user_as_regular_user(client: TestClient, user_token: str) -> None:
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"},
        data={"username": "newuser", "password": "newpassword"},
    )
    assert response.status_code == 403


def test_get_users_as_admin(client: TestClient, admin_token: str, regular_user: User) -> None:
    _ = regular_user
    response = client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    try:
        adapter = TypeAdapter(list[UserResponse])
        data = adapter.validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as list[UserResponse]: {e}") from e
    assert len(data) >= 2  # admin + regular_user


def test_update_user_permissions(client: TestClient, admin_token: str, regular_user: User) -> None:
    response = client.put(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={"permissions": "new_perm"},
    )
    assert response.status_code == 200
    try:
        data = UserResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
    assert "new_perm" in data.permissions


def test_delete_user(client: TestClient, admin_token: str, regular_user: User) -> None:
    response = client.delete(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 204

    # Verify deleted
    response = client.get(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404


def test_read_users_me(client: TestClient, regular_user: User, user_token: str) -> None:
    response = client.get("/users/me", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200
    try:
        data = UserResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
    assert data.username == regular_user.username
    assert data.id == regular_user.id


def test_read_user_by_id(client: TestClient, admin_token: str, regular_user: User) -> None:
    response = client.get(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    try:
        data = UserResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
    assert data.username == regular_user.username


def test_update_user_fields(client: TestClient, admin_token: str, regular_user: User) -> None:
    # Test updating is_active and is_admin
    response = client.put(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={"is_active": "false", "is_admin": "true"},
    )
    assert response.status_code == 200
    try:
        data = UserResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as UserResponse: {e}") from e
    assert data.is_active is False
    assert data.is_admin is True


def test_create_duplicate_user(client: TestClient, admin_token: str, regular_user: User) -> None:
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={"username": regular_user.username, "password": "somepassword"},
    )
    assert response.status_code == 400
    try:
        error = ErrorResponse.model_validate_json(response.text)
    except ValidationError as e:
        raise AssertionError(f"Failed to parse response as ErrorResponse: {e}") from e
    assert "Username already registered" in error.detail


def test_delete_non_existent_user(client: TestClient, admin_token: str) -> None:
    response = client.delete("/users/99999", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 404


def test_update_non_existent_user(client: TestClient, admin_token: str) -> None:
    response = client.put(
        "/users/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={"is_active": "false"},
    )
    assert response.status_code == 404
