from fastapi.testclient import TestClient

from auth.models import User


def test_regular_user_cannot_create_user(client: TestClient, user_token: str) -> None:
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"username": "newuser", "password": "newpassword"},
    )
    assert response.status_code == 403


def test_regular_user_cannot_list_users(client: TestClient, user_token: str) -> None:
    response = client.get("/users/", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 403


def test_regular_user_cannot_read_other_user(client: TestClient, user_token: str, admin_user: User) -> None:
    response = client.get(
        f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403


def test_regular_user_cannot_update_other_user(client: TestClient, user_token: str, admin_user: User) -> None:
    response = client.put(
        f"/users/{admin_user.id}",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"is_active": False},
    )
    assert response.status_code == 403


def test_regular_user_cannot_delete_user(client: TestClient, user_token: str, admin_user: User) -> None:
    response = client.delete(
        f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403
