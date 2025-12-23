def test_create_user_as_admin(client, admin_token):
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={
            "username": "newuser",
            "password": "newpassword",
            "permissions": "[read, write]",  # Dart List.toString() format
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert "read" in data["permissions"]
    assert "write" in data["permissions"]


def test_create_user_as_regular_user(client, user_token):
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"},
        data={"username": "newuser", "password": "newpassword"},
    )
    assert response.status_code == 403


def test_get_users_as_admin(client, admin_token, regular_user):
    response = client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2  # admin + regular_user


def test_update_user_permissions(client, admin_token, regular_user):
    response = client.put(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"permissions": ["new_perm"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "new_perm" in data["permissions"]


def test_delete_user(client, admin_token, regular_user):
    response = client.delete(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 204

    # Verify deleted
    response = client.get(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404


def test_read_users_me(client, regular_user, user_token):
    response = client.get("/users/me", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == regular_user.username
    assert data["id"] == regular_user.id


def test_read_user_by_id(client, admin_token, regular_user):
    response = client.get(
        f"/users/{regular_user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == regular_user.username


def test_update_user_fields(client, admin_token, regular_user):
    # Test updating is_active and is_admin
    response = client.put(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False, "is_admin": True},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_active"] is False
    assert data["is_admin"] is True


def test_create_duplicate_user(client, admin_token, regular_user):
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        data={"username": regular_user.username, "password": "somepassword"},
    )
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]


def test_delete_non_existent_user(client, admin_token):
    response = client.delete("/users/99999", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 404


def test_update_non_existent_user(client, admin_token):
    response = client.put(
        "/users/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False},
    )
    assert response.status_code == 404
