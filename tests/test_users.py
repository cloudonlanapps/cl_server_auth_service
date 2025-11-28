def test_create_user_as_admin(client, admin_token):
    response = client.post(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "newuser",
            "password": "newpassword",
            "permissions": ["read", "write"]
        }
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
        json={
            "username": "newuser",
            "password": "newpassword"
        }
    )
    assert response.status_code == 403

def test_get_users_as_admin(client, admin_token, regular_user):
    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2  # admin + regular_user

def test_update_user_permissions(client, admin_token, regular_user):
    response = client.put(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "permissions": ["new_perm"]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "new_perm" in data["permissions"]

def test_delete_user(client, admin_token, regular_user):
    response = client.delete(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 204
    
    # Verify deleted
    response = client.get(
        f"/users/{regular_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404
