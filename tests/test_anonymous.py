def test_anonymous_cannot_access_users_me(client):
    response = client.get("/users/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_anonymous_cannot_list_users(client):
    response = client.get("/users/")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_anonymous_cannot_create_user(client):
    response = client.post("/users/", json={"username": "newuser", "password": "newpassword"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_anonymous_cannot_read_user(client, regular_user):
    response = client.get(f"/users/{regular_user.id}")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_anonymous_cannot_update_user(client, regular_user):
    response = client.put(f"/users/{regular_user.id}", json={"is_active": False})
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_anonymous_cannot_delete_user(client, regular_user):
    response = client.delete(f"/users/{regular_user.id}")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
