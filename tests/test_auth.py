from auth import auth_utils


def test_login_success(client, regular_user):
    response = client.post("/auth/token", data={"username": "user", "password": "password"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_failure(client):
    response = client.post("/auth/token", data={"username": "wrong", "password": "wrong"})
    assert response.status_code == 401


def test_get_public_key(client):
    response = client.get("/auth/public-key")
    assert response.status_code == 200
    data = response.json()
    assert "public_key" in data
    assert "algorithm" in data
    assert data["algorithm"] == "ES256"


def test_token_contains_permissions(client, db_session, regular_user):
    # Add permission to user using set_permissions_list
    regular_user.set_permissions_list(["read", "write"])
    db_session.commit()

    # Login
    response = client.post("/auth/token", data={"username": "user", "password": "password"})
    token = response.json()["access_token"]

    # Decode token
    payload = auth_utils.decode_token(token)
    assert "permissions" in payload
    assert "read" in payload["permissions"]
    assert "write" in payload["permissions"]


def test_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "authentication service is running"}
