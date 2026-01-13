
from sqlmodel import Session
from app.crud import create_user

LOGIN_URL = "/api/v1/login"
REFRESH_URL = "/api/v1/refresh"
LOGOUT_URL = "/api/v1/logout"
ITEMS_URL = "/api/v1/items"

EMAIL = "test@example.com"
PASSWORD = "2345678"

def test_login_refresh_rotation_and_reuse_fail(client, db_session: Session):
    # Seed user
    create_user(db_session, email=EMAIL, password=PASSWORD)

    # 1) Login
    resp = client.post(LOGIN_URL, data={"username": EMAIL, "password": PASSWORD})
    assert resp.status_code == 200
    data = resp.json()
    access = data["access_token"]
    refresh = data["refresh_token"]

    # 2) Gọi endpoint bảo vệ bằng access
    r = client.get(ITEMS_URL, headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200

    # 3) Refresh → rotation (revoke refresh cũ)
    r = client.post(REFRESH_URL, json={"refresh_token": refresh})
    assert r.status_code == 200
    new_tokens = r.json()
    new_access = new_tokens["access_token"]
    new_refresh = new_tokens["refresh_token"]
    assert new_access != access
    assert new_refresh != refresh

    # 4) Reuse refresh cũ → phải fail (401)
    r = client.post(REFRESH_URL, json={"refresh_token": refresh})
    assert r.status_code == 401
    assert "revoked" in r.json().get("detail", "").lower() or "expired" in r.json().get("detail", "").lower()

    # 5) Access mới vẫn OK
    r = client.get(ITEMS_URL, headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 200

    # 6) Logout (revoke refresh mới)
    r = client.post(LOGOUT_URL, json={"refresh_token": new_refresh})
    assert r.status_code == 200

    # 7) Reuse refresh đã revoke → fail 401
    r = client.post(REFRESH_URL, json={"refresh_token": new_refresh})
    assert r.status_code == 401

def test_refresh_with_invalid_token_should_fail(client, db_session: Session):
    create_user(db_session, email=EMAIL, password=PASSWORD)
    r = client.post(REFRESH_URL, json={"refresh_token": "invalid.token.format"})
    assert r.status_code in (400, 401)
