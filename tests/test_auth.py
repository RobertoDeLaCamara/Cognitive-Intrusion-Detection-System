"""Tests for JWT authentication and RBAC."""

import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.models import Base, User
from src.api.main import app
from src.api.database import get_db
from src.api.auth import (
    hash_password, verify_password, create_token, decode_token,
    is_enabled, authenticate_user,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "securepassword123"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrongpassword", hashed)

    def test_different_hashes_for_same_password(self):
        password = "testpass"
        h1 = hash_password(password)
        h2 = hash_password(password)
        assert h1 != h2  # bcrypt uses random salt


class TestJWTTokens:
    @patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac")
    def test_create_and_decode_token(self):
        token = create_token("testuser", "analyst")
        payload = decode_token(token)
        assert payload["sub"] == "testuser"
        assert payload["role"] == "analyst"

    @patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac")
    def test_expired_token(self):
        import jwt
        payload = {
            "sub": "user",
            "role": "viewer",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        }
        token = jwt.encode(payload, "testsecret_32bytes_long_for_hmac", algorithm="HS256")
        with pytest.raises(Exception) as exc:
            decode_token(token)
        assert "expired" in str(exc.value.detail).lower()

    @patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac")
    def test_invalid_token(self):
        with pytest.raises(Exception) as exc:
            decode_token("invalid.token.here")
        assert "Invalid" in str(exc.value.detail)


class TestIsEnabled:
    @patch("src.api.auth.JWT_SECRET", "")
    def test_disabled_when_no_secret(self):
        assert not is_enabled()

    @patch("src.api.auth.JWT_SECRET", "somesecret_32bytes_long_for_hmac")
    def test_enabled_when_secret_set(self):
        assert is_enabled()


@pytest_asyncio.fixture(loop_scope="function")
async def auth_test_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="function")
async def auth_test_session(auth_test_engine):
    async_session = async_sessionmaker(auth_test_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture(loop_scope="function")
async def auth_client(auth_test_engine):
    async_session = async_sessionmaker(auth_test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with patch("src.api.main.init_db", new_callable=AsyncMock):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_authenticate_user_success(auth_test_session):
    user = User(
        username="testuser",
        password_hash=hash_password("testpass"),
        role="analyst",
    )
    auth_test_session.add(user)
    await auth_test_session.commit()

    result = await authenticate_user(auth_test_session, "testuser", "testpass")
    assert result is not None
    assert result.username == "testuser"


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password(auth_test_session):
    user = User(
        username="testuser2",
        password_hash=hash_password("correctpass"),
        role="viewer",
    )
    auth_test_session.add(user)
    await auth_test_session.commit()

    result = await authenticate_user(auth_test_session, "testuser2", "wrongpass")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_user_not_found(auth_test_session):
    result = await authenticate_user(auth_test_session, "nonexistent", "anypass")
    assert result is None


@pytest.mark.asyncio
async def test_login_endpoint_success(auth_client, auth_test_session):
    with patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac"):
        user = User(
            username="loginuser",
            password_hash=hash_password("loginpass"),
            role="analyst",
        )
        auth_test_session.add(user)
        await auth_test_session.commit()

        resp = await auth_client.post("/api/auth/token", json={
            "username": "loginuser",
            "password": "loginpass",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_endpoint_invalid_credentials(auth_client):
    with patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac"):
        resp = await auth_client.post("/api/auth/token", json={
            "username": "nobody",
            "password": "wrongpass",
        })
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_endpoint_jwt_disabled(auth_client):
    with patch("src.api.auth.JWT_SECRET", ""):
        resp = await auth_client.post("/api/auth/token", json={
            "username": "user",
            "password": "pass",
        })
        assert resp.status_code == 501


@pytest.mark.asyncio
async def test_user_management_requires_admin(auth_client, auth_test_session):
    with patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac"):
        # Create admin user
        admin = User(username="admin", password_hash=hash_password("adminpass"), role="admin")
        auth_test_session.add(admin)
        await auth_test_session.commit()

        # Get admin token
        resp = await auth_client.post("/api/auth/token", json={"username": "admin", "password": "adminpass"})
        token = resp.json()["access_token"]

        # Create user as admin
        resp = await auth_client.post(
            "/api/auth/users",
            json={"username": "newuser", "password": "newpass", "role": "viewer"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "newuser"

        # List users
        resp = await auth_client.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_viewer_cannot_create_users(auth_client, auth_test_session):
    with patch("src.api.auth.JWT_SECRET", "testsecret_32bytes_long_for_hmac"):
        viewer = User(username="viewer", password_hash=hash_password("viewerpass"), role="viewer")
        auth_test_session.add(viewer)
        await auth_test_session.commit()

        resp = await auth_client.post("/api/auth/token", json={"username": "viewer", "password": "viewerpass"})
        token = resp.json()["access_token"]

        resp = await auth_client.post(
            "/api/auth/users",
            json={"username": "hacker", "password": "hack", "role": "admin"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
