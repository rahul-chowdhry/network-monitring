from datetime import datetime, timedelta, timezone

import hashlib
import hmac
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import AdminUser


security = HTTPBearer(auto_error=False)


# =========================
# Password Hashing
# =========================

def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.

    Format:
        pbkdf2_sha256$iterations$salt$hash
    """

    if not password:
        raise ValueError("Password cannot be empty")

    iterations = 310_000
    salt = secrets.token_hex(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )

    password_hash = derived_key.hex()

    return f"pbkdf2_sha256${iterations}${salt}${password_hash}"


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against a stored PBKDF2 hash.
    """

    try:
        algorithm, iterations, salt, stored_hash = password_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )

        calculated_hash = derived_key.hex()

        return hmac.compare_digest(
            calculated_hash,
            stored_hash,
        )

    except (ValueError, TypeError):
        return False


# =========================
# Simple Local Token System
# =========================

def _token_digest(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# In-memory token store.
#
# This is intentionally local-only and suitable for the initial
# development stage. Tokens disappear when the backend restarts.
_active_tokens: dict[str, dict] = {}


def create_access_token(
    user_id: int,
    username: str,
) -> str:
    """
    Create a random local access token.

    No external authentication service is used.
    """

    token = secrets.token_urlsafe(48)

    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=12
    )

    _active_tokens[_token_digest(token)] = {
        "user_id": user_id,
        "username": username,
        "expires_at": expires_at,
    }

    return token


def revoke_access_token(token: str) -> None:
    """
    Revoke a currently active token.
    """

    _active_tokens.pop(
        _token_digest(token),
        None,
    )


def get_token_payload(token: str) -> dict | None:
    """
    Return token information if valid and not expired.
    """

    token_hash = _token_digest(token)

    payload = _active_tokens.get(token_hash)

    if payload is None:
        return None

    expires_at = payload.get("expires_at")

    if not isinstance(expires_at, datetime):
        _active_tokens.pop(token_hash, None)
        return None

    if datetime.now(timezone.utc) >= expires_at:
        _active_tokens.pop(token_hash, None)
        return None

    return payload


# =========================
# Database User Helpers
# =========================

def get_user_by_username(
    db: Session,
    username: str,
) -> AdminUser | None:
    statement = select(AdminUser).where(
        AdminUser.username == username
    )

    return db.scalar(statement)


def authenticate_user(
    db: Session,
    username: str,
    password: str,
) -> AdminUser | None:
    """
    Authenticate an active admin user.
    """

    user = get_user_by_username(
        db,
        username,
    )

    if user is None:
        return None

    if not user.is_active:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


# =========================
# FastAPI Authentication
# =========================

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> AdminUser:
    """
    FastAPI dependency for protected API routes.
    """

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = get_token_payload(
        credentials.credentials
    )

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("user_id")

    if not isinstance(user_id, int):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(
        AdminUser,
        user_id,
    )

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# =========================
# Local Development Helper
# =========================

def ensure_development_admin(
    db: Session,
    username: str = "admin",
    password: str = "admin12345",
) -> AdminUser:
    """
    Create a development admin only if no admin users exist.

    This helper is intended for local development.
    Production credentials should be configured separately.
    """

    existing_user = db.scalar(
        select(AdminUser).limit(1)
    )

    if existing_user is not None:
        return existing_user

    user = AdminUser(
        username=username,
        password_hash=hash_password(password),
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user