from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple

from jose import JWTError, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
)

# Password hashing
import bcrypt


def _generate_keys() -> Tuple[str, str]:
    """Generate ECDSA key pair and save to files."""
    from pathlib import Path

    # Ensure key directory exists (lazy creation)
    key_dir = os.path.dirname(PRIVATE_KEY_PATH)
    Path(key_dir).mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save to files
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(pem_private)

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pem_public)

    return pem_private.decode(), pem_public.decode()


def get_keys() -> Tuple[str, str]:
    """Load keys from files or generate if missing."""
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        return _generate_keys()

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read().decode()

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read().decode()

    return private_key, public_key


# Load keys on module import
PRIVATE_KEY, PUBLIC_KEY = get_keys()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)


def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})

    # Use the private key for signing
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> dict:
    # Use the public key for verification
    return jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
