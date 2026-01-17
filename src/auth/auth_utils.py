from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

# Password hashing
import bcrypt
from cl_server_shared import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt


def _generate_keys() -> tuple[str, str]:
    """Generate ECDSA key pair and save to files."""
    from pathlib import Path

    # Ensure key directory exists (lazy creation)
    key_dir = os.path.dirname(Config.PRIVATE_KEY_PATH)
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
    with open(Config.PRIVATE_KEY_PATH, "wb") as f:
        _ = f.write(pem_private)

    with open(Config.PUBLIC_KEY_PATH, "wb") as f:
        _ = f.write(pem_public)

    return pem_private.decode(), pem_public.decode()


def get_keys() -> tuple[str, str]:
    """Load keys from files or generate if missing."""
    if not os.path.exists(Config.PRIVATE_KEY_PATH) or not os.path.exists(Config.PUBLIC_KEY_PATH):
        return _generate_keys()

    with open(Config.PRIVATE_KEY_PATH, "rb") as f:
        private_key_pem = f.read()

    with open(Config.PUBLIC_KEY_PATH, "rb") as f:
        public_key_pem = f.read()

    try:
        # Verify integrity: ensure the public key matches the private key
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        # Derive expected public key from the private key
        if hasattr(private_key, "public_key"):
            derived_pub_key = private_key.public_key()
            derived_pub_pem = derived_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            if derived_pub_pem.strip() != public_key_pem.strip():
                print("Warning: Key pair mismatch detected. Regenerating keys...")
                return _generate_keys()
        else:
            print("Warning: Loaded private key does not support public key derivation.")
            return _generate_keys()

    except Exception as e:
        print(f"Warning: Error verifying key integrity ({e}). Regenerating keys...")
        return _generate_keys()

    return private_key_pem.decode(), public_key_pem.decode()


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


def create_access_token(data: dict[str, object], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Use the private key for signing
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=Config.ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> dict[str, object]:
    # Use the public key for verification
    return jwt.decode(token, PUBLIC_KEY, algorithms=[Config.ALGORITHM])
