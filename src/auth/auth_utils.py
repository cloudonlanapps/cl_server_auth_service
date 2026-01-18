
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Password hashing
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt

from .config import AuthConfig

# Global keys
PRIVATE_KEY: str | None = None
PUBLIC_KEY: str | None = None


def _generate_keys(private_path: Path, public_path: Path) -> tuple[str, str]:
    """Generate ECDSA key pair and save to files."""
    # Ensure key directory exists (lazy creation)
    key_dir = private_path.parent
    key_dir.mkdir(parents=True, exist_ok=True)

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
    with open(private_path, "wb") as f:
        _ = f.write(pem_private)

    with open(public_path, "wb") as f:
        _ = f.write(pem_public)

    return pem_private.decode(), pem_public.decode()



def load_keys(config: AuthConfig) -> None:
    """Load keys from files or generate if missing."""
    global PRIVATE_KEY, PUBLIC_KEY
    
    if not config.private_key_path.exists() or not config.public_key_path.exists():
        PRIVATE_KEY, PUBLIC_KEY = _generate_keys(config.private_key_path, config.public_key_path)
        return

    with open(config.private_key_path, "rb") as f:
        private_key_pem = f.read()

    with open(config.public_key_path, "rb") as f:
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
                PRIVATE_KEY, PUBLIC_KEY = _generate_keys(config.private_key_path, config.public_key_path)
                return
        else:
            print("Warning: Loaded private key does not support public key derivation.")
            PRIVATE_KEY, PUBLIC_KEY = _generate_keys(config.private_key_path, config.public_key_path)
            return

    except Exception as e:
        print(f"Warning: Error verifying key integrity ({e}). Regenerating keys...")
        PRIVATE_KEY, PUBLIC_KEY = _generate_keys(config.private_key_path, config.public_key_path)
        return

    PRIVATE_KEY = private_key_pem.decode()
    PUBLIC_KEY = public_key_pem.decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)


def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode("utf-8")


def create_access_token(
    data: dict[str, object], 
    expires_delta: timedelta,
    algorithm: str
) -> str:
    if PRIVATE_KEY is None:
        raise RuntimeError("Auth keys not loaded")
        
    to_encode = data.copy()
    expire = datetime.now(UTC) + expires_delta

    to_encode.update({"exp": expire})

    # Use the private key for signing
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=algorithm)
    return encoded_jwt


def decode_token(token: str, algorithm: str) -> dict[str, object]:
    if PUBLIC_KEY is None:
        raise RuntimeError("Auth keys not loaded")
    # Use the public key for verification
    return jwt.decode(token, PUBLIC_KEY, algorithms=[algorithm])
