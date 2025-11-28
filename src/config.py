from __future__ import annotations

import os
from pathlib import Path

# CL_SERVER_DIR is required - root directory for all persistent data
CL_SERVER_DIR = os.getenv("CL_SERVER_DIR")
if not CL_SERVER_DIR:
    raise ValueError("CL_SERVER_DIR environment variable must be set")

# Check write permission
if not os.access(CL_SERVER_DIR, os.W_OK):
    raise ValueError(f"CL_SERVER_DIR does not exist or no write permission: {CL_SERVER_DIR}")

# Database configuration
# Derived from CL_SERVER_DIR; can be overridden with DATABASE_URL environment variable
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{CL_SERVER_DIR}/user_auth.db")

# Key paths configuration
# Derived from CL_SERVER_DIR; can be overridden with environment variables
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", f"{CL_SERVER_DIR}/private_key.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH", f"{CL_SERVER_DIR}/public_key.pem")

# Auth configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key_change_in_production")
ALGORITHM = "ES256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Admin configuration
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

__all__ = [
    "CL_SERVER_DIR",
    "DATABASE_URL",
    "PRIVATE_KEY_PATH",
    "PUBLIC_KEY_PATH",
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "ADMIN_USERNAME",
    "ADMIN_PASSWORD"
]
