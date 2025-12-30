from __future__ import annotations

import json
from datetime import timedelta
from typing import cast

from cl_server_shared import Config
from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .auth_utils import PUBLIC_KEY, create_access_token, decode_token, verify_password
from .database import get_db
from .models import User
from .schemas import RootResponse, Token, UserCreate, UserResponse, UserUpdate
from .service import UserService

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        user_id_str: str | None = cast(str | None, payload.get("id"))
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)  # Convert string ID back to integer
    except Exception:
        raise credentials_exception

    user_service = UserService(db)
    user = user_service.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user


def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


@router.post("/auth/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user_service = UserService(db)
    user = user_service.get_user_by_username(form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create permissions list from comma-separated string
    permissions = user.get_permissions_list()

    access_token_expires = timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    # Generate JWT token with user ID (not username) for uniqueness
    access_token = create_access_token(
        data={
            "id": str(user.id),
            "permissions": permissions,
            "is_admin": user.is_admin,
        },
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/auth/token/refresh", response_model=Token)
async def refresh_access_token(current_user: User = Depends(get_current_user)):
    """Refresh access token for authenticated user."""
    permissions = current_user.get_permissions_list()
    access_token_expires = timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "id": str(current_user.id),
            "permissions": permissions,
            "is_admin": current_user.is_admin,
        },
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/auth/public-key")
async def get_public_key() -> dict[str, object]:
    """Return the public key for verifying tokens."""
    return {"public_key": PUBLIC_KEY, "algorithm": Config.ALGORITHM}


@router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Admin routes
@router.post(
    "/users/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    username: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    is_active: bool = Form(True),
    permissions: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    _ = current_user
    user_service = UserService(db)

    # Check if exists
    db_user = user_service.get_user_by_username(username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Parse permissions from string to list
    permissions_list: list[str] = []
    if permissions:
        try:
            # Try parsing as JSON array first
            permissions_list = cast(list[str], json.loads(permissions))
        except (json.JSONDecodeError, ValueError):
            # Handle Dart's List.toString() format: [item1, item2]
            # Remove brackets and split by comma
            cleaned = permissions.strip()
            if cleaned.startswith("[") and cleaned.endswith("]"):
                cleaned = cleaned[1:-1]  # Remove brackets
                if cleaned:  # Only parse if not empty
                    permissions_list = [p.strip() for p in cleaned.split(",") if p.strip()]
            elif cleaned:
                # Fallback to comma-separated parsing
                permissions_list = [p.strip() for p in cleaned.split(",") if p.strip()]

    # Convert back to Pydantic schema
    user = UserCreate(
        username=username,
        password=password,
        is_admin=is_admin,
        is_active=is_active,
        permissions=permissions_list,
    )

    # Create user using service
    return user_service.create_user(user=user)


@router.get("/users/", response_model=list[UserResponse])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    _ = current_user
    user_service = UserService(db)
    users = user_service.get_users(skip=skip, limit=limit)
    return users


@router.get("/users/{user_id}", response_model=UserResponse)
def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    _ = current_user
    user_service = UserService(db)
    db_user = user_service.get_user(user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    password: str | None = Form(None),
    permissions: str | None = Form(None),
    is_active: bool | None = Form(None),
    is_admin: bool | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    _ = current_user
    user_service = UserService(db)

    # Parse permissions from comma-separated string to list
    permissions_list: list[str] | None = None
    if permissions is not None:
        if permissions:  # Non-empty string
            permissions_list = [p.strip() for p in permissions.split(",") if p.strip()]
        else:  # Empty string means clear permissions
            permissions_list = []

    # Create UserUpdate model
    user_update = UserUpdate(
        password=password,
        permissions=permissions_list,
        is_active=is_active,
        is_admin=is_admin,
    )

    db_user = user_service.update_user(user_id=user_id, user_update=user_update)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    _ = current_user
    user_service = UserService(db)
    success = user_service.delete_user(user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return None


@router.get(
    "/",
    summary="Root",
    description="Returns a simple welcome string",
    response_model=RootResponse,
    operation_id="root_get",
)
async def root():
    return RootResponse(message="authentication service is running")
