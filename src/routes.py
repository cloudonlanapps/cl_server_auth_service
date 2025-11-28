from __future__ import annotations

from datetime import timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import auth_utils, database, schemas, service
from .database import get_db
from .config import ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth_utils.decode_token(token)
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)  # Convert string ID back to integer
    except Exception:
        raise credentials_exception

    user_service = service.UserService(db)
    user = user_service.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user


def get_current_admin_user(current_user=Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


@router.post("/auth/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user_service = service.UserService(db)
    user = user_service.get_user_by_username(form_data.username)

    if not user or not auth_utils.verify_password(
        form_data.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create permissions list
    permissions = [p.permission for p in user.permissions]

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Generate JWT token with user ID (not username) for uniqueness
    access_token = auth_utils.create_access_token(
        data={
            "sub": str(user.id),
            "permissions": permissions,
            "is_admin": user.is_admin,
        },
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/auth/public-key")
async def get_public_key():
    """Return the public key for verifying tokens."""
    return {"public_key": auth_utils.PUBLIC_KEY, "algorithm": auth_utils.ALGORITHM}


@router.get("/users/me", response_model=schemas.UserResponse)
async def read_users_me(current_user=Depends(get_current_user)):
    return current_user


# Admin routes
@router.post(
    "/users/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED
)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_admin_user),
):
    user_service = service.UserService(db)
    db_user = user_service.get_user_by_username(user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return user_service.create_user(user=user)


@router.get("/users/", response_model=List[schemas.UserResponse])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_admin_user),
):
    user_service = service.UserService(db)
    users = user_service.get_users(skip=skip, limit=limit)
    return users


@router.get("/users/{user_id}", response_model=schemas.UserResponse)
def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_admin_user),
):
    user_service = service.UserService(db)
    db_user = user_service.get_user(user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_admin_user),
):
    user_service = service.UserService(db)
    db_user = user_service.update_user(user_id=user_id, user_update=user_update)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_admin_user),
):
    user_service = service.UserService(db)
    success = user_service.delete_user(user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return None


@router.get(
    "/",
    summary="Root",
    description="Returns a simple welcome string",
    response_model=schemas.RootResponse,
    operation_id="root_get",
)
async def root():
    return schemas.RootResponse(message="authentication service is running")
