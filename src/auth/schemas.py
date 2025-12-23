from __future__ import annotations

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, field_validator


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    permissions: List[str] = []
    is_admin: bool = False


# User schemas
class UserBase(BaseModel):
    username: str
    is_admin: bool = False
    is_active: bool = True


class UserCreate(UserBase):
    password: str
    permissions: List[str] = []


class UserUpdate(BaseModel):
    password: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None


class UserResponse(UserBase):
    id: int
    created_at: datetime
    permissions: List[str] = []

    model_config = {"from_attributes": True}

    @field_validator("permissions", mode="before")
    @classmethod
    def parse_permissions(cls, v):
        if not v:
            return []
        # Handle SQLAlchemy relationship - it might be a list-like object
        # We check if the first item has a 'permission' attribute
        if hasattr(v, "__iter__") and not isinstance(v, str):
            items = list(v)
            if items and hasattr(items[0], "permission"):
                return [p.permission for p in items]
        return v


class PermissionResponse(BaseModel):
    permission: str

    model_config = {"from_attributes": True}


class RootResponse(BaseModel):
    message: str
