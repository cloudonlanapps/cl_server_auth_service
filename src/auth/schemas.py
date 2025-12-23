from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol, cast, runtime_checkable

from pydantic import BaseModel, field_validator


@runtime_checkable
class PermissionLike(Protocol):
    permission: str


type PermissionsInput = list[str] | Iterable[PermissionLike] | None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
    permissions: list[str] = []
    is_admin: bool = False


# User schemas
class UserBase(BaseModel):
    username: str
    is_admin: bool = False
    is_active: bool = True


class UserCreate(UserBase):
    password: str
    permissions: list[str] = []


class UserUpdate(BaseModel):
    password: str | None = None
    permissions: list[str] | None = None
    is_active: bool | None = None
    is_admin: bool | None = None


class UserResponse(UserBase):
    id: int
    created_at: datetime
    permissions: list[str] = []

    model_config = {"from_attributes": True}  # pyright: ignore[reportUnannotatedClassAttribute]

    @field_validator("permissions", mode="before")
    @classmethod
    def parse_permissions(cls, v: list[str] | None) -> list[str]:
        if v is None:
            return []

            # Either list[str] or list[PermissionLike]
        return [p.permission for p in cast(list[PermissionLike], v)]


class PermissionResponse(BaseModel):
    permission: str

    model_config = {"from_attributes": True}  # pyright: ignore[reportUnannotatedClassAttribute]


class RootResponse(BaseModel):
    message: str
    model_config = {"from_attributes": True}  # pyright: ignore[reportUnannotatedClassAttribute]
