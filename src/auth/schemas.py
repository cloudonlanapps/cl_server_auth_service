from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, field_validator


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
    def parse_permissions(cls, v: str | list[str] | None) -> list[str]:
        """Parse permissions from comma-separated string or list."""
        if v is None or v == "":
            return []
        if isinstance(v, str):
            # Parse comma-separated string
            return [p.strip() for p in v.split(",") if p.strip()]
        # Already a list
        return v


class PermissionResponse(BaseModel):
    permission: str

    model_config = {"from_attributes": True}  # pyright: ignore[reportUnannotatedClassAttribute]


class RootResponse(BaseModel):
    message: str
    model_config = {"from_attributes": True}  # pyright: ignore[reportUnannotatedClassAttribute]
