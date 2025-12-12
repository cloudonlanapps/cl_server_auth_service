from __future__ import annotations

from datetime import datetime
from typing import List

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from cl_server_shared.models import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    permissions = relationship(
        "UserPermission", back_populates="user", cascade="all, delete-orphan"
    )


class UserPermission(Base):
    __tablename__ = "user_permissions"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    permission = Column(String, primary_key=True)

    user = relationship("User", back_populates="permissions")
