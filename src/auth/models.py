from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """Base class for Auth service models."""
    pass
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column


class User(Base):
    __tablename__ = "users"  # pyright: ignore[reportUnannotatedClassAttribute]

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    permissions: Mapped[str] = mapped_column(String, default="", nullable=False)

    def get_permissions_list(self) -> list[str]:
        """Parse comma-separated permissions string into list."""
        if not self.permissions:
            return []
        return [p.strip() for p in self.permissions.split(",") if p.strip()]

    def set_permissions_list(self, permissions: list[str]) -> None:
        """Convert permissions list to comma-separated string."""
        self.permissions = ",".join(permissions) if permissions else ""
