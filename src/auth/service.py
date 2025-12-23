from __future__ import annotations

from sqlalchemy.orm import Session

from .auth_utils import get_password_hash
from .models import User
from .schemas import UserCreate, UserUpdate


class UserService:
    def __init__(self, db: Session):
        self.db: Session = db

    def get_user(self, user_id: int) -> User | None:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_user_by_id(self, user_id: int) -> User | None:
        """Alias for get_user for consistency with get_user_by_username."""
        return self.get_user(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        return self.db.query(User).filter(User.username == username).first()

    def get_users(self, skip: int = 0, limit: int = 100) -> list[User]:
        return self.db.query(User).offset(skip).limit(limit).all()

    def create_user(self, user: UserCreate) -> User:
        hashed_password = get_password_hash(user.password)
        db_user = User(
            username=user.username,
            hashed_password=hashed_password,
            is_admin=user.is_admin,
            is_active=user.is_active,
        )
        # Set permissions using helper method
        db_user.set_permissions_list(user.permissions)

        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)

        return db_user

    def update_user(self, user_id: int, user_update: UserUpdate) -> User | None:
        db_user = self.get_user(user_id)
        if not db_user:
            return None

        if user_update.password:
            db_user.hashed_password = get_password_hash(user_update.password)

        if user_update.is_active is not None:
            db_user.is_active = user_update.is_active

        if user_update.is_admin is not None:
            db_user.is_admin = user_update.is_admin

        if user_update.permissions is not None:
            db_user.set_permissions_list(user_update.permissions)

        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def delete_user(self, user_id: int) -> bool:
        db_user = self.get_user(user_id)
        if not db_user:
            return False

        self.db.delete(db_user)
        self.db.commit()
        return True
