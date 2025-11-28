from __future__ import annotations

from typing import List, Optional
from sqlalchemy.orm import Session

from . import models, schemas, auth_utils

class UserService:
    def __init__(self, db: Session):
        self.db = db

    def get_user(self, user_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.id == user_id).first()
    
    def get_user_by_id(self, user_id: int) -> Optional[models.User]:
        """Alias for get_user for consistency with get_user_by_username."""
        return self.get_user(user_id)

    def get_user_by_username(self, username: str) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.username == username).first()

    def get_users(self, skip: int = 0, limit: int = 100) -> List[models.User]:
        return self.db.query(models.User).offset(skip).limit(limit).all()

    def create_user(self, user: schemas.UserCreate) -> models.User:
        hashed_password = auth_utils.get_password_hash(user.password)
        db_user = models.User(
            username=user.username,
            hashed_password=hashed_password,
            is_admin=user.is_admin,
            is_active=user.is_active
        )
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)

        # Add permissions
        if user.permissions:
            for perm in user.permissions:
                db_perm = models.UserPermission(user_id=db_user.id, permission=perm)
                self.db.add(db_perm)
            self.db.commit()
            self.db.refresh(db_user)
            
        return db_user
    
    def update_user(self, user_id: int, user_update: schemas.UserUpdate) -> Optional[models.User]:
        db_user = self.get_user(user_id)
        if not db_user:
            return None
            
        if user_update.password:
            db_user.hashed_password = auth_utils.get_password_hash(user_update.password)
            
        if user_update.is_active is not None:
            db_user.is_active = user_update.is_active
            
        if user_update.is_admin is not None:
            db_user.is_admin = user_update.is_admin
            
        if user_update.permissions is not None:
            # Remove existing permissions
            self.db.query(models.UserPermission).filter(models.UserPermission.user_id == user_id).delete()
            # Add new permissions
            for perm in user_update.permissions:
                db_perm = models.UserPermission(user_id=user_id, permission=perm)
                self.db.add(db_perm)
                
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
