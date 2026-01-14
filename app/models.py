
from typing import List, Optional
from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime


class UserRoleLink(SQLModel, table=True):
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    role_id: int = Field(foreign_key="role.id", primary_key=True)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    is_superuser: bool = False
    is_active: bool = True
    # Nhiều role gắn vào User qua bảng liên kết
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRoleLink)


class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)   # "admin", "editor", "viewer"
    description: Optional[str] = None

    users: List[User] = Relationship(back_populates="roles", link_model=UserRoleLink)


class Item(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    owner_id: int = Field(foreign_key="user.id")


class RefreshToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    jti: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")
    revoked: bool = False
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

