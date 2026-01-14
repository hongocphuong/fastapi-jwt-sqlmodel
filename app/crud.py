
from typing import List, Optional
from sqlmodel import Session, select
from .models import Item, User, RefreshToken,Role, UserRoleLink
from datetime import datetime
from .core.security import get_password_hash


def create_item(session: Session, name: str, description: Optional[str] = None, owner_id: int = None) -> Item:
    item = Item(name=name, description=description, owner_id=owner_id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def list_items(session: Session, owner_id: int) -> List[Item]:
    return session.exec(select(Item).where(Item.owner_id == owner_id)).all()

def list_items_all(session: Session) -> List[Item]:
    return session.exec(select(Item)).all()

def get_item(session: Session, item_id: int) -> Optional[Item]:
    return session.get(Item, item_id)

def delete_item(session: Session, item: Item) -> None:
    session.delete(item)
    session.commit()

def update_item(session: Session, item: Item, *, name: Optional[str] = None, description: Optional[str] = None) -> Item:
    if name is not None:
        item.name = name
    if description is not None:
        item.description = description

    session.add(item)
    session.commit()
    session.refresh(item)
    return item

# --- User CRUD ---

def create_user(session: Session, email: str, password: str, *,
                is_superuser: bool = False, is_active: bool = True) -> User:
    user = User(
        email=email,
        hashed_password=get_password_hash(password),
        is_superuser=is_superuser,
        is_active=is_active,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def get_user_by_email(session: Session, email: str) -> Optional[User]:
    return session.exec(select(User).where(User.email == email)).first()


def get_user(session: Session, user_id: int) -> Optional[User]:
    return session.get(User, user_id)


def list_users(session: Session) -> List[User]:
    return session.exec(select(User)).all()


def set_user_flags(session: Session, user: User, *,
                   is_superuser: Optional[bool] = None,
                   is_active: Optional[bool] = None) -> User:
    if is_superuser is not None:
        user.is_superuser = is_superuser
    if is_active is not None:
        user.is_active = is_active
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def update_user_password(session: Session, user: User, new_password: str) -> User:
    user.hashed_password = get_password_hash(new_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def delete_user(session: Session, user: User) -> None:
    session.delete(user)
    session.commit()


# --- Roles ---
def create_role(session: Session, name: str, description: Optional[str] = None) -> Role:
    role = session.exec(select(Role).where(Role.name == name)).first()
    if role:
        return role
    role = Role(name=name, description=description)
    session.add(role)
    session.commit()
    session.refresh(role)
    return role

def list_roles(session: Session) -> List[Role]:
    return session.exec(select(Role)).all()

def get_role_by_name(session: Session, name: str) -> Optional[Role]:
    return session.exec(select(Role).where(Role.name == name)).first()

def assign_role_to_user(session: Session, user_id: int, role_name: str) -> List[Role]:
    user = session.get(User, user_id)
    if not user:
        raise ValueError("User not found")
    role = get_role_by_name(session, role_name) or create_role(session, role_name)
    link_exists = session.exec(
        select(UserRoleLink).where(
            UserRoleLink.user_id == user_id, UserRoleLink.role_id == role.id
        )
    ).first()
    if not link_exists:
        session.add(UserRoleLink(user_id=user_id, role_id=role.id))
        session.commit()
    # Trả về danh sách role sau khi gán
    roles = session.exec(
        select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)
    ).all()
    return roles

def remove_role_from_user(session: Session, user_id: int, role_name: str) -> List[Role]:
    role = get_role_by_name(session, role_name)
    if not role:
        return []
    link = session.exec(
        select(UserRoleLink).where(
            UserRoleLink.user_id == user_id, UserRoleLink.role_id == role.id
        )
    ).first()
    if link:
        session.delete(link)
        session.commit()
    roles = session.exec(
        select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)
    ).all()
    return roles

def get_user_roles(session: Session, user_id: int) -> List[Role]:
    return session.exec(
        select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)
    ).all()


# --- Refresh Tokens ---
def create_refresh_token_record(session: Session, user_id: int, jti: str, expires_at: datetime) -> RefreshToken:
    rt = RefreshToken(user_id=user_id, jti=jti, expires_at=expires_at)
    session.add(rt)
    session.commit()
    session.refresh(rt)
    return rt

def revoke_refresh_token(session: Session, jti: str) -> None:
    rt = session.exec(select(RefreshToken).where(RefreshToken.jti == jti)).first()
    if rt and not rt.revoked:
        rt.revoked = True
        session.add(rt)
        session.commit()

def is_refresh_token_revoked(session: Session, jti: str) -> bool:
    rt = session.exec(select(RefreshToken).where(RefreshToken.jti == jti)).first()
    return (rt is None) or rt.revoked or (rt.expires_at < datetime.utcnow())
