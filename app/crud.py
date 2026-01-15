from typing import Optional, List
from datetime import datetime, timedelta
from uuid import uuid4
from sqlmodel import Session, select
from app.models import (
    User, Item, RefreshToken,
    Role, UserRoleLink, EmailToken, PasswordResetToken,
)
from app.core.security import get_password_hash

# ===== Users =====
def get_user_by_email(session: Session, email: str) -> Optional[User]:
    return session.exec(select(User).where(User.email == email)).first()

def create_user(session: Session, email: str, password: str, *,
                full_name: Optional[str] = None,
                is_superuser: bool = False, is_active: bool = True) -> User:
    user = User(email=email, hashed_password=get_password_hash(password),
                full_name=full_name, is_superuser=is_superuser, is_active=is_active)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def update_user(session: Session, user: User, *,
                full_name: Optional[str] = None,
                is_active: Optional[bool] = None,
                is_superuser: Optional[bool] = None) -> User:
    if full_name is not None:
        user.full_name = full_name
    if is_active is not None:
        user.is_active = is_active
    if is_superuser is not None:
        user.is_superuser = is_superuser
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def list_users(session: Session, *, q: Optional[str] = None, skip: int = 0, limit: int = 20) -> List[User]:
    stmt = select(User)
    if q:
        q_like = f"%{q}%"
        stmt = stmt.where((User.email.ilike(q_like)) | (User.full_name.ilike(q_like)))
    stmt = stmt.offset(skip).limit(limit)
    return session.exec(stmt).all()

# ===== Items =====
def create_item(session: Session, owner_id: int, name: str, description: Optional[str] = None) -> Item:
    item = Item(name=name, description=description, owner_id=owner_id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item

def list_items(session: Session, owner_id: int) -> List[Item]:
    return session.exec(select(Item).where(Item.owner_id == owner_id)).all()


def list_items_all(session: Session) -> List[Item]:
    return session.exec(select(Item)).all()

# ===== Refresh Tokens =====
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

# ===== Roles =====
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
        select(UserRoleLink).where(UserRoleLink.user_id == user_id, UserRoleLink.role_id == role.id)
    ).first()
    if not link_exists:
        session.add(UserRoleLink(user_id=user_id, role_id=role.id))
        session.commit()
    roles = session.exec(select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)).all()
    return roles

def remove_role_from_user(session: Session, user_id: int, role_name: str) -> List[Role]:
    role = get_role_by_name(session, role_name)
    if not role:
        return []
    link = session.exec(
        select(UserRoleLink).where(UserRoleLink.user_id == user_id, UserRoleLink.role_id == role.id)
    ).first()
    if link:
        session.delete(link)
        session.commit()
    roles = session.exec(select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)).all()
    return roles

def get_user_roles(session: Session, user_id: int) -> List[Role]:
    return session.exec(select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id)).all()

# ===== Email & Password Reset Tokens =====
def create_email_token(session: Session, user_id: int, purpose: str, *, ttl_minutes: int = 60) -> EmailToken:
    token = str(uuid4())
    exp = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    et = EmailToken(token=token, user_id=user_id, purpose=purpose, expires_at=exp)
    session.add(et)
    session.commit()
    session.refresh(et)
    return et

def mark_email_token_used(session: Session, token: str) -> Optional[EmailToken]:
    et = session.exec(select(EmailToken).where(EmailToken.token == token)).first()
    if et:
        et.used = True
        session.add(et)
        session.commit()
    return et

def get_valid_email_token(session: Session, token: str, purpose: str) -> Optional[EmailToken]:
    et = session.exec(select(EmailToken).where(EmailToken.token == token, EmailToken.purpose == purpose)).first()
    if not et or et.used or et.expires_at < datetime.utcnow():
        return None
    return et

def create_password_reset_token(session: Session, user_id: int, *, ttl_minutes: int = 30) -> PasswordResetToken:
    token = str(uuid4())
    exp = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    prt = PasswordResetToken(token=token, user_id=user_id, expires_at=exp)
    session.add(prt)
    session.commit()
    session.refresh(prt)
    return prt

def consume_password_reset_token(session: Session, token: str) -> Optional[PasswordResetToken]:
    prt = session.exec(select(PasswordResetToken).where(PasswordResetToken.token == token)).first()
    if prt and (not prt.used) and prt.expires_at >= datetime.utcnow():
        prt.used = True
        session.add(prt)
        session.commit()
        session.refresh(prt)
        return prt
    return None
