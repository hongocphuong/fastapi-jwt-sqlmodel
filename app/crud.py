
from typing import List, Optional
from sqlmodel import Session, select
from .models import Item, User, RefreshToken
from datetime import datetime
from .core.security import get_password_hash


def create_item(session: Session, name: str, description: Optional[str] = None) -> Item:
    item = Item(name=name, description=description)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def list_items(session: Session) -> List[Item]:
    return session.exec(select(Item)).all()


# --- User CRUD ---
def create_user(session: Session, email: str, password: str) -> User:
    hashed = get_password_hash(password)
    user = User(email=email, hashed_password=hashed)
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


def update_user_password(session: Session, user: User, new_password: str) -> User:
    user.hashed_password = get_password_hash(new_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def delete_user(session: Session, user: User) -> None:
    session.delete(user)
    session.commit()



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
