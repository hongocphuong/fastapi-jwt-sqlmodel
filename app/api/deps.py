from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlmodel import Session, select

from app.db import engine
from app.models import User, Role, UserRoleLink
from app.core.config import settings
from app.core.security import ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

def get_db():
    with Session(engine) as session:
        yield session

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    user = db.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    return current_user

def get_current_superuser(current_user: User = Depends(get_current_active_user)) -> User:
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return current_user

def _user_has_role(db: Session, user_id: int, role_name: str) -> bool:
    return db.exec(select(Role).join(UserRoleLink).where(UserRoleLink.user_id == user_id, Role.name == role_name)).first() is not None

def require_role(role_name: str):
    def _require(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)) -> User:
        if current_user.is_superuser:
            return current_user
        if not _user_has_role(db, current_user.id, role_name):
            raise HTTPException(status_code=403, detail=f"Role '{role_name}' required")
        return current_user
    return _require
