
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlmodel import Session, select
from fastapi.security import OAuth2PasswordBearer

from app.db import engine
from app.models import User
from app.core.security import ALGORITHM
from app.core.config import settings

#OAuth2PasswordBearer — lấy token từ header Authorization: Bearer ... (được cấu hình tokenUrl="/api/v1/login").
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

def get_db():
    with Session(engine) as session:
        yield session

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
