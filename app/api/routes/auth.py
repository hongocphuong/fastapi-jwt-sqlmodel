
# app/api/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel,EmailStr
from sqlmodel import Session, select

from app.api.deps import get_db
from app.models import User
from app.core.security import verify_password, create_access_token, create_refresh_token, decode_refresh_token
from app.crud import create_refresh_token_record, revoke_refresh_token, is_refresh_token_revoked, get_user_by_email,create_user

router = APIRouter(tags=["auth"])

class RefreshBody(BaseModel):
    refresh_token: str


class RegisterBody(BaseModel):
    email: EmailStr
    password: str

@router.post("/register")
def register(payload: RegisterBody, db: Session = Depends(get_db)):
    # kiểm tra tồn tại
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email đã tồn tại")
    # tạo user thường (is_active=True, is_superuser=False)
    user = create_user(db, email=payload.email, password=payload.password, is_superuser=False, is_active=True)
    return {"id": user.id, "email": user.email}


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.exec(select(User).where(User.email == form_data.username)).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access = create_access_token(subject=user.email)
    refresh, jti, expires_at = create_refresh_token(subject=user.email)
    create_refresh_token_record(db, user_id=user.id, jti=jti, expires_at=expires_at)

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

@router.post("/refresh")
def refresh_tokens(body: RefreshBody, db: Session = Depends(get_db)):
    # 1) Decode refresh token
    try:
        claims = decode_refresh_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # 2) Validate type & status
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    jti = claims.get("jti")
    email = claims.get("sub")
    if not jti or not email:
        raise HTTPException(status_code=401, detail="Invalid claims")

    # 3) Check revoked/expired (DB)
    if is_refresh_token_revoked(db, jti):
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    # 4) ROTATION: revoke old refresh, issue new refresh + access
    revoke_refresh_token(db, jti)

    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access = create_access_token(subject=email)
    new_refresh, new_jti, new_expires = create_refresh_token(subject=email)
    create_refresh_token_record(db, user_id=user.id, jti=new_jti, expires_at=new_expires)

    return {"access_token": access, "refresh_token": new_refresh, "token_type": "bearer"}

@router.post("/logout")
def logout(body: RefreshBody, db: Session = Depends(get_db)):
    # Client gửi refresh token hiện có để revoke
    try:
        claims = decode_refresh_token(body.refresh_token)
        jti = claims.get("jti")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    revoke_refresh_token(db, jti)
    return {"detail": "Logged out"}
