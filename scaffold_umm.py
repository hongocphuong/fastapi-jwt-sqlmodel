
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scaffold Full User Management Module (UMM) for FastAPI + SQLModel

Usage:
  python scaffold_umm.py            # tạo file mới, KHÔNG ghi đè file đã tồn tại
  python scaffold_umm.py --force    # ghi đè nếu file đã tồn tại
  python scaffold_umm.py --root .   # chỉ định root khác (mặc định .)

Yêu cầu dự án đã có:
- FastAPI, Uvicorn, SQLModel, Alembic
- Pydantic Settings, python-jose[cryptography], passlib[bcrypt]

Sau khi chạy:
- TẠO/CẬP NHẬT các file module UMM vào ./app/
- Thử sửa alembic/env.py để import models đầy đủ
- In checklist chạy Alembic migration

Tác giả: M365 Copilot
"""

import argparse
import os
from pathlib import Path
import re
import sys
from textwrap import dedent

# -----------------------------
# CLI
# -----------------------------
parser = argparse.ArgumentParser(description="Scaffold Full User Management Module for FastAPI")
parser.add_argument("--force", action="store_true", help="Ghi đè file nếu đã tồn tại")
parser.add_argument("--root", default=".", help="Thư mục root repo (mặc định .)")
parser.add_argument("--with-items", action="store_true", help="Tạo route items tối thiểu nếu chưa có")
args = parser.parse_args()

ROOT = Path(args.root).resolve()
APP = ROOT / "app"
CORE = APP / "core"
API = APP / "api"
ROUTES = API / "routes"
SERVICES = APP / "services"
ALEMBIC = ROOT / "alembic"
ALEMBIC_ENV = ALEMBIC / "env.py"

if not APP.exists():
    print(f"[ERROR] Không tìm thấy thư mục 'app/' trong: {ROOT}")
    sys.exit(1)

for d in [CORE, API, ROUTES, SERVICES]:
    d.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Utilities
# -----------------------------
def safe_write(path: Path, content: str, force: bool):
    """
    Ghi file nếu chưa tồn tại. Nếu tồn tại và force=True thì ghi đè.
    """
    if path.exists() and not force:
        print(f"[SKIP] {path} (đã tồn tại, dùng --force để ghi đè)")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[WRITE] {path}")
    return True

def try_patch_alembic_env(env_path: Path):
    """
    Cố gắng vá alembic/env.py để import đầy đủ models mới:
    User, Item, RefreshToken, Role, UserRoleLink, EmailToken, PasswordResetToken
    """
    if not env_path.exists():
        print(f"[WARN] Không tìm thấy {env_path}, bỏ qua patch.")
        return

    txt = env_path.read_text(encoding="utf-8")
    changed = False

    # 1) Thay dòng import models nếu có
    pattern = r"^from\s+app\.models\s+import\s+.*$"
    repl = "from app.models import User, Item, RefreshToken, Role, UserRoleLink, EmailToken, PasswordResetToken  # noqa"
    if re.search(pattern, txt, flags=re.MULTILINE):
        txt_new = re.sub(pattern, repl, txt, flags=re.MULTILINE)
        if txt_new != txt:
            txt = txt_new
            changed = True
    else:
        # 2) Nếu chưa có import, chèn trước khi set target_metadata
        anchor = "target_metadata ="
        ins = repl + "\n"
        if anchor in txt and repl not in txt:
            txt = txt.replace(anchor, ins + anchor)
            changed = True

    if changed:
        env_path.write_text(txt, encoding="utf-8")
        print(f"[PATCH] Đã cập nhật imports trong {env_path}")
    else:
        print(f"[INFO] Không cần patch {env_path} (đã phù hợp).")

# -----------------------------
# File contents
# -----------------------------
config_py = dedent("""
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "app"
    POSTGRES_USER: str = "appuser"
    POSTGRES_PASSWORD: str = "apppass"

    # JWT
    SECRET_KEY: str = "CHANGE_ME_SUPER_SECRET_KEY"            # access token
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_SECRET_KEY: str = "CHANGE_ME_REFRESH_SECRET_KEY"  # refresh token
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 30

    # URLs for building email links
    FRONTEND_BASE_URL: str = "http://localhost:5173"
    BACKEND_BASE_URL: str = "http://localhost:8000"

    # SMTP (prod); dev: None -> in-console
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_USE_TLS: bool = True
    EMAIL_FROM: str = "no-reply@example.com"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
""").lstrip()

security_py = dedent("""
from datetime import datetime, timedelta
from uuid import uuid4
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings

ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "type": "access", "exp": expire, "iat": datetime.utcnow()}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(subject: str) -> tuple[str, str, datetime]:
    jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "type": "refresh", "jti": jti, "exp": expire, "iat": datetime.utcnow()}
    token = jwt.encode(payload, settings.REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return token, jti, expire

def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])

def decode_refresh_token(token: str) -> dict:
    return jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
""").lstrip()

models_py = dedent("""
from typing import Optional, List
from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    full_name: Optional[str] = None
    is_superuser: bool = False
    is_active: bool = True

    roles: List["Role"] = Relationship(back_populates="users", link_model="UserRoleLink")

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

class EmailToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")
    purpose: str  # "verify_email"
    used: bool = False
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")
    used: bool = False
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: Optional[str] = None

    users: List[User] = Relationship(back_populates="roles", link_model="UserRoleLink")

class UserRoleLink(SQLModel, table=True):
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    role_id: int = Field(foreign_key="role.id", primary_key=True)
""").lstrip()

crud_py = dedent("""
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
""").lstrip()

schemas_py = dedent("""
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field

# Tokens
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Users
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(min_length=6)

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None

class UserRead(UserBase):
    id: int
    is_active: bool
    is_superuser: bool

    class Config:
        from_attributes = True

# Auth
class LoginRequest(BaseModel):
    username: EmailStr
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6)

class RefreshRequest(BaseModel):
    refresh_token: str

# Email verification / reset password
class RequestEmailVerification(BaseModel):
    email: EmailStr

class ConfirmEmailVerification(BaseModel):
    token: str

class RequestPasswordReset(BaseModel):
    email: EmailStr

class ConfirmPasswordReset(BaseModel):
    token: str
    new_password: str = Field(min_length=6)

# Roles
class RoleRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
""").lstrip()

email_service_py = dedent("""
from app.core.config import settings

# DEV: in-console; PROD: tích hợp SMTP/Provider (SendGrid, Mailgun...) tại đây
async def send_email(to_email: str, subject: str, html_body: str):
    if not settings.SMTP_HOST:
        print("===== EMAIL (DEV) =====")
        print("To:", to_email)
        print("Subject:", subject)
        print("Body:\\n", html_body)
        print("=======================")
        return
    # TODO: SMTP send (aiosmtplib/smtplib) hoặc SDK nhà cung cấp
    raise NotImplementedError("SMTP sending not implemented in this scaffold")
""").lstrip()

deps_py = dedent("""
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
""").lstrip()

api_py = dedent("""
from fastapi import APIRouter
from app.api.routes import auth, users, admin

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(admin.router)
""").lstrip()

auth_route_py = dedent("""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from sqlmodel import Session, select

from app.api.deps import get_db, get_current_active_user
from app.models import User
from app.core.security import (
    verify_password, get_password_hash,
    create_access_token, create_refresh_token,
    decode_refresh_token,
)
from app.schemas import (
    TokenPair, RefreshRequest, UserCreate, ChangePasswordRequest,
    RequestEmailVerification, ConfirmEmailVerification,
    RequestPasswordReset, ConfirmPasswordReset,
)
from app.crud import (
    get_user_by_email, create_user,
    create_refresh_token_record, revoke_refresh_token, is_refresh_token_revoked,
    create_email_token, get_valid_email_token, mark_email_token_used,
    create_password_reset_token, consume_password_reset_token,
)
from app.core.config import settings
from app.services.email_service import send_email

router = APIRouter(tags=["auth"])

# ===== Register =====
@router.post("/register", response_model=dict)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email already exists")
    user = create_user(db, email=payload.email, password=payload.password, full_name=payload.full_name)
    # Email verify token (optional in dev)
    et = create_email_token(db, user_id=user.id, purpose="verify_email", ttl_minutes=60)
    verify_link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={et.token}"
    subject = "Verify your email"
    html = f"<p>Hello, please verify your email: {verify_link}Verify</a></p>"
    try:
        import anyio
        anyio.from_thread.run(send_email, user.email, subject, html)
    except Exception:
        pass
    return {"id": user.id, "email": user.email}

# ===== Login =====
@router.post("/login", response_model=TokenPair)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.email == form.username)).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    access = create_access_token(subject=user.email)
    refresh, jti, exp = create_refresh_token(subject=user.email)
    create_refresh_token_record(db, user_id=user.id, jti=jti, expires_at=exp)
    return TokenPair(access_token=access, refresh_token=refresh)

# ===== Refresh (rotation) =====
@router.post("/refresh", response_model=TokenPair)
def refresh_tokens(body: RefreshRequest, db: Session = Depends(get_db)):
    try:
        claims = decode_refresh_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")
    jti = claims.get("jti")
    email: EmailStr | None = claims.get("sub")
    if not jti or not email:
        raise HTTPException(status_code=401, detail="Invalid claims")
    if is_refresh_token_revoked(db, jti):
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    revoke_refresh_token(db, jti)  # rotation
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    access = create_access_token(subject=email)
    new_refresh, new_jti, new_exp = create_refresh_token(subject=email)
    create_refresh_token_record(db, user_id=user.id, jti=new_jti, expires_at=new_exp)
    return TokenPair(access_token=access, refresh_token=new_refresh)

# ===== Logout =====
@router.post("/logout", response_model=dict)
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    try:
        claims = decode_refresh_token(body.refresh_token)
        jti = claims.get("jti")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    revoke_refresh_token(db, jti)
    return {"detail": "Logged out"}

# ===== Who am I & Change password =====
@router.get("/me", response_model=dict)
def whoami(current=Depends(get_current_active_user)):
    return {
        "id": current.id, "email": current.email,
        "full_name": current.full_name,
        "is_active": current.is_active, "is_superuser": current.is_superuser
    }

@router.post("/change-password", response_model=dict)
def change_password(body: ChangePasswordRequest, current=Depends(get_current_active_user), db: Session = Depends(get_db)):
    if not verify_password(body.old_password, current.hashed_password):
        raise HTTPException(status_code=400, detail="Old password invalid")
    current.hashed_password = get_password_hash(body.new_password)
    db.add(current)
    db.commit()
    return {"detail": "Password changed"}

# ===== Email verification =====
@router.post("/verify-email/request", response_model=dict)
def request_email_verification(body: RequestEmailVerification, db: Session = Depends(get_db)):
    user = get_user_by_email(db, body.email)
    if user:
        et = create_email_token(db, user_id=user.id, purpose="verify_email", ttl_minutes=60)
        link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={et.token}"
        subject = "Verify your email"
        html = f"<p>Verify: {link}Link</a></p>"
        try:
            import anyio
            anyio.from_thread.run(send_email, user.email, subject, html)
        except Exception:
            pass
    return {"detail": "If the email exists, a verification was sent"}

@router.post("/verify-email/confirm", response_model=dict)
def confirm_email(body: ConfirmEmailVerification, db: Session = Depends(get_db)):
    et = get_valid_email_token(db, body.token, purpose="verify_email")
    if not et:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.get(User, et.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    db.add(user)
    db.commit()
    mark_email_token_used(db, body.token)
    return {"detail": "Email verified"}

# ===== Password reset =====
@router.post("/password-reset/request", response_model=dict)
def password_reset_request(body: RequestPasswordReset, db: Session = Depends(get_db)):
    user = get_user_by_email(db, body.email)
    if user:
        pr = create_password_reset_token(db, user.id, ttl_minutes=30)
        link = f"{settings.FRONTEND_BASE_URL}/reset-password?token={pr.token}"
        subject = "Password reset"
        html = f"<p>Reset: {link}Link</a></p>"
        try:
            import anyio
            anyio.from_thread.run(send_email, user.email, subject, html)
        except Exception:
            pass
    return {"detail": "If the email exists, a reset link was sent"}

@router.post("/password-reset/confirm", response_model=dict)
def password_reset_confirm(body: ConfirmPasswordReset, db: Session = Depends(get_db)):
    prt = consume_password_reset_token(db, body.token)
    if not prt:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.get(User, prt.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(body.new_password)
    db.add(user)
    db.commit()
    return {"detail": "Password reset successful"}
""").lstrip()

users_route_py = dedent("""
from fastapi import APIRouter, Depends
from sqlmodel import Session
from app.api.deps import get_db, get_current_active_user
from app.schemas import UserUpdate, UserRead
from app.crud import update_user

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me", response_model=UserRead)
def get_me(current=Depends(get_current_active_user)):
    return current

@router.patch("/me", response_model=UserRead)
def update_me(payload: UserUpdate, db: Session = Depends(get_db), current=Depends(get_current_active_user)):
    user = update_user(db, current, full_name=payload.full_name)
    return user
""").lstrip()

admin_route_py = dedent("""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from typing import List
from app.api.deps import get_db, get_current_superuser
from app.schemas import UserRead, UserUpdate, RoleRead, RoleCreate
from app.models import User
from app.crud import (
    list_users, update_user, create_role, list_roles, assign_role_to_user, remove_role_from_user
)

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/users", response_model=List[UserRead])
def admin_list_users(q: str | None = None, page: int = 1, size: int = 20,
                     db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    skip = (page - 1) * size
    return list_users(db, q=q, skip=skip, limit=size)

@router.patch("/users/{user_id}", response_model=UserRead)
def admin_update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user = update_user(db, user, full_name=payload.full_name, is_active=payload.is_active, is_superuser=payload.is_superuser)
    return user

@router.post("/roles", response_model=RoleRead)
def admin_create_role(payload: RoleCreate, db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    return create_role(db, name=payload.name, description=payload.description)

@router.get("/roles", response_model=List[RoleRead])
def admin_list_roles(db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    return list_roles(db)

@router.post("/users/{user_id}/roles/{role_name}", response_model=List[RoleRead])
def admin_assign_role(user_id: int, role_name: str, db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    return assign_role_to_user(db, user_id=user_id, role_name=role_name)

@router.delete("/users/{user_id}/roles/{role_name}", response_model=List[RoleRead])
def admin_remove_role(user_id: int, role_name: str, db: Session = Depends(get_db), current=Depends(get_current_superuser)):
    return remove_role_from_user(db, user_id=user_id, role_name=role_name)
""").lstrip()

items_route_py = dedent("""
from fastapi import APIRouter, Depends
from sqlmodel import Session
from app.api.deps import get_db, get_current_active_user
from app.crud import create_item, list_items
from app.models import Item, User

router = APIRouter(prefix="/items", tags=["items"])

@router.get("")
def get_items(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    return list_items(db, owner_id=current_user.id)

@router.post("")
def create_items(item: Item, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    return create_item(db, owner_id=current_user.id, name=item.name, description=item.description)
""").lstrip()

# -----------------------------
# Write files
# -----------------------------
# core
safe_write(CORE / "config.py", config_py, args.force)
safe_write(CORE / "security.py", security_py, args.force)

# app root models/crud/schemas/services
safe_write(APP / "models.py", models_py, args.force)
safe_write(APP / "crud.py", crud_py, args.force)
safe_write(APP / "schemas.py", schemas_py, args.force)
safe_write(SERVICES / "email_service.py", email_service_py, args.force)

# api deps/api and routes
safe_write(API / "deps.py", deps_py, args.force)
safe_write(API / "api.py", api_py, args.force)
safe_write(ROUTES / "auth.py", auth_route_py, args.force)
safe_write(ROUTES / "users.py", users_route_py, args.force)
safe_write(ROUTES / "admin.py", admin_route_py, args.force)

# items (tùy chọn)
items_path = ROUTES / "items.py"
if args.with_items and not items_path.exists():
    safe_write(items_path, items_route_py, force=True)

# attempt patch alembic
try_patch_alembic_env(ALEMBIC_ENV)

print("\n✅ Hoàn tất scaffold UMM.")
print("➡️  Tiếp theo:")
print("  1) Kiểm tra/cập nhật .env (thêm SECRET_KEY, REFRESH_SECRET_KEY, FRONTEND_BASE_URL, SMTP_* nếu cần).")
print("  2) Chạy Alembic:")
print("     alembic revision --autogenerate -m \"user management module\"")
print("     alembic upgrade head")
print("  3) Khởi động API và test các endpoint /api/v1/* (login/register/refresh/logout, verify, reset, admin).")

