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
