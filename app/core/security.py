
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings
from uuid import uuid4

# Config from settings (SECRET_KEY should come from env or .env)
ALGORITHM = "HS256"
#ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# dùng để hash và kiểm tra mật khẩu.
# Prefer Argon2 when available (more modern, no 72-byte limit); fall back to bcrypt.
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

#Hash mật khẩu thô bằng pwd_context.hash(...) và trả về chuỗi đã hash.
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

#So sánh mật khẩu thô với hash bằng pwd_context.verify(...), trả về True nếu khớp.
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# def create_access_token(subject: str) -> str:
#     expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
#     payload = {"sub": subject, "exp": expire}
#     return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "type": "access", "exp": expire, "iat": datetime.utcnow()}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(subject: str) -> tuple[str, str, datetime]:
    """
    Returns: (token, jti, expires_at)
    """
    jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "type": "refresh", "jti": jti, "exp": expire, "iat": datetime.utcnow()}
    token = jwt.encode(payload, settings.REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return token, jti, expire

def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])

def decode_refresh_token(token: str) -> dict:
    return jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
