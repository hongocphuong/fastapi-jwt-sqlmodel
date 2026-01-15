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
