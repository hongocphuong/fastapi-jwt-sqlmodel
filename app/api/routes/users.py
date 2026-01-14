from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session

from app.api.deps import get_db, get_current_user
from app.models import User
from app.crud import (
    create_user as crud_create_user,
    get_user_by_email,
    update_user_password,
    delete_user,
    list_users as crud_list_users,
)

router = APIRouter(prefix="/users", tags=["users"]) 


class UserCreate(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str


class UserUpdate(BaseModel):
    password: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    #print('Registering user:', user_in.email, user_in.password)
    #print("pw repr:", repr(user_in.password))
    #print("pw bytes len:", len(user_in.password.encode("utf-8")))
    existing = get_user_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    # bcrypt has a 72-byte password limit; validate to avoid internal server error
    if len(user_in.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password too long: bcrypt supports up to 72 bytes. Use a shorter password.",
        )
    try:
        user = crud_create_user(db, user_in.email, user_in.password)
    except Exception as exc:
        # log exception for debugging and rollback will be handled by session
        print("Error creating user:", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create user",
        )

    return UserOut(id=user.id, email=user.email)


@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    return UserOut(id=current_user.id, email=current_user.email)


@router.put("/me", response_model=UserOut)
def update_current_user(payload: UserUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if payload.password:
        if len(payload.password.encode("utf-8")) > 72:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password too long: bcrypt supports up to 72 bytes. Use a shorter password.",
            )
        user = update_user_password(db, current_user, payload.password)
    else:
        user = current_user
    return UserOut(id=user.id, email=user.email)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_current_user(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    delete_user(db, current_user)
    return None


@router.get("", response_model=list[UserOut])
def list_all_users(db: Session = Depends(get_db)):
    users = crud_list_users(db)
    return [UserOut(id=u.id, email=u.email) for u in users]