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
