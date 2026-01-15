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
