
from fastapi import APIRouter, Depends
from sqlmodel import Session
from pydantic import BaseModel

from app.api.deps import get_db, get_current_superuser
from app.crud import create_role, list_roles, assign_role_to_user, remove_role_from_user, get_user_roles

router = APIRouter(prefix="/roles", tags=["roles"])

class RoleCreate(BaseModel):
    name: str
    description: str | None = None

@router.post("", dependencies=[Depends(get_current_superuser)])
def create_role_api(payload: RoleCreate, db: Session = Depends(get_db)):
    print("Creating role:", payload.name)
    role = create_role(db, name=payload.name, description=payload.description)
    print("Created role:", role)
    return role

@router.get("", dependencies=[Depends(get_current_superuser)])
def list_roles_api(db: Session = Depends(get_db)):
    return list_roles(db)

@router.post("/assign/{user_id}/{role_name}", dependencies=[Depends(get_current_superuser)])
def assign_role(user_id: int, role_name: str, db: Session = Depends(get_db)):
    return assign_role_to_user(db, user_id=user_id, role_name=role_name)

@router.delete("/remove/{user_id}/{role_name}", dependencies=[Depends(get_current_superuser)])
def remove_role(user_id: int, role_name: str, db: Session = Depends(get_db)):
    return remove_role_from_user(db, user_id=user_id, role_name=role_name)

@router.get("/user/{user_id}", dependencies=[Depends(get_current_superuser)])
def list_user_roles(user_id: int, db: Session = Depends(get_db)):
    return get_user_roles(db, user_id=user_id)

