
from fastapi import APIRouter, Depends
from sqlmodel import Session
from app.api.deps import get_db, get_current_superuser
from app.crud import list_users

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_superuser = Depends(get_current_superuser)
):
    return list_users(db)
