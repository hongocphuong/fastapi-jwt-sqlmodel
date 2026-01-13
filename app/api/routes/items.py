
from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_db, get_current_user
from app.models import Item, User

router = APIRouter(prefix="/items", tags=["items"])

@router.get("")
def get_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Item).where(Item.owner_id == current_user.id)
    return db.exec(stmt).all()

@router.post("")
def create_item(
    item: Item,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item.owner_id = current_user.id
    db.add(item)
    db.commit()
    db.refresh(item)
    return item
