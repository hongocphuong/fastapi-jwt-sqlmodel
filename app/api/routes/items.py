
from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_db, require_role, get_current_active_user
from app.crud import create_item, list_items, list_items_all
from app.models import Item, User, Role, UserRoleLink

router = APIRouter(prefix="/items", tags=["items"])

@router.get("")
def get_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    # Admins or superusers see everything; others see only their items
    is_admin_role = db.exec(
        select(Role).join(UserRoleLink).where(UserRoleLink.user_id == current_user.id, Role.name == "admin")
    ).first() is not None
    if current_user.is_superuser or is_admin_role:
        return list_items_all(db)
    return list_items(db, owner_id=current_user.id)

@router.post("")
def create_items(
    item: Item,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("editor")),   # ✅ cần role 'editor'
):
    return create_item(db, owner_id=current_user.id, name=item.name, description=item.description)

@router.post("/basic-create")
def create_items_basic(
    item: Item,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),  # ✅ chỉ cần user active
):
    return create_item(db, owner_id=current_user.id, name=item.name, description=item.description)  

@router.get("/basic-list")
def get_items_basic(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),  # ✅ chỉ cần user active
):
    return list_items(db, owner_id=current_user.id) 

@router.get("/admin-list")
def get_items_admin(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),  # ✅ cần role 'admin'
):
    return list_items_all(db)

@router.put("/{item_id}")
def update_item(
    item_id: int,
    item: Item,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("editor")),   # ✅ cần role 'editor'
):
    db_item = db.get(Item, item_id)
    if not db_item or db_item.owner_id != current_user.id:
        return {"error": "Item not found or access denied"}
    db_item.name = item.name
    db_item.description = item.description
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# --- IGNORE ---


