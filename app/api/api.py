
from fastapi import APIRouter
from app.api.routes import auth, items, admin, roles , users

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(items.router)
api_router.include_router(admin.router)
api_router.include_router(roles.router)   
#api_router.include_router(users.router)   
