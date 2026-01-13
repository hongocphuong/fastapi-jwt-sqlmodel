
from fastapi import FastAPI
from app.api.api import api_router

app = FastAPI(title="FastAPI + JWT + Alembic")

app.include_router(api_router)

@app.get("/health")
def health():
    return {"status": "ok"}
