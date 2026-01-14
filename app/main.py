
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.api import api_router

app = FastAPI(title="FastAPI + JWT + Alembic")


# Cho phép frontend Vite (port 5173) gọi backend (port 8000)
origins = [
    "http://localhost:3000",
    # nếu bạn dùng 127.0.0.1:5173, thêm vào đây
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,         # KHÔNG nên dùng "*" nếu có credentials
    allow_credentials=True,        # dùng cookies/Authorization thì bật
    allow_methods=["*"],           # hoặc liệt kê: ["GET","POST","PUT","DELETE","OPTIONS"]
    allow_headers=["*"],           # hoặc liệt kê các header bạn dùng
)


app.include_router(api_router)

@app.get("/health")
def health():
    return {"status": "ok"}
