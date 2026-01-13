
from sqlmodel import SQLModel, create_engine
from .core.config import settings

# Dùng SQLAlchemy URI (khác JDBC):
DATABASE_URL = (
    f"postgresql+psycopg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
)

engine = create_engine(DATABASE_URL, echo=True)  # echo=True để xem SQL log

def init_db():
    SQLModel.metadata.create_all(engine)
    print("Database initialized.")