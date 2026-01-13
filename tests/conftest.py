
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine, Session

from app.main import app
from app.api import deps

# In-memory SQLite cho test
engine = create_engine("sqlite://", connect_args={"check_same_thread": False})

@pytest.fixture(scope="session", autouse=True)
def create_db():
    SQLModel.metadata.create_all(engine)
    yield

@pytest.fixture()
def db_session():
    with Session(engine) as session:
        yield session

# Override dependency get_db để dùng session test
@app.on_event("startup")
def _override_deps():
    def _get_db_override():
        with Session(engine) as session:
            yield session
    app.dependency_overrides[deps.get_db] = _get_db_override

@pytest.fixture()
def client():
    return TestClient(app)
