import os
os.environ["DATABASE_URL"]="sqlite:///./test_guardx.db"
from app.db.database import Base,engine
import pytest
from fastapi.testclient import TestClient
from app.main import app
@pytest.fixture(scope="session",autouse=True)
def db():
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine);yield
@pytest.fixture
def client(): return TestClient(app)
