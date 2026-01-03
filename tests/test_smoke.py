import os
import pytest
from fastapi.testclient import TestClient
from app import app

@pytest.fixture()
def client():
    return TestClient(app)

def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
