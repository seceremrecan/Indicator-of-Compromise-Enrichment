import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from main import app
from models import IoC, HashIoC, UrlIoC, DomainIoC

client = TestClient(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("ioc_value, ioc_type", [
    ("170.64.154.53", IoC),  # Örnek bir IPv4
    ("904343ba2502d390b36403181e77192a62f31e98c87eb91906fbae27019b4c0d", HashIoC),  # Örnek bir hash değeri
    ("http://check.topgearmemory.com/dw/9c890e1b2b4f2723a68fc905268ee010cae232be.txt", UrlIoC),  # Örnek bir URL
    ("apple-shop.org-help.com", DomainIoC)  # Örnek bir domain
])
async def test_ioc_submission(ioc_value, ioc_type):
    response = client.post("/search", data={"ioc": ioc_value})
    assert response.status_code == 200

