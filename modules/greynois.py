import httpx
from config import settings


async def query_greynoise(ioc):
    base_url = "https://api.greynoise.io/v3/community/"
    url = base_url + ioc

    headers = {"key": settings.GREY_NOIS_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

    return response.text
