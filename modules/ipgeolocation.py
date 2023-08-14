import httpx
import logging


async def get_ip_location(ioc):
    url = f"http://ip-api.com/json/{ioc}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            data = response.json()
            return data
        except Exception as e:
            logging.error(f"Failed to get IP location data for {ioc}. Error: {str(e)}")
            return {}
