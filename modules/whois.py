import httpx
from urllib.parse import urlparse
import logging
from config import settings


async def get_whois_data(ioc: str):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={settings.WHOIS_API_KEY}&domainName={ioc}&outputFormat=JSON"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            data = response.json()
            return data  # Now returns the whole data
        except Exception as e:
            logging.error(f"Failed to get WHOIS data for {ioc}. Error: {str(e)}")
            return {}


# https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_U2TCFAy54P4XvoZyX6NChAcg1ruOq&domainName=24.48.0.1&outputFormat=JSON
