import requests
import logging
from config import settings


async def get_dns_records(domain: str):
    api_url = "https://api.api-ninjas.com/v1/dnslookup?domain={}".format(
        domain
    )  # API endpoint'unu dökümantasyona göre düzenleyin
    headers = {"X-Api-Key": settings.API_NINJAS_API_KEY}

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            logging.error(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

    return None
