import httpx
import json
from dotenv import load_dotenv
import os
from config import settings




async def fetch_abuse_ipdb_data(ip):
    api_url = "https://api.abuseipdb.com/api/v2/check"

    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    headers = {"Accept": "application/json", "Key": settings.ABUSE_IPDB_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(api_url, params=params, headers=headers)
        response_data = response.json()

        return json.dumps(response_data, sort_keys=True, indent=4)
