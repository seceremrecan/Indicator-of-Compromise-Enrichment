import httpx
import json
import logging
from tenacity import retry, wait_fixed
from config import settings


async def get_file_info(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": settings.VIRUS_TOTAL_API_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        if response.status_code == 200:
            file_info = response.json()
            file_name = file_info["data"]["attributes"]["names"]
            file_type = file_info["data"]["attributes"]["type_tag"]
            file_size = file_info["data"]["attributes"]["size"]
            return file_name, file_type, file_size
        else:
            logging.error(f"Error: {response.status_code}")
            return None, None, None


@retry(wait=wait_fixed(10))  # 10 saniye bekleyip yeniden deneme
async def get_virustotal_data(ioc: str, ioc_type: str):
    headers = {"x-apikey": settings.VIRUS_TOTAL_API_KEY}

    async with httpx.AsyncClient(timeout=30.0) as client:  # 30 saniye zaman aşımı
        if ioc_type == "IPv4":  # It's an IP
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "hash":  # It's a hash
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "URL":  # It's a URL
            # First get the URL id
            id_url = f"https://www.virustotal.com/api/v3/urls"
            url_id_response = await client.post(
                id_url, data={"url": ioc}, headers=headers
            )

            if url_id_response.status_code != 200:
                logging.error(f"Failed to get URL id. Response: {url_id_response.text}")
                return 0
            url_id = url_id_response.json()["data"]["id"]
            # Then get the analysis results
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif ioc_type == "Domain":  # It's a domain
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            return (
                0,0  # Virustotal API does not support this ioc_type for malicious count
            )

        try:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                logging.error(
                    f"Received status code {response.status_code}. Response: {response.text}"
                )
                return 0,0
            data = response.json()
            malicious_count = data["data"]["attributes"]["last_analysis_stats"][
                "malicious"
            ]
            last_analysis_date = data["data"]["attributes"]["last_analysis_date"]
            return malicious_count, last_analysis_date
        except Exception as e:
            logging.error(
                f"Failed to get data from Virustotal for {ioc}. Error: {str(e)}"
            )
            return 0,0


async def find_hash_type(given_hash):
    url = f"https://www.virustotal.com/api/v3/files/{given_hash}"
    headers = {"x-apikey": settings.VIRUS_TOTAL_API_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        if response.status_code == 200:
            file_info = response.json()
            md5 = file_info["data"]["attributes"]["md5"]
            sha1 = file_info["data"]["attributes"]["sha1"]
            sha256 = file_info["data"]["attributes"]["sha256"]

            if given_hash == md5:
                return "MD5"
            elif given_hash == sha1:
                return "SHA-1"
            elif given_hash == sha256:
                return "SHA-256"
            else:
                return None
        else:
            logging.error(f"Error: {response.status_code}")
            return None


async def get_custom_attributes(file_hash):
    # API endpoint'ini belirtin
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": settings.VIRUS_TOTAL_API_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            magic = json_response["data"]["attributes"]["magic"]  # Magic değerini alın
            trid = json.dumps(
                json_response["data"]["attributes"]["trid"]
            )  # TrID değerini alın
            vhash = json_response["data"]["attributes"]["vhash"]  # Vhash değerini alın
            tlsh = json_response["data"]["attributes"]["tlsh"]
            return vhash, tlsh, magic, trid
        else:
            logging.error(f"Error: {response.status_code}")
            return None
