import os
import httpx
import json
from OTXv2 import OTXv2, IndicatorTypes
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from urllib.parse import quote
import ipaddress
import logging
from config import settings


async def get_ioc_data(ioc: str):
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

    try:
        ipaddress.ip_address(ioc)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:  # IP adresi ise
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
        ioc_type = "IPv4"
    elif "/" in ioc:  # Muhtemelen bir URL
        quoted_ioc = quote(ioc, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{quoted_ioc}/general"
        ioc_type = "URL"
    elif "." in ioc:  # Muhtemelen bir alan adı
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
        ioc_type = "Domain"
    else:  # Muhtemelen bir kriptoğrafik hash
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
        ioc_type = "hash"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            

            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            tags = set()
            for pulse in pulses:
                pulse_tags = pulse.get("tags", [])
                tags.update(pulse_tags)
                
            return {
                "data": data,
                "type": ioc_type,
                "tags": list(tags),
            }
        except Exception as e:
            logging.error(f"{ioc} için AlienVault verileri alınamadı. Hata: {str(e)}")
            return {
                "data": {},
                "type": ioc_type,
                "tags": [],
            }


async def get_hash_details_async(hash_value):
    loop = asyncio.get_running_loop()

    def sync_code():
        otx = OTXv2(settings.OTX_API_KEY)

        # Hangi hash tipi olduğunu belirleme
        hash_type = None
        if len(hash_value) == 32:
            hash_type = IndicatorTypes.FILE_HASH_MD5
        elif len(hash_value) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1
        elif len(hash_value) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        else:
            logging.error("Geçersiz hash uzunluğu")
            return "unknown", "unknown"

        pulses = otx.get_indicator_details_full(hash_type, hash_value)

        # ip_contacted verilerini almak
        ip_contacted = (
            pulses.get("analysis", {})
            .get("analysis", {})
            .get("plugins", {})
            .get("cuckoo", {})
            .get("result", {})
            .get("network", {})
            .get("hosts", [])
        )
        ip_contacted_json = json.dumps(ip_contacted) if ip_contacted else "unknown"

        # yara_detections verilerini almak
        yara_detections = (
            pulses.get("analysis", {})
            .get("analysis", {})
            .get("plugins", {})
            .get("yarad", {})
            .get("results", {})
            .get("detection", [])
        )
        yara_detections_str = (
            ", ".join(
                [
                    result.get("rule_name")
                    for result in yara_detections
                    if result.get("rule_name")
                ]
            )
            if yara_detections
            else "unknown"
        )

        return ip_contacted_json, yara_detections_str

    return await loop.run_in_executor(ThreadPoolExecutor(), sync_code)
