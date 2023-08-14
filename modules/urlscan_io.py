import requests
import time
import logging
from config import settings


def scan_url(url_to_scan):
    headers = {
        "Content-Type": "application/json",
        "API-Key": settings.URL_SCAN_IO,
    }

    data = {
        "url": url_to_scan,
        "public": "on",
    }

    response = requests.post(
        "https://urlscan.io/api/v1/scan/", json=data, headers=headers
    )

    if response.status_code == 200:
        scan_data = response.json()
        uuid = scan_data["uuid"]
    else:
        logging.error("Tarama başarısız oldu!")
        return

    time.sleep(40)

    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    result_response = requests.get(result_url)

    if result_response.status_code == 200:
        result_data = result_response.json()
        ip_address = result_data.get("lists", {}).get("ips")  # Güncellendi
        country = result_data.get("lists", {}).get("countries")
        contacted_urls = result_data.get("lists", {}).get("urls")
        servers = result_data.get("lists", {}).get("servers")
        # İlgilendiğiniz diğer bilgileri alabilirsiniz, bu örnekte yalnızca IP istatistiklerini alıyoruz
        return ip_address, country, contacted_urls, servers
    else:
        logging.error("Sonuç alınamadı!")
        return None
