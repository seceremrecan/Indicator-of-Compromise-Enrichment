import httpx
import logging
from config import settings




async def get_blacklist_data(ip: str):
    # Burada URL'yi doğru bir şekilde belirtin.
    url = f"https://api.blacklistchecker.com/check/{ip}"

    async with httpx.AsyncClient(auth=(settings.BLACKLIST_API_KEY, "")) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                detections = data["detections"]
                if detections > 0:
                    return "yes"
                else:
                    return "no"
            else:
                logging.error(
                    f"{ip} için veriler alinamadi. Hata kodu: {response.status_code}"
                )
                return None
        except Exception as e:
            logging.error(f"{ip} için veriler alinamadi. Hata: {str(e)}")
            return None
