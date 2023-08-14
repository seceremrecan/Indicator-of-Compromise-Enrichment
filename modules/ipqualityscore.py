import requests
import urllib
import json
import logging
from config import settings


def get_ip_quality_score_attributes(url, strictness=0):
    API_URL = f"https://www.ipqualityscore.com/api/json/url/{settings.IP_QUALITY_SCORE}/{urllib.parse.quote_plus(url)}"

    additional_params = {"strictness": strictness}

    response = requests.get(API_URL, params=additional_params)

    if response.status_code == 200:
        json_response = json.loads(response.text)
        if "success" in json_response and json_response["success"] == True:
            suspicious = json_response["suspicious"]
            unsafe = json_response["unsafe"]
            risk_score = json_response["risk_score"]
            malware = json_response["malware"]
            phishing = json_response["phishing"]
            spamming = json_response["spamming"]
            return suspicious, unsafe, risk_score, malware, phishing, spamming
        else:
            logging.error(
                "API request successful, but the response does not contain expected data."
            )
    else:
        logging.error(f"Error: {response.status_code}")
    return None
