from models import UrlIoC
from datetime import datetime
from database import create_engine, SessionLocal, create_specific_ioc_db
from modules.alienvault import get_ioc_data
from modules.whois import get_whois_data
from modules.ipqualityscore import get_ip_quality_score_attributes
from modules.urlscan_io import scan_url


async def handle_url(ioc: str):
    alien_vault_data = await get_ioc_data(ioc)
    ioc_type = alien_vault_data.get("type", "Unknown")
    whois_data = await get_whois_data(ioc)
    # virustotal_data, last_analysis_unix_timestamp = await get_virustotal_data(ioc, ioc_type)
    # last_analysis_date = datetime.utcfromtimestamp(last_analysis_unix_timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    (
        suspicious,
        unsafe,
        risk_score,
        malware,
        spamming,
        phishing,
    ) = get_ip_quality_score_attributes(ioc)
    try:
        ip_address, country, contacted_urls, servers =  scan_url(ioc)
    except Exception as e:
        print(f"Error while scanning URL: {str(e)}")
        ip_address, country, contacted_urls, servers = None, None, None, None

    tags = alien_vault_data.get("tags", [])
    related_tags = ", ".join(set(tags)) if tags else None
    


    

    db_ioc = UrlIoC(
        ioc=ioc,
        ioc_type=ioc_type,
        whois=str(whois_data),
        related_tags=related_tags,  # Please make sure that "related_tags" is the correct column name in your database
        suspicious=suspicious,
        unsafe=unsafe,
        risk_score=risk_score,
        malware=malware,
        spamming=spamming,
        phishing=phishing,
        ip_address=ip_address,
        country=country,
        contacted_urls=contacted_urls,
        servers=servers,
    )
    status = create_specific_ioc_db(db_ioc, UrlIoC)
    return status
