from models import DomainIoC
from datetime import datetime
from database import create_engine, SessionLocal, create_specific_ioc_db
from modules.alienvault import get_ioc_data
from modules.whois import get_whois_data
from modules.virustotal import get_virustotal_data
from modules.ipgeolocation import get_ip_location
from modules.blacklistchecker import get_blacklist_data
from modules.apininjas import get_dns_records


async def handle_domain(ioc: str):
    

    alien_vault_data = await get_ioc_data(ioc)
    
    ioc_type = alien_vault_data.get("type", "Unknown")
    whois_data = await get_whois_data(ioc)
    virustotal_data, last_analysis_unix_timestamp = await get_virustotal_data(
        ioc, ioc_type
    )
    last_analysis_date = datetime.utcfromtimestamp(
        last_analysis_unix_timestamp
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    ip_data = await get_ip_location(ioc)
    blacklist_data = await get_blacklist_data(ioc)
    lat = ip_data.get("lat", "Unknown")
    lon = ip_data.get("lon", "Unknown")
    geometric_location = (
        f"{lat}, {lon}" if lat != "Unknown" and lon != "Unknown" else "Unknown"
    )
    city = ip_data.get("city", "Unknown")
    country = ip_data.get("country", "Unknown")
    isp = ip_data.get("isp", "Unknown")
    ip = ip_data.get("query", "Unknown")

    
    tags = alien_vault_data.get("tags", [])
    related_tags = ", ".join(set(tags))
    dns_record = await get_dns_records(ioc)

    db_ioc = DomainIoC(
        ioc=ioc,
        ioc_type=ioc_type,
        whois=str(whois_data),
        malicious=str(
            virustotal_data
        ),  # Now inserting the malicious count from Virustotal
        geometric_location=geometric_location,
        blacklist=blacklist_data,
        isp=isp,
        city=city,
        country=country,
        related_tags=related_tags,  # Please make sure that "related_tags" is the correct column name in your database
        ip=ip,
        dns_record=str(dns_record),
        last_analysis_date=last_analysis_date,
    )
    status = create_specific_ioc_db(db_ioc, DomainIoC)
    return status
