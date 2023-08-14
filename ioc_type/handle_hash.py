from models import HashIoC
from datetime import datetime
from database import create_engine, SessionLocal, create_specific_ioc_db
from modules.alienvault import get_ioc_data, get_hash_details_async
from modules.whois import get_whois_data
from modules.virustotal import (
    get_virustotal_data,
    get_file_info,
    find_hash_type,
    get_custom_attributes,
)
from modules.ipgeolocation import get_ip_location
from modules.blacklistchecker import get_blacklist_data


async def handle_hash(ioc: str):
    alien_vault_data = await get_ioc_data(ioc)
    ioc_type = alien_vault_data.get("type", "Unknown")
    virustotal_data, last_analysis_unix_timestamp = await get_virustotal_data(
        ioc, ioc_type
    )
    last_analysis_date = datetime.utcfromtimestamp(
        last_analysis_unix_timestamp
    ).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        file_type, file_name, file_size = await get_file_info(ioc)
        
    except Exception as e:
        print(f"Error while scanning URL: {str(e)}")
        file_type, file_name, file_size = None, None, None

    try:
        vhash, tlsh, magic, tr_id = await get_custom_attributes(ioc)
    except Exception as e:
        print(f"Error while scanning URL: {str(e)}")
        vhash, tlsh, magic, tr_id = None, None, None, None    
    #file_type, file_name, file_size = await get_file_info(ioc)
    hash_type = await find_hash_type(ioc)
    ip_contacted, yara_detections = await get_hash_details_async(ioc)
    
    #vhash, tlsh, magic, tr_id = await get_custom_attributes(ioc)
    tags = alien_vault_data.get("tags", [])
    related_tags = ", ".join(set(tags)) if tags else "None"


    db_ioc = HashIoC(
        ioc=ioc,
        ioc_type=ioc_type,
        malicious=str(
            virustotal_data
        ),  # Now inserting the malicious count from Virustotal
        related_tags=related_tags,  # Please make sure that "related_tags" is the correct column name in your database
        last_analysis_date=last_analysis_date,
        file_type=file_type,
        file_size=file_size,
        file_name=file_name,
        hash_type=hash_type,
        tr_ID=tr_id,
        vhash=vhash,
        magic=magic,
        tlsh=tlsh,
        yara_detections=yara_detections,
        ip_contacted=ip_contacted,
    )
    status = create_specific_ioc_db(db_ioc, HashIoC)
    return status
