from sqlalchemy import Column, String, Integer, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class IoC(Base):
    __tablename__ = "ipv4"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String)
    ioc_type = Column(String)
    blacklist = Column(String)
    whois = Column(String, index=True)
    malicious = Column(String)

    geometric_location = Column(String)
    isp = Column(String)
    city = Column(String)
    country = Column(String)
    related_tags = Column(String)
    last_analysis_date = Column(String)
    abuse_ip_db = Column(String)
    grey_nois_data = Column(String)


class DomainIoC(Base):
    __tablename__ = "domain"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String)
    ip = Column(String)
    ioc_type = Column(String)
    blacklist = Column(String)
    whois = Column(String)
    malicious = Column(String)
    geometric_location = Column(String)
    isp = Column(String)
    city = Column(String)
    country = Column(String)
    related_tags = Column(String)
    dns_record = Column(String)
    last_analysis_date = Column(String)


class HashIoC(Base):
    __tablename__ = "hash"

    id = Column(Integer, primary_key=True, autoincrement=True)

    ioc = Column(String)
    ioc_type = Column(String)
    malicious = Column(String)
    related_tags = Column(String)
    hash_type = Column(String)
    file_name = Column(String)  # Dosya adı
    file_size = Column(String)  # Dosya boyutu
    file_type = Column(String)  # Dosya türü
    magic = Column(String)
    vhash = Column(String)
    tlsh = Column(String)
    ip_contacted = Column(String)
    yara_detections = Column(String)
    tr_ID = Column(String)
    last_analysis_date = Column(String)


class UrlIoC(Base):
    __tablename__ = "url"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String)
    ioc_type = Column(String)

    # ipquality
    suspicious = Column(Boolean)  # unsafe
    unsafe = Column(Boolean)  # unsafe
    risk_score = Column(Integer)
    malware = Column(Boolean)  # unsafe
    spamming = Column(Boolean)  # unsafe
    phishing = Column(Boolean)  # unsafe

    # urlscan.io
    ip_address = Column(String)
    country = Column(String)
    contacted_urls = Column(String)
    servers = Column(String)
    # alien_vault

    whois = Column(String)
    related_tags = Column(String)
