import os
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text,
    Float, ForeignKey, DateTime, JSON,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL") or (
    f"postgresql://{os.getenv('POSTGRES_USER','intel_admin')}"
    f":{os.getenv('POSTGRES_PASSWORD','change_me')}"
    f"@{os.getenv('POSTGRES_HOST','db')}:5432"
    f"/{os.getenv('POSTGRES_DB','threat_intel')}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ThreatReport(Base):
    __tablename__ = "threat_reports"
    id = Column(Integer, primary_key=True, index=True)
    source_feed = Column(String(100), index=True)
    source_id = Column(String(255), unique=True, index=True)
    threat_actor = Column(String(255), default="Unknown")
    target_industry = Column(String(255), default="Unknown")
    ttps = Column(JSON, default=list)
    associated_cves = Column(JSON, default=list)
    confidence_score = Column(Integer, default=0)
    summary = Column(Text)
    raw_source = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    iocs = relationship("IOC", back_populates="report", cascade="all, delete-orphan")


class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("threat_reports.id"), index=True)
    ioc_type = Column(String(50), index=True)
    value = Column(String(512))
    malware_family = Column(String(255))
    tags = Column(JSON, default=list)
    report = relationship("ThreatReport", back_populates="iocs")


class CVERecord(Base):
    __tablename__ = "cve_records"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True)
    description = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(255))
    vendor = Column(String(255))
    product = Column(String(255))
    cisa_due_date = Column(String(50))
    is_kev = Column(Integer, default=0)
    published_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class FeedStatus(Base):
    __tablename__ = "feed_status"
    id = Column(Integer, primary_key=True, index=True)
    feed_name = Column(String(100), unique=True, index=True)
    last_run = Column(DateTime(timezone=True))
    last_success = Column(DateTime(timezone=True))
    records_fetched = Column(Integer, default=0)
    total_records = Column(Integer, default=0)
    status = Column(String(50), default="pending")
    error_message = Column(Text)


Base.metadata.create_all(bind=engine)
