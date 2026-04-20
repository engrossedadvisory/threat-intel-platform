import os
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text,
    Float, ForeignKey, DateTime, JSON,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from sqlalchemy.engine import URL as _URL

# Use URL.create() so passwords with special characters ($, !, @, etc.)
# are passed safely without requiring percent-encoding in the env file.
engine = create_engine(
    _URL.create(
        drivername="postgresql+psycopg2",
        username=os.getenv("POSTGRES_USER", "intel_admin"),
        password=os.getenv("POSTGRES_PASSWORD", "change_me"),
        host=os.getenv("POSTGRES_HOST", "db"),
        port=5432,
        database=os.getenv("POSTGRES_DB", "threat_intel"),
    ),
    pool_pre_ping=True,
)
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


class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"
    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), unique=True, index=True)  # T1566.001
    stix_id = Column(String(100), unique=True)
    name = Column(String(255))
    tactic = Column(String(500))    # comma-separated tactic names
    description = Column(Text)
    mitigations = relationship(
        "MITREMitigation", back_populates="technique", cascade="all, delete-orphan"
    )


class MITREMitigation(Base):
    __tablename__ = "mitre_mitigations"
    id = Column(Integer, primary_key=True, index=True)
    technique_fk = Column(Integer, ForeignKey("mitre_techniques.id"), index=True)
    mitigation_id = Column(String(20))   # M1234
    name = Column(String(255))
    description = Column(Text)
    technique = relationship("MITRETechnique", back_populates="mitigations")


Base.metadata.create_all(bind=engine)
