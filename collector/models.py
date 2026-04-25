import os
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text,
    Float, ForeignKey, DateTime, JSON, Boolean,
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


class DarkWebMention(Base):
    __tablename__ = "dark_web_mentions"
    id              = Column(Integer, primary_key=True, index=True)
    source_name     = Column(String(200))
    source_url      = Column(String(500))
    keyword_matched = Column(String(200), index=True)
    title           = Column(String(500))
    snippet         = Column(Text)
    actor_handle    = Column(String(100))
    record_estimate = Column(String(100))
    data_types      = Column(JSON, default=list)
    severity        = Column(String(20), default="medium", index=True)
    ai_summary      = Column(Text)
    first_seen      = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc))
    last_seen       = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc))
    fingerprint     = Column(String(64), unique=True, index=True)


class PlatformSettings(Base):
    """Key/value store for runtime-configurable platform settings.
    Written by the WebUI admin panel; read by the collector at fetch time.
    Env vars act as fallback when a key is not yet in this table.
    """
    __tablename__ = "platform_settings"
    key        = Column(String(100), primary_key=True)
    value      = Column(Text)
    updated_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(100), default="admin")


class WatchedAsset(Base):
    """Assets belonging to the organisation that should be monitored across all feeds."""
    __tablename__ = "watched_assets"
    id         = Column(Integer, primary_key=True, index=True)
    asset_type = Column(String(50), index=True)   # domain, ip, cidr, email_domain, keyword
    value      = Column(String(500))
    label      = Column(String(200))              # human-readable description
    active     = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class WatchlistHit(Base):
    """Records when a watched asset appears in a feed or enrichment result."""
    __tablename__ = "watchlist_hits"
    id               = Column(Integer, primary_key=True, index=True)
    watched_asset_id = Column(Integer, ForeignKey("watched_assets.id"), index=True)
    hit_type         = Column(String(50))    # ioc_match, dark_web, cert, github, paste
    severity         = Column(String(20), default="high")
    source_feed      = Column(String(100))
    matched_value    = Column(String(500))
    context          = Column(Text)          # sanitised snippet
    alerted          = Column(Boolean, default=False)
    fingerprint      = Column(String(64), unique=True, index=True)
    found_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AlertChannel(Base):
    """Notification channels for watchlist hits."""
    __tablename__ = "alert_channels"
    id           = Column(Integer, primary_key=True, index=True)
    channel_type = Column(String(50))   # slack, teams, email
    label        = Column(String(200))
    config       = Column(JSON)         # {webhook_url, to_email, smtp_*}
    min_severity = Column(String(20), default="medium")
    active       = Column(Boolean, default=True)

class IOCEnrichment(Base):
    """VirusTotal / GreyNoise / Shodan enrichment results per IOC."""
    __tablename__ = "ioc_enrichments"
    id          = Column(Integer, primary_key=True, index=True)
    ioc_value   = Column(String(512), index=True)
    ioc_type    = Column(String(50))
    source      = Column(String(50))    # virustotal, greynoise, shodan
    score       = Column(Float)         # 0-100 maliciousness
    verdict     = Column(String(50))    # malicious, suspicious, benign, noise
    raw_data    = Column(JSON)
    enriched_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class CertMention(Base):
    """Certificate Transparency log entries for monitored domains."""
    __tablename__ = "cert_mentions"
    id               = Column(Integer, primary_key=True, index=True)
    watched_asset_id = Column(Integer, ForeignKey("watched_assets.id"), index=True)
    domain_matched   = Column(String(200))
    common_name      = Column(String(500))
    issuer           = Column(String(200))
    not_before       = Column(DateTime(timezone=True))
    not_after        = Column(DateTime(timezone=True))
    fingerprint      = Column(String(64), unique=True, index=True)
    found_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class GithubFinding(Base):
    """GitHub secret/credential scan results."""
    __tablename__ = "github_findings"
    id              = Column(Integer, primary_key=True, index=True)
    repo_full_name  = Column(String(500))
    file_path       = Column(String(500))
    keyword_matched = Column(String(200))
    snippet         = Column(Text)       # sanitised — no actual credentials
    severity        = Column(String(20), default="high")
    github_url      = Column(String(500))
    fingerprint     = Column(String(64), unique=True, index=True)
    found_at        = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Campaign(Base):
    """Grouped threat activity attributed to a single actor or operation."""
    __tablename__ = "campaigns"
    id           = Column(Integer, primary_key=True, index=True)
    name         = Column(String(200), unique=True)
    threat_actor = Column(String(200))
    description  = Column(Text)
    status       = Column(String(50), default="active")   # active, historical
    confidence   = Column(Integer, default=50)
    first_seen   = Column(DateTime(timezone=True))
    last_seen    = Column(DateTime(timezone=True))
    report_ids   = Column(JSON, default=list)
    ioc_ids      = Column(JSON, default=list)
    ttps         = Column(JSON, default=list)
    created_at   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class APIKey(Base):
    """API keys for the REST API — stored as SHA-256 hashes."""
    __tablename__ = "api_keys"
    id          = Column(Integer, primary_key=True, index=True)
    key_hash    = Column(String(64), unique=True, index=True)
    key_prefix  = Column(String(8))     # first 8 chars shown in UI (e.g. "vntl_abc")
    label       = Column(String(200))
    permissions = Column(JSON, default=list)   # ["read","write","taxii","admin"]
    active      = Column(Boolean, default=True)
    last_used   = Column(DateTime(timezone=True))
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ThreatBriefing(Base):
    """AI-generated threat intelligence briefings (daily or on-demand)."""
    __tablename__ = "threat_briefings"
    id                = Column(Integer, primary_key=True, index=True)
    briefing_type     = Column(String(50), default="daily")   # daily, on_demand
    title             = Column(String(500))
    executive_summary = Column(Text)
    key_findings      = Column(JSON, default=list)
    recommendations   = Column(JSON, default=list)
    trending_actors   = Column(JSON, default=list)
    risk_level        = Column(String(20), default="medium")
    ioc_count         = Column(Integer, default=0)
    report_count      = Column(Integer, default=0)
    period_hours      = Column(Integer, default=24)
    generated_at      = Column(DateTime(timezone=True),
                               default=lambda: datetime.now(timezone.utc))


class AssetThreatProfile(Base):
    """Per-asset AI threat assessment — updated each research cycle."""
    __tablename__ = "asset_threat_profiles"
    id                = Column(Integer, primary_key=True, index=True)
    watched_asset_id  = Column(Integer, ForeignKey("watched_assets.id"),
                               index=True, unique=True)
    risk_score        = Column(Integer, default=0)
    risk_level        = Column(String(20), default="low")
    matched_iocs      = Column(JSON, default=list)
    matched_actors    = Column(JSON, default=list)
    attack_vectors    = Column(JSON, default=list)
    recommendations   = Column(JSON, default=list)
    immediate_actions = Column(JSON, default=list)
    ai_assessment     = Column(Text)
    last_assessed     = Column(DateTime(timezone=True),
                               default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)
