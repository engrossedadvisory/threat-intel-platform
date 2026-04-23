from .cisa_kev import CISAKEVFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed
from .malwarebazaar import MalwareBazaarFeed
from .nvd import NVDFeed
from .mitre_attack import MITREAttackFeed
from .otx import OTXFeed
from .darkweb_tor import DarkWebFeed
from .cert_transparency import CertTransparencyFeed
from .rss_feeds import SecurityRSSFeed
from .github_monitor import GithubMonitorFeed

ALL_FEEDS = [
    CISAKEVFeed(),
    ThreatFoxFeed(),
    URLhausFeed(),
    MalwareBazaarFeed(),
    NVDFeed(),
    MITREAttackFeed(),
    OTXFeed(),
    DarkWebFeed(),         # always registered; configure() controls enablement at runtime
    CertTransparencyFeed(),
    SecurityRSSFeed(),
    GithubMonitorFeed(),
]
