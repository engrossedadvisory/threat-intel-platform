import os

from .cisa_kev import CISAKEVFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed
from .malwarebazaar import MalwareBazaarFeed
from .nvd import NVDFeed
from .mitre_attack import MITREAttackFeed
from .otx import OTXFeed
from .darkweb_tor import DarkWebFeed

_DARK_WEB_ENABLED = os.getenv("DARK_WEB_ENABLED", "false").lower() in ("1", "true", "yes")

ALL_FEEDS = [
    CISAKEVFeed(),
    ThreatFoxFeed(),
    URLhausFeed(),
    MalwareBazaarFeed(),
    NVDFeed(),
    MITREAttackFeed(),
    OTXFeed(),
]

# Only register the dark web feed if explicitly enabled
if _DARK_WEB_ENABLED:
    ALL_FEEDS.append(DarkWebFeed())
