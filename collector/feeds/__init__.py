from .cisa_kev import CISAKEVFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed
from .malwarebazaar import MalwareBazaarFeed
from .nvd import NVDFeed
from .mitre_attack import MITREAttackFeed
from .otx import OTXFeed

ALL_FEEDS = [
    CISAKEVFeed(),
    ThreatFoxFeed(),
    URLhausFeed(),
    MalwareBazaarFeed(),
    NVDFeed(),
    MITREAttackFeed(),
    OTXFeed(),
]
