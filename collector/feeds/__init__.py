from .cisa_kev import CISAKEVFeed
# URLhaus and ThreatFox removed — replaced by RansomwareLiveFeed and
# CybercrimeTrackerFeed which provide named threat actors and richer context.
from .malwarebazaar import MalwareBazaarFeed
from .nvd import NVDFeed
from .mitre_attack import MITREAttackFeed
from .otx import OTXFeed
from .darkweb_tor import DarkWebFeed
from .cert_transparency import CertTransparencyFeed
from .rss_feeds import SecurityRSSFeed
from .github_monitor import GithubMonitorFeed
from .feodo_tracker import FeodoTrackerFeed
from .sslbl import SSLBLFeed
from .openphish import OpenPhishFeed
from .dshield import DShieldFeed
from .ransomware_live import RansomwareLiveFeed
from .cybercrime_tracker import CybercrimeTrackerFeed

ALL_FEEDS = [
    CISAKEVFeed(),
    RansomwareLiveFeed(),       # replaces URLhaus — named actors, victims, industries
    CybercrimeTrackerFeed(),    # replaces ThreatFox — C2 panels with malware families
    MalwareBazaarFeed(),
    NVDFeed(),
    MITREAttackFeed(),
    OTXFeed(),
    DarkWebFeed(),              # always registered; configure() controls enablement at runtime
    CertTransparencyFeed(),
    SecurityRSSFeed(),
    GithubMonitorFeed(),
    FeodoTrackerFeed(),
    SSLBLFeed(),
    OpenPhishFeed(),
    DShieldFeed(),
]
