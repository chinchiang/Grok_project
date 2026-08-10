"""SOC CTI Dashboard configuration — Taiwan timezone, layers, TW industry watchlist."""

from __future__ import annotations

import os
from pathlib import Path
from zoneinfo import ZoneInfo

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cti.db"

TZ_TAIPEI = ZoneInfo("Asia/Taipei")

# Scheduled harvests: 07:00 and 15:00 Asia/Taipei
SCHEDULE_HOURS = (7, 15)

# Manual scan cooldown (seconds)
MANUAL_SCAN_COOLDOWN_SEC = 30 * 60

# --- API security ---
# When set, POST /api/scan/manual requires X-API-Key or Authorization: Bearer <key>
API_KEY = (os.environ.get("SOC_CTI_API_KEY") or os.environ.get("API_KEY") or "").strip()
# Comma-separated allowed origins. Default: the port run.py actually serves on
# (8787) — the bundled frontend is same-origin, so CORS only matters when the UI
# is hosted separately. Production: CORS_ORIGINS=https://chinchiang.github.io,…
_CORS_RAW = (
    os.environ.get("CORS_ORIGINS")
    or "http://127.0.0.1:8787,http://localhost:8787"
).strip()
CORS_ORIGINS = [o.strip() for o in _CORS_RAW.split(",") if o.strip()]

# Public feeds
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
# GitHub mirror when cisa.gov is blocked (cisagov maintains KEV data)
CISA_KEV_GITHUB_MIRROR = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json"
)
# Alternate community mirrors
CISA_KEV_MIRRORS = (
    CISA_KEV_URL,
    CISA_KEV_GITHUB_MIRROR,
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/"
    "cisa/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
# Official CISA advisory RSS (often blocked by Akamai/WAF from some networks)
CISA_ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_ICS_MEDICAL_RSS = (
    "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
)
CISA_ALERTS_RSS = "https://www.cisa.gov/cybersecurity-advisories/alerts.xml"
CISA_CYBER_ADVISORIES_RSS = (
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
)
CISA_NEWS_RSS = "https://www.cisa.gov/news.xml"
CISA_ADVISORIES_RSS_CANDIDATES = (
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    CISA_ICS_MEDICAL_RSS,
)

# --- OT/IT 官方與政府級預警來源（優先訂閱）---
# National CERTs / civil cyber agencies. Prefer official RSS; Google News site:
# mirrors for WAF / cloud-egress blocks (GitHub Actions).
NCSC_UK_ALL_RSS = "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
NCSC_UK_REPORT_RSS = "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"
NCSC_UK_NEWS_RSS = "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"
JPCERT_EN_RSS = "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"
JPCERT_JA_RSS = "https://www.jpcert.or.jp/rss/jpcert.rdf"
CIS_ADVISORIES_RSS = "https://www.cisecurity.org/feed/advisories"
CIS_ALERTS_RSS = "https://www.cisecurity.org/feed/alert"
# ACSC / CCCS / CERT-EU / NSA often lack stable public RSS → GNews site mirrors
ACSC_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:cyber.gov.au+(advisory+OR+alert+OR+vulnerability+OR+ransomware+OR+OT+OR+ICS)"
    "&hl=en-AU&gl=AU&ceid=AU:en"
)
CCCS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:cyber.gc.ca+(advisory+OR+alert+OR+vulnerability+OR+ransomware+OR+ICS)"
    "&hl=en-CA&gl=CA&ceid=CA:en"
)
CERT_EU_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:cert.europa.eu+(advisory+OR+alert+OR+vulnerability+OR+threat)"
    "&hl=en-US&gl=US&ceid=US:en"
)
NSA_CYBER_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:nsa.gov+(cybersecurity+advisory+OR+%22Cybersecurity+Advisory%22+OR+CSA)"
    "&hl=en-US&gl=US&ceid=US:en"
)
BSI_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:bsi.bund.de+(Cyber-Sicherheitswarnung+OR+advisory+OR+Schwachstelle+OR+ICS)"
    "&hl=de&gl=DE&ceid=DE:de"
)
# Community mirror of CISA ICS advisories (CSV) — used when official RSS returns 403
# https://github.com/icsadvprj/ICS-Advisory-Project
CISA_ICS_GITHUB_API = (
    "https://api.github.com/repos/icsadvprj/ICS-Advisory-Project/contents/ICS-CERT_ADV"
)
CISA_ICS_MAX_ITEMS = 40
# Fallback / mirror-friendly ransomware & breach news RSS
BLEEPING_RSS = "https://www.bleepingcomputer.com/feed/"
THEHACKERNEWS_RSS = "https://feeds.feedburner.com/TheHackersNews"

# --- Additional OSINT news / research / PSIRT / EPSS / OTX ---
UNIT42_RSS = "https://unit42.paloaltonetworks.com/feed/"
DATABREACHES_RSS = "https://databreaches.net/feed/"
# Reuters cybersecurity via Google News (official Reuters RSS is limited)
REUTERS_CYBER_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:reuters.com+(cyber+OR+cybersecurity+OR+ransomware+OR+hack+OR+breach+OR+malware)"
    "&hl=en-US&gl=US&ceid=US:en"
)
# Cyber Security News often 403 on direct feed → Google News mirror
CYBERSECURITYNEWS_RSS = "https://cybersecuritynews.com/feed/"
CYBERSECURITYNEWS_GNEWS_RSS = (
    "https://news.google.com/rss/search?q=site:cybersecuritynews.com"
    "&hl=en-US&gl=US&ceid=US:en"
)
SECURITYWEEK_RSS = "https://www.securityweek.com/feed/"
THERECORD_RSS = "https://therecord.media/feed/"
# Record Media may block datacenter IPs (GitHub Actions) → Google News fallback
THERECORD_GNEWS_RSS = (
    "https://news.google.com/rss/search?q=site:therecord.media"
    "+(cyber+OR+ransomware+OR+breach+OR+hack+OR+malware)"
    "&hl=en-US&gl=US&ceid=US:en"
)
# Dragos OT research — site may block bots; Google News fallback
DRAGOS_RSS_CANDIDATES = (
    "https://www.dragos.com/feed/",
    "https://www.dragos.com/blog/feed/",
)
DRAGOS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:dragos.com+(OT+OR+ICS+OR+industrial+OR+advisory+OR+threat)"
    "&hl=en-US&gl=US&ceid=US:en"
)
# —— 2. 專業 OT／ICS 威脅研究機構 ——
CLAROTY_RSS_CANDIDATES = (
    "https://claroty.com/feed",
    "https://claroty.com/blog/feed",
    "https://claroty.com/team82/research/rss",
)
CLAROTY_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:claroty.com+(Team82+OR+OT+OR+ICS+OR+SCADA+OR+CPS+OR+vulnerability)"
    "&hl=en-US&gl=US&ceid=US:en"
)
NOZOMI_RSS_CANDIDATES = (
    "https://www.nozominetworks.com/blog/feed",
    "https://www.nozominetworks.com/feed",
)
NOZOMI_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:nozominetworks.com+(OT+OR+ICS+OR+IoT+OR+vulnerability+OR+report)"
    "&hl=en-US&gl=US&ceid=US:en"
)
SANS_ICS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:sans.org+(ICS+OR+%22industrial+control%22+OR+%22OT+security%22+OR+SCADA)"
    "&hl=en-US&gl=US&ceid=US:en"
)
# —— 3. 產業新聞與專題媒體（ICS/OT 專區）——
SECURITYWEEK_ICS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:securityweek.com+(ICS+OR+OT+OR+SCADA+OR+%22industrial+control%22+OR+PLC)"
    "&hl=en-US&gl=US&ceid=US:en"
)
INDUSTRIAL_CYBER_RSS = "https://industrialcyber.co/feed/"
INDUSTRIAL_CYBER_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:industrialcyber.co+(OT+OR+ICS+OR+SCADA+OR+vulnerability)"
    "&hl=en-US&gl=US&ceid=US:en"
)
DARKREADING_ICS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:darkreading.com+(ICS+OR+OT+OR+SCADA+OR+%22industrial+control%22"
    "+OR+path:/ics-ot-security)"
    "&hl=en-US&gl=US&ceid=US:en"
)
THN_ICS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:thehackernews.com+(ICS+OR+SCADA+OR+%22industrial+control%22+OR+PLC+OR+OT+security)"
    "&hl=en-US&gl=US&ceid=US:en"
)
INFOSECURITY_ICS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:infosecurity-magazine.com+(ICS+OR+OT+OR+SCADA+OR+%22industrial+control%22)"
    "&hl=en-US&gl=US&ceid=US:en"
)
# Fortinet PSIRT / FortiGuard IR advisories
FORTINET_PSIRT_RSS = "https://www.fortiguard.com/rss/ir.xml"
# AlienVault OTX (optional API key for pulse stream)
OTX_API_KEY = (os.environ.get("OTX_API_KEY") or "").strip()
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_PULSE_ACTIVITY_URL = "https://otx.alienvault.com/api/v1/pulses/activity"
OTX_MAX_PULSES = int(os.environ.get("OTX_MAX_PULSES") or "25")
# FIRST EPSS — top scores as predictive exploit intel (public API)
EPSS_TOP_URL = "https://api.first.org/data/v1/epss"
EPSS_TOP_LIMIT = int(os.environ.get("EPSS_TOP_LIMIT") or "30")
EPSS_TOP_MIN = float(os.environ.get("EPSS_TOP_MIN") or "0.5")
# Independent P2 scoring threshold (R2-3). Defaults to EPSS_TOP_MIN so behaviour
# is unchanged unless operator sets EPSS_P2_THRESHOLD explicitly.
EPSS_P2_THRESHOLD = float(os.environ.get("EPSS_P2_THRESHOLD") or EPSS_TOP_MIN)

# abuse.ch ThreatFox — free recent JSON export; Auth-Key optional for API
# https://threatfox.abuse.ch/export/ / https://threatfox.abuse.ch/api/
ABUSECH_AUTH_KEY = (
    os.environ.get("ABUSECH_AUTH_KEY") or os.environ.get("THREATFOX_API_KEY") or ""
).strip()
THREATFOX_RECENT_EXPORT = "https://threatfox.abuse.ch/export/json/recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_MAX_FAMILIES = int(os.environ.get("THREATFOX_MAX_FAMILIES") or "35")
THREATFOX_MIN_CONFIDENCE = int(os.environ.get("THREATFOX_MIN_CONFIDENCE") or "50")

# --- Source reliability classes (R3-1) ---
# Admiralty-style source-reliability axis, kept separate from the credibility
# (evidence-count) axis. Only authoritative classes may be rated "credible" on a
# SINGLE source; media/community/osint need >= 2 independent sources. This stops
# one ICS/OT news article that merely mentions a watchlist company + "ransomware"
# from passing the TW+ransomware P0 gate in assign_priority().
SOURCE_CLASS_OFFICIAL_GOV = "official-gov"   # CISA / TWCERT / NCSC / JPCERT / CIS …
SOURCE_CLASS_VENDOR_PSIRT = "vendor-psirt"   # Fortinet PSIRT / MSRC / MS Security Blog
SOURCE_CLASS_RESEARCH = "research"           # Unit 42 / Dragos / Claroty / Nozomi / DFIR
SOURCE_CLASS_MEDIA = "media"                 # trade press (Dark Reading, THN, SecurityWeek…)
SOURCE_CLASS_COMMUNITY = "community"         # community IOC feeds (OTX, ThreatFox)
SOURCE_CLASS_OSINT = "osint"                 # X / leak sites / dark-web indirect

# source_id → reliability class. Anything unlisted defaults to "media"
# (conservative: unlisted sources never get single-source credible).
SOURCE_CLASS_REGISTRY: dict[str, str] = {
    # ① Official / government
    "cisa_ics_medical_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "cisa_alerts_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "cisa_cyber_advisories_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "cisa_news_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "cisa_ics_advisories": SOURCE_CLASS_OFFICIAL_GOV,
    "ncsc_uk_all_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "jpcert_en_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "cis_advisories_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "acsc_gnews": SOURCE_CLASS_OFFICIAL_GOV,
    "cccs_gnews": SOURCE_CLASS_OFFICIAL_GOV,
    "cert_eu_gnews": SOURCE_CLASS_OFFICIAL_GOV,
    "nsa_cyber_gnews": SOURCE_CLASS_OFFICIAL_GOV,
    "bsi_gnews": SOURCE_CLASS_OFFICIAL_GOV,
    "twcert_news_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "twcert_tvn_rss": SOURCE_CLASS_OFFICIAL_GOV,
    "twcert_rss": SOURCE_CLASS_OFFICIAL_GOV,
    # ② Vendor PSIRT / vendor official security comms
    "fortinet_psirt": SOURCE_CLASS_VENDOR_PSIRT,
    "msrc_update_guide": SOURCE_CLASS_VENDOR_PSIRT,
    "ms_security_blog": SOURCE_CLASS_VENDOR_PSIRT,
    "ms_defender_ti_blog": SOURCE_CLASS_VENDOR_PSIRT,
    # ③ First-party threat research
    "unit42_rss": SOURCE_CLASS_RESEARCH,
    "dragos_ot_rss": SOURCE_CLASS_RESEARCH,
    "claroty_team82_rss": SOURCE_CLASS_RESEARCH,
    "nozomi_labs_rss": SOURCE_CLASS_RESEARCH,
    "sans_ics_gnews": SOURCE_CLASS_RESEARCH,
    "sans_isc_rss": SOURCE_CLASS_RESEARCH,
    "dfir_report_rss": SOURCE_CLASS_RESEARCH,
    # ④ Trade press — single report is NOT credible (needs corroboration)
    "securityweek_rss": SOURCE_CLASS_MEDIA,
    "securityweek_ics_gnews": SOURCE_CLASS_MEDIA,
    "industrial_cyber_rss": SOURCE_CLASS_MEDIA,
    "darkreading_rss": SOURCE_CLASS_MEDIA,
    "darkreading_ics_gnews": SOURCE_CLASS_MEDIA,
    "thn_news_rss": SOURCE_CLASS_MEDIA,
    "thn_ics_gnews": SOURCE_CLASS_MEDIA,
    "infosecurity_ics_gnews": SOURCE_CLASS_MEDIA,
    "therecord_rss": SOURCE_CLASS_MEDIA,
    "reuters_cyber_gnews": SOURCE_CLASS_MEDIA,
    "cybersecuritynews_rss": SOURCE_CLASS_MEDIA,
    "bleeping_news_rss": SOURCE_CLASS_MEDIA,
    "krebs_rss": SOURCE_CLASS_MEDIA,
    "databreaches_rss": SOURCE_CLASS_MEDIA,
    "ms_vuln_gnews": SOURCE_CLASS_MEDIA,
    # ⑤ Community IOC / OSINT
    "otx_pulses": SOURCE_CLASS_COMMUNITY,
    "abusech_threatfox": SOURCE_CLASS_COMMUNITY,
    "x_osint_accounts": SOURCE_CLASS_OSINT,
    "ransomware_live": SOURCE_CLASS_OSINT,
    "ransomlook": SOURCE_CLASS_OSINT,
}

# Tag fallback for sources not in the registry (e.g. feeds added later).
_TAG_CLASS_HINTS: tuple[tuple[str, str], ...] = (
    ("official-gov", SOURCE_CLASS_OFFICIAL_GOV),
    ("ot-gov", SOURCE_CLASS_OFFICIAL_GOV),
    ("psirt", SOURCE_CLASS_VENDOR_PSIRT),
    ("ot-research", SOURCE_CLASS_RESEARCH),
    ("ot-media", SOURCE_CLASS_MEDIA),
)


def derive_source_class(
    source_id: str = "", extra_tags: list[str] | None = None
) -> str:
    """Resolve a source's reliability class: registry → tags → conservative default."""
    if source_id and source_id in SOURCE_CLASS_REGISTRY:
        return SOURCE_CLASS_REGISTRY[source_id]
    tags = {str(t).lower() for t in (extra_tags or [])}
    for tag, cls in _TAG_CLASS_HINTS:
        if tag in tags:
            return cls
    return SOURCE_CLASS_MEDIA


# Registered multi-layer news/research feeds collected each harvest
# force_all=True keeps all items (general news), False filters to CTI-relevant
INTEL_FEEDS: list[dict] = [
    {
        "source_id": "unit42_rss",
        "layer_id": "L2",
        "name": "Palo Alto Unit 42",
        "url": UNIT42_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "fortinet_psirt",
        "layer_id": "L2",
        "name": "Fortinet PSIRT",
        "url": FORTINET_PSIRT_RSS,
        "force_all": True,
        "max_items": 30,
        "darkweb_indirect": False,
    },
    {
        "source_id": "databreaches_rss",
        "layer_id": "L5",
        "name": "DataBreaches.net",
        "url": DATABREACHES_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "reuters_cyber_gnews",
        "layer_id": "L6",
        "name": "Reuters Cyber (Google News)",
        "url": REUTERS_CYBER_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "cybersecuritynews_rss",
        "layer_id": "L6",
        "name": "Cyber Security News",
        "url": CYBERSECURITYNEWS_RSS,
        "fallback_url": CYBERSECURITYNEWS_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "securityweek_rss",
        "layer_id": "L6",
        "name": "SecurityWeek",
        "url": SECURITYWEEK_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "thn_news_rss",
        "layer_id": "L6",
        "name": "The Hacker News",
        "url": THEHACKERNEWS_RSS,
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
    },
    {
        "source_id": "therecord_rss",
        "layer_id": "L6",
        "name": "The Record",
        "url": THERECORD_RSS,
        "fallback_url": THERECORD_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "bleeping_news_rss",
        "layer_id": "L6",
        "name": "BleepingComputer",
        "url": BLEEPING_RSS,
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
    },
    # Official blogs for accounts that also exist on X — prefer RSS over X (dedupe)
    {
        "source_id": "krebs_rss",
        "layer_id": "L6",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
    },
    {
        "source_id": "darkreading_rss",
        "layer_id": "L6",
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "fallback_url": (
            "https://news.google.com/rss/search?q=site:darkreading.com"
            "+(cyber+OR+ransomware+OR+breach+OR+vulnerability)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "dfir_report_rss",
        "layer_id": "L6",
        "name": "The DFIR Report",
        "url": "https://thedfirreport.com/feed/",
        "force_all": True,
        "max_items": 12,
        "darkweb_indirect": False,
    },
    {
        "source_id": "sans_isc_rss",
        "layer_id": "L6",
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "fallback_url": "https://isc.sans.edu/rssfeed.xml",
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
    },
    {
        "source_id": "dragos_ot_rss",
        "layer_id": "L7",
        "name": "Dragos (OT)",
        "url": DRAGOS_RSS_CANDIDATES[0],
        "fallback_url": DRAGOS_RSS_CANDIDATES[1],
        "fallback_urls": [DRAGOS_GNEWS_RSS],
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-research", "ot-vendor", "dragos"],
        "title_prefix": "🔬 Dragos",
    },
    # —— 2. 專業 OT／ICS 威脅研究機構 ——
    {
        "source_id": "claroty_team82_rss",
        "layer_id": "L7",
        "name": "Claroty Team82",
        "url": CLAROTY_RSS_CANDIDATES[0],
        "fallback_url": CLAROTY_RSS_CANDIDATES[1],
        "fallback_urls": [CLAROTY_RSS_CANDIDATES[2], CLAROTY_GNEWS_RSS],
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-research", "ot-vendor", "claroty", "cps"],
        "title_prefix": "🔬 Claroty",
    },
    {
        "source_id": "nozomi_labs_rss",
        "layer_id": "L7",
        "name": "Nozomi Networks Labs",
        "url": NOZOMI_RSS_CANDIDATES[0],
        "fallback_url": NOZOMI_RSS_CANDIDATES[1],
        "fallback_urls": [NOZOMI_GNEWS_RSS],
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-research", "ot-vendor", "nozomi"],
        "title_prefix": "🔬 Nozomi",
    },
    {
        "source_id": "sans_ics_gnews",
        "layer_id": "L7",
        "name": "SANS ICS (Google News)",
        "url": SANS_ICS_GNEWS_RSS,
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-research", "sans-ics"],
        "title_prefix": "📚 SANS ICS",
    },
    # —— 3. 產業新聞與專題媒體（ICS/OT）——
    {
        "source_id": "securityweek_ics_gnews",
        "layer_id": "L7",
        "name": "SecurityWeek ICS/OT",
        "url": SECURITYWEEK_ICS_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-media", "securityweek", "ics"],
        "title_prefix": "📰 SW ICS/OT",
    },
    {
        "source_id": "industrial_cyber_rss",
        "layer_id": "L7",
        "name": "Industrial Cyber",
        "url": INDUSTRIAL_CYBER_RSS,
        "fallback_url": INDUSTRIAL_CYBER_GNEWS_RSS,
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-media", "industrial-cyber"],
        "title_prefix": "📰 Industrial Cyber",
    },
    {
        "source_id": "darkreading_ics_gnews",
        "layer_id": "L7",
        "name": "Dark Reading ICS/OT",
        "url": DARKREADING_ICS_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-media", "darkreading", "ics"],
        "title_prefix": "📰 DR ICS/OT",
    },
    {
        "source_id": "thn_ics_gnews",
        "layer_id": "L7",
        "name": "The Hacker News ICS",
        "url": THN_ICS_GNEWS_RSS,
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-media", "thn", "ics"],
        "title_prefix": "📰 THN ICS",
    },
    {
        "source_id": "infosecurity_ics_gnews",
        "layer_id": "L7",
        "name": "Infosecurity Magazine ICS",
        "url": INFOSECURITY_ICS_GNEWS_RSS,
        "force_all": True,
        "max_items": 12,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-media", "infosecurity", "ics"],
        "title_prefix": "📰 Infosec ICS",
    },
    # —— 1. 官方與政府級預警來源（優先訂閱）OT/IT ——
    # CISA family (US) — ICS / alerts / cyber advisories / news
    {
        "source_id": "cisa_ics_medical_rss",
        "layer_id": "L7",
        "name": "CISA ICS Medical Advisories",
        "url": CISA_ICS_MEDICAL_RSS,
        "fallback_url": (
            "https://news.google.com/rss/search?"
            "q=site:cisa.gov+(ICSMA+OR+%22ICS+Medical%22+OR+medical+device)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
        "extra_tags": ["ot", "ot-gov", "official-gov", "cisa", "ics", "medical"],
        "title_prefix": "🏥 CISA ICSMA",
    },
    {
        "source_id": "cisa_alerts_rss",
        "layer_id": "L1",
        "name": "CISA Alerts",
        "url": CISA_ALERTS_RSS,
        "fallback_url": (
            "https://news.google.com/rss/search?"
            "q=site:cisa.gov+(Alert+OR+AA2+OR+%22Cybersecurity+Alert%22)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "cisa", "alert"],
        "title_prefix": "🚨 CISA Alert",
    },
    {
        "source_id": "cisa_cyber_advisories_rss",
        "layer_id": "L1",
        "name": "CISA Cybersecurity Advisories",
        "url": CISA_CYBER_ADVISORIES_RSS,
        "fallback_url": (
            "https://news.google.com/rss/search?"
            "q=site:cisa.gov+%22Cybersecurity+Advisory%22"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 30,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "cisa", "advisory"],
        "title_prefix": "🇺🇸 CISA CSA",
    },
    {
        "source_id": "cisa_news_rss",
        "layer_id": "L1",
        "name": "CISA News",
        "url": CISA_NEWS_RSS,
        "fallback_url": (
            "https://news.google.com/rss/search?"
            "q=site:cisa.gov/news+(cyber+OR+critical+infrastructure+OR+ICS)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "official-gov", "cisa", "news"],
        "title_prefix": "🇺🇸 CISA News",
    },
    # UK NCSC
    {
        "source_id": "ncsc_uk_all_rss",
        "layer_id": "L2",
        "name": "UK NCSC (all)",
        "url": NCSC_UK_ALL_RSS,
        "fallback_url": NCSC_UK_REPORT_RSS,
        "fallback_urls": [NCSC_UK_NEWS_RSS],
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "ncsc", "uk"],
        "title_prefix": "🇬🇧 NCSC",
    },
    # JPCERT/CC (Japan — electronics supply-chain adjacent)
    {
        "source_id": "jpcert_en_rss",
        "layer_id": "L2",
        "name": "JPCERT/CC (EN)",
        "url": JPCERT_EN_RSS,
        "fallback_url": JPCERT_JA_RSS,
        "fallback_urls": [
            "https://news.google.com/rss/search?"
            "q=site:jpcert.or.jp+(advisory+OR+alert+OR+vulnerability+OR+ICS)"
            "&hl=en-US&gl=US&ceid=US:en"
        ],
        "force_all": True,
        "max_items": 25,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "jpcert", "jp"],
        "title_prefix": "🇯🇵 JPCERT",
    },
    # CIS (Multi-State ISAC / critical infrastructure alerts — US state/local)
    {
        "source_id": "cis_advisories_rss",
        "layer_id": "L2",
        "name": "CIS Advisories",
        "url": CIS_ADVISORIES_RSS,
        "fallback_url": CIS_ALERTS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "cis", "ms-isac"],
        "title_prefix": "🛡️ CIS",
    },
    # ACSC Australia (GNews mirror — stable public RSS varies)
    {
        "source_id": "acsc_gnews",
        "layer_id": "L2",
        "name": "ACSC Australia (Google News)",
        "url": ACSC_GNEWS_RSS,
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "acsc", "au"],
        "title_prefix": "🇦🇺 ACSC",
    },
    # CCCS Canada
    {
        "source_id": "cccs_gnews",
        "layer_id": "L2",
        "name": "CCCS Canada (Google News)",
        "url": CCCS_GNEWS_RSS,
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "cccs", "ca"],
        "title_prefix": "🇨🇦 CCCS",
    },
    # CERT-EU
    {
        "source_id": "cert_eu_gnews",
        "layer_id": "L2",
        "name": "CERT-EU (Google News)",
        "url": CERT_EU_GNEWS_RSS,
        "force_all": True,
        "max_items": 15,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "cert-eu", "eu"],
        "title_prefix": "🇪🇺 CERT-EU",
    },
    # NSA Cybersecurity Advisories
    {
        "source_id": "nsa_cyber_gnews",
        "layer_id": "L1",
        "name": "NSA Cybersecurity Advisories (Google News)",
        "url": NSA_CYBER_GNEWS_RSS,
        "force_all": True,
        "max_items": 12,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "nsa"],
        "title_prefix": "🇺🇸 NSA CSA",
    },
    # BSI Germany
    {
        "source_id": "bsi_gnews",
        "layer_id": "L2",
        "name": "BSI Germany (Google News)",
        "url": BSI_GNEWS_RSS,
        "force_all": True,
        "max_items": 12,
        "darkweb_indirect": False,
        "extra_tags": ["ot-it", "ot-gov", "official-gov", "bsi", "de"],
        "title_prefix": "🇩🇪 BSI",
    },
    # Microsoft official / TI (feeds into is_microsoft classification)
    {
        # microsoft.com /feed and /feed/atom often timeout from cloud egress (0 items
        # or 30s hang). Prefer Google News site: mirror first for reliability.
        "source_id": "ms_security_blog",
        "layer_id": "L2",
        "name": "Microsoft Security Blog",
        "url": (
            "https://news.google.com/rss/search?"
            "q=site:microsoft.com/en-us/security/blog"
            "+(security+OR+threat+OR+defender+OR+vulnerability+OR+ransomware+OR+CVE)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "fallback_url": (
            "https://news.google.com/rss/search?"
            "q=site:microsoft.com/en-us/security/blog"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "fallback_urls": [
            "https://www.microsoft.com/en-us/security/blog/feed/atom/",
            "https://www.microsoft.com/en-us/security/blog/feed/",
        ],
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "msrc_update_guide",
        "layer_id": "L1",
        "name": "MSRC Update Guide",
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "force_all": True,
        "max_items": 40,
        "darkweb_indirect": False,
    },
    {
        "source_id": "ms_defender_ti_blog",
        "layer_id": "L2",
        "name": "Microsoft Defender TI Blog",
        "url": "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftThreatProtectionBlog",
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    {
        "source_id": "ms_vuln_gnews",
        "layer_id": "L6",
        "name": "Microsoft Vuln (Google News)",
        "url": (
            "https://news.google.com/rss/search?"
            "q=Microsoft+(Windows+OR+Exchange+OR+SharePoint+OR+Defender+OR+Entra+OR+Azure)"
            "+(vulnerability+OR+exploit+OR+KEV+OR+zero-day)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
]

# --- L6 ransomware / dark-web indirect trackers ---
# Ransomware.live: free data dump (v2 REST often 404/rate-limited; data.* is reliable)
RANSOMWARE_LIVE_VICTIMS_URL = "https://data.ransomware.live/victims.json"
RANSOMWARE_LIVE_API_V2 = "https://api.ransomware.live/v2/recentvictims"
RANSOMWARE_LIVE_MAX_ITEMS = int(os.environ.get("RANSOMWARE_LIVE_MAX_ITEMS") or "60")
# Optional free PRO key: https://my.ransomware.live
RANSOMWARE_LIVE_API_KEY = (os.environ.get("RANSOMWARE_LIVE_API_KEY") or "").strip()
RANSOMWARE_LIVE_PRO_RECENT = "https://api-pro.ransomware.live/victims/recent"

# RansomLook (open API, no key for recent posts)
RANSOMLOOK_RECENT_URL = "https://www.ransomlook.io/api/recent"
RANSOMLOOK_RSS_URL = "https://www.ransomlook.io/rss.xml"
RANSOMLOOK_MAX_ITEMS = int(os.environ.get("RANSOMLOOK_MAX_ITEMS") or "60")

# X accounts: multi-mirror Nitter → blog RSS → Google News (no X API key).
# Nitter instances are flaky; always keep blog/gnews fallbacks.
#
# Dedupe policy (do NOT also collect X for these — already have primary feeds):
#   @TheHackersNews     → The Hacker News RSS
#   @BleepinComputer    → BleepingComputer RSS
#   @haveibeenpwned     → HIBP API (L5)
#   @briankrebs         → Krebs on Security RSS
#   @DarkReading        → Dark Reading RSS
#   @TheDFIRReport      → The DFIR Report RSS
#   @sans_isc           → SANS ISC RSS
X_NITTER_MIRRORS = (
    "https://nitter.net",
    "https://nitter.privacyredirect.com",
    "https://xcancel.com",
)
X_OSINT_ACCOUNTS = [
    # —— 一、暗網／勒索／地下威脅專攻 ——
    {
        "handle": "DailyDarkWeb",
        "category": "darkweb",
        "blog_rss": "https://dailydarkweb.net/feed/",
        "gnews_rss": (
            "https://news.google.com/rss/search?q=site:dailydarkweb.net"
            "+(breach+OR+ransomware+OR+leak+OR+hack+OR+dark)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/DailyDarkWeb",
        "max_items": 25,
    },
    {
        "handle": "DarkWebInformer",
        "category": "darkweb",
        "blog_rss": "https://darkwebinformer.com/rss/",
        "gnews_rss": (
            "https://news.google.com/rss/search?q=site:darkwebinformer.com"
            "+(breach+OR+ransomware+OR+leak+OR+hack+OR+dark)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/DarkWebInformer",
        "max_items": 25,
    },
    {
        "handle": "vxunderground",
        "category": "darkweb",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(vx-underground+OR+vxunderground+OR+%22@vxunderground%22)"
            "+(malware+OR+ransomware+OR+threat+OR+sample+OR+forum)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/vxunderground",
        "max_items": 15,
    },
    {
        "handle": "Gi7w0rm",
        "category": "darkweb",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(Gi7w0rm+OR+Gitworm+OR+%22@Gi7w0rm%22)"
            "+(malware+OR+ransomware+OR+telegram+OR+dark+OR+threat+OR+breach)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/Gi7w0rm",
        "max_items": 20,
    },
    {
        # Automated ransomware leak-site bot (complements Ransomware.live / RansomLook APIs)
        "handle": "ransomistan",
        "category": "darkweb",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(ransomistan+OR+%22@ransomistan%22+OR+%22Ransomware+Map%22)"
            "+(ransomware+OR+lockbit+OR+blackbasta+OR+victim+OR+leak)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/ransomistan",
        "max_items": 25,
    },
    {
        "handle": "MonThreat",
        "category": "darkweb",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(MonThreat+OR+ThreatMon+OR+%22@MonThreat%22)"
            "+(ransomware+OR+breach+OR+leak+OR+dark+web+OR+threat)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/MonThreat",
        "max_items": 15,
    },
    {
        "handle": "Bank_Security",
        "category": "darkweb",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22Bank_Security%22+OR+%22@Bank_Security%22)"
            "+(bank+OR+ransomware+OR+malware+OR+breach+OR+swift)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/Bank_Security",
        "max_items": 15,
    },
    # —— 二、頂尖記者／獨立研究員（X 為主）——
    {
        "handle": "campuscodi",
        "category": "news",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22Catalin+Cimpanu%22+OR+campuscodi)"
            "+(cyber+OR+ransomware+OR+breach+OR+vulnerability+OR+hack)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/campuscodi",
        "max_items": 12,
    },
    {
        "handle": "GossiTheDog",
        "category": "news",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22Kevin+Beaumont%22+OR+GossiTheDog)"
            "+(CVE+OR+exploit+OR+vulnerability+OR+ransomware+OR+zero-day)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/GossiTheDog",
        "max_items": 15,
    },
    {
        "handle": "cyb3rops",
        "category": "news",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22Florian+Roth%22+OR+cyb3rops+OR+Nextron)"
            "+(detection+OR+sigma+OR+malware+OR+DFIR+OR+threat)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/cyb3rops",
        "max_items": 12,
    },
    {
        "handle": "troyhunt",
        "category": "news",
        "blog_rss": "https://www.troyhunt.com/rss/",
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22Troy+Hunt%22+OR+troyhunt)"
            "+(breach+OR+pwned+OR+password+OR+leak)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/troyhunt",
        "max_items": 12,
    },
    # —— 三、專業媒體：BleepingComputer / DFIR Report 已用官方 RSS（見 INTEL_FEEDS）——
    # —— 四、OT／ICS 研究（SANS ICS 公開帳號）——
    {
        "handle": "SANSICS",
        "category": "ot-research",
        "blog_rss": None,
        "gnews_rss": (
            "https://news.google.com/rss/search?q="
            "(%22SANS+ICS%22+OR+SANSICS+OR+%22@SANSICS%22)"
            "+(ICS+OR+OT+OR+SCADA+OR+industrial+OR+security)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/SANSICS",
        "max_items": 15,
    },
]
# Backward-compatible alias
X_DARKWEB_ACCOUNTS = X_OSINT_ACCOUNTS
X_DARKWEB_MAX_ITEMS = int(os.environ.get("X_DARKWEB_MAX_ITEMS") or "20")
X_OSINT_MAX_ITEMS = X_DARKWEB_MAX_ITEMS
# Obsolete source_health rows to strip from layer dashboard
OBSOLETE_SOURCE_IDS = frozenset({"x_darkweb_accounts"})
# TWCERT/CC public RSS (official channels; old /tw/rss/rss.xml is 404)
# See https://www.twcert.org.tw/tw/cp-40-2835-507dc-1.html
TWCERT_NEWS_RSS = "https://www.twcert.org.tw/tw/rss-104-1.xml"  # 資安新聞
TWCERT_TVN_RSS = "https://www.twcert.org.tw/tw/rss-132-1.xml"  # TVN 漏洞公告（中文）
TWCERT_TVN_EN_RSS = "https://www.twcert.org.tw/en/rss-139-2.xml"  # TVN List（英文備援）
TWCERT_NEWS_EN_RSS = "https://www.twcert.org.tw/en/rss-104-2.xml"  # 資安新聞英文頁
# Actions/datacenter may get blocked → Google News fallbacks
TWCERT_TVN_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:twcert.org.tw+(TVN+OR+ICSA+OR+漏洞+OR+vulnerability)"
    "&hl=zh-TW&gl=TW&ceid=TW:zh-Hant"
)
TWCERT_NEWS_GNEWS_RSS = (
    "https://news.google.com/rss/search?"
    "q=site:twcert.org.tw+(資安+OR+ransomware+OR+漏洞)"
    "&hl=zh-TW&gl=TW&ceid=TW:zh-Hant"
)
# Backward-compatible alias used by older call sites
TWCERT_RSS = TWCERT_NEWS_RSS

# 7 intelligence layers (order = priority of trust)
LAYERS = [
    {
        "id": "L1",
        "name_zh": "官方權威漏洞",
        "name_en": "Official / Authority Vuln",
        "sources": [
            "CISA KEV",
            "CISA Alerts / Cybersecurity Advisories / News",
            "NSA Cybersecurity Advisories",
            "FIRST EPSS top scores",
            "CVE/NVD",
        ],
        "schedule_hint": "hourly / daily",
    },
    {
        "id": "L2",
        "name_zh": "國家 CERT／廠商 PSIRT",
        "name_en": "National CERT / Vendor PSIRT",
        "sources": [
            "TWCERT/CC（優先）",
            "UK NCSC",
            "JPCERT/CC",
            "CIS Advisories / MS-ISAC",
            "ACSC / CCCS / CERT-EU / BSI",
            "Fortinet PSIRT",
            "Palo Alto Unit 42",
            "Vendor PSIRT",
        ],
        "schedule_hint": "daily (gov CERTs = priority subscribe)",
    },
    {
        "id": "L3",
        "name_zh": "社群 IOC／工具",
        "name_en": "Community IOC / Tools",
        "sources": ["abuse.ch ThreatFox", "AlienVault OTX Pulse"],
        "schedule_hint": "daily (ThreatFox free export; OTX optional key)",
    },
    {
        "id": "L4",
        "name_zh": "外部攻擊面 (EASM)",
        "name_en": "External Attack Surface",
        "sources": ["Shodan InternetDB / API", "Censys host lookup"],
        "schedule_hint": "daily (InternetDB free with EASM_WATCH_IPS; keys optional)",
    },
    {
        "id": "L5",
        "name_zh": "外洩／憑證監控",
        "name_en": "Breach / Credential Monitor",
        "sources": ["Have I Been Pwned", "DataBreaches.net"],
        "schedule_hint": "daily",
    },
    {
        "id": "L6",
        "name_zh": "暗網間接情資",
        "name_en": "Indirect Dark Web",
        "sources": [
            "Ransomware.live",
            "RansomLook",
            "BleepingComputer",
            "The Hacker News",
            "Krebs on Security",
            "Dark Reading",
            "The DFIR Report",
            "SANS Internet Storm Center",
            "The Record",
            "SecurityWeek",
            "Cyber Security News",
            "Reuters (Google News)",
            "BleepingComputer / The DFIR Report (RSS)",
            "@DailyDarkWeb / @DarkWebInformer / @Gi7w0rm / @ransomistan (X)",
            "@vxunderground / @MonThreat / @Bank_Security (X)",
            "@campuscodi / @GossiTheDog / @cyb3rops / @troyhunt (X)",
        ],
        "schedule_hint": "07:00 & 15:00 + dual-source verify; X via Nitter/blog (no API key)",
    },
    {
        "id": "L7",
        "name_zh": "OT／ICS 專屬",
        "name_en": "OT / ICS Specialized",
        "sources": [
            "① CISA ICS／KEV／ICS 專區（優先，每日必查）",
            "ICS Advisory Project mirror + KEV 關聯",
            "② Dragos／Claroty Team82／Nozomi／SANS ICS",
            "③ SecurityWeek ICS／Industrial Cyber／Dark Reading ICS／THN ICS",
            "④ MITRE ATT&CK for ICS（知識庫）",
            "National CERTs (TWCERT／NCSC／JPCERT…)",
        ],
        "schedule_hint": "daily (gov + research + media; frameworks = reference)",
    },
]

# Full OT/IT source catalog (4 categories) for UI / docs / API
# cat: 1=gov priority, 2=research, 3=media, 4=framework (reference only)
OT_IT_SOURCE_CATALOG: list[dict] = [
    # —— 1. 官方與政府級預警（優先訂閱）——
    {
        "cat": 1,
        "id": "cisa_ics",
        "name": "CISA ICS Advisories",
        "url": "https://www.cisa.gov/news-events/ics-advisories",
        "role_zh": "美國 CISA 最核心 ICS／OT 漏洞預警（PLC、SCADA、HMI、工程軟體等），含 CVE 與緩解措施；幾乎每日更新。建議訂閱 RSS／Email，設為每日必查。",
        "role_en": "Core US CISA ICS/OT advisories (PLC/SCADA/HMI). Near-daily; CVE + mitigations. Subscribe RSS/email; daily must-check.",
        "usage_zh": "訂閱 RSS 或 Email；搭配 ICS Advisory Project 做視覺化與 CSV 匯出",
        "usage_en": "Subscribe RSS/Email; pair with ICS Advisory Project for dashboard/CSV",
        "layer": "L7",
        "ingest": "rss+csv_mirror",
        "priority": "daily_must",
    },
    {
        "cat": 1,
        "id": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "role_zh": "已確認遭實際利用的漏洞清單，含大量 ICS 相關項目；作為優先修補清單，與 ICS Advisories 交叉比對。",
        "role_en": "Confirmed in-the-wild vulns (many ICS-relevant). Patch priority list; cross-check with ICS Advisories.",
        "usage_zh": "優先修補清單；與 ICS Advisories 交叉比對",
        "usage_en": "Priority patch list; cross-check ICS Advisories",
        "layer": "L1",
        "ingest": "json",
        "priority": "daily_must",
    },
    {
        "cat": 1,
        "id": "cisa_ics_topic",
        "name": "CISA Industrial Control Systems 專區",
        "url": "https://www.cisa.gov/topics/industrial-control-systems",
        "role_zh": "彙整 ICS 指導文件、醫療設備建議、最佳實務；政策與框架參考。",
        "role_en": "ICS guidance hub: medical device advice, best practices, policy frameworks.",
        "usage_zh": "政策與框架參考（非即時 feed）",
        "usage_en": "Policy/framework reference (not a live feed)",
        "layer": "L7",
        "ingest": "reference",
        "priority": "reference",
    },
    {
        "cat": 1,
        "id": "ics_advisory_project",
        "name": "ICS Advisory Project",
        "url": "https://www.icsadvisoryproject.com/",
        "role_zh": "開源專案，將 CISA ICS Advisories 轉成 Dashboard + CSV，並提供 KEV 關聯分析。",
        "role_en": "Open project: CISA ICS → dashboard/CSV + KEV correlation.",
        "usage_zh": "內部資產漏洞對應與優先排序；本系統 CSV 鏡像備援",
        "usage_en": "Asset-to-vuln mapping; used as CSV mirror fallback",
        "layer": "L7",
        "ingest": "csv_mirror",
        "priority": "daily",
    },
    {
        "cat": 1,
        "id": "cisa_icsma",
        "name": "CISA ICS Medical Advisories",
        "url": "https://www.cisa.gov/news-events/ics-medical-advisories",
        "role_zh": "醫療器材／ICS 醫療安全公告",
        "role_en": "ICS medical device advisories",
        "usage_zh": "醫療／生命科學 OT 環境優先關注",
        "usage_en": "Priority for medical/life-science OT",
        "layer": "L7",
        "ingest": "rss",
        "priority": "daily",
    },
    {
        "cat": 1,
        "id": "twcert",
        "name": "TWCERT/CC",
        "url": "https://www.twcert.org.tw/",
        "role_zh": "台灣 CERT：資安新聞 + TVN 漏洞公告",
        "role_en": "Taiwan CERT: news + TVN",
        "usage_zh": "本地法規／供應鏈相關必訂",
        "usage_en": "Must-subscribe for local/regulatory context",
        "layer": "L2",
        "ingest": "rss",
        "priority": "daily",
    },
    # —— 2. 專業 OT／ICS 威脅研究機構 ——
    {
        "cat": 2,
        "id": "dragos",
        "name": "Dragos",
        "url": "https://www.dragos.com/blog",
        "role_zh": "工業控制系統威脅情報；Year in Review、威脅群體（PIPEDREAM、KAMACITE 等）、勒索對工業影響；常結合 MITRE ATT&CK for ICS。",
        "role_en": "ICS TI: Year in Review, groups (PIPEDREAM/KAMACITE), industrial ransomware; ATT&CK for ICS mapping.",
        "usage_zh": "威脅建模與 ATT&CK mapping 輸入",
        "usage_en": "Threat modeling & ATT&CK mapping input",
        "layer": "L7",
        "ingest": "rss",
        "priority": "high",
    },
    {
        "cat": 2,
        "id": "claroty",
        "name": "Claroty Team82",
        "url": "https://claroty.com/team82",
        "role_zh": "漏洞研究與 CPS 攻擊鏈分析；遠端存取協議濫用、HMI／SCADA 暴露。",
        "role_en": "Vuln research & CPS kill-chains; remote-access abuse, HMI/SCADA exposure.",
        "usage_zh": "外網暴露與遠端存取風險評估",
        "usage_en": "Internet exposure & remote-access risk",
        "layer": "L7",
        "ingest": "rss",
        "priority": "high",
    },
    {
        "cat": 2,
        "id": "nozomi",
        "name": "Nozomi Networks Labs",
        "url": "https://www.nozominetworks.com/blog",
        "role_zh": "OT／IoT Security Report：協議漏洞、攻擊趨勢、實際案例。",
        "role_en": "OT/IoT reports: protocol vulns, trends, case studies.",
        "usage_zh": "協議面威脅與趨勢研判",
        "usage_en": "Protocol-level threat & trends",
        "layer": "L7",
        "ingest": "rss",
        "priority": "high",
    },
    {
        "cat": 2,
        "id": "sans_ics",
        "name": "SANS ICS",
        "url": "https://www.sans.org",
        "role_zh": "State of ICS/OT Security 調查、白皮書、5 Critical Controls；X @SANSICS。",
        "role_en": "State of ICS/OT surveys, whitepapers, 5 Critical Controls; X @SANSICS.",
        "usage_zh": "實務控制框架與年度態勢",
        "usage_en": "Practical controls & annual posture",
        "layer": "L7",
        "ingest": "gnews+x",
        "priority": "high",
    },
    # —— 3. 產業新聞與專題媒體 ——
    {
        "cat": 3,
        "id": "securityweek_ics",
        "name": "SecurityWeek ICS/OT",
        "url": "https://www.securityweek.com/category/ics-ot/",
        "role_zh": "長期追蹤 ICS 漏洞、事件與會議（含 ICS Cybersecurity Conference）。",
        "role_en": "ICS vulns, incidents, conferences (ICS Cybersecurity Conference).",
        "usage_zh": "專題媒體掃描",
        "usage_en": "Specialist media scan",
        "layer": "L7",
        "ingest": "gnews",
        "priority": "media",
    },
    {
        "cat": 3,
        "id": "industrial_cyber",
        "name": "Industrial Cyber",
        "url": "https://industrialcyber.co/",
        "role_zh": "專注 OT／ICS／SCADA 新聞、報告與社群；更新頻率高。",
        "role_en": "OT/ICS/SCADA news, reports, community; high cadence.",
        "usage_zh": "高頻 OT 新聞流",
        "usage_en": "High-frequency OT news stream",
        "layer": "L7",
        "ingest": "rss",
        "priority": "media",
    },
    {
        "cat": 3,
        "id": "darkreading_ics",
        "name": "Dark Reading ICS/OT Security",
        "url": "https://www.darkreading.com/ics-ot-security",
        "role_zh": "實際攻擊案例、國家級威脅與技術分析。",
        "role_en": "Attack cases, nation-state threats, technical analysis.",
        "usage_zh": "案例與國家級威脅",
        "usage_en": "Cases & nation-state OT threats",
        "layer": "L7",
        "ingest": "gnews",
        "priority": "media",
    },
    {
        "cat": 3,
        "id": "thn_ics",
        "name": "The Hacker News (ICS Security)",
        "url": "https://thehackernews.com/search/label/ICS%20Security",
        "role_zh": "快速掌握重大 ICS 漏洞與事件。",
        "role_en": "Fast take on major ICS vulns/incidents.",
        "usage_zh": "重大事件快訊",
        "usage_en": "Breaking major ICS events",
        "layer": "L7",
        "ingest": "gnews",
        "priority": "media",
    },
    {
        "cat": 3,
        "id": "infosecurity_ics",
        "name": "Infosecurity Magazine (ICS)",
        "url": "https://www.infosecurity-magazine.com/",
        "role_zh": "轉載重要 ICS 漏洞統計與趨勢。",
        "role_en": "ICS vulnerability stats and trend coverage.",
        "usage_zh": "趨勢與統計補強",
        "usage_en": "Trend/stats reinforcement",
        "layer": "L7",
        "ingest": "gnews",
        "priority": "media",
    },
    # —— 4. 框架與知識庫（非即時，但極重要）——
    {
        "cat": 4,
        "id": "mitre_attack_ics",
        "name": "MITRE ATT&CK for ICS",
        "url": "https://attack.mitre.org/matrices/ics/",
        "role_zh": "ICS 專用戰術與技術矩陣（含 Inhibit Response Function 等 ICS 特有技術）；威脅建模與偵測對照基準。",
        "role_en": "ICS tactics/techniques matrix (e.g. Inhibit Response Function); baseline for threat modeling & detection mapping.",
        "usage_zh": "非即時新聞；威脅建模、偵測規則與報告對照必備",
        "usage_en": "Not live news; required for modeling, detection mapping, report alignment",
        "layer": "L7",
        "ingest": "reference",
        "priority": "framework",
    },
    {
        "cat": 4,
        "id": "mitre_attack_ics_techniques",
        "name": "MITRE ATT&CK for ICS — Techniques",
        "url": "https://attack.mitre.org/techniques/ics/",
        "role_zh": "ICS 技術清單（細項 T-codes），供 SIEM／狩獵規則映射。",
        "role_en": "ICS technique catalog for SIEM/hunt rule mapping.",
        "usage_zh": "對應 playbook 與偵測工程",
        "usage_en": "Map playbooks & detection engineering",
        "layer": "L7",
        "ingest": "reference",
        "priority": "framework",
    },
]

# Backward-compatible alias
OT_IT_GOV_PRIORITY_SOURCES = [s for s in OT_IT_SOURCE_CATALOG if s.get("cat") == 1]

# Taiwan electronics "Big 5" ODM/EMS + listed semiconductor / electronics manufacturing
TW_ELECTRONICS_WATCHLIST = [
    # 電子五哥（ODM：廣達／仁寶／英業達／緯創／和碩；不含鴻海）
    {"key": "quanta", "aliases": ["quanta computer", "quanta", "廣達", "2382"], "tier": "big5"},
    {"key": "compal", "aliases": ["compal", "仁寶", "2324"], "tier": "big5"},
    {"key": "inventec", "aliases": ["inventec", "英業達", "2356"], "tier": "big5"},
    {"key": "wistron", "aliases": ["wistron", "緯創", "3231"], "tier": "big5"},
    {"key": "pegatron", "aliases": ["pegatron", "和碩", "4938"], "tier": "big5"},
    # 鴻海為大型 EMS，非電子五哥
    {"key": "foxconn", "aliases": ["foxconn", "hon hai", "鴻海", "富士康", "2317"], "tier": "ems"},
    # 半導體／封測／IC 設計（上市櫃重點）
    {"key": "tsmc", "aliases": ["tsmc", "taiwan semiconductor", "台積電", "2330"], "tier": "semi"},
    {"key": "umc", "aliases": ["umc", "united microelectronics", "聯電", "2303"], "tier": "semi"},
    {"key": "ase", "aliases": ["ase technology", "ase group", "日月光", "3711", "asx"], "tier": "semi"},
    {"key": "mediatek", "aliases": ["mediatek", "聯發科", "2454"], "tier": "semi"},
    {"key": "novatek", "aliases": ["novatek", "聯詠", "3034"], "tier": "semi"},
    {"key": "realtek", "aliases": ["realtek", "瑞昱", "2379"], "tier": "semi"},
    {"key": "nanya", "aliases": ["nanya", "南亞科", "2408"], "tier": "semi"},
    {"key": "powerchip", "aliases": ["powerchip", "力積電", "6770"], "tier": "semi"},
    {"key": "vis", "aliases": ["vanguard international", "世界先進", "5347"], "tier": "semi"},
    {"key": "psmc", "aliases": ["psmc", "力成", "6239"], "tier": "semi"},
    {"key": "kyec", "aliases": ["kyec", "京元電子", "2449"], "tier": "semi"},
    {"key": "chipbond", "aliases": ["chipbond", "頎邦", "6147"], "tier": "semi"},
    {"key": "auo", "aliases": ["auo", "友達", "2409"], "tier": "display"},
    {"key": "innolux", "aliases": ["innolux", "群創", "3481"], "tier": "display"},
    {"key": "liteon", "aliases": ["lite-on", "liteon", "光寶", "2301"], "tier": "electronics"},
    {"key": "delta", "aliases": ["delta electronics", "台達電", "2308"], "tier": "electronics"},
    {"key": "asus", "aliases": ["asus", "華碩", "2357"], "tier": "electronics"},
    {"key": "acer", "aliases": ["acer", "宏碁", "2353"], "tier": "electronics"},
    {"key": "gigabyte", "aliases": ["gigabyte", "技嘉", "2376"], "tier": "electronics"},
    {"key": "msi", "aliases": ["micro-star", "msi ", "微星", "2377"], "tier": "electronics"},
    {"key": "advantech", "aliases": ["advantech", "研華", "2395"], "tier": "industrial"},
    {"key": "chunghwa", "aliases": ["chunghwa telecom", "中華電信", "2412"], "tier": "telecom"},
]

RANSOMWARE_KEYWORDS = [
    "ransomware",
    "勒索",
    "ransom",
    "lockbit",
    "clop",
    "alphv",
    "blackcat",
    "play ransomware",
    "akira",
    "royal ransomware",
    "leak site",
    "data leak",
    "double extortion",
    "雙重勒索",
    "加密勒索",
]

# Financial sector / payment / banking threat watchlist
# Note: short tokens like "bank" use word-boundary regex in match_finance_entities
# (avoid CISA ICS "Financial Services" sector laundry-list false positives).
FINANCE_WATCHLIST = [
    {
        "key": "banking",
        "aliases": [
            "banking",
            "financial institution",
            "financial sector",
            "financial services firm",
            "financial firm",
            "investment bank",
            "commercial bank",
            "retail bank",
            "central bank",
            "savings bank",
            "online bank",
            "digital bank",
            "neobank",
            "challenger bank",
            "credit union",
            "building society",
            "金融",
            "銀行",
            "金控",
            "銀控",
        ],
        "tier": "sector",
    },
    {
        "key": "payments",
        "aliases": [
            "payment card industry",
            "pos malware",
            "atm malware",
            "atm jackpot",
            "swift network",
            "swift messaging",
            "pci dss",
            "fintech",
            "wire transfer",
            "ach fraud",
            "payment processor",
            "open banking",
            "支付機構",
            "行動支付",
            "電子支付",
        ],
        "tier": "payments",
    },
    {
        "key": "markets",
        "aliases": [
            "stock exchange",
            "securities firm",
            "securities brokerage",
            "stock brokerage",
            "broker-dealer",
            "finra",
            "investment management",
            "wealth management firm",
            "hedge fund",
            "private equity",
            "mutual fund",
            "insurance company",
            "life insurance",
            "life assurance",
            "health insurance",
            "reinsurance",
            "cryptocurrency exchange",
            "crypto exchange",
            "證交所",
            "證券商",
            "保險業",
            "壽險",
            "產險",
            "投信",
            "投顧",
        ],
        "tier": "markets",
    },
    # Taiwan major banks / fintech
    {"key": "ctbc", "aliases": ["ctbc", "chinatrust", "中國信託", "中信銀"], "tier": "tw-bank"},
    {"key": "cathay", "aliases": ["cathay united", "cathay bank", "國泰世華", "國泰金", "國泰人壽"], "tier": "tw-bank"},
    {"key": "fubon", "aliases": ["fubon bank", "台北富邦", "富邦金", "富邦銀行", "富邦人壽"], "tier": "tw-bank"},
    {"key": "esun", "aliases": ["esun bank", "玉山銀行", "玉山金"], "tier": "tw-bank"},
    {"key": "firstbank", "aliases": ["first bank", "第一銀行", "一銀"], "tier": "tw-bank"},
    {"key": "megabank", "aliases": ["mega bank", "兆豐銀行", "兆豐金"], "tier": "tw-bank"},
    {"key": "bot", "aliases": ["bank of taiwan", "台灣銀行", "台銀"], "tier": "tw-bank"},
    {"key": "hncb", "aliases": ["hua nan", "華南銀行", "華南金"], "tier": "tw-bank"},
    {"key": "tcb", "aliases": ["taiwan cooperative", "合作金庫", "合庫"], "tier": "tw-bank"},
    {"key": "linebank", "aliases": ["line bank", "linebank", "連線銀行"], "tier": "tw-fintech"},
    {"key": "jko", "aliases": ["jkopay", "街口支付", "街口"], "tier": "tw-fintech"},
    # Global finance brands often in CTI
    {"key": "swift", "aliases": ["swift system", "swift cve", "swift alliance"], "tier": "infra"},
    {"key": "visa", "aliases": ["visa inc", "visa payment", "visa card"], "tier": "payments"},
    {"key": "mastercard", "aliases": ["mastercard"], "tier": "payments"},
    {"key": "paypal", "aliases": ["paypal"], "tier": "payments"},
    {"key": "jpmorgan", "aliases": ["jpmorgan", "jp morgan", "chase bank"], "tier": "global-bank"},
    {"key": "hsbc", "aliases": ["hsbc"], "tier": "global-bank"},
    {"key": "citibank", "aliases": ["citibank", "citigroup", "citi bank"], "tier": "global-bank"},
]

# Word-boundary patterns for short finance *organization* tokens (after FP scrub).
# Avoid bare "financial" — ransomware dumps always list "financial documents".
FINANCE_WORD_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, key, tier)
    (r"(?<![a-z])banks?(?![a-z])", "banking", "sector"),  # bank/banks; not bankruptcy
    (r"(?<![a-z])banking(?![a-z])", "banking", "sector"),
    (r"(?<![a-z])fintech(?![a-z])", "payments", "payments"),
    (r"(?<![a-z])financi[eè]re(?![a-z])", "banking", "sector"),
    (r"(?<![a-z])insurance(?![a-z])", "markets", "markets"),
    (r"(?<![a-z])assurance(?![a-z])", "markets", "markets"),
    (r"(?<![a-z])reinsurance(?![a-z])", "markets", "markets"),
    (r"(?<![a-z])finorion(?![a-z])", "banking", "sector"),
    (r"(?<![a-z])neobank(?![a-z])", "banking", "sector"),
    (r"金融|銀行|金控|壽險|產險|證交所|證券商", "banking", "sector"),
]

# Microsoft product / ecosystem watchlist (prefer specific product strings over bare "windows")
MICROSOFT_WATCHLIST = [
    {
        "key": "microsoft",
        "aliases": ["microsoft", "微軟", "msrc", "patch tuesday"],
        "tier": "vendor",
    },
    {
        "key": "windows",
        "aliases": [
            "windows server",
            "windows 10",
            "windows 11",
            "windows 7",
            "windows 8",
            "microsoft windows",
            "win32k",
            "ntoskrnl",
            "windows kernel",
            "print spooler",
            "smbv1",
            "rdp ",
            "remote desktop",
        ],
        "tier": "os",
    },
    {
        "key": "exchange",
        "aliases": [
            "exchange server",
            "microsoft exchange",
            "outlook web",
            "owa ",
            "exchange online",
            "proxy logon",
            "proxyshell",
            "proxynotshell",
        ],
        "tier": "mail",
    },
    {
        "key": "azure",
        "aliases": [
            "microsoft azure",
            "azure ad",
            "azure active directory",
            "entra id",
            "microsoft entra",
            "azure devops",
            "azure portal",
            "azure arc",
        ],
        "tier": "cloud",
    },
    {
        "key": "m365",
        "aliases": [
            "microsoft 365",
            "office 365",
            "office365",
            "m365",
            "microsoft office",
            "sharepoint",
            "sharepoint online",
            "onedrive",
            "microsoft teams",
            "teams phishing",
        ],
        "tier": "productivity",
    },
    {
        "key": "identity",
        "aliases": [
            "active directory",
            "domain controller",
            "kerberos",
            "ntlm ",
            "ad fs",
            "adfs",
            "group policy",
            "entra ",
        ],
        "tier": "identity",
    },
    {
        "key": "security_stack",
        "aliases": [
            "microsoft defender",
            "defender for endpoint",
            "defender atp",
            "defender for identity",
            "defender for cloud",
            "microsoft intune",
            "sccm",
            "configmgr",
            "system center",
            "sentinel ",
            "microsoft sentinel",
        ],
        "tier": "security",
    },
    {
        "key": "threat_intel",
        "aliases": [
            "microsoft threat intelligence",
            "mstic",
            "threat actor",
            "nation-state",
            "storm-",
            "midnight blizzard",
            "nobelium",
            "apt29",
            "ioc ",
            "indicators of compromise",
        ],
        "tier": "ti",
    },
    {
        "key": "server_apps",
        "aliases": [
            "sql server",
            "iis ",
            "internet information services",
            "hyper-v",
            "powershell",
            "visual studio",
            ".net framework",
            "asp.net",
            "dynamics 365",
            "microsoft edge",
        ],
        "tier": "apps",
    },
]

# HTTP
USER_AGENT = "SOC-CTI-Dashboard/1.0 (+internal-research; Asia/Taipei)"
HTTP_TIMEOUT = 45.0

# Have I Been Pwned — public breach catalog is free (no key).
# Domain/email search requires a paid API key: https://haveibeenpwned.com/API/Key
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_LATEST_URL = "https://haveibeenpwned.com/api/v3/latestbreach"
HIBP_API_KEY = (os.environ.get("HIBP_API_KEY") or "").strip()
# Comma-separated domains for paid domain search, e.g. "inventec.com,example.com"
HIBP_WATCH_DOMAINS = [
    d.strip().lower()
    for d in (os.environ.get("HIBP_WATCH_DOMAINS") or "").split(",")
    if d.strip()
]
# Ingest breaches whose AddedDate is within this many days (catalog is large)
HIBP_RECENT_DAYS = int(os.environ.get("HIBP_RECENT_DAYS") or "120")
HIBP_MAX_ITEMS = int(os.environ.get("HIBP_MAX_ITEMS") or "40")

# --- L4 External Attack Surface (EASM) ---
# Free path: Shodan InternetDB (no API key) — needs watch IPs/hosts
# https://internetdb.shodan.io/
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_API_KEY = (os.environ.get("SHODAN_API_KEY") or "").strip()
SHODAN_API_HOST = "https://api.shodan.io/shodan/host"
# Censys free/platform lookup (requires API ID + Secret)
CENSYS_API_ID = (os.environ.get("CENSYS_API_ID") or "").strip()
CENSYS_API_SECRET = (os.environ.get("CENSYS_API_SECRET") or "").strip()
CENSYS_HOST_API = "https://search.censys.io/api/v2/hosts"
# Comma-separated public IPs and/or hostnames to monitor (e.g. edge VPN, mail, web)
EASM_WATCH_IPS = [
    ip.strip()
    for ip in (os.environ.get("EASM_WATCH_IPS") or "").split(",")
    if ip.strip()
]
EASM_WATCH_HOSTS = [
    h.strip().lower()
    for h in (os.environ.get("EASM_WATCH_HOSTS") or "").split(",")
    if h.strip()
]
EASM_MAX_TARGETS = int(os.environ.get("EASM_MAX_TARGETS") or "30")
