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

# Public feeds
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_API = "https://api.first.org/data/v1/epss"
# Official CISA advisory RSS (often blocked by Akamai/WAF from some networks)
CISA_ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_ADVISORIES_RSS_CANDIDATES = (
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
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

# abuse.ch ThreatFox — free recent JSON export; Auth-Key optional for API
# https://threatfox.abuse.ch/export/ / https://threatfox.abuse.ch/api/
ABUSECH_AUTH_KEY = (
    os.environ.get("ABUSECH_AUTH_KEY") or os.environ.get("THREATFOX_API_KEY") or ""
).strip()
THREATFOX_RECENT_EXPORT = "https://threatfox.abuse.ch/export/json/recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_MAX_FAMILIES = int(os.environ.get("THREATFOX_MAX_FAMILIES") or "35")
THREATFOX_MIN_CONFIDENCE = int(os.environ.get("THREATFOX_MIN_CONFIDENCE") or "50")

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
    {
        "source_id": "dragos_ot_rss",
        "layer_id": "L7",
        "name": "Dragos (OT)",
        "url": DRAGOS_RSS_CANDIDATES[0],
        "fallback_url": DRAGOS_GNEWS_RSS,
        "force_all": True,
        "max_items": 20,
        "darkweb_indirect": False,
    },
    # Microsoft official / TI (feeds into is_microsoft classification)
    {
        "source_id": "ms_security_blog",
        "layer_id": "L2",
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
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

# X accounts: multi-mirror Nitter → blog RSS → Google News (no X API key)
# Nitter instances are flaky; always keep blog/gnews fallbacks.
X_NITTER_MIRRORS = (
    "https://nitter.net",
    "https://nitter.privacyredirect.com",
    "https://xcancel.com",
)
X_DARKWEB_ACCOUNTS = [
    {
        "handle": "DailyDarkWeb",
        "blog_rss": "https://dailydarkweb.net/feed/",
        "gnews_rss": (
            "https://news.google.com/rss/search?q=site:dailydarkweb.net"
            "+(breach+OR+ransomware+OR+leak+OR+hack+OR+dark)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/DailyDarkWeb",
    },
    {
        "handle": "DarkWebInformer",
        "blog_rss": "https://darkwebinformer.com/rss/",
        "gnews_rss": (
            "https://news.google.com/rss/search?q=site:darkwebinformer.com"
            "+(breach+OR+ransomware+OR+leak+OR+hack+OR+dark)"
            "&hl=en-US&gl=US&ceid=US:en"
        ),
        "profile": "https://x.com/DarkWebInformer",
    },
]
X_DARKWEB_MAX_ITEMS = int(os.environ.get("X_DARKWEB_MAX_ITEMS") or "25")
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
        "sources": ["CISA KEV", "FIRST EPSS top scores", "CVE/NVD"],
        "schedule_hint": "hourly / daily",
    },
    {
        "id": "L2",
        "name_zh": "國家 CERT／廠商 PSIRT",
        "name_en": "National CERT / Vendor PSIRT",
        "sources": [
            "TWCERT/CC",
            "Fortinet PSIRT",
            "Palo Alto Unit 42",
            "Vendor PSIRT",
        ],
        "schedule_hint": "daily",
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
            "The Record",
            "SecurityWeek",
            "Cyber Security News",
            "Reuters (Google News)",
            "@DailyDarkWeb (X)",
            "@DarkWebInformer (X)",
        ],
        "schedule_hint": "07:00 & 15:00 + dual-source verify",
    },
    {
        "id": "L7",
        "name_zh": "OT／ICS 專屬",
        "name_en": "OT / ICS Specialized",
        "sources": [
            "CISA ICS Advisories",
            "Dragos (OT)",
            "ICS Advisory Project mirror",
        ],
        "schedule_hint": "daily (RSS or GitHub CSV / Google News fallback)",
    },
]

# Taiwan electronics "Big 5" ODM/EMS + listed semiconductor / electronics manufacturing
TW_ELECTRONICS_WATCHLIST = [
    # 電子五哥 / ODM EMS
    {"key": "foxconn", "aliases": ["foxconn", "hon hai", "鴻海", "富士康", "2317"], "tier": "big5"},
    {"key": "pegatron", "aliases": ["pegatron", "和碩", "4938"], "tier": "big5"},
    {"key": "quanta", "aliases": ["quanta computer", "quanta", "廣達", "2382"], "tier": "big5"},
    {"key": "compal", "aliases": ["compal", "仁寶", "2324"], "tier": "big5"},
    {"key": "wistron", "aliases": ["wistron", "緯創", "3231"], "tier": "big5"},
    {"key": "inventec", "aliases": ["inventec", "英業達", "2356"], "tier": "odm"},
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
FINANCE_WATCHLIST = [
    # Sector keywords
    {
        "key": "banking",
        "aliases": [
            "banking",
            "bank ",
            " bank",
            "banks ",
            "金融",
            "銀行",
            "financial institution",
            "financial sector",
            "financial services",
        ],
        "tier": "sector",
    },
    {
        "key": "payments",
        "aliases": [
            "payment card",
            "credit card",
            "debit card",
            "pos malware",
            "atm malware",
            "atm jackpot",
            "swift ",
            "swift network",
            "pci dss",
            "fintech",
            "wire transfer",
            "ach fraud",
            "支付",
            "刷卡",
            "atm ",
        ],
        "tier": "payments",
    },
    {
        "key": "markets",
        "aliases": [
            "stock exchange",
            "securities",
            "brokerage",
            "finra",
            "證交所",
            "證券",
            "保險業",
            "insurance company",
            "cryptocurrency exchange",
            "crypto exchange",
        ],
        "tier": "markets",
    },
    # Taiwan major banks / fintech
    {"key": "ctbc", "aliases": ["ctbc", "chinatrust", "中國信託", "中信銀"], "tier": "tw-bank"},
    {"key": "cathay", "aliases": ["cathay united", "cathay bank", "國泰世華", "國泰金"], "tier": "tw-bank"},
    {"key": "fubon", "aliases": ["fubon bank", "台北富邦", "富邦金", "富邦銀行"], "tier": "tw-bank"},
    {"key": "esun", "aliases": ["esun bank", "玉山銀行", "玉山金"], "tier": "tw-bank"},
    {"key": "firstbank", "aliases": ["first bank", "第一銀行", "一銀"], "tier": "tw-bank"},
    {"key": "megabank", "aliases": ["mega bank", "兆豐銀行", "兆豐金"], "tier": "tw-bank"},
    {"key": "bot", "aliases": ["bank of taiwan", "台灣銀行", "台銀"], "tier": "tw-bank"},
    {"key": "hncb", "aliases": ["hua nan", "華南銀行", "華南金"], "tier": "tw-bank"},
    {"key": "tcb", "aliases": ["taiwan cooperative", "合作金庫", "合庫"], "tier": "tw-bank"},
    {"key": "linebank", "aliases": ["line bank", "linebank", "連線銀行"], "tier": "tw-fintech"},
    {"key": "jko", "aliases": ["jkopay", "街口支付", "街口"], "tier": "tw-fintech"},
    # Global finance brands often in CTI
    {"key": "swift", "aliases": ["swift messaging", "swift system", "swift cve"], "tier": "infra"},
    {"key": "visa", "aliases": ["visa inc", "visa payment"], "tier": "payments"},
    {"key": "mastercard", "aliases": ["mastercard"], "tier": "payments"},
    {"key": "paypal", "aliases": ["paypal"], "tier": "payments"},
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
