"""SOC CTI Dashboard configuration — Taiwan timezone, layers, TW industry watchlist."""

from __future__ import annotations

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
CISA_ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
# Fallback / mirror-friendly ransomware & breach news RSS
BLEEPING_RSS = "https://www.bleepingcomputer.com/feed/"
THEHACKERNEWS_RSS = "https://feeds.feedburner.com/TheHackersNews"
# TWCERT / NICS public news (best-effort)
TWCERT_RSS = "https://www.twcert.org.tw/tw/rss/rss.xml"

# 7 intelligence layers (order = priority of trust)
LAYERS = [
    {
        "id": "L1",
        "name_zh": "官方權威漏洞",
        "name_en": "Official / Authority Vuln",
        "sources": ["CISA KEV", "FIRST EPSS", "CVE/NVD"],
        "schedule_hint": "hourly / daily",
    },
    {
        "id": "L2",
        "name_zh": "國家 CERT／廠商 PSIRT",
        "name_en": "National CERT / Vendor PSIRT",
        "sources": ["TWCERT/CC", "Vendor PSIRT"],
        "schedule_hint": "daily",
    },
    {
        "id": "L3",
        "name_zh": "社群 IOC／工具",
        "name_en": "Community IOC / Tools",
        "sources": ["abuse.ch", "OTX"],
        "schedule_hint": "daily",
    },
    {
        "id": "L4",
        "name_zh": "外部攻擊面 (EASM)",
        "name_en": "External Attack Surface",
        "sources": ["Shodan", "Censys"],
        "schedule_hint": "daily (API key required)",
    },
    {
        "id": "L5",
        "name_zh": "外洩／憑證監控",
        "name_en": "Breach / Credential Monitor",
        "sources": ["HIBP", "Public breach news"],
        "schedule_hint": "daily",
    },
    {
        "id": "L6",
        "name_zh": "暗網間接情資",
        "name_en": "Indirect Dark Web",
        "sources": ["Ransomware leak trackers", "Security news"],
        "schedule_hint": "07:00 & 15:00 + dual-source verify",
    },
    {
        "id": "L7",
        "name_zh": "OT／ICS 專屬",
        "name_en": "OT / ICS Specialized",
        "sources": ["CISA ICS Advisories", "SEMI / manufacturing OT"],
        "schedule_hint": "daily",
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

# HTTP
USER_AGENT = "SOC-CTI-Dashboard/1.0 (+internal-research; Asia/Taipei)"
HTTP_TIMEOUT = 45.0
