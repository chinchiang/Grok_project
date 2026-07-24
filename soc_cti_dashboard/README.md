# SOC 即時威脅情資中心（CTI Early Warning Dashboard）

依 OSINT CTI 研究報告（七層來源、CISA KEV、雙來源核實、P0–P3）建置的即時情資網站，時區 **Asia/Taipei**，介面 **正體中文 / English** 可切換。

## 部署到 GitHub Pages

本站可透過 **GitHub Actions** 每日 07:00／15:00（臺灣時間）抓取情資，輸出靜態 JSON，並發佈到 **GitHub Pages**。

### 一次設定

1. 將程式 push 到 GitHub（見下方指令）。
2. 開啟 repo → **Settings → Pages**：
   - Source 選 **GitHub Actions**
3. 開啟 **Actions** 分頁，允許 workflow 執行。
4. 手動跑一次：**Actions → Deploy SOC CTI Dashboard → Run workflow**。

網站網址（依帳號／repo 名稱）：

```
https://chinchiang.github.io/Grok_project/
```

> GitHub Pages 為**靜態站**：瀏覽器內「立即巡檢」會提示改用 Actions 手動更新。本機 `python run.py` 仍支援完整 API 與 30 分鐘冷卻巡檢。

### 排程（Actions cron → 臺灣時間）

| 臺灣時間 | UTC cron |
|---------|----------|
| 07:00 | `0 23 * * *` |
| 15:00 | `0 7 * * *` |

## 功能對照

| 需求 | 實作 |
|------|------|
| CISA KEV 即時介接 | 官方 JSON feed + EPSS 豐富化 |
| P0–P3 精準互斥 | 單一規則引擎，P1 不會混入其他級 |
| 七層來源健康 | L1–L7 狀態看板 + 排程資訊 |
| 暗網雙來源核實 | 雙 RSS 交叉比對；單源標 **未核實** |
| 臺灣時區 / 行動版 | `Asia/Taipei` 時鐘與排程；RWD |
| 大膽用色 | P0 紅 / P1 橙 / P2 黃 / P3 青；核實狀態綠／藍／紫 |
| 中英切換 | 右上角 EN / 中文 |
| 手動巡檢 | 每 30 分鐘一次（429 冷卻） |
| 電子五哥／半導體 Dashboard | 獨立分頁；勒索高亮 |
| 金融相關 Dashboard | 銀行／支付／SWIFT 等關鍵字與實體；勒索與 KEV 分區 |
| 微軟相關 Dashboard | Microsoft 廠商／Windows／Exchange／Azure／M365 等；KEV 分區 |
| 上方四項 KPI | P0、KEV 近 7 日、台灣產業／勒索、來源健康度 |
| 每日 07:00、15:00 | APScheduler Cron（臺灣時間） |

### 優先級（互斥）

- **P0**：KEV 且已知勒索活動使用；或 **已核實／多源** 且台灣電子／半導體 + 勒索；或 台灣產業 + KEV  
- **P1**：列入 CISA KEV 且未達 P0  
- **P2**：非 KEV，EPSS ≥ 0.5 或多來源可信  
- **P3**：其餘監控項；**單源未核實**（X OSINT／暗網間接／洩漏站）一律進 P3 人工複核，**不得**因關鍵字／監控名單自動升 P0  

### 核實狀態

- **已證實 Confirmed**：官方 KEV 等  
- **可信 Credible**：≥ 2 獨立來源  
- **未核實 Unverified**：單源（尤其暗網間接、X OSINT）；未核實不得單獨開立 IR 工單  

## 本機啟動（完整 API 模式）

```powershell
cd soc_cti_dashboard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

瀏覽器開啟：<http://127.0.0.1:8787>

首次啟動會自動抓取 KEV 與公開 RSS；可按 **立即巡檢**（每 30 分鐘一次）。

### 本機產生靜態檔（模擬 Pages）

```powershell
cd soc_cti_dashboard
python scripts/export_static.py
# 輸出至 frontend/data/*.json
```

## API 摘要

- `GET /api/kpis` — 四項 KPI  
- `GET /api/intel?priority=P0&verification=confirmed&ransomware=true&tw=true&finance=true&microsoft=true`  
- `GET /api/tw-dashboard` — 台灣產業獨立看板  
- `GET /api/finance-dashboard` — 金融相關看板  
- `GET /api/microsoft-dashboard` — 微軟相關看板  
- `GET /api/layers` — 七層健康  
- `POST /api/scan/manual` — 手動巡檢（30 分鐘冷卻）  

## 選用 API 金鑰（強化 L3/L4/L5）

| 層級 | 來源 | 預設 | 環境變數 |
|------|------|------|----------|
| L5 | **Have I Been Pwned** | **公開外洩目錄免金鑰**（近期 `AddedDate`） | 可選 `HIBP_API_KEY` + `HIBP_WATCH_DOMAINS`（公司網域信箱監控，付費） |
| L7 | **CISA ICS Advisories** | 先試官方 RSS；若 WAF 403 則改用 [ICS Advisory Project](https://github.com/icsadvprj/ICS-Advisory-Project) CSV 鏡像 | 無需金鑰 |
| L1/L2/L7 | **OT/IT 官方政府級預警（優先）** | CISA Alerts／CSA／News／ICS Medical；TWCERT；UK NCSC；JPCERT；CIS；ACSC／CCCS／CERT-EU／NSA／BSI（GNews 備援） | 無需金鑰 |
| L6 | **Ransomware.live** | `data.ransomware.live/victims.json` 近期受駭 | 可選 `RANSOMWARE_LIVE_API_KEY`（PRO） |
| L6 | **RansomLook** | `ransomlook.io/api/recent` | 無需金鑰 |
| L6 | **X OSINT 帳號** | Nitter → blog RSS → Google News；已排除與 THN／BC／HIBP／Krebs／Dark Reading／DFIR／SANS 重複 | 無需 X API 金鑰 |
| L4 | **Shodan** | **InternetDB 免金鑰**（需監控 IP） | `EASM_WATCH_IPS` / `EASM_WATCH_HOSTS`；可選 `SHODAN_API_KEY` |
| L4 | **Censys** | Host lookup（需金鑰 + 監控 IP） | `CENSYS_API_ID` + `CENSYS_API_SECRET` + 上述監控目標 |
| L3 | **AlienVault OTX Pulse** | 需免費 API key | `OTX_API_KEY` |
| L3 | **abuse.ch ThreatFox** | **公開 recent JSON 免金鑰**（依家族彙整） | 可選 `ABUSECH_AUTH_KEY` 用 API |
| L1 | **FIRST EPSS** | 高 EPSS CVE 公開 API + KEV 豐富化 | 無需金鑰 |
| L2 | **Unit 42 / Fortinet PSIRT** | 官方 RSS | 無需金鑰 |
| L5 | **DataBreaches.net** | RSS | 無需金鑰 |
| L6 | **資安媒體** | THN / BC / Record / SecurityWeek / CSN / Reuters(GNews) | 無需金鑰 |
| L7 | **Dragos (OT)** | RSS 或 Google News 備援 | 無需金鑰 |

### OT／ICS 來源四層（訂閱指南）

| 類 | 來源 | 建議用法 | 採集 |
|----|------|----------|------|
| **① 官方政府級（優先／每日必查）** | [CISA ICS Advisories](https://www.cisa.gov/news-events/ics-advisories)、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)、[CISA ICS 專區](https://www.cisa.gov/topics/industrial-control-systems)、[ICS Advisory Project](https://www.icsadvisoryproject.com/)、ICS Medical、TWCERT | ICS 與 KEV 交叉比對；CSV 鏡像做資產對應 | RSS／JSON／CSV |
| **② 專業研究** | [Dragos](https://www.dragos.com/blog)、[Claroty Team82](https://claroty.com/team82)、[Nozomi Labs](https://www.nozominetworks.com/blog)、[SANS ICS](https://www.sans.org) + @SANSICS | 威脅建模、ATT&CK for ICS mapping | RSS／GNews／X |
| **③ 專題媒體** | [SecurityWeek ICS/OT](https://www.securityweek.com/category/ics-ot/)、[Industrial Cyber](https://industrialcyber.co/)、[Dark Reading ICS/OT](https://www.darkreading.com/ics-ot-security)、[THN ICS](https://thehackernews.com/search/label/ICS%20Security)、Infosecurity | 高頻事件與會議 | RSS／GNews |
| **④ 框架知識庫** | [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) | 非即時；偵測／狩獵對照 | 參考連結 |

> CISA ICS Advisory 為目前全球最權威、更新最即時的公開 OT／ICS 漏洞預警，建議設為**每日必查**。  
> API：`GET /api/ot-catalog` · 靜態：`frontend/data/ot-catalog.json`

```powershell
# 可選：HIBP 付費網域搜尋（否則仍會抓公開 breaches 目錄）
$env:HIBP_API_KEY = "your-key"
$env:HIBP_WATCH_DOMAINS = "inventec.com,example.com"
$env:HIBP_RECENT_DAYS = "120"   # 預設 120
$env:HIBP_MAX_ITEMS = "40"      # 預設 40

# L4 EASM：Shodan InternetDB 免金鑰（必填監控目標才會有資料）
$env:EASM_WATCH_IPS = "203.0.113.10,198.51.100.20"
$env:EASM_WATCH_HOSTS = "vpn.example.com,mail.example.com"
# 可選進階
$env:SHODAN_API_KEY = "..."
$env:CENSYS_API_ID = "..."
$env:CENSYS_API_SECRET = "..."
```

GitHub Actions 可於 repo **Settings → Secrets** 設定同名變數（workflow 已接線）。

## 免責

防禦與研究用途。間接暗網情資來自公開新聞，未經雙源核實者不得單獨開立 IR 工單。請依實際資產與法遵政策調校。
