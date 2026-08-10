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
| 微軟相關 Dashboard | 獨立「🪟 微軟專區」分頁：KEV／P1／勒索／Windows／企業平台（Exchange・SharePoint・Entra・Defender・M365）／MSTI／官方旁證 分區 |
| 上方四項 KPI | P0、KEV 近 7 日、台灣產業／勒索、來源健康度 |
| 每日 07:00、15:00 | APScheduler Cron（臺灣時間） |
| 複核佇列與規則準確率 | 獨立「🔎 複核佇列」分頁；標記真／偽陽性後計算每條規則 precision |
| 跨來源佐證 | 同一事件被多家獨立來源報導時自動合併佐證數並重評 |
| 情資生命週期 | 逾 14 日未再觀測轉 `stale`，退出「未結」計數但保留可查 |

### 監控名單比對（字界）

英數別名採**字界比對**，中文別名維持子字串，股票代號需**市場上下文**（`TWSE 2330`／`2330.TW`／`(2330)`）才算命中。

> 這解決了實測語料中的系統性誤判：勒索外洩貼文樣板「we have hundreds of **gigabytes** of your files」曾使**每一篇**勒索貼文命中「技嘉 GIGABYTE」，再與勒索旗標疊加就是 P0 誤報；股號亦曾命中 `CVE-2023-32315`、時間戳與外洩筆數。  
> 別名可加後綴宣告比對模式：`storm-`＝前綴（`storm-1175`）、`threat actor*`＝容許字尾變化（複數）。

### 優先級（互斥）

- **P0**：KEV 且已知勒索活動使用；或 **已核實／多源** 且台灣電子／半導體 + 勒索；或 台灣產業 + KEV  
- **P1**：列入 CISA KEV 且未達 P0  
- **P2**：非 KEV，EPSS ≥ 0.5 或多來源可信  
- **P3**：其餘監控項；**單源未核實**（X OSINT／暗網間接／洩漏站）一律進 P3 人工複核，**不得**因關鍵字／監控名單自動升 P0  

### 核實狀態

- **已證實 Confirmed**：官方 KEV 等  
- **可信 Credible**：≥ 2 獨立來源；或**官方／PSIRT／研究單位**之單一來源  
- **未核實 Unverified**：**媒體／社群／OSINT 之單源**（尤其暗網間接、X OSINT）；未核實不得單獨開立 IR 工單  

### 來源可靠度分級（單源可信門檻）

來源可靠度與佐證數是**獨立兩軸**（Admiralty 精神）。L2／L7 同時混編權威來源與專題媒體，因此**層級本身不足以authorize單源可信**——改由來源類別決定：

| 類別 | 代表來源 | 單一來源 |
|------|---------|---------|
| `official-gov` | CISA（KEV／ICS／Alerts）、TWCERT、NCSC、JPCERT、CIS、ACSC、CCCS、CERT-EU、NSA、BSI | **可信 Credible** |
| `vendor-psirt` | Fortinet PSIRT、MSRC、Microsoft Security Blog／Defender TI | **可信 Credible** |
| `research` | Unit 42、Dragos、Claroty Team82、Nozomi Labs、SANS ICS／ISC、The DFIR Report | **可信 Credible** |
| `media` | Dark Reading、The Hacker News、SecurityWeek、Industrial Cyber、Infosecurity、BleepingComputer、The Record | 未核實（**需 ≥2 獨立來源**） |
| `community` / `osint` | OTX、ThreatFox、X 帳號、洩漏站 | 未核實（需雙源） |

> 效果：**單篇 ICS／OT 媒體報導不得**因命中台灣監控名單＋勒索關鍵字而自動升 P0；官方公告或雙源佐證才可以。  
> 分級表位於 `backend/config.py` 的 `SOURCE_CLASS_REGISTRY`（未列名的來源一律保守視為 `media`）。

### 跨來源佐證（自動識別同一事件）

各採集器只看得到自己的 feed，因此都以 `source_count=1` 寫入——「≥2 獨立來源」規則對新聞幾乎從未生效：五家媒體報導同一起事故，會變成五筆各自單源的 P3。

巡檢後會執行 `backend/aggregate.py`：

- **同一事件的判定**：相同 CVE，或標題 token 重疊度 ≥ 0.55（中文以 bigram 切分）；
- **獨立性檢查**：來源名稱不同，且**連結網域不同**——同一篇文章的 Google News 鏡像與原站 feed 不算兩個來源；
- **不合併記錄**：分析師仍能分別開啟各家報導，只是佐證數、核實狀態與優先級依實際來源數重算。

> 實測（400 筆語料）：同一個 SharePoint RCE 被 CISA KEV、BleepingComputer、The Hacker News、Microsoft GNews 四個獨立來源報導，原本各自為政，現在正確聚合，5 筆由 P3 升為 P2。

### 暗網雙來源比對（三要件）

`Ransomware.live × RansomLook` 的受害者比對，需滿足**其一**：

1. **受害者網域相同**（最強訊號）；或
2. **名稱相同 ＋ 勒索集團相同 ＋ 張貼日期相差 ≤ 14 天**。

> 舊版將名稱正規化為純英數後做完全比對，短名或通用名極易跨受害者撞名，而一次撞名就直接升為「可信」。

### 情資生命週期與 KPI 時間窗

- 逾 **14 天**未再觀測的項目轉為 `stale`，退出「未結」計數（資料保留，仍可查詢）；再次被觀測會自動回到 `open`。
- KPI 同時提供 **未結（open）／全期（total）／近 7 日新增／近 30 日新增**，避免「P0 只增不減」造成告警疲乏。
- 所有日界改以 **Asia/Taipei** 計算（SQLite `date('now')` 為 UTC，臺灣每日前 8 小時的「近 7 日」都會差一天）。
- 核實度分兩軸呈現：整體，以及**排除 L1 後的 OSINT 核實率**（L1 幾乎全是 KEV，本質即已證實，會淹沒 OSINT 的真實佐證品質）。

### 複核佇列與規則準確率（回饋迴路）

方法論一直要求「未核實單源只進人工複核佇列」，但佇列從未出現在介面上，複核結論也沒有任何欄位記錄——規則準確率無從量測，調整只能憑感覺。

- 「🔎 複核佇列」分頁列出 **P3 ＋ 未核實 ＋ 未判定 ＋ 未逾期** 的項目；
- 本機 API 模式下可直接標記**真陽性／偽陽性／無法判定**；
- 判定寫入專屬欄位，**下次巡檢不會覆蓋**（`upsert` 的 `ON CONFLICT` 刻意不含這些欄位）；
- `GET /api/rule-accuracy` 依 13 個規則面向（P0–P3、核實狀態、TW＋勒索、金融、微軟、KEV…）計算 precision＝TP/(TP+FP)。**未複核者 precision 為 `null` 而非 0**——未複核代表未知，不是完美。

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
- `GET /api/review-queue` — 待人工複核佇列（P3 · 未核實 · 未判定）  
- `GET /api/rule-accuracy` — 各規則面向的 precision 與複核覆蓋率  
- `POST /api/intel/{id}/verdict` — 記錄分析師判定（需金鑰；body：`{"verdict":"true_positive|false_positive|unknown","note":"…"}`）  
- `POST /api/scan/manual` — 手動巡檢（30 分鐘冷卻；設定金鑰後需帶驗證標頭）  

`GET /api/intel` 另支援 `status=open|stale`、`verdict=…`、`unreviewed=true` 篩選。

## 服務設定（選用環境變數）

| 變數 | 預設 | 說明 |
|------|------|------|
| `SOC_CTI_API_KEY`（或 `API_KEY`） | 未設＝**不驗證** | 設定後 `POST /api/scan/manual` 與判定端點需帶 `X-API-Key: <key>` 或 `Authorization: Bearer <key>`（常數時間比對）。內網／共享部署建議必設 |
| `CORS_ORIGINS` | `http://127.0.0.1:8787,http://localhost:8787` | 逗號分隔允許來源。內建前端與 API **同源**，僅前端分離部署時需調整 |
| `EPSS_P2_THRESHOLD` | 沿用 `EPSS_TOP_MIN`（`0.5`） | **P2 判級**門檻，與抓取門檻 `EPSS_TOP_MIN` 獨立；調整會直接改變評鑑結果 |

```powershell
$env:SOC_CTI_API_KEY = "your-long-random-key"
$env:EPSS_P2_THRESHOLD = "0.6"   # 收緊 P2（預設 0.5）
```

```bash
# 記錄一筆判定
curl -X POST http://127.0.0.1:8787/api/intel/<id>/verdict \
  -H "X-API-Key: your-long-random-key" -H "Content-Type: application/json" \
  -d '{"verdict":"false_positive","note":"媒體單篇，非台廠"}'
```

> `GET /api/health` 與 `GET /api/scan/status` 會回報 `api_key_required`，可確認金鑰是否生效。

## 測試

```powershell
cd soc_cti_dashboard
pip install -r requirements.txt pytest pytest-asyncio
$env:PYTHONPATH = "."
python -m pytest tests/ -q
```

GitHub Actions 於部署前執行同一組檢查（`node --check` ＋ `py_compile` ＋ pytest）；未通過即**中止部署**，不會把壞版本推上 Pages。

## 服務設定（選用環境變數）

| 變數 | 預設 | 說明 |
|------|------|------|
| `SOC_CTI_API_KEY`（或 `API_KEY`） | 未設＝**不驗證** | 設定後 `POST /api/scan/manual` 需帶 `X-API-Key: <key>` 或 `Authorization: Bearer <key>`（常數時間比對）。內網／共享環境部署建議必設 |
| `CORS_ORIGINS` | `http://127.0.0.1:8787,http://localhost:8787` | 逗號分隔的允許來源。內建前端與 API **同源**，僅在前端分離部署時需調整（例：`https://chinchiang.github.io`） |
| `EPSS_P2_THRESHOLD` | 沿用 `EPSS_TOP_MIN`（`0.5`） | **P2 判級**門檻，與抓取門檻 `EPSS_TOP_MIN` 互相獨立；調整會直接改變評鑑結果 |

```powershell
$env:SOC_CTI_API_KEY = "your-long-random-key"
$env:CORS_ORIGINS = "https://cti.example.com"
$env:EPSS_P2_THRESHOLD = "0.6"   # 收緊 P2（預設 0.5）
```

```bash
# 設定金鑰後觸發手動巡檢
curl -X POST http://127.0.0.1:8787/api/scan/manual -H "X-API-Key: your-long-random-key"
```

> `GET /api/health` 與 `GET /api/scan/status` 會回報 `api_key_required`，可用來確認金鑰是否已生效。

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
