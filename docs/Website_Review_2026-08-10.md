# SOC CTI 情資網站 — 功能與評鑑方法審查報告

- **審查日期**：2026-08-10
- **審查範圍**：`soc_cti_dashboard/`（FastAPI 後端、靜態前端、GitHub Actions 部署）與 P0–P3 優先級／核實狀態評鑑方法
- **程式規模**：後端約 6,500 行、前端約 1,800 行、零測試

---

## 一、總體評價

整體架構清晰、方法論明確，屬於水準以上的 OSINT CTI 儀表板：

**做得好的地方**

1. **優先級與核實狀態分離**（`priority.py`）— 「Priority is not proof; verification is separate」的設計原則正確，P0–P3 互斥、首個命中即定案，規則可讀可稽核。
2. **單源 OSINT 強制 P3 複核**（`force_p3_review`）— 防止 X／洩漏站單源情資因關鍵字自動升級，這是多數同類專案沒做到的紀律。
3. **每筆情資附判定依據（rationale）、SOP、Owner、SLA**（`ops.py`）— 讓卡片可直接轉為行動，而非只是新聞牆。
4. **來源備援設計**：KEV 鏡像、GNews 備援 RSS、ICS Advisory Project CSV 鏡像，來源健康度（source_health）可視化。
5. **雙軌部署**（本機 FastAPI ／ Pages 靜態 JSON）共用同一套 collector 與資料模型。
6. 前端絕大多數欄位輸出都有 `escapeHtml()`；路徑遍歷有防護（`main.py:375-378`）。

**主要風險（詳見下文）**：評鑑規則與文件宣稱不一致（P0 升級條件過鬆）、比對邏輯以子字串為主易誤報、Actions 每次執行資料庫歸零導致趨勢與雙源核實狀態失真、一處 XSS 注入面、以及整個規則引擎沒有任何測試與回饋迴路。

---

## 二、評鑑方法審查（P0–P3 與核實狀態）

### 2.1 【高】P0 規則與 README 宣稱不一致：TW＋勒索關鍵字即 P0

`priority.py:194`：

```python
if is_tw_industry and is_ransomware:
    return "P0"
```

README 宣稱 P0 需「**已核實／多源** 且台灣電子／半導體 + 勒索」，但程式只靠 `force_p3_review` 擋掉「單源未核實 OSINT」。任何**兩家新聞媒體轉載同一則未經證實的消息**（多源但未核實），或一篇官方 RSS 文章同時提到某台灣公司名與「ransomware」字樣（例如趨勢分析文），就會自動 P0。P0 定義是「需立即處置」，誤報成本極高。

**改進方式**：把 `verification` 作為參數傳入 `assign_priority`，TW＋勒索路徑要求 `verification in ("confirmed", "credible")` 才升 P0，否則落 P1/P2；`explain_priority` 同步更新理由文字。

### 2.2 【高】監控名單比對用子字串、無字界（word boundary）

`priority.py:45`：`if alias_l in t:` — 純子字串比對。短別名（如 `UMC`、`AUO`、股號 `2317`）會命中一般英文單字或無關數字（`"umcommon"`、電話號碼、CVE 編號片段），直接放大 2.1 的 P0 誤升風險，也污染 TW／金融／微軟三個專區的統計。

**改進方式**：
- 英數別名改用 `\b` 字界 regex（中文別名維持子字串）；
- 別名長度 < 4 的一律要求字界＋大小寫敏感或上下文詞（如股號需前後有「股」「TW」等）；
- 在 watchlist 資料結構加 `match: "word"|"substring"` 欄位，逐別名控制。

### 2.3 【中】L2／L7 單一來源自動評為 credible／B2

`priority.py:233-234`：

```python
if layer_id in ("L2", "L7", "T2", "T7"):
    return "credible", "B2"
```

問題有二：(1) L2 包含廠商 PSIRT 與媒體混編的 feed，單源即 credible 過寬；(2) Admiralty 代碼被硬編碼成三檔（A1/A2/B2/C3），**來源可靠度（字母）與訊息可信度（數字）兩軸被綁死**，失去 Admiralty 系統原意。

**改進方式**：建立來源評級表（`config.py` 中每個 source 標注 reliability A–F），訊息可信度依佐證數量獨立計分（官方原文=1、多源=2、跨層交叉=3…），組合出 A1–F6；credible 門檻改為「來源 ≥ B 且可信度 ≤ 3」或「≥2 獨立來源」。

### 2.4 【中】EPSS 只富化前 80 個 CVE、門檻寫死

`collectors.py:163`：`epss_map = await _fetch_epss_batch(cve_list[:80])`，但 KEV 預設收錄 120 筆 → 40 筆沒有 EPSS。EPSS ≥ 0.5 的 P2 門檻寫死在 `priority.py:204`。

**改進方式**：EPSS API 支援批量查詢（每批 100 個 CVE），分批抓齊全部；門檻移至 `config.py`（環境變數 `EPSS_P2_THRESHOLD`），並在方法論卡片顯示目前值。

### 2.5 【中】`source_count` 在 ingest 時幾乎恆為 1，「多源升 P2」形同虛設

各 collector 寫入時 `source_count=1`（如 `collectors.py:192`），跨來源同一事件不會在 ingest 階段聚合；多源升級只靠 `dual_source_ransom_trackers` / `dual_source_darkweb_verify` 兩個專用後處理。RSS 新聞層（THN、BC、SecurityWeek 報同一事件）永遠各算一筆單源 P3。

**改進方式**：ingest 後加一個通用聚合 pass：以「正規化標題 token ＋ CVE ＋ 命中實體」做相似度分群，同群者合併 `sources_json`、重算 `source_count` 與 priority/verification。

### 2.6 【中】雙源比對正規化過寬，可能誤升 credible

`collectors.py:3069-3082`：`norm()` 去掉所有非英數字後做 exact-key 比對，長度門檻僅 4。`"Alta"`、`"Ford"` 級別的短名或母子公司同名可能在兩個追蹤站撞名而被升為 credible（B2）。

**改進方式**：比對鍵優先用受害者網域（website 欄位）；名稱比對需同時滿足「勒索集團名一致」與「發現日期相差 ≤ 14 天」才升級。

### 2.7 【中】情資無生命週期：P0 永不清零、KPI 是歷史累計

`intel_items` 沒有 status（open/ack/resolved）與時效衰減；`get_kpis` 的 P0/P1 計數是全歷史累計（`database.py:358-361`）。跑得越久 P0 數字越大，「P0 緊急 N 件」會失去警示意義（告警疲乏）。

**改進方式**：
- KPI 加時間窗（近 7／30 天）雙數字呈現：「新增 P0（7 日）／未結 P0」；
- 加 `status` 欄位與簡易複核 API（本機模式）；靜態模式至少以 `date_added` 過濾顯示；
- 超過 N 天未再現的 P3 監控項自動標記 stale。

### 2.8 【低】其他評鑑細節

| 位置 | 問題 | 建議 |
|------|------|------|
| `database.py:335,369` | `date('now')` 用 UTC 日界，與全站宣稱的 Asia/Taipei 不一致，早上 8 點前「近 7 日」會差一天 | SQL 改 `date('now','+8 hours')` 或在 Python 端算日界 |
| `database.py:386-392` | breach KPI 把 ThreatFox（IOC feed）算進「外洩」 | 從 breach 條件移除，IOC 另立 KPI |
| `database.py:394-424` | 以 `LIKE '%"big5"%'` 比對 JSON 字串，脆弱且無法用索引 | 改用 SQLite `json_each()`，或 ingest 時寫入正規化的 entity 關聯表 |
| `collectors.py:159-160` | KEV 只收最近 120 筆，KPI 的「KEV 總數」實為快取量非目錄總量 | KPI 改名「KEV 追蹤中」或用 `catalog_total` 另列 |
| 核實度 KPI | (confirmed+credible)/全部 被 KEV 大量灌高，無法反映 OSINT 品質 | 分層計算：排除 L1 後另列「OSINT 核實率」 |

### 2.9 【建議】評鑑方法缺回饋迴路（最重要的長期改進）

目前規則的準確率（precision/recall）完全沒有量測：P3 人工複核佇列的結論（真陽性／誤報）沒有任何記錄欄位，規則調整只能憑感覺。**建議**：加 `analyst_verdict`（tp/fp/unknown）與 `verdict_note` 欄位＋一個極簡標記 UI（本機模式），每月產出「各規則觸發數 vs 誤報率」報表——這才構成完整的「評鑑」閉環，也是後續調整字界、門檻的數據依據。

---

## 三、網站功能審查

### 3.1 【高】XSS：`item.url` 未跳脫直接寫入 `href`

`app.js:139-141`：

```js
const link = item.url
  ? `<a class="meta-link" href="${item.url}" ...>`
```

`item.url` 來自外部 RSS／API（攻擊面：任何被抓取的 feed）。含 `"` 的 URL 可注入屬性，`javascript:` 協定可執行腳本。其餘欄位都有 `escapeHtml`，唯獨這裡漏了。

**改進方式**：`escapeHtml(item.url)` ＋ 協定白名單（僅允許 `http(s)://`），不合法者不渲染連結。後端 ingest 時也做一次 URL 驗證（縱深防禦）。

### 3.2 【高】Actions 每次執行資料庫歸零，歷史與核實演進全部丟失

`data/*.db` 在 `.gitignore`，Pages 部署由無狀態 runner 執行 → 每次排程都是全新 DB。影響：
- 30 天趨勢線（sparkline）只剩 feed 自帶日期的項目，`fetched_at` 系列失真；
- 「未核實 → 雙源可信」的跨執行演進不可能發生（每次重新開始）；
- 已下架的 feed 項目直接消失，無法對比。

**改進方式**（擇一，由簡到繁）：
1. `actions/cache` 快取 `data/cti.db`（key 固定＋每日 restore-keys）；
2. 部署前從上一版 Pages artifact 下載前次 JSON 回填；
3. DB 推到獨立 `data` 分支或外部儲存（R2/S3）。
建議先做 1，成本最低。

### 3.3 【中】無認證的 `POST /api/scan/manual` ＋ CORS `*`

`main.py:91-96` 全開 CORS；手動巡檢端點無認證。GitHub Pages 模式無此問題，但 README 鼓勵本機／內網部署——內網任何人（或誘導瀏覽器發請求的網頁，因 CORS 全開）都能觸發巡檢，消耗外部 API 配額。另 `main.py:322-347` 的冷卻檢查與取鎖之間有 TOCTOU 競態（影響小）。

**改進方式**：CORS 收斂為同源＋明確允許清單；manual scan 加簡單 token（環境變數）；把冷卻判斷移進 `_harvest_lock` 臨界區內。

### 3.4 【中】靜態匯出體積：`intel.json` 內含 `raw_json`

`export_static.py:73` 匯出 400 筆完整 item，每筆 `raw_json` 上限 8KB、`summary` 未截斷 → `intel.json` 可達數 MB，行動網路首載慢（README 有宣稱 RWD／行動版）。

**改進方式**：匯出時剝除 `raw_json`、截斷 summary（如 600 字）、`indent=None`；大清單可拆 `intel-p0p1.json`／`intel-rest.json` 延遲載入。

### 3.5 【低】前端其他

| 項目 | 問題 | 建議 |
|------|------|------|
| 靜態模式「立即巡檢」（`app.js:921`） | 直接從瀏覽器抓 cisa.gov／ransomlook.io，多數來源無 CORS 標頭會失敗，使用者看到一排紅字 | 預先只列已知支援 CORS 的鏡像（raw.githubusercontent.com），其餘顯示「請用 Actions 更新」引導 |
| 分頁 a11y | `role="tablist"` 但未維護 `aria-selected`／`tabindex` 巡覽 | 切換時同步 aria 屬性 |
| `index.html` | 無 favicon、無 `<meta name="description">` | 補上；SOC 內網環境可考慮字型自載避免依賴 Google Fonts |
| 搜尋 `q` | LIKE 萬用字元 `%`／`_` 未跳脫（`database.py:305-309`） | escape 後加 `ESCAPE '\'` |
| `_bootstrap`（`main.py:74-81`） | `except Exception: pass` 靜默失敗，首啟無資料且無日誌 | 至少 `logging.exception` |

---

## 四、工程品質

1. **【高】零測試**。`priority.py` 與 `assign_verification` 是純函式、最該有表驅動單元測試（每條規則一組案例＋2.1/2.2 的迴歸案例）；`_scrub_finance_false_positives`、`match_microsoft_entities` 這類 heuristic 尤其需要案例鎖定行為。建議加 `pytest` ＋ GitHub Actions CI（lint + test），在部署 workflow 前置。
2. **【中】依賴未鎖版**：`requirements.txt` 全部 `>=`，CI 每次抓最新，上游 breaking change 會直接打壞排程部署。建議 `pip-compile` 產生 lock 檔供 CI 使用。
3. **【中】`collectors.py` 3,637 行單檔**：每個來源的 fetch→parse→enrich→upsert 大量複製貼上。建議拆成 `collectors/` 套件（每來源一模組）＋共用 ingest pipeline（fetch 與評分分離，也讓評分可單測）。
4. **【低】workflow 無 `timeout-minutes`**：collector 雖有 45–120s 逾時，但整體無上限；建議 job 設 30 分鐘。
5. **【低】大量 `except Exception: pass/continue`**：失敗來源雖有 `_mark` 記錄，但空 except（如 `collectors.py:3060-3067` 一段 no-op 死碼）應清理。

---

## 五、優先改進路線圖

| 優先 | 項目 | 對應章節 | 工作量 |
|------|------|----------|--------|
| 🔴 立即 | `item.url` XSS 修補（跳脫＋協定白名單） | 3.1 | 極小 |
| 🔴 立即 | P0 升級加 verification gate，與 README 對齊 | 2.1 | 小 |
| 🔴 立即 | EPSS 批次抓齊 120 筆；門檻進 config | 2.4 | 小 |
| 🟠 本週 | watchlist 字界比對＋短別名規則 | 2.2 | 小–中 |
| 🟠 本週 | `priority.py` 表驅動單元測試＋CI | 四.1 | 中 |
| 🟠 本週 | 靜態匯出剝除 raw_json、鎖依賴版本、workflow timeout | 3.4／四.2／四.4 | 小 |
| 🟡 本月 | Actions DB 持久化（actions/cache） | 3.2 | 中 |
| 🟡 本月 | KPI 時間窗（新增 vs 未結）＋ UTC 日界修正 | 2.7／2.8 | 中 |
| 🟡 本月 | 雙源比對改域名＋集團＋日期三要件 | 2.6 | 中 |
| 🟢 下季 | 來源評級表＋Admiralty 兩軸分離 | 2.3 | 中 |
| 🟢 下季 | 跨來源事件聚合（多源自動合併） | 2.5 | 大 |
| 🟢 下季 | 分析師回饋迴路與規則準確率月報 | 2.9 | 大 |

---

*本報告為程式碼靜態審查結果，未包含實際部署站點的動態測試（效能量測、真實 feed 資料驗證）。*
