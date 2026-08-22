# SOC CTI 情資網站 — 第四輪審查報告

- **審查日期**：2026-08-22
- **審查基準**：工作區 `master`（第三輪結案後的現行碼）
- **範圍**：網站功能、評分方法、資料可信度、JavaScript／XSS、CSP、GitHub Actions、supply-chain，以及其他改進
- **方法**：靜態審查現行碼與測試；對照 README 與第三輪結案表。**未含**線上 `chinchiang.github.io` 實測。

---

## 總評

第三輪之後的工程體質是實在的：媒體單源不能再靠 L7 層級直升 P0、`escapeHtml`／`safeHref`＋無 `'unsafe-inline'` 的 CSP 有測試守門、PR 不會部署 Pages、寫入端點 fail-closed。這次不是「再抓一次已修過的洞」，而是評分引擎**周圍**還有幾條旁路、GitHub Actions 權限過寬、以及文件／UI 與實際行為不一致。

最該先動的三件事：

1. **Google News 佐證邏輯與註解／測試相反**——同一媒體的站內 RSS＋GNews 鏡像可被算成雙源，兩家都走 GNews 的真實雙源反而被擋。這會重新打開 R3-1 想關的 P0 路徑。
2. **多個採集器跳過 `assign_verification`**，把社群／預測分數標成「可信／已證實」。
3. **本機 UI 沒有地方送 API 金鑰**，README 宣稱的「立即巡檢」與複核判定在預設安全姿態下恆為 401。

XSS 主路徑（標題、摘要、URL）目前是守住的；CSP 是有效的第二層，不是唯一層。

---

## 第三輪已結案、本輪複查仍成立（不再當新問題）

| 項目 | 落地 |
|------|------|
| 媒體單源不得因層級變 `credible` | `priority.py` `SINGLE_SOURCE_CREDIBLE_CLASSES`；`rss.py` 先 `derive_source_class` 再評分 |
| 監控名單英數字界、股號需市場上下文 | `_alias_regex()`；`gigabytes`／`tracer` 迴歸仍在 |
| P0 的 TW＋勒索需 `confirmed`／`credible` | `assign_priority`；`test_verification.py` |
| 微軟分頁、手機底欄、`prefers-reduced-motion` | `index.html`／`app.js`／`styles.css` 均有；資產測試守門 |
| API 金鑰常數時間比對、CORS 預設 8787、無 `*` | `main.py`／`config.py`／`test_api_security.py` |
| 靜態匯出剝 `raw_json`、sanity 裝 `requirements.txt`、workflow timeout、PR 不部署 | `export_static.py`、`deploy-cti-dashboard.yml` |
| `script-src 'self'`、無 inline handler、`escapeHtml` 用字串串接實體 | `index.html`、`app.js`、`test_frontend_csp.py` |

---

## 一、網站功能

### R4-1（中）本機「立即巡檢」與複核按鈕無法帶金鑰

`app.js` 的 `api()` 與判定 POST **從不**設 `X-API-Key`／Bearer。後端 `require_api_key` 在未設金鑰時 fail-closed（401），設了金鑰 UI 也送不出去。

結果：照 README 設 `SOC_CTI_API_KEY` 後，畫面上的巡檢與真／偽陽性按鈕永遠 401。唯一讓按鈕「能按」的是 `SOC_CTI_ALLOW_UNAUTHENTICATED=1`，而那正是 CSRF 可觸發巡檢的腳槍。

**建議**：UI 用 `sessionStorage` 讓值班人員貼一次金鑰（只活在該分頁、不要寫進 JS 檔）；或從 `/api/health` 的 `write_endpoints_enabled` 直接停用按鈕並說明改用 curl。不要為了讓按鈕能動而開未驗證寫入。

### R4-2（中）Pages「立即巡檢」不是文件寫的行為

README：靜態站會提示改走 Actions。實際 `manualScan()` 在 `USE_STATIC` 時呼叫 `browserLiveScan()`（KEV GitHub 鏡像＋ransomware.live；RansomLook 通常被 CORS 擋）。KPI 列還寫「可瀏覽器即時巡檢」。

瀏覽器端雙源比對是受害者名稱去非英數後的完全相等（`app.js`），**不是**後端的網域／集團／日期三要件。同一受害者也不會套用台灣監控名單升 P0。

**建議**：文件改寫實際行為；瀏覽器雙源改走與 `ransom.py` 相同規則，或乾脆只提示 Actions。

### R4-3（中）KPI／生命週期有後端、沒有對應 UI

README 寫上方四卡是「P0、KEV 近 7 日、台灣產業／勒索、來源健康」。畫面上是 **P0／P1／核實度／完整度**。`kpis.json` 已有 `priority_windows`、`kev_recent_7d`、`stale_count`、`verified_pct`、`osint_verified_pct`、`series_30d`，前端不算這些，也沒有 stale 篩選或徽章。核實度是 `1 - unverified/total`，不是後端的兩軸百分比。

### R4-4（低–中）靜態 JSON 不是同一快照；API 模式快取會過期

- 倉裡的 `kpis.json`／`meta.json`：`exported_at` **2026-08-11**；`preemptive-brief.json` 的 `date` 是 **2026-08-15**。總覽磚與 KPI 可能顯示兩個「今天」。線上站以最近一次 Actions 匯出為準，但 git 內快照已過期。
- API 模式 `ensureIntel()` 把 `/api/intel?limit=300` 快取到手動巡檢或整頁重載為止；120 秒 refresh **不清**這份快取。排程巡檢後，開著的分頁清單是舊的。靜態匯出 400 筆、API 預設 300，兩邊集合不一致。

### R4-5（低）其餘功能落差

- 卡片時間：有 `date_added` 就原樣字串，否則才 `formatTs`（臺北）。`published_at` 不用在卡片上。倉內 `review-queue.json` 仍可見 RFC-822（`Wed, 22 Jul 2026 … GMT`）。
- 時鐘後綴 `TST` 不是臺灣慣用縮寫（易與其他 TST 混淆）。
- 微軟專區在 dashboard JSON 過瘦時會自己拼 KEV／P1／勒索，但 Windows／企業平台／MSTI 分區維持空陣列。
- 載入失敗只 `console.error`，畫面停在「—」。
- 無 hash routing，重新整理回到總覽。
- `run.py` 綁 `0.0.0.0:8787`：GET 全無認證，區網可讀整庫（含 `raw_json`）。

微軟分頁、金融、先制、複核、來源、底欄捷徑**有接線**，不再是孤兒功能。

---

## 二、評分方法

規則引擎本身（`assign_priority` 互斥、TW＋勒索要核實、`force_p3_review`）是對的。問題在**呼叫端繞過它**，以及「勒索／台灣產業」旗標太寬。

### R4-6（高）Google News 佐證與程式註解相反

`aggregate.py` `link_domain()` 註解寫：GNews 代理要收成同一網域，避免站內 feed 與自己的 GNews 鏡像互證。實作只回 hostname。

| 配對 | 實際 |
|------|------|
| SecurityWeek RSS（`securityweek.com`）＋ SecurityWeek ICS GNews（`news.google.com`） | 來源名不同、網域不同 → **假雙源** → `credible` → TW＋勒索可 **P0** |
| Dark Reading GNews ＋ THN GNews（兩家真實媒體） | 都是 `news.google.com` → **不能互證** |

`force_p3_review` 在聚合時被明確拿掉。`test_aggregate.py` 的「GNews 鏡像」案例用的是 `thehackernews.com` vs `www.thehackernews.com`，**從沒測過 `news.google.com`**。

L6 已有 `thn_news_rss`／`securityweek_rss`，L7 另有對應 `*_ics_gnews`，這條路徑是活的。

**建議**：把 `news.google.com`／`google.com` 新聞連結還原到出版社註冊網域（或規定 GNews URL 不得當獨立證據）；補一個真正用 GNews URL 的測試。

### R4-7（高）採集器硬編核實狀態，不走 `source_class`

README：社群／OSINT／媒體單源＝未核實。OTX 有照做。下列沒有：

| 位置 | 硬編 | `assign_verification` 會給的 | 影響 |
|------|------|------------------------------|------|
| `iocs.py` ThreatFox | `credible`／B2 | L3＋community＋1 源 → unverified | 高信心家族再被抬成 P2；TW＋勒索家族可 P0 |
| `easm.py` | `credible`／B2 | L4 不在單源可信層 → unverified | 單次 InternetDB 看起來像雙源可信 |
| `ics.py` CSV 鏡像 | `confirmed`／A2 | L7＋official-gov → **credible**，不是 confirmed | 第三方 GitHub CSV 被標成 KEV 級 |
| `kev.py` EPSS top | `confirmed`／A2 | 預測分數 | 卡片文字寫「非 KEV」，徽章卻是已證實 |
| `breaches.py` HIBP | confirmed／credible | L5 → unverified | 外洩目錄當成已證實利用 |

ThreatFox 還在 `is_ransomware` 時寫 `known_ransomware_campaign=1`（`iocs.py`）。今天因 `in_kev=False` 不會觸發 KEV 的 P0 共因，但這個旗標不該出現在社群 IOC 彙總上。

### R4-8（高）L1 短路把非 KEV 標成「已證實」

```python
if layer_id in ("L1", "T1") and source_count >= 1 and not is_darkweb_indirect:
    return "confirmed", "A2"
```

L1 實際包含 **CISA News、CISA Alerts、NSA Cyber GNews、MSRC Update Guide**。README 的 Confirmed 是「官方 KEV 等」，official-gov 單源應為 **Credible**。`test_kev_and_l1_unaffected_by_class` 把這個混合寫成了迴歸、鎖死錯誤語意。

一篇 CISA 新聞或 NSA 的 Google News 結果，只要同時命中監控名單＋勒索關鍵字，就是 P0。

### R4-9（中）`is_ransomware` 仍是子字串 OR

監控名單已改字界；勒索偵測沒有。`RANSOMWARE_KEYWORDS` 含 `"ransom"`、`"data leak"`、`"akira"`、`"clop"`、`"blackcat"`。媒體單源仍是 P3；官方／研究／L1／硬編 credible 的來源加上監控名單命中就是 P0。

HIBP 用較嚴的清單（不含 `"data leak"`），對照剛好說明 RSS 路徑過寬。

### R4-10（中）`msi`／`asx` 監控名單誤中

- `"msi "` 經 `alias.strip()` 變成單詞 `msi` → Windows **MSI 安裝套件**公告會被標台灣電子。
- ASE（日月光）別名 `"asx"` → **澳洲證交所**財經稿會被標 `is_tw_industry`。
- `"psmc"` 別名含「力成」（6239，力成科技），與「力積電／PSMC」條目衝突。

### R4-11（中）暗網「雙源」新聞只要求標題 3 個 token 交集

`osint.py` `dual_source_darkweb_verify`：BleepingComputer × THN，標題 token 交集 ≥ 3 且與勒索／TW／金融／微軟有關即 `source_count=2`、解除 `force_p3`。沒有 Jaccard、網域、日期窗。兩則不同受害者的 LockBit 標題很容易共享 `lockbit`／`ransomware`／`attack`。

這兩條 feed 已在 `INTEL_FEEDS` 以媒體單源進一次，這裡又用不同 id 再進一次，同一事件可能同時是「未核實 P3」與「間接暗網雙源 P0」。

### R4-12（低）其他評分漂移

- ICS CSV 把 `sources_json` 寫成 `["CISA ICS", "ICS Advisory Project mirror"]`（兩個名字、一份資料）。評分用 `source_count=1`，但 UI `evidence_count` 來自 `len(sources)`。`test_fake_corroboration.py` 只禁字串 `secondary-media-citation`，抓不到這個。
- ICS 在引擎之後用 CVSS≥9／Critical 把 P3 抬成 P2，破壞「單一規則引擎」。
- EASM 對危險埠／CVE 同樣 P3→P2。
- `explain_priority` 的 P2 分支寫死 `epss >= 0.5`，不管 `EPSS_P2_THRESHOLD`。
- DFIR Report／SANS ISC 在 registry 是 `research`、README 說單源可信，但它們在 **L6**，單源可信只給 L2／L7 → 實際未核實。
- README 勒索雙源日期窗「≤14 日」；程式預設 7 日、硬上限 14。網域相同即可雙源（不需集團／日期）。
- RSS 多數呼叫沒接 `explain_priority`，判定依據要等聚合才可能出現。

---

## 三、資料可信度

1. **Google News 被當成官方源。** `nsa_cyber_gnews` 在 L1（已證實）；ACSC／CCCS／CERT-EU／BSI 的 GNews 是 official-gov（單源可信）。`site:` 查詢大致限制網域，但標題與連結仍是 Google 的聚合，不是機關 RSS。
2. **CISA ICS 官方 RSS 被擋時，改信 `icsadvprj/ICS-Advisory-Project` CSV**，卻標 `confirmed`／A2。這是第三方 GitHub 資料當 CISA。
3. **瀏覽器即時巡檢**吃 `raw.githubusercontent.com/cisagov/kev-data` 與 `data.ransomware.live`，不經 `clean_text`、也不經 SQLite CHECK。
4. **Nitter／xcancel 等鏡像**是額外的中間人信任。
5. **分析師判定偽陽性不會改 priority**（有意為之）。錯的 P0 會待到 14 日 stale。看板 precision 與 P0 數字會分家。
6. **`osint_verified_pct` 只排除 L1**，TWCERT／CISA ICS／Unit 42 算進「OSINT 核實率」。
7. 倉內匯出仍可能帶著修字界**之前**的列（Actions cache 沿用 DB）。沒有對 `is_tw_industry` 的一次性重評，舊誤中會待到過期。

---

## 四、JavaScript 安全與 XSS

**主路徑是好的。** 標題、摘要、rationale、owner、SOP、assets、來源晶片、OT 目錄、巡檢結果、實體標都經 `escapeHtml`。`safeHref` 用 `URL` 解析、只准 `http:`／`https:`，再編碼進屬性。無 `eval`／`Function`／`document.write`／inline handler。Toast 與 i18n 用 `textContent`。SQLite `CHECK (priority IN ('P0'…))` 擋住 RSS 文字寫入 enum。

### R4-13（低，防禦縱深）`innerHTML` 仍有未編碼插值

`cardHTML` 把 `priority` 當 class 與 pill **文字**插入、未跳脫；`evidence` 亦然。今日資料只能是 P0–P3／數字，CSP 也擋 inline script。這正是 CSP 註解假設「escapeHtml 漏了」時要撐住的縫。`briefCardHTML` 已跳脫 pill 文字、沒跳脫 class。

**建議**：渲染時 allowlist `P0|P1|P2|P3`；所有插值（含 enum、`t()` 進 HTML）都走 `escapeHtml`。

### R4-14（低）標題在採集時沒剝 HTML

`_parse_rss_entries` 對 summary 做 `clean_text`，**title 只 `.strip()`**。儀表板會顯示成文字；以後若有 `innerHTML = item.title` 的消費者會中招。連結也是到點擊才被 `safeHref` 擋。

### R4-15（低）`safeHref` 不管惡意 https

分析師仍會一鍵開 leak-site `post_url`、憑證釣魚 URL、IDN。這是情資站的產品選擇，不是 XSS。可對非白名單網域改成「只複製、不當連結」。

---

## 五、CSP

政策本身偏嚴、位置正確（任何 `<link>`／`<script>` 之前）：

- `default-src 'none'`；`script-src 'self'`；**沒有** `'unsafe-inline'`／`'unsafe-eval'`
- `object-src`／`base-uri`／`form-action` 皆 `'none'`
- `connect-src` 與 `browserLiveScan()` 主機有雙向測試

### R4-16（中）僅 meta、本機也沒有安全標頭

`<meta>` **忽略** `frame-ancestors`／`sandbox`／`report-uri`。FastAPI 的 `FileResponse` **不設** `Content-Security-Policy`、`X-Frame-Options`、`X-Content-Type-Options`。Pages 無法設標頭。本機儀表板可被嵌框；Pages 點擊劫持「立即巡檢」影響有限（無認證寫入）。

**建議**：ASGI middleware 複製同一 CSP，加上 `X-Frame-Options: DENY`、`nosniff`。Pages 維持 meta。

### R4-17（低）CSP 測試可被繞過

- 未斷言 `script-src == ["'self'"]`；`connect-src`／`img-src` 的 `*` 不會被現有檢查抓到
- `style="` 抓不到 `style='…'`；event handler 清單不全，且**不掃 `app.js` 模板**
- `_fetched_hosts()` 只看同一行字面 `https://`，組出來的 URL 會漏

Google Fonts 在 `style-src`／`font-src` 無 SRI：被攻陷的 CSS 可以改版面（釣魚殼），不能跑 JS。SOC 站還會把訪客 IP 洩給 Google。宜自架 woff2。

`connect-src` 放行整個 `raw.githubusercontent.com`，可收窄到 `cisagov/kev-data` 路徑（CSP3 path source）。

---

## 六、GitHub Actions

已做好的：PR 只跑 sanity、不部署；無 `pull_request_target`；concurrency 按 ref；兩個 job 有 timeout；secrets 只在 harvest 步驟注入；SQLite 不進 Pages artifact。

### R4-18（中）workflow 層 `pages: write`＋`id-token: write` 落到 PR 的 sanity

```yaml
permissions:
  contents: read
  pages: write
  id-token: write
```

對**每個** job 生效。同倉 PR 的 `GITHUB_TOKEN` 帶 Pages／OIDC 權限；`actions/checkout` 預設 `persist-credentials: true`，token 留在 `.git/config` 供 pip／pytest 期間使用。`github-pages` environment 不掛在 sanity 上，保護規則管不到。

Fork PR 在公開倉仍是 read-only。風險是同倉協作者／被植入的測試或 PyPI 輪。

**建議**：workflow 層只留 `contents: read`；`pages`／`id-token` 只給 `build-and-deploy`；兩處 checkout 都 `persist-credentials: false`。

### R4-19（低–中）其餘 workflow

- 所有 `uses:` 是漂浮 tag（`actions/checkout@v7` 等），不是 SHA。
- `pip install --upgrade pip` 無上界；pytest 無釘版。
- `py_compile backend/*.py` **不含** `backend/collectors/*.py`（pytest 有 import 多數模組，語法錯誤多半仍會爆）。
- `workflow_dispatch` 可對非預設分支跑（該分支的 workflow 檔＋倉 secrets），除非 environment 要審核。
- Shodan 金鑰走 query string。外層 `except` 把 `str(e)[:500]` 寫進 `source_health`；`layers.json` 會進 Pages。內層單 IP 失敗有吞掉，但模式不安全。

---

## 七、Supply-chain

### R4-20（中）Python 依賴無 hash、無 Dependabot

`requirements.txt` 只有上下界。每日兩次 harvest 解析「當天早上還在範圍內的輪」。無 lockfile、無 `--require-hashes`、無 Dependabot／Renovate、無 CODEOWNERS、無 SECURITY.md。被攻陷的 FastAPI／httpx／feedparser 小版本與 harvest 同程序，讀得到 `SHODAN_API_KEY`、`CENSYS_API_SECRET`、`HIBP_API_KEY` 等。

### R4-21（高，若有設定監控目標）EASM／HIBP 監控目標會出現在公開 Pages

`EASM_WATCH_IPS`／`HOSTS`／`HIBP_WATCH_DOMAINS` 放在 Actions **secrets**，harvest 之後寫進卡片標題／摘要（IP、主機名、埠、CVE、監控網域），`slim()` 不刪。公開 `chinchiang.github.io` 等於公布攻擊面。Secret 只是不讓 YAML 印出來。

未設這些 secret 時採集器 no-op，這份公開倉現況可能沒事。**文件卻引導把監控目標當成 secret 接上這條會匯出的路徑。**

**建議**：Pages 匯出跳過 L4 與 HIBP 網域監控；那些只留本機 API。或把公開站與內部站拆開。

### R4-22（中）第三方內容 → 靜態 JSON → Pages

設計上就是如此：排程 runner 抓不可信 RSS／JSON，寫進 `frontend/data/*.json`。XSS 有 sanitizer＋CSP；**內容完整性／假情資**沒有（GNews、Nitter、社群 CSV）。`official-gov` 標在部分 GNews 鏡像上會放大這個問題。

Google Fonts 無完整性（見 CSP）。自架字型可同時拿掉兩個 CSP 來源。

---

## 八、建議優先順序

| 優先 | 項目 | 對應 |
|------|------|------|
| 1 | 還原／隔離 `news.google.com` 佐證＋用真實 GNews URL 的測試 | R4-6 |
| 2 | ThreatFox／EASM／ICS／EPSS／HIBP 走 `assign_verification`；EPSS 不得 `confirmed`；L1 不得一律 A2 | R4-7、R4-8 |
| 3 | 權限拆開；checkout `persist-credentials: false`；Pages 不匯出 EASM／HIBP 網域監控 | R4-18、R4-21 |
| 4 | 本機 UI 金鑰或停用按鈕；README 對齊 `browserLiveScan` | R4-1、R4-2 |
| 5 | 勒索關鍵字改字界；拿掉／改寫 `msi `、`asx`；收緊暗網 token 雙源 | R4-9–R4-11 |
| 6 | Actions SHA pin、`pip-compile --generate-hashes`、Dependabot | R4-19、R4-20 |
| 7 | 本機安全標頭；CSP 測試鎖死 `script-src 'self'`；自架字型 | R4-16、R4-17 |
| 8 | KPI 接到 `priority_windows`／兩軸核實度；失效 intel 快取；卡片時間一律 `formatTs` | R4-3、R4-4、R4-5 |

---

*本輪未含線上站點點擊實測。XSS 結論來自對 `innerHTML` 呼叫點、CSP meta、以及 SQLite CHECK 的靜態追蹤。*
