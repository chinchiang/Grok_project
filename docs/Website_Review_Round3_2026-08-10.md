# SOC CTI 情資網站 — 第三輪審查報告

- **審查日期**：2026-08-10（第三輪）
- **審查基準**：`origin/master` @ `b9f885b`（對照第二輪 `docs/Website_Review_Round2_2026-08-10.md`）
- **本輪方法**：靜態審查 ＋ **實際執行驗證**（`node --check`、runtime 跳脫測試、`pytest`、AST 掃描全部呼叫點）

---

## 一、驗收結論：R2 四項阻斷性問題全部確實修正 ✅

這輪修得很紮實，而且修正手法有考慮到根因（不只是把症狀壓下去）。

| 編號 | 項目 | 驗證方式 | 結果 |
|------|------|---------|------|
| R2-1 | `app.js` 語法錯誤／跳脫失效 | `node --check` → exit 0；實際 eval 函式測試 | ✅ **通過**。`escapeHtml("<img onerror=alert(1)> & \"q\"")` → `&lt;img onerror=alert(1)&gt; &amp; &quot;q&quot;`；`safeHref("javascript:alert(1)")` → `""`；`safeHref("data:text/html,…")` → `""` |
| R2-2 | P0 verification gate 未接線 | AST 掃描 `collectors.py` 全部 12 個 `assign_priority()` 呼叫點 | ✅ **12/12 全數接線**，且順序正確（verification 先解析再評分） |
| R2-3 | EPSS 門檻耦合 | `config.py:210` 新增獨立 `EPSS_P2_THRESHOLD` env，`priority.py` 改 import | ✅ **通過** |
| R2-4 | 無 CI 守門 | 實跑 `PYTHONPATH=. pytest tests/ -q` | ✅ **5 passed**；workflow 新增 `sanity` job 且 `build-and-deploy` 有 `needs: sanity`，壞版本無法上線 |
| — | collectors.py 完整性 | 比對 `66472d1` 與現況的函式清單 | ✅ **27 個函式完全一致**，還原乾淨無遺漏 |
| 3.3（第一輪） | CORS 全開＋巡檢無認證 | 程式審查 | ✅ 額外完成：`CORS_ORIGINS` env、`X-API-Key`／Bearer 驗證 |

**特別值得肯定的三個細節**：

1. `escapeHtml` 改用 `"&" + "amp;"` 字串串接，讓編輯器無法再次自動反解實體——直接堵住 R2-1 的**根因**而非只修表徵。
2. `_upsert_ransom_victim_item` 把 `is_tw_industry=is_tw and dual_verified` 改回 `is_tw`，改由 verification gate 統一把關，消除了雙重防線互相掩蓋的問題。
3. `test_priority.py` 的 `test_dual_source_tw_ransom_mimics_collector_order` 直接把 R2-2 的錯誤呼叫順序寫成迴歸案例——這正是防止同類錯誤復發的正確做法。

---

## 二、本輪新發現

### 🟠 R3-1（中｜**最重要**）：P0 gate 已接線，但 `credible` 的定義太寬，媒體單篇報導即可觸發 P0

R2-2 的 gate 依賴 `verification in ("confirmed", "credible")`。但 `priority.py:233-234` 的判定是：

```python
if layer_id in ("L2", "L7", "T2", "T7"):
    return "credible", "B2"      # 單一來源即可
```

問題在於 **L7 實際上混編了大量媒體 feed**，而非只有權威來源。實查 `INTEL_FEEDS`：

| L7 中的媒體來源 | 標籤 |
|----------------|------|
| Dark Reading ICS/OT | `ot-media` |
| SecurityWeek ICS/OT | `ot-media` |
| The Hacker News ICS | `ot-media` |
| Industrial Cyber | `ot-media` |
| Infosecurity Magazine ICS | `ot-media` |
| SANS ICS（Google News） | — |

**結果**：一篇 Dark Reading ICS 報導只要同時提到某台灣公司名與 ransomware，`verification` 就會是 `credible` → 通過 P0 gate → **自動升 P0**。這正是 R2-2 想關掉的誤報路徑，只是換了個入口。

**風險被第一輪 2.2 進一步放大**：監控名單目前仍是無字界的子字串比對（`priority.py:45`），`UMC`、`AUO`、股號 `2317` 會誤中無關文字——兩個問題疊加，就是「媒體文章隨機誤中公司名 → 直升 P0」。

**修正方式**（資料結構已就緒，改動不大）：`INTEL_FEEDS` 的 `extra_tags` 已經區分了 `official-gov` 與 `ot-media`。把來源可靠度傳進 `assign_verification`，只讓官方／PSIRT 享有單源 credible：

```python
def assign_verification(
    *, in_kev, layer_id, source_count, is_darkweb_indirect,
    source_class: str = "media",   # official-gov | vendor-psirt | media | osint
) -> tuple[str, str]:
    ...
    if source_count >= 2:
        return "credible", "B2"
    # 單源只有官方／廠商 PSIRT 才算可信
    if source_class in ("official-gov", "vendor-psirt") and layer_id in ("L2", "L7"):
        return "credible", "B2"
    return "unverified", "C3"
```

`collect_rss_layer` 依 `extra_tags` 推導 `source_class` 傳入即可。這同時也把第一輪 2.3（Admiralty 兩軸分離）往前推進一步。

**建議一併補的測試**：

```python
def test_single_media_source_tw_ransom_is_not_p0():
    """L7 媒體單篇報導不得因 TW+勒索關鍵字升 P0。"""
    v, _ = assign_verification(
        in_kev=False, layer_id="L7", source_count=1,
        is_darkweb_indirect=False, source_class="media",
    )
    assert v == "unverified"
    assert assign_priority(
        in_kev=False, known_ransomware_campaign=False, is_ransomware=True,
        is_tw_industry=True, epss=None, source_count=1, layer_id="L7",
        verification=v,
    ) == "P3"
```

### 🟠 R3-2（中）：微軟專區是「孤兒功能」——後端全做了，前端沒有入口

實查結果：

| 層 | 狀態 |
|----|------|
| `backend/ms_dashboard.py`（244 行） | ✅ 存在 |
| `GET /api/microsoft-dashboard` | ✅ 存在 |
| `frontend/data/microsoft-dashboard.json` | ✅ 有匯出 |
| `app.js:503-505` 靜態路由 handler | ✅ 存在 |
| `app.js:647` 讀取 `#filterMs` | ⚠️ 該元素 **index.html 中不存在**（grep = 0） |
| index.html 微軟分頁 | ❌ **沒有**（分頁只有 overview／highrisk／taiwan／ot／dark／ems／finance／sources） |
| `loadMicrosoft()` | ❌ **不存在** |
| i18n 微軟字串 | ❌ **沒有** |

但**兩份 README 都把「微軟相關 Dashboard」列為已實作功能**（根 README 功能表、`soc_cti_dashboard/README.md` 功能對照表與 API 摘要）。使用者看文件找不到入口。

**修正方式**（擇一）：
1. 補齊 UI——資料結構已完備，約 30 行 HTML＋40 行 JS 即可（可直接複製金融專區的 `loadFinance()` 結構）；
2. 或從兩份 README 移除該功能宣稱，把 API 標注為「僅 API，尚無 UI」。

不論選哪個，`app.js:647` 對不存在元素的 `#filterMs` 參照都該清掉。

### 🟡 R3-3（低–中）：CI sanity job 未安裝專案相依，測試無法擴充

`deploy-cti-dashboard.yml` 的 sanity job 只跑 `pip install -q pytest`。目前能通過，純粹因為 `test_priority.py` 只 import `backend.priority` → `backend.config`，兩者都僅用標準庫。

**但任何要測 `collectors` / `main` / `database` 的測試都會 `ImportError`**（缺 httpx／fastapi／aiosqlite／feedparser）而讓 CI 紅燈——等於把測試涵蓋面鎖死在 `priority.py` 一個模組。

**修正方式**：

```yaml
          pip install -r requirements.txt
          pip install -q pytest
```

（`setup-python` 已設 `cache: pip`，成本很低。）

### 🟡 R3-4（低）：`explain_priority` 的 `verification` 參數同樣沒接線——新的 P3 說明文字永遠不會出現

R2 在 `ops.py:155-160` 新增了「TW＋勒索但核實不足 → 維持 P3」的判定依據文字，但 `collectors.py` 三個 `explain_priority()` 呼叫點（`line 202 / 2305 / 2860`）**都沒有傳入 `verification=`**，全部落在預設 `"unverified"`。

實際影響：該分支的條件 `is_tw_industry and is_ransomware and verification not in (...)` 在預設值下**反而恆為真**，所以只要 TW＋勒索且落 P3 就會顯示這段文字——碰巧結果是對的，但**是靠預設值巧合達成，不是靠正確的資料流**。一旦有呼叫點改傳真實值，行為就會不一致。

與 R2-2 屬同一類錯誤（新增參數但未更新呼叫端），只是這次僅影響顯示文字、不影響評級。建議三處一併補上 `verification=verification`。

### 🟡 R3-5（低）：commit 訊息與實際變更不符

`47796f8` 的訊息宣稱四件事：

> API key auth + CORS restrict, **Microsoft tab UI**, **JSON slim**, priority unit tests

但該 commit **實際只改了 `config.py`（+11 行）**。其中：
- 「Microsoft tab UI」→ 見 R3-2，從未實作；
- 「static JSON strips raw_json/tags_json」→ `scripts/export_static.py` **自始至終未被修改**（第一輪 3.4 的 `intel.json` 肥大問題仍在）。

API key 與 CORS 的實作其實在後續的 `bb5901b`、測試在 `1c3cd4a`。訊息與內容脫節會讓日後事故回溯誤判「這個功能應該早就有了」。建議 commit 訊息只描述該 commit 真正包含的變更。

### 🟡 R3-6（低）：CORS 預設清單不含實際服務埠

`config.py:206-209` 預設允許 `localhost:8000`、`127.0.0.1:8000`、`localhost:3000`，但 `run.py:12` 實際監聽 **8787**，README 也是引導使用者開 `http://127.0.0.1:8787`。

目前不影響運作（前端與 API 同源，根本不走 CORS），但預設值有誤導性，日後前後端分離部署會踩到。另 `allow_credentials=True` 搭配 fallback `["*"]` 時瀏覽器會拒絕帶憑證的請求；既然 `CORS_ORIGINS` 有預設值不可能為空，該 fallback 可直接移除。

**修正方式**：預設改 `http://127.0.0.1:8787,http://localhost:8787`，並移除 `if CORS_ORIGINS else ["*"]`。

### 🟡 R3-7（低）：API 金鑰比對非常數時間 ＋ 三個新環境變數未寫進 README

- `main.py` 的 `provided != API_KEY` 建議改 `secrets.compare_digest(provided, API_KEY)`（一行，消除時序側通道）。
- 新增的 `SOC_CTI_API_KEY`／`API_KEY`、`CORS_ORIGINS`、`EPSS_P2_THRESHOLD` **都沒進 README 的選用金鑰表**。其中 `EPSS_P2_THRESHOLD` 會直接改變評鑑規則，尤其應該寫進方法論段落並在「來源與排程」分頁顯示目前值。

---

## 三、第一輪未處理項目（狀態追蹤）

| 項目 | 章節 | 狀態 | 備註 |
|------|------|------|------|
| 監控名單字界比對 | 2.2 | ⏳ | **優先度提升**——P0 gate 已生效，子字串誤中現在是 P0 誤報的主要剩餘來源（見 R3-1） |
| L2/L7 單源 credible／Admiralty 兩軸 | 2.3 | ⏳ | **優先度提升為本輪第一**（R3-1） |
| 跨來源事件聚合 | 2.5 | ⏳ | |
| 雙源比對三要件（域名＋集團＋日期） | 2.6 | ⏳ | |
| 情資生命週期／KPI 時間窗 | 2.7 | ⏳ | |
| UTC 日界、breach KPI 含 ThreatFox、JSON LIKE | 2.8 | ⏳ | |
| 分析師回饋迴路 | 2.9 | ⏳ | 長期最重要 |
| Actions DB 持久化 | 3.2 | ⏳ | |
| 靜態匯出剝除 raw_json | 3.4 | ⏳ | 曾在 commit 訊息中宣稱完成，實際未做（R3-5） |
| 依賴鎖版、workflow timeout | 四.2／四.4 | ⏳ | |

---

## 四、更新後的優先順序

| 優先 | 項目 | 對應 | 工作量 |
|------|------|------|--------|
| 🟠 本週 | `assign_verification` 加 source_class，媒體單源不得 credible ＋ 迴歸測試 | R3-1 | 小–中 |
| 🟠 本週 | 監控名單字界比對（與上一項同屬 P0 誤報控制） | 2.2 | 小–中 |
| 🟠 本週 | 微軟專區：補 UI 或改 README | R3-2 | 小 |
| 🟡 本週 | sanity job 安裝 requirements.txt | R3-3 | 極小 |
| 🟡 本週 | `explain_priority` 三處接線、CORS 預設埠、`compare_digest`、README 補三個 env | R3-4／6／7 | 極小 |
| 🟡 本月 | 靜態匯出剝 raw_json、依賴鎖版、workflow timeout | 3.4／四.2／四.4 | 小 |
| 🟡 本月 | Actions DB 持久化、KPI 時間窗＋UTC 日界 | 3.2／2.7／2.8 | 中 |
| 🟢 下季 | Admiralty 兩軸完整化、事件聚合、分析師回饋迴路 | 2.3／2.5／2.9 | 大 |

---

## 五、總評

第二輪的四項阻斷性問題**全部確實修正並經實測驗證**，CI 守門也已就位——專案已脫離「壞版本會直接上線」的高風險狀態，工程體質有明顯提升。

本輪最值得處理的是 **R3-1**：P0 gate 的**接線**已經正確，但它所依賴的 `credible` **定義**仍讓 L7 媒體單篇報導過關。修正資料（`extra_tags` 的 `official-gov` / `ot-media`）已經在 config 裡了，改動不大，卻是讓 P0 真正回到「需立即處置」語意的最後一哩路。

---

*本輪含實際執行驗證：`node --check`（app.js／i18n.js 皆 exit 0）、escapeHtml／safeHref runtime 行為測試、`pytest tests/ -q`（5 passed）、AST 掃描 12 個 `assign_priority` 與 3 個 `explain_priority` 呼叫點、collectors.py 函式清單比對。未含線上站點實測。*
