# SOC CTI 情資網站 — 第二輪審查報告（修正驗收）

- **審查日期**：2026-08-10（第二輪）
- **審查基準**：`origin/master` @ `e98a835`（對照第一輪報告 `docs/Website_Review_2026-08-10.md`）
- **本輪範圍**：驗收 `cf41e8d`～`e98a835` 五個修正 commit，並重新檢視整體功能與評鑑方法

---

## ⚠️ 結論先講：兩個新引入的阻斷性問題，需立即處理

修正的**方向全部正確**，但其中兩處在落地時出了問題——其一會讓**整個網站無法運作**，且 master 的 push 已觸發 Pages 部署，**線上站點目前應已是空白頁**。

### 🔴 R2-1（阻斷）：`app.js` 語法錯誤，全站前端掛掉

`e98a835` 強化 `escapeHtml` 時，HTML 實體字串被工具反解成了字元本身（`app.js:392-398`，master 現況）：

```js
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&")      // ← 應為 &amp;（現在是原字取代原字，等於沒跳脫）
    .replace(/</g, "<")      // ← 應為 &lt;
    .replace(/>/g, ">")      // ← 應為 &gt;
    .replace(/"/g, """)      // ← 應為 &quot;；三個引號連寫是【語法錯誤】
    .replace(/'/g, "&#39;"); // ← 只有這行是對的
}
```

`node --check` 確認：`SyntaxError: missing ) after argument list`。單一語法錯誤使**整份 app.js 無法解析**——所有分頁、KPI、卡片、巡檢全部失效。即使修好語法，前三行「原字取代原字」也等於**把跳脫功能整個移除**，XSS 防護反而比修正前更差。

**修正方式**（將實體字串還原）：

```js
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
```

修好後請立刻重新部署 Pages。**根因**是編輯流程把 HTML 實體反解，建議提交前固定跑一次 `node --check frontend/app.js`（見 R2-4 的 CI 建議）。

### 🔴 R2-2（高）：P0 verification gate 設計正確，但沒有任何呼叫端接線

`priority.py:206` 新增的門檻是對的：

```python
if is_tw_industry and is_ransomware and verification in ("confirmed", "credible"):
    return "P0"
```

但 grep 全部 12 個 `assign_priority()` 呼叫點（`collectors.py:186/486/689/870/1157/1309/1793/2166/2299/2862/3272/3402`），**沒有一個傳入 `verification=`**，全部落在預設值 `"unverified"`——這條 P0 路徑因此**永遠不會觸發**。

最關鍵的是 `_upsert_ransom_victim_item`（`collectors.py:2299`）：雙源核實（Ransomware.live ∩ RansomLook）的台灣受害者，正是這條規則**應該**升 P0 的唯一情境，但該處 `verification` 是在 `assign_priority` **之後**才計算（`collectors.py:2317-2326`），且未回傳給規則引擎。結果：雙源可信的台灣勒索受害現在只會落在 P2（多源規則），**比修正前（會升 P0）更保守，也讓新規則形同虛設**。

**修正方式**：把 verification 的計算移到 assign_priority 之前，並把已知的核實狀態傳入。以 `_upsert_ransom_victim_item` 為例：

```python
    # 先定核實狀態（雙源→credible），再算優先級
    if dual_verified:
        verification, admiralty = "credible", "B2"
    else:
        verification, admiralty = "unverified", "C3"

    priority = assign_priority(
        in_kev=False,
        known_ransomware_campaign=False,
        is_ransomware=is_ransom,
        is_tw_industry=is_tw and dual_verified,
        epss=None,
        source_count=source_count,
        layer_id="L6",
        force_p3_review=force_p3,
        verification=verification,          # ← 接線
    )
```

其他呼叫端同理：KEV（`collectors.py:186`）傳 `verification="confirmed"`；官方 RSS 層先呼叫 `assign_verification` 再傳入結果。**驗收條件**：寫一個單元測試斷言「dual_verified 台灣勒索受害 → P0；單源同樣內容 → P3」。

---

## 二、修正驗收明細

| 第一輪編號 | 修正內容 | 驗收結果 |
|-----------|---------|---------|
| 3.1 XSS `item.url` | `safeHref()`：`new URL()` 解析＋http/https 白名單＋跳脫，`rel` 加 `noreferrer`；OT catalog 連結與文字也補了跳脫 | ✅ **設計正確**，但被 R2-1 的 escapeHtml 損壞連帶影響——escapeHtml 修好後即完整生效 |
| 2.1 P0 需核實門檻 | `assign_priority` 加 `verification` 參數；`explain_priority` 理由文字同步，並新增「TW＋勒索但未核實 → 維持 P3」的說明 | ⚠️ **規則對、接線缺**（R2-2）；rationale 文字部分 ✅ |
| 2.4 EPSS 全量 | `_fetch_epss_batch(cve_list)` 移除 `[:80]`；內部以 40 個一批分段呼叫 | ✅ **完整修正**，120 筆 KEV 全數富化 |
| 2.4 門檻進 config | `EPSS_P2_THRESHOLD = float(EPSS_TOP_MIN)` | ⚠️ 見 R2-3 |
| （事故）collectors.py 曾被佔位檔覆寫 | `d2a2cb0` 還原 | ✅ 確認完整還原（3,637 行，與修正前版本僅差 EPSS 一行） |

### 🟡 R2-3（低）：EPSS 門檻的註解與程式不符，且兩個旋鈕耦合

`priority.py:38-39` 註解寫「overridable via env `EPSS_TOP_MIN` / `EPSS_P2_THRESHOLD`」，但程式只讀 `EPSS_TOP_MIN`（`config.py:196`），`EPSS_P2_THRESHOLD` 環境變數實際上**無效**。且 `EPSS_TOP_MIN` 同時控制「EPSS top-score 抓取門檻」與「P2 判級門檻」——調高抓取門檻會不知不覺同時改變評鑑規則。

**修正方式**：`config.py` 增加獨立變數：

```python
EPSS_P2_THRESHOLD = float(os.environ.get("EPSS_P2_THRESHOLD") or EPSS_TOP_MIN)
```

`priority.py` 改 import 這個值，README 的方法論段落補上目前門檻值。

---

## 三、本輪事故的共同根因：沒有 CI 守門

### 🔴 R2-4：這輪三個問題（app.js 語法錯誤、gate 未接線、collectors.py 被覆寫）全部可被最小 CI 攔下

- `node --check frontend/app.js` —— 一行指令就能擋住 R2-1（**部署 workflow 目前完全沒有語法檢查，壞檔直接上線**）；
- `python -m py_compile backend/*.py` ＋ 一個 20 行的 pytest（表驅動測 `assign_priority`）—— 能擋住 R2-2 與覆寫事故；
- 建議在 `deploy-cti-dashboard.yml` 的 harvest 步驟**之前**插入 check job，失敗即中止部署，避免壞版本發佈到 Pages。

最小可行版本（供直接採用）：

```yaml
      - name: Sanity checks (block bad deploys)
        working-directory: soc_cti_dashboard
        run: |
          node --check frontend/app.js
          node --check frontend/i18n.js
          python -m py_compile backend/*.py scripts/*.py
          pip install pytest && python -m pytest tests/ -q
```

搭配第一批測試案例（`tests/test_priority.py`）：

```python
from backend.priority import assign_priority

def test_dual_verified_tw_ransom_is_p0():
    assert assign_priority(
        in_kev=False, known_ransomware_campaign=False, is_ransomware=True,
        is_tw_industry=True, epss=None, source_count=2, layer_id="L6",
        verification="credible",
    ) == "P0"

def test_single_source_tw_ransom_stays_p3():
    assert assign_priority(
        in_kev=False, known_ransomware_campaign=False, is_ransomware=True,
        is_tw_industry=True, epss=None, source_count=1, layer_id="L6",
        force_p3_review=True, verification="unverified",
    ) == "P3"

def test_kev_without_elevation_is_p1():
    assert assign_priority(
        in_kev=True, known_ransomware_campaign=False, is_ransomware=False,
        is_tw_industry=False, epss=None, source_count=1, layer_id="L1",
        verification="confirmed",
    ) == "P1"
```

---

## 四、第一輪未處理項目（狀態追蹤）

> **狀態更新：2026-08-19。本表全部結案。**
> 這張追蹤表與第三輪報告的第三節是同一份清單，逐項的落地位置與驗證方式記在
> **`Website_Review_Round3_2026-08-10.md` 第三節**，該處為主；此處只留結果，
> 避免兩份文件各記一半而再度失準。

| 項目 | 章節（第一輪） | 狀態 | 備註 |
|------|--------------|------|------|
| 監控名單字界比對 | 2.2 | ✅ `6516911` | `priority.py:65 _alias_regex()` |
| L2/L7 單源 credible／Admiralty 兩軸分離 | 2.3 | ✅ `773498b` | `assign_verification(source_class=…)` |
| 跨來源事件聚合（source_count 恆為 1） | 2.5 | ✅ `6516911` | 新增 `backend/aggregate.py` |
| 雙源比對改「域名＋集團＋日期」三要件 | 2.6 | ✅ `6516911` | `collectors/ransom.py` |
| 情資生命週期／KPI 時間窗 | 2.7 | ✅ `6516911` | `first_seen`／`last_seen`／`STALE_AFTER_DAYS` |
| UTC 日界、breach KPI 含 ThreatFox、JSON LIKE | 2.8 | ✅ `6516911` | `today_taipei()`；改用 `json_each()` |
| 分析師回饋迴路 | 2.9 | ✅ `6516911` | `set_analyst_verdict()`／`get_rule_accuracy()`＋複核佇列分頁 |
| Actions DB 持久化（actions/cache） | 3.2 | ✅ `6516911` | workflow「Restore intel database」 |
| CORS 收斂＋manual scan token | 3.3 | ✅ `bd61f76` | `CORS_ORIGINS` env ＋ `X-API-Key`／Bearer |
| 靜態匯出剝除 raw_json | 3.4 | ✅ `6516911` | `export_static.py:55 _DROP_FIELDS` |
| 依賴鎖版、workflow timeout | 四.2/四.4 | ✅ `6516911` | `requirements.txt` 上界；`timeout-minutes: 10`／`30` |

---

## 五、更新後的優先順序

1. 🔴 **立即**：修復 `escapeHtml`（R2-1）並重新部署——線上站點目前無法使用。
2. 🔴 **立即**：接線 `verification` gate（R2-2）＋上面三個單元測試。
3. 🔴 **本週**：workflow 加 sanity-check job（R2-4）——這是防止同類事故再發生的結構性解法。
4. 🟡 **本週**：EPSS 門檻獨立環境變數（R2-3）、靜態匯出剝 raw_json、依賴鎖版。
5. 其餘照第一輪路線圖（🟡 本月：DB 持久化、KPI 時間窗、字界比對；🟢 下季：來源評級、事件聚合、回饋迴路）。

---

*本輪為靜態審查＋語法驗證（node --check）；未含線上站點實測。R2-1 的影響推論自「push 已觸發 Pages workflow」，建議開站確認。*
