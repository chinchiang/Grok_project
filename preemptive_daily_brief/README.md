# 先制式資安日報模組（Preemptive Cybersecurity Daily Brief）

臺灣 ODM/EMS 電子製造集團全球資安管理處用的 **OSINT → 三訊號排序 → 正體中文日報** 模組。

日報回答的不是「昨天發生了什麼」，而是「**今天必須先做什麼，才能讓攻擊鏈第一環無法形成**」。

SOC 儀表板「⚔ 先制式資安」分頁讀取同一份產出。

## 快速產出

在倉庫根目錄：

```bash
# 獨立抓取（KEV / EPSS / NVD / RSS）並寫出當日日報
python -m preemptive_daily_brief.scripts.generate_brief

# 只從既有 SOC 情資庫組裝（不額外打外網；儀表板／Actions 用這條）
python -m preemptive_daily_brief.scripts.generate_brief --from-intel
```

產出：

| 路徑 | 說明 |
|------|------|
| `output/daily_YYYY-MM-DD.md` | 完整八節正體中文日報 |
| `output/daily_YYYY-MM-DD.json` | 儀表板／API 用結構化資料 |
| `state/reported.json` | 去重指紋（CVE、URL hash、EPSS 快照） |

## 三訊號優先級

| 級別 | 條件 | 進「今日必辦」？ |
|------|------|------------------|
| **P0** | 列入 CISA KEV，或已確認大規模利用 | 是 |
| **P1** | EPSS ≥ 0.5 或 24h 跳升 ≥ 0.2，且 CVSS ≥ 7.0，且命中本組織資產類型 | 是 |
| **P2** | CVSS ≥ 9.0 但 EPSS 低 | 否（觀察） |
| **P3** | 其餘 | 否 |

命中 `config/assets.yaml` 者升一級，並標〔本組織相關〕。

證據分級：【已證實】一手官方／【第三方評論】媒體與分析／【尚未證實】傳聞或單源預測。

## 目錄

```
preemptive_daily_brief/
├── CLAUDE.md                 # 情報代理指令（日報規格）
├── config/
│   ├── sources.yaml          # Tier 1–4 來源
│   ├── assets.yaml           # 本組織技術堆疊（升級排序）
│   └── vendors.yaml          # PSIRT 監控廠商
├── lib/                      # 分類、組裝、狀態、YAML
├── scripts/                  # fetch_kev / epss / nvd / rss + generate_brief
├── state/reported.json
└── output/
```

## 與儀表板的關係

`soc_cti_dashboard/backend/preemptive.py` 呼叫本模組的 `compose_from_intel()`：

- 本機 API：`GET /api/preemptive-brief`
- GitHub Pages：`frontend/data/preemptive-brief.json`（`export_static.py` 一併寫出）

OT 建議一律經變更管制（CAB），模組不會產出主動掃描或未核准自動化補救。
