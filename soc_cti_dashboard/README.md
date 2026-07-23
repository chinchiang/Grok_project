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
| 上方四項 KPI | P0、KEV 近 7 日、台灣產業／勒索、來源健康度 |
| 每日 07:00、15:00 | APScheduler Cron（臺灣時間） |

### 優先級（互斥）

- **P0**：KEV 且已知勒索活動使用；或 台灣電子／半導體受害且勒索；或 台灣產業 + KEV  
- **P1**：列入 CISA KEV 且未達 P0  
- **P2**：非 KEV，EPSS ≥ 0.5 或多來源可信  
- **P3**：其餘監控項  

### 核實狀態

- **已證實 Confirmed**：官方 KEV 等  
- **可信 Credible**：≥ 2 獨立來源  
- **未核實 Unverified**：單源（尤其暗網間接）  

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
- `GET /api/intel?priority=P0&verification=confirmed&ransomware=true&tw=true`  
- `GET /api/tw-dashboard` — 台灣產業獨立看板  
- `GET /api/layers` — 七層健康  
- `POST /api/scan/manual` — 手動巡檢（30 分鐘冷卻）  

## 選用 API 金鑰（強化 L3/L4/L5）

目前 L4 Shodan/Censys、L5 HIBP、L3 abuse.ch 預設為 `not_configured`（不影響 KEV／新聞層）。日後可於環境變數擴充。

## 免責

防禦與研究用途。間接暗網情資來自公開新聞，未經雙源核實者不得單獨開立 IR 工單。請依實際資產與法遵政策調校。
