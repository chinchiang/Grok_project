# Grok_project

Inventec / GSMD 相關資安研究與 SOC 工具集。

---

## 🌐 SOC 即時威脅情資中心

**線上儀表板（GitHub Pages）：**

### 👉 [https://chinchiang.github.io/Grok_project/](https://chinchiang.github.io/Grok_project/)

| 功能 | 說明 |
|------|------|
| CISA KEV | 官方已知遭利用漏洞即時介接 |
| P0–P3 | 互斥優先級（P1 不混入其他級） |
| 七層情資 | 來源健康與排程狀態 |
| 暗網間接 | 雙來源核實；單源標「未核實」且強制 P3 複核（含 X OSINT） |
| 🇹🇼 電子／半導體 | 電子五哥、上市櫃半導體受害與**勒索**強調 |
| 語系 | 正體中文 ／ English 可切換 |
| 時區 | Asia/Taipei（每日 07:00、15:00 自動更新） |

> 若頁面 404：請至 repo **Settings → Pages** 將 Source 設為 **GitHub Actions**，並在 **Actions → Deploy SOC CTI Dashboard** 執行一次 **Run workflow**。

詳細說明與本機啟動：[`soc_cti_dashboard/README.md`](./soc_cti_dashboard/README.md)

---

## 📂 倉庫內容

| 路徑 | 說明 |
|------|------|
| [`soc_cti_dashboard/`](./soc_cti_dashboard/) | SOC 即時情資網站（FastAPI 本機版 + Pages 靜態匯出） |
| [`SOC_Hunting_Detection_Playbook_2026-07-17.md`](./SOC_Hunting_Detection_Playbook_2026-07-17.md) | SOC 狩獵假設與 SIEM 規則草稿（SPL / KQL） |
| [`.github/workflows/deploy-cti-dashboard.yml`](./.github/workflows/deploy-cti-dashboard.yml) | 每日排程抓取並部署 Pages |

---

## 🖥️ 本機執行情資站

```powershell
cd soc_cti_dashboard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

瀏覽器開啟：http://127.0.0.1:8787  

本機版支援完整 API 與「立即巡檢」（每 30 分鐘一次）。

---

## 免責

文件與儀表板僅供**防禦與內部研究**用途（建議 TLP:AMBER）。部署前請依實際資產、日誌 schema 與法遵政策調校。
