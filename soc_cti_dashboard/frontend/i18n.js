const I18N = {
  zh: {
    appTitle: "SOC 即時威脅情資中心",
    appSubtitle: "OSINT CTI · CISA KEV · 七層來源 · 臺灣時區",
    manualScan: "立即巡檢",
    tabOverview: "總覽",
    tabIntel: "情資串流",
    tabTw: "🇹🇼 電子／半導體",
    tabLayers: "七層健康",
    kpiP0: "P0 緊急",
    kpiP0Hint: "勒索 KEV／台灣產業受害",
    kpiKev: "KEV 近 7 日",
    kpiTw: "台灣產業／勒索",
    kpiTwHint: "電子五哥＋半導體",
    kpiHealth: "來源健康度",
    overviewTitle: "優先情資快覽",
    colP0: "緊急",
    colP1: "KEV 在野利用",
    colP2: "高 EPSS／多源",
    colP3: "監控",
    vConfirmed: "已證實",
    vCredible: "可信",
    vUnverified: "未核實",
    filterAllP: "全部優先級",
    filterAllV: "全部核實狀態",
    filterRansom: "僅勒索",
    filterTw: "僅台灣產業",
    searchPh: "CVE / 關鍵字…",
    apply: "套用",
    twTitle: "台灣電子五哥／半導體・上市櫃受害情資",
    twDesc: "獨立監控 ODM/EMS 與半導體供應鏈；勒索相關以高亮強調。",
    twStatTotal: "產業相關",
    twStatRansom: "勒索強調",
    twRansomSection: "🔐 勒索相關（優先關注）",
    twOtherSection: "其他台灣產業情資",
    globalRansomSection: "全球高優先勒索（供應鏈風險）",
    layersTitle: "七層情資來源與排程健康",
    footer: "TLP:AMBER · 防禦用途 · 暗網採間接雙來源核實 · 未核實情資不得單獨驅動工單",
    empty: "目前此區間無資料",
    scanning: "巡檢執行中…",
    scanOk: "巡檢完成",
    scanCooldown: "冷卻中，請稍候再試",
    scanBusy: "已有巡檢進行中",
    lastManual: "上次手動",
    lastSched: "上次排程",
    nextCooldown: "下次可巡檢",
    sources: "來源",
    layer: "層級",
    openLink: "開啟來源",
    loading: "載入中…",
  },
  en: {
    appTitle: "SOC Live Threat Intel Center",
    appSubtitle: "OSINT CTI · CISA KEV · 7 Layers · Asia/Taipei",
    manualScan: "Scan Now",
    tabOverview: "Overview",
    tabIntel: "Intel Feed",
    tabTw: "🇹🇼 Electronics / Semi",
    tabLayers: "Layer Health",
    kpiP0: "P0 Critical",
    kpiP0Hint: "Ransom KEV / TW industry hit",
    kpiKev: "KEV last 7 days",
    kpiTw: "TW industry / Ransom",
    kpiTwHint: "ODM Big-5 + semiconductor",
    kpiHealth: "Source health",
    overviewTitle: "Priority snapshot",
    colP0: "Critical",
    colP1: "KEV in-the-wild",
    colP2: "High EPSS / multi-source",
    colP3: "Monitor",
    vConfirmed: "Confirmed",
    vCredible: "Credible",
    vUnverified: "Unverified",
    filterAllP: "All priorities",
    filterAllV: "All verification",
    filterRansom: "Ransomware only",
    filterTw: "TW industry only",
    searchPh: "CVE / keywords…",
    apply: "Apply",
    twTitle: "TW Electronics Big-5 / Semiconductor Victims",
    twDesc: "Dedicated ODM/EMS & semiconductor watch; ransomware is highlighted.",
    twStatTotal: "Industry-related",
    twStatRansom: "Ransomware focus",
    twRansomSection: "🔐 Ransomware (priority)",
    twOtherSection: "Other TW industry intel",
    globalRansomSection: "Global high-priority ransomware (supply-chain risk)",
    layersTitle: "7-layer sources & schedule health",
    footer: "TLP:AMBER · Defensive use · Indirect dark-web dual-source verify · Unverified must not ticket alone",
    empty: "No items in this slice",
    scanning: "Scanning…",
    scanOk: "Scan complete",
    scanCooldown: "Cooldowning down — try later",
    scanBusy: "A scan is already running",
    lastManual: "Last manual",
    lastSched: "Last scheduled",
    nextCooldown: "Next scan in",
    sources: "Sources",
    layer: "Layer",
    openLink: "Open source",
    loading: "Loading…",
  },
};

let currentLang = localStorage.getItem("cti_lang") || "zh";

function t(key) {
  return (I18N[currentLang] && I18N[currentLang][key]) || I18N.zh[key] || key;
}

function applyI18n() {
  document.documentElement.lang = currentLang === "zh" ? "zh-Hant" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) el.setAttribute("placeholder", t(key));
  });
  const langBtn = document.getElementById("langToggle");
  if (langBtn) langBtn.textContent = currentLang === "zh" ? "EN" : "中文";
}

function toggleLang() {
  currentLang = currentLang === "zh" ? "en" : "zh";
  localStorage.setItem("cti_lang", currentLang);
  applyI18n();
  if (window.refreshAll) window.refreshAll();
}
