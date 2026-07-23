const I18N = {
  zh: {
    appTitle: "SOC 即時威脅情資中心",
    appSubtitle: "OSINT CTI · CISA KEV · 七層來源 · 臺灣時區",
    manualScan: "立即巡檢",
    // —— 分頁 ——
    tabOverview: "總覽",
    tabHighRisk: "P0／P1 高風險",
    tabTaiwan: "🇹🇼 臺灣專區",
    tabOt: "⚙️ OT／ICS",
    tabDark: "🌑 暗網／外洩",
    tabEms: "🏭 臺灣電子製造",
    tabFinance: "💰 金融專區",
    tabSources: "來源與排程",
    // 營運概況四卡
    opsP0: "P0 緊急",
    opsP0Hint: "需立即處置",
    opsP1: "P1 在野利用",
    opsP1Hint: "KEV／高優先",
    opsVerify: "核實度",
    opsComplete: "完整度",
    unitJian: "件",
    // 總覽
    navTilesTitle: "專區導覽",
    highRiskLatest: "最新高風險情資",
    highRiskLatestHint: "P0／P1 前 8 筆精簡列表",
    highRiskFullHint: "完整高風險情資列表（不含 P2／P3）",
    viewAll: "查看全部",
    taiwanZoneHint: "僅顯示與臺灣產業／本地相關之情資列表",
    otZoneHint: "僅顯示 OT／ICS／工業控制相關情資",
    darkPrinciple:
      "暗網雙來源核實原則：Ransomware.live 與 RansomLook 交叉比對；雙源命中標「可信」。單一來源一律「未核實」，且僅進入 P3 人工複核佇列，不得單獨開立 IR 工單。",
    // 電子製造看板
    emsTitle: "🏭 臺灣電子製造監控看板",
    emsDesc:
      "電子五哥 5 家、半導體與電子製造次產業監控名單（中英別名／股號）；勒索徽章置頂。名單為監控範圍，非統計數字。",
    emsHitTotal: "名單命中",
    emsHitRansom: "勒索",
    emsOtherSection: "其他電子製造命中",
    watchBig5Title: "電子五哥 · 監控企業（5）",
    watchSemiTitle: "半導體 · 監控次產業",
    watchEmsTitle: "電子製造 · 監控次產業",
    watchNotStats: "非統計數字 · 名單導向",
    twRansomSection: "🔐 勒索相關（置頂強調）",
    // 金融專區
    finTitle: "💰 金融專區",
    finDesc:
      "銀行／支付／證券／保險與 SWIFT 等金融關鍵字命中；勒索置頂，KEV 獨立列出。監控名單為範圍，非統計數字。",
    finStatTotal: "金融相關",
    finStatRansom: "勒索",
    finStatKev: "KEV",
    finWatchTitle: "金融監控範圍（關鍵字／實體）",
    finRansomSection: "🔐 金融＋勒索（優先關注）",
    finKevSection: "KEV 金融相關",
    finOtherSection: "其他金融情資",
    // 來源與方法論
    layersHealthTitle: "七層來源健康",
    methodTitle: "方法論",
    methodPrioTitle: "P0–P3 決策（首個命中即定案）",
    methodP0: "KEV＋已知勒索活動；或台灣產業名單＋勒索／KEV",
    methodP1: "列入 CISA KEV 且未達 P0（絕不混入 P2）",
    methodP2: "非 KEV；EPSS≥0.5 或多源／雙源可信",
    methodP3: "其餘監控；暗網單源強制 P3 複核佇列",
    methodConfTitle: "信心分級（核實狀態）",
    methodConfA: "官方權威（如 CISA KEV）· Admiralty A1/A2",
    methodConfB: "≥2 獨立來源或雙源交叉 · B2",
    methodConfC: "單源／暗網間接 · C3 · 不得單獨開單",
    methodDarkTitle: "暗網雙來源核實",
    methodDarkBody:
      "Ransomware.live × RansomLook 交叉比對。雙源→可信；單源→未核實且僅 P3 人工複核。",
    // 共用
    colP0: "緊急",
    colP1: "KEV 在野利用",
    colP2: "高 EPSS／多源",
    colP3: "監控",
    vConfirmed: "已證實",
    vCredible: "可信",
    vUnverified: "未核實",
    rationale: "判定依據",
    evidence: "佐證數",
    assets: "資產關聯",
    liveTag: "即時",
    close: "關閉",
    scanResultTitle: "立即巡檢結果",
    footer: "TLP:AMBER · 防禦用途 · 暗網雙來源核實 · 未核實不得單獨開立工單",
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
    metaCve: "CVE",
    metaEpss: "EPSS",
    metaDate: "日期",
    copyCve: "點擊複製 CVE",
    cveCopied: "已複製 {cve}",
    cveCopyFail: "複製失敗，請手動選取",
    openLink: "開啟來源",
    loading: "載入中…",
  },
  en: {
    appTitle: "SOC Live Threat Intel Center",
    appSubtitle: "OSINT CTI · CISA KEV · 7 Layers · Asia/Taipei",
    manualScan: "Scan Now",
    // —— tabs ——
    tabOverview: "Overview",
    tabHighRisk: "P0 / P1 High risk",
    tabTaiwan: "🇹🇼 Taiwan",
    tabOt: "⚙️ OT / ICS",
    tabDark: "🌑 Dark web / Breach",
    tabEms: "🏭 TW electronics mfg",
    tabFinance: "💰 Finance",
    tabSources: "Sources & schedule",
    // Ops KPIs
    opsP0: "P0 Critical",
    opsP0Hint: "Immediate action",
    opsP1: "P1 In-the-wild",
    opsP1Hint: "KEV / high priority",
    opsVerify: "Verification",
    opsComplete: "Completeness",
    unitJian: "",
    // Overview
    navTilesTitle: "Zone navigation",
    highRiskLatest: "Latest high-risk intel",
    highRiskLatestHint: "Top 8 P0 / P1 items",
    highRiskFullHint: "Full high-risk list (no P2 / P3)",
    viewAll: "View all",
    taiwanZoneHint: "Taiwan industry / local-related intel only",
    otZoneHint: "OT / ICS / industrial control intel only",
    darkPrinciple:
      "Dark-web dual-source rule: cross-check Ransomware.live × RansomLook. Dual hit = Credible. Single-source = Unverified, P3 human-review queue only — never open an IR ticket alone.",
    // EMS board
    emsTitle: "🏭 TW electronics manufacturing watchboard",
    emsDesc:
      "Big-5 (5 firms), semi & electronics mfg watchlists (aliases / tickers); ransomware pinned. Lists are scope, not statistics.",
    emsHitTotal: "Watchlist hits",
    emsHitRansom: "Ransomware",
    emsOtherSection: "Other electronics mfg hits",
    watchBig5Title: "ODM Big-5 · companies (5)",
    watchSemiTitle: "Semiconductor · sub-sectors",
    watchEmsTitle: "Electronics mfg · sub-sectors",
    watchNotStats: "Not statistics · list-based scope",
    twRansomSection: "🔐 Ransomware (pinned)",
    // Finance zone
    finTitle: "💰 Finance zone",
    finDesc:
      "Banking / payments / securities / insurance & SWIFT keyword hits; ransomware pinned, KEV listed separately. Watchlist is scope, not statistics.",
    finStatTotal: "Finance-related",
    finStatRansom: "Ransomware",
    finStatKev: "KEV",
    finWatchTitle: "Finance watch scope (keywords / entities)",
    finRansomSection: "🔐 Finance + ransomware (priority)",
    finKevSection: "KEV finance-related",
    finOtherSection: "Other finance intel",
    // Sources & methodology
    layersHealthTitle: "7-layer source health",
    methodTitle: "Methodology",
    methodPrioTitle: "P0–P3 decision (first match wins)",
    methodP0: "KEV + known ransomware activity; or TW industry list + ransom / KEV",
    methodP1: "On CISA KEV and not P0 (never mixed into P2)",
    methodP2: "Non-KEV; EPSS ≥ 0.5 or multi / dual-source credible",
    methodP3: "Monitor otherwise; dark-web single-source forced to P3 review",
    methodConfTitle: "Confidence (verification)",
    methodConfA: "Authoritative official (e.g. CISA KEV) · Admiralty A1/A2",
    methodConfB: "≥2 independent sources or dual cross-check · B2",
    methodConfC: "Single-source / indirect dark web · C3 · no solo ticket",
    methodDarkTitle: "Dark-web dual-source verify",
    methodDarkBody:
      "Ransomware.live × RansomLook. Dual → Credible; single → Unverified P3 human review only.",
    // Shared
    colP0: "Critical",
    colP1: "KEV in-the-wild",
    colP2: "High EPSS / multi-source",
    colP3: "Monitor",
    vConfirmed: "Confirmed",
    vCredible: "Credible",
    vUnverified: "Unverified",
    rationale: "Rationale",
    evidence: "Evidence #",
    assets: "Assets",
    liveTag: "LIVE",
    close: "Close",
    scanResultTitle: "Live scan results",
    footer: "TLP:AMBER · Defensive use · Dark-web dual-source verify · Unverified must not ticket alone",
    empty: "No items in this slice",
    scanning: "Scanning…",
    scanOk: "Scan complete",
    scanCooldown: "Cooldowning down — try later",
    scanBusy: "A scan is already running",
    lastManual: "Last manual",
    lastSched: "Last scheduled",
    nextCooldown: "Next scan in",
    sources: "Source",
    layer: "Layer",
    metaCve: "CVE",
    metaEpss: "EPSS",
    metaDate: "Date",
    copyCve: "Click to copy CVE",
    cveCopied: "Copied {cve}",
    cveCopyFail: "Copy failed — select manually",
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
