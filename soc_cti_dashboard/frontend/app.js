/* global t, applyI18n, toggleLang, currentLang */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

/** Live API when backend is present; otherwise GitHub Pages static JSON. */
let USE_STATIC = false;
const STATIC_BASE = "data";

const cache = {
  intel: null,
  tw: null,
  finance: null,
  microsoft: null,
  layers: null,
  kpis: null,
  scan: null,
};

function titleOf(item) {
  return currentLang === "en" && item.title_en ? item.title_en : item.title;
}
function summaryOf(item) {
  return currentLang === "en" && item.summary_en ? item.summary_en : item.summary;
}

function verLabel(v) {
  if (v === "confirmed") return t("vConfirmed");
  if (v === "credible") return t("vCredible");
  return t("vUnverified");
}

function verClass(v) {
  if (v === "confirmed") return "v-confirmed";
  if (v === "credible") return "v-credible";
  return "v-unverified";
}

function formatTs(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString(currentLang === "zh" ? "zh-TW" : "en-US", {
      timeZone: "Asia/Taipei",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function cardHTML(item) {
  const p = item.priority || "P3";
  const ransom = item.is_ransomware;
  const unverified = item.verification === "unverified";
  const classes = ["card", p.toLowerCase()];
  if (ransom) classes.push("ransom-glow");
  if (unverified) classes.push("card-unverified");
  if (item.is_live) classes.push("card-live");

  const tags = [];
  tags.push(`<span class="pill ${p.toLowerCase()}">${p}</span>`);
  tags.push(
    `<span class="pill ${verClass(item.verification)}">${verLabel(item.verification)}</span>`
  );
  if (item.is_live) tags.push(`<span class="pill live-pill" data-i18n="liveTag">即時</span>`);
  if (ransom) tags.push(`<span class="pill ransom">RANSOM</span>`);
  if (item.is_tw_industry)
    tags.push(
      `<span class="pill" style="background:#4a0028;color:#ff80ab;border-color:#ff4081">TW</span>`
    );
  if (item.is_finance)
    tags.push(
      `<span class="pill" style="background:#00331a;color:#69f0ae;border-color:#00c853">FIN</span>`
    );
  if (item.is_microsoft)
    tags.push(
      `<span class="pill" style="background:#0a2540;color:#4fc3f7;border-color:#0288d1">MS</span>`
    );
  if (item.admiralty)
    tags.push(
      `<span class="pill" style="background:#1a1a2e;border-color:#555;color:#ccc" title="Admiralty">${item.admiralty}</span>`
    );

  const rationale =
    currentLang === "en" && item.priority_rationale_en
      ? item.priority_rationale_en
      : item.priority_rationale || "";
  const sop =
    currentLang === "en" && item.sop_en ? item.sop_en : item.sop_zh || item.sop_id || "";
  const assets = Array.isArray(item.assets)
    ? item.assets
    : [];
  const evidence =
    item.evidence_count != null
      ? item.evidence_count
      : (item.sources || []).length || 1;
  const owner = item.owner || "—";
  const sla = item.sla_hours != null ? `${item.sla_hours}h` : "—";

  const meta = [];
  if (item.cve_id) meta.push(item.cve_id);
  if (item.source_name) meta.push(item.source_name);
  if (item.layer_id) meta.push(item.layer_id);
  if (item.epss != null) meta.push(`EPSS ${(Number(item.epss) * 100).toFixed(1)}%`);
  if (item.date_added) meta.push(item.date_added);
  else if (item.fetched_at) meta.push(formatTs(item.fetched_at));

  const link = item.url
    ? `<a href="${item.url}" target="_blank" rel="noopener">${t("openLink")}</a>`
    : "";

  return `
    <article class="${classes.join(" ")}">
      <div class="card-top">${tags.join("")}</div>
      <h4>${escapeHtml(titleOf(item))}</h4>
      <p>${escapeHtml(summaryOf(item) || "")}</p>
      ${
        rationale
          ? `<div class="card-rationale"><strong>${t("rationale")}</strong> ${escapeHtml(rationale)}</div>`
          : ""
      }
      <div class="card-ops">
        <span title="Evidence"><b>${t("evidence")}</b> ${evidence}</span>
        <span title="Owner"><b>Owner</b> ${escapeHtml(owner)}</span>
        <span title="SLA"><b>SLA</b> ${escapeHtml(sla)}</span>
        ${sop ? `<span title="SOP"><b>SOP</b> ${escapeHtml(sop)}</span>` : ""}
      </div>
      ${
        assets.length
          ? `<div class="card-assets"><b>${t("assets")}</b> ${assets.map((a) => escapeHtml(String(a))).join(" · ")}</div>`
          : ""
      }
      <div class="card-meta">
        ${meta.map((m) => `<span>${escapeHtml(String(m))}</span>`).join("")}
        ${link}
      </div>
    </article>
  `;
}

function drawSpark(canvas, series, color) {
  if (!canvas || !series || !series.length) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const vals = series.map((s) => s.count || 0);
  const max = Math.max(1, ...vals);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  vals.forEach((v, i) => {
    const x = (i / Math.max(1, vals.length - 1)) * (w - 4) + 2;
    const y = h - 2 - (v / max) * (h - 6);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawTrendChart(seriesMap) {
  const canvas = $("#trendChart");
  if (!canvas || !seriesMap) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const keys = ["breach", "big5", "semi", "ems"];
  const colors = {
    breach: "#ff1744",
    big5: "#ff4081",
    semi: "#ff9100",
    ems: "#00e5ff",
  };
  const labels = {
    breach: t("kpiBreach"),
    big5: t("kpiBig5"),
    semi: t("kpiSemi"),
    ems: t("kpiEms"),
  };
  let max = 1;
  keys.forEach((k) => {
    (seriesMap[k] || []).forEach((s) => {
      if ((s.count || 0) > max) max = s.count;
    });
  });
  keys.forEach((k) => {
    const series = seriesMap[k] || [];
    if (!series.length) return;
    ctx.strokeStyle = colors[k];
    ctx.lineWidth = 2;
    ctx.beginPath();
    series.forEach((s, i) => {
      const x = (i / Math.max(1, series.length - 1)) * (w - 20) + 10;
      const y = h - 12 - ((s.count || 0) / max) * (h - 24);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  });
  // hover tooltip via title on legend only; simple day readout on mousemove
  canvas.onmousemove = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const series = seriesMap.breach || [];
    if (!series.length) return;
    const idx = Math.min(
      series.length - 1,
      Math.max(0, Math.round((x / rect.width) * (series.length - 1)))
    );
    const d = series[idx]?.date || "";
    const parts = keys.map(
      (k) => `${labels[k]}: ${(seriesMap[k] || [])[idx]?.count ?? 0}${t("unitJian")}`
    );
    canvas.title = `${d}\n${parts.join("\n")}`;
  };
  const leg = $("#trendLegend");
  if (leg) {
    leg.innerHTML = keys
      .map(
        (k) =>
          `<span style="color:${colors[k]}">● ${escapeHtml(labels[k])}</span>`
      )
      .join(" ");
  }
}

const WATCH_BIG5 = [
  "鴻海 2317 Foxconn",
  "和碩 4938 Pegatron",
  "廣達 2382 Quanta",
  "仁寶 2324 Compal",
  "緯創 3231 Wistron",
];
const WATCH_SEMI = [
  "台積電 2330",
  "聯電 2303",
  "日月光 3711",
  "聯發科 2454",
  "聯詠 3034",
  "瑞昱 2379",
  "南亞科 2408",
  "力積電 6770",
  "世界先進 5347",
  "力成 6239",
  "京元電 2449",
  "頎邦 6147",
  "…",
];
const WATCH_EMS = [
  "英業達 2356",
  "光寶 2301",
  "台達電 2308",
  "華碩 2357",
  "宏碁 2353",
  "技嘉 2376",
  "微星 2377",
  "友達 2409",
  "群創 3481",
  "研華 2395",
  "…",
];

function fillWatchLists() {
  const fill = (id, list) => {
    const el = $(id);
    if (!el) return;
    el.innerHTML = list.map((x) => `<span>${escapeHtml(x)}</span>`).join("");
  };
  fill("#watchBig5", WATCH_BIG5);
  fill("#watchSemi", WATCH_SEMI);
  fill("#watchEms", WATCH_EMS);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderList(el, items, limit = 12) {
  if (!el) return;
  const slice = (items || []).slice(0, limit);
  if (!slice.length) {
    el.innerHTML = `<div class="empty">${t("empty")}</div>`;
    return;
  }
  el.innerHTML = slice.map(cardHTML).join("");
}

async function detectMode() {
  try {
    const res = await fetch("/api/health", { cache: "no-store" });
    if (res.ok) {
      USE_STATIC = false;
      return;
    }
  } catch {
    /* fall through */
  }
  try {
    const res = await fetch(`${STATIC_BASE}/meta.json`, { cache: "no-store" });
    USE_STATIC = res.ok;
  } catch {
    USE_STATIC = true;
  }
}

async function api(path, opts) {
  if (USE_STATIC) {
    return staticApi(path, opts);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("api_error");
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function loadStaticJson(name) {
  const res = await fetch(`${STATIC_BASE}/${name}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`static ${name} ${res.status}`);
  return res.json();
}

async function staticApi(path, opts) {
  const method = (opts && opts.method) || "GET";
  if (method === "POST" && path.includes("/scan/manual")) {
    const err = new Error("static_mode");
    err.status = 501;
    err.data = {
      detail: {
        message_zh:
          "GitHub Pages 為靜態站，無法在瀏覽器直接巡檢。請至 repo → Actions → Deploy SOC CTI Dashboard → Run workflow",
        message_en:
          "Static GitHub Pages cannot scan from the browser. Use Actions → Deploy SOC CTI Dashboard → Run workflow",
      },
    };
    throw err;
  }

  if (path.startsWith("/api/kpis")) {
    if (!cache.kpis) cache.kpis = await loadStaticJson("kpis.json");
    return cache.kpis;
  }
  if (path.startsWith("/api/scan/status")) {
    if (!cache.scan) cache.scan = await loadStaticJson("scan-status.json");
    return cache.scan;
  }
  if (path.startsWith("/api/layers")) {
    if (!cache.layers) cache.layers = await loadStaticJson("layers.json");
    return cache.layers;
  }
  if (path.startsWith("/api/tw-dashboard")) {
    if (!cache.tw) cache.tw = await loadStaticJson("tw-dashboard.json");
    return cache.tw;
  }
  if (path.startsWith("/api/finance-dashboard")) {
    if (!cache.finance) cache.finance = await loadStaticJson("finance-dashboard.json");
    return cache.finance;
  }
  if (path.startsWith("/api/microsoft-dashboard")) {
    if (!cache.microsoft) cache.microsoft = await loadStaticJson("microsoft-dashboard.json");
    return cache.microsoft;
  }
  if (path.startsWith("/api/intel")) {
    if (!cache.intel) cache.intel = await loadStaticJson("intel.json");
    const u = new URL(path, "http://local");
    let items = [...(cache.intel.items || [])];
    const priority = u.searchParams.get("priority");
    const verification = u.searchParams.get("verification");
    const ransomware = u.searchParams.get("ransomware") === "true";
    const tw = u.searchParams.get("tw") === "true";
    const finance = u.searchParams.get("finance") === "true";
    const microsoft = u.searchParams.get("microsoft") === "true";
    const q = (u.searchParams.get("q") || "").toLowerCase();
    const limit = parseInt(u.searchParams.get("limit") || "150", 10);
    if (priority) items = items.filter((i) => i.priority === priority);
    if (verification) items = items.filter((i) => i.verification === verification);
    if (ransomware) items = items.filter((i) => i.is_ransomware);
    if (tw) items = items.filter((i) => i.is_tw_industry);
    if (finance) items = items.filter((i) => i.is_finance);
    if (microsoft) items = items.filter((i) => i.is_microsoft);
    const layer = u.searchParams.get("layer");
    if (layer) items = items.filter((i) => i.layer_id === layer);
    if (q) {
      items = items.filter((i) =>
        [i.title, i.summary, i.cve_id, i.vendor, i.product]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(q)
      );
    }
    items = items.slice(0, limit);
    return { count: items.length, items };
  }
  return {};
}

async function loadKpis() {
  const k = await api("/api/kpis");
  $("#kpiP0").textContent = k.p0_count ?? 0;
  $("#kpiKev").textContent = k.kev_recent_7d ?? 0;
  $("#kpiKevHint").textContent =
    currentLang === "zh"
      ? `近60日 ${k.kev_recent_60d ?? 0} · 本庫 ${k.kev_total ?? 0}`
      : `60d ${k.kev_recent_60d ?? 0} · DB ${k.kev_total ?? 0}`;
  $("#kpiTw").textContent = `${k.tw_industry_count ?? 0} / ${k.tw_ransomware_count ?? 0}`;
  $("#kpiHealth").textContent = `${k.source_health_pct ?? 0}%`;
  $("#kpiHealthHint").textContent =
    currentLang === "zh"
      ? `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} 來源正常`
      : `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} sources OK`;

  // Risk KPIs
  if ($("#kpiBreach")) $("#kpiBreach").textContent = k.breach_count ?? k.ransomware_count ?? 0;
  if ($("#kpiBig5")) $("#kpiBig5").textContent = k.big5_count ?? 0;
  if ($("#kpiSemi")) $("#kpiSemi").textContent = k.semi_count ?? 0;
  if ($("#kpiEms")) $("#kpiEms").textContent = k.ems_count ?? 0;
  if ($("#kpiUnverified")) $("#kpiUnverified").textContent = k.unverified_count ?? 0;

  const s = k.series_30d || {};
  drawSpark($("#sparkBreach"), s.breach, "#ff1744");
  drawSpark($("#sparkBig5"), s.big5, "#ff4081");
  drawSpark($("#sparkSemi"), s.semi, "#ff9100");
  drawSpark($("#sparkEms"), s.ems, "#00e5ff");
  drawSpark($("#sparkUnverified"), s.unverified, "#e040fb");
  drawTrendChart(s);

  if ($("#kevStat60")) $("#kevStat60").textContent = k.kev_recent_60d ?? 0;
  if ($("#kevStatTotal")) $("#kevStatTotal").textContent = k.kev_total ?? 0;

  fillWatchLists();

  const scan = await api("/api/scan/status");
  const parts = [
    `${t("lastSched")}: ${formatTs(scan.last_scheduled_scan)}`,
    `${t("lastManual")}: ${formatTs(scan.last_manual_scan)}`,
  ];
  if (USE_STATIC) {
    parts.push(
      currentLang === "zh"
        ? "模式：靜態＋瀏覽器即時巡檢（KEV／勒索雙源）"
        : "Mode: static + browser live scan (KEV/ransom dual)"
    );
  } else if (!scan.manual_scan_allowed) {
    const m = Math.ceil((scan.cooldown_remaining_sec || 0) / 60);
    parts.push(`${t("nextCooldown")}: ${m}m`);
  }
  $("#scanMeta").textContent = parts.join(" · ");

  const btn = $("#manualScanBtn");
  if (btn) {
    btn.disabled = USE_STATIC ? false : !scan.manual_scan_allowed || scan.harvest_running;
  }
}

async function loadOverview() {
  const [p0, p1, p2, p3] = await Promise.all([
    api("/api/intel?priority=P0&limit=20"),
    api("/api/intel?priority=P1&limit=20"),
    api("/api/intel?priority=P2&limit=20"),
    api("/api/intel?priority=P3&limit=20"),
  ]);
  renderList($("#colP0"), p0.items, 8);
  renderList($("#colP1"), p1.items, 8);
  renderList($("#colP2"), p2.items, 8);
  renderList($("#colP3"), p3.items, 8);
}

async function loadIntelStream() {
  const params = new URLSearchParams();
  const p = $("#filterPriority").value;
  const v = $("#filterVerification").value;
  const q = $("#filterQ").value.trim();
  if (p) params.set("priority", p);
  if (v) params.set("verification", v);
  if ($("#filterRansom").checked) params.set("ransomware", "true");
  if ($("#filterTw").checked) params.set("tw", "true");
  if ($("#filterFinance")?.checked) params.set("finance", "true");
  if ($("#filterMs")?.checked) params.set("microsoft", "true");
  if (q) params.set("q", q);
  params.set("limit", "80");
  const data = await api(`/api/intel?${params}`);
  renderList($("#intelStream"), data.items, 80);
}

function renderEntityChips(el, counts) {
  if (!el) return;
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    el.innerHTML = `<span>${t("empty")}</span>`;
    return;
  }
  el.innerHTML = entries
    .map(([k, n]) => `<span>${escapeHtml(k)} · ${n}</span>`)
    .join("");
}

async function loadTw() {
  const data = await api("/api/tw-dashboard");
  $("#twStatTotal").textContent = data.stats?.tw_total ?? 0;
  $("#twStatRansom").textContent = data.stats?.tw_ransomware ?? 0;

  renderEntityChips($("#entityChips"), data.entity_counts);

  renderList($("#twRansomList"), data.tw_ransomware, 40);
  renderList($("#twOtherList"), data.tw_other, 40);
  renderList($("#globalRansomList"), data.global_ransomware_highlight, 30);
}

async function loadFinance() {
  const data = await api("/api/finance-dashboard");
  $("#finStatTotal").textContent = data.stats?.total ?? 0;
  $("#finStatRansom").textContent = data.stats?.ransomware ?? 0;
  $("#finStatKev").textContent = data.stats?.kev ?? 0;
  renderEntityChips($("#financeChips"), data.entity_counts);
  renderList($("#finRansomList"), data.ransomware, 40);
  renderList($("#finKevList"), data.kev_items, 40);
  renderList($("#finOtherList"), data.other, 40);
}

async function loadMicrosoft() {
  const data = await api("/api/microsoft-dashboard");
  const s = data.stats || {};
  $("#msStatTotal").textContent = s.total ?? 0;
  if ($("#msStatP1")) $("#msStatP1").textContent = s.p1 ?? 0;
  $("#msStatKev").textContent = s.kev ?? 0;
  if ($("#msStatConfirmed")) $("#msStatConfirmed").textContent = s.confirmed ?? 0;
  if ($("#msStatWindows")) $("#msStatWindows").textContent = s.windows_os ?? 0;
  if ($("#msStatEnterprise")) $("#msStatEnterprise").textContent = s.enterprise_platform ?? 0;
  if ($("#msStatTi")) $("#msStatTi").textContent = s.threat_intel ?? 0;
  renderEntityChips($("#msChips"), data.entity_counts);
  renderList($("#msP1List"), data.p1_items, 30);
  renderList($("#msKevList"), data.kev_items, 40);
  renderList($("#msConfirmedList"), data.confirmed_items, 30);
  renderList($("#msWindowsList"), data.windows_os, 40);
  renderList($("#msEnterpriseList"), data.enterprise_platform, 40);
  renderList($("#msTiList"), data.threat_intel, 30);
  renderList($("#msRansomList"), data.ransomware, 30);
  renderList($("#msOtherList"), data.other, 30);
}

async function loadZoneTw() {
  const data = await api("/api/intel?tw=true&limit=80");
  const items = [...(data.items || [])].sort((a, b) => {
    if (a.is_ransomware && !b.is_ransomware) return -1;
    if (!a.is_ransomware && b.is_ransomware) return 1;
    return 0;
  });
  renderList($("#zoneTwList"), items, 60);
}

async function loadZoneOt() {
  // OT/ICS: L7 layer + ICS/OT keywords
  if (USE_STATIC && !cache.intel) cache.intel = await loadStaticJson("intel.json");
  let items = [];
  if (USE_STATIC) {
    items = (cache.intel.items || []).filter(
      (i) =>
        i.layer_id === "L7" ||
        /ics|ot\b|industrial|scada|plc|cisa ics|dragos/i.test(
          `${i.title} ${i.summary} ${i.source_name}`
        )
    );
  } else {
    const d = await api("/api/intel?layer=L7&limit=80");
    items = d.items || [];
  }
  renderList($("#zoneOtList"), items, 50);
}

async function loadZoneDark() {
  if (USE_STATIC && !cache.intel) cache.intel = await loadStaticJson("intel.json");
  const all = USE_STATIC
    ? cache.intel.items || []
    : (await api("/api/intel?ransomware=true&limit=150")).items || [];
  const dark = all.filter(
    (i) =>
      /ransom|dark|threatfox|hibp|databreach|x @/i.test(
        `${i.source_name} ${i.title}`
      ) || i.is_ransomware
  );
  const dual = dark.filter(
    (i) => i.verification === "credible" || (i.sources || []).length >= 2
  );
  const p3 = dark.filter(
    (i) => i.verification === "unverified" || i.priority === "P3"
  );
  renderList($("#zoneDarkDual"), dual, 40);
  renderList($("#zoneDarkP3"), p3, 40);
}

async function loadZoneKev() {
  if (USE_STATIC && !cache.intel) cache.intel = await loadStaticJson("intel.json");
  let items = [];
  if (USE_STATIC) {
    items = (cache.intel.items || []).filter(
      (i) => (i.source_name || "").includes("KEV") || (i.tags || []).includes("kev")
    );
  } else {
    const d = await api("/api/intel?q=KEV&limit=120");
    items = (d.items || []).filter((i) => (i.source_name || "").includes("KEV"));
  }
  renderList($("#zoneKevList"), items, 80);
}

/** Browser-side live scan: KEV mirror + ransomware dual sources (static Pages). */
const LIVE_COOLDOWN_KEY = "cti_live_scan_ts";
const LIVE_COOLDOWN_MS = 30 * 60 * 1000;

async function browserLiveScan() {
  const last = parseInt(localStorage.getItem(LIVE_COOLDOWN_KEY) || "0", 10);
  const left = LIVE_COOLDOWN_MS - (Date.now() - last);
  if (last && left > 0) {
    showToast(
      currentLang === "zh"
        ? `冷卻中，約 ${Math.ceil(left / 60000)} 分鐘後可再巡檢`
        : `Cooldown — retry in ~${Math.ceil(left / 60000)}m`,
      true
    );
    return;
  }
  const btn = $("#manualScanBtn");
  if (btn) btn.disabled = true;
  showToast(t("scanning"));
  const results = [];
  const newItems = [];

  // 1) KEV mirrors
  const kevUrls = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
  ];
  let kevOk = false;
  let kevN = 0;
  for (const u of kevUrls) {
    try {
      const r = await fetch(u, { cache: "no-store" });
      if (!r.ok) throw new Error(String(r.status));
      const data = await r.json();
      const vulns = (data.vulnerabilities || [])
        .sort((a, b) => (b.dateAdded || "").localeCompare(a.dateAdded || ""))
        .slice(0, 40);
      kevN = vulns.length;
      kevOk = true;
      results.push({
        name: "CISA KEV",
        ok: true,
        detail: `${kevN} recent · ${u.includes("github") ? "GitHub mirror" : "cisa.gov"}`,
      });
      vulns.slice(0, 8).forEach((v) => {
        newItems.push({
          id: `live-kev-${v.cveID}`,
          title: `[即時 LIVE][KEV] ${v.cveID} — ${v.vulnerabilityName || ""}`,
          title_en: `[LIVE][KEV] ${v.cveID}`,
          summary: v.shortDescription || "",
          priority:
            String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known"
              ? "P0"
              : "P1",
          priority_rationale:
            String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known"
              ? "判定依據：KEV + known ransomware campaign → P0"
              : "判定依據：CISA KEV 在野利用 → P1",
          verification: "confirmed",
          source_name: "CISA KEV (live)",
          sources: ["CISA KEV"],
          cve_id: v.cveID,
          vendor: v.vendorProject,
          product: v.product,
          is_ransomware:
            String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known",
          is_live: true,
          admiralty: "A1",
          evidence_count: 1,
          sop_id: "T-01",
          sop_zh: "T-01 KEV 緊急修補",
          owner: "Vuln Mgmt",
          sla_hours: 24,
          url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${v.cveID}`,
          date_added: v.dateAdded,
        });
      });
      break;
    } catch (e) {
      results.push({ name: `KEV ${u.slice(0, 40)}…`, ok: false, detail: String(e) });
    }
  }

  // 2) RansomLook recent
  let lookTitles = new Set();
  try {
    const r = await fetch("https://www.ransomlook.io/api/recent", { cache: "no-store" });
    const data = await r.json();
    const rows = Array.isArray(data) ? data.slice(0, 30) : [];
    results.push({ name: "RansomLook", ok: true, detail: `${rows.length} posts` });
    rows.forEach((row) => {
      const victim = row.post_title || row.title || "";
      lookTitles.add(String(victim).toLowerCase().replace(/[^a-z0-9]/g, ""));
      newItems.push({
        id: `live-rl-${victim}`,
        title: `[即時 LIVE][未核實] 🔐 ${victim} — ${row.group_name || "?"}`,
        priority: "P3",
        priority_rationale: "判定依據：洩漏站單一來源 → P3 人工複核",
        verification: "unverified",
        source_name: "RansomLook (live)",
        sources: ["RansomLook"],
        is_ransomware: true,
        is_live: true,
        admiralty: "C3",
        evidence_count: 1,
        sop_id: "T-07",
        sop_zh: "T-07 未核實暗網複核佇列",
        owner: "CTI Analyst",
        sla_hours: 72,
      });
    });
  } catch (e) {
    results.push({ name: "RansomLook", ok: false, detail: String(e) });
  }

  // 3) Ransomware.live dump (heavy — skip full; try API v2 then skip)
  try {
    const r = await fetch("https://data.ransomware.live/victims.json", {
      cache: "no-store",
    });
    if (r.ok) {
      const all = await r.json();
      const rows = (Array.isArray(all) ? all : [])
        .sort((a, b) => String(b.discovered || "").localeCompare(String(a.discovered || "")))
        .slice(0, 25);
      let dual = 0;
      rows.forEach((row) => {
        const victim = row.post_title || row.victim || "";
        const key = String(victim).toLowerCase().replace(/[^a-z0-9]/g, "");
        const isDual = key && lookTitles.has(key);
        if (isDual) dual++;
        newItems.push({
          id: `live-rsl-${victim}`,
          title: isDual
            ? `[即時 LIVE] 🔐 ${victim} — ${row.group_name || "?"}`
            : `[即時 LIVE][未核實] 🔐 ${victim} — ${row.group_name || "?"}`,
          priority: isDual ? "P2" : "P3",
          priority_rationale: isDual
            ? "判定依據：Ransomware.live ∩ RansomLook 雙源 → P2 credible"
            : "判定依據：單源洩漏站 → P3 複核佇列",
          verification: isDual ? "credible" : "unverified",
          source_name: isDual
            ? "Ransomware.live + RansomLook (live)"
            : "Ransomware.live (live)",
          sources: isDual ? ["Ransomware.live", "RansomLook"] : ["Ransomware.live"],
          is_ransomware: true,
          is_live: true,
          admiralty: isDual ? "B2" : "C3",
          evidence_count: isDual ? 2 : 1,
          sop_id: isDual ? "T-02" : "T-07",
          sop_zh: isDual ? "T-02 勒索應變" : "T-07 未核實暗網複核",
          owner: isDual ? "IR Lead" : "CTI Analyst",
          sla_hours: isDual ? 4 : 72,
          url: row.post_url || "https://www.ransomware.live/",
        });
      });
      results.push({
        name: "Ransomware.live",
        ok: true,
        detail: `${rows.length} victims · dual≈${dual}`,
      });
    } else {
      results.push({ name: "Ransomware.live", ok: false, detail: `HTTP ${r.status}` });
    }
  } catch (e) {
    results.push({ name: "Ransomware.live", ok: false, detail: String(e.message || e) });
  }

  // Merge into static cache for UI
  if (!cache.intel) {
    try {
      cache.intel = await loadStaticJson("intel.json");
    } catch {
      cache.intel = { items: [] };
    }
  }
  const existing = new Set((cache.intel.items || []).map((i) => i.id));
  const fresh = newItems.filter((i) => !existing.has(i.id));
  cache.intel.items = [...fresh, ...(cache.intel.items || [])].slice(0, 400);
  cache.kpis = null;

  localStorage.setItem(LIVE_COOLDOWN_KEY, String(Date.now()));
  const list = $("#scanResultList");
  if (list) {
    list.innerHTML = results
      .map(
        (r) =>
          `<li class="${r.ok ? "ok" : "bad"}"><b>${escapeHtml(r.name)}</b> — ${escapeHtml(
            r.detail || ""
          )}</li>`
      )
      .join("");
  }
  $("#scanModal")?.classList.remove("hidden");
  showToast(
    currentLang === "zh"
      ? `巡檢完成：新標「即時」 ${fresh.length} 筆`
      : `Scan done: ${fresh.length} live items`
  );
  await refreshAll();
  if (btn) btn.disabled = false;
}

async function loadLayers() {
  const data = await api("/api/layers");
  const badge = $("#scheduleBadge");
  badge.textContent =
    currentLang === "zh" ? data.schedule?.description_zh : data.schedule?.description_en;

  const grid = $("#layersGrid");
  const statusLabel = (st) => {
    if (st === "healthy") return currentLang === "zh" ? "正常" : "OK";
    if (st === "degraded") return currentLang === "zh" ? "異常" : "Degraded";
    if (st === "not_configured") return currentLang === "zh" ? "待組態" : "Pending config";
    if (st === "partial") return currentLang === "zh" ? "部分" : "Partial";
    return st || "—";
  };
  grid.innerHTML = (data.layers || [])
    .map((L) => {
      const tid = String(L.id || "").replace(/^L/, "T");
      const name = currentLang === "zh" ? L.name_zh : L.name_en;
      const srcs = (L.sources || [])
        .map((s) => {
          const lat =
            s.latency_ms != null ? ` · ${s.latency_ms}ms` : "";
          const n = s.item_count != null ? ` · ${s.item_count}` : "";
          return `
        <li>
          <span class="src-name">${escapeHtml(s.name)}</span>
          <span>
            <span class="status-dot ${escapeHtml(s.status || "unknown")}"></span>
            ${escapeHtml(statusLabel(s.status))}
            ${n}${lat}
          </span>
        </li>`;
        })
        .join("");
      return `
        <article class="layer-card">
          <h3>
            <span class="layer-id">${escapeHtml(tid)}</span>
            ${escapeHtml(name)}
            <span class="status-dot ${escapeHtml(L.overall)}" title="${escapeHtml(L.overall)}"></span>
          </h3>
          <div style="font-size:0.75rem;color:var(--muted)">${escapeHtml(L.schedule_hint || "")}</div>
          <ul>${srcs || `<li>${t("empty")}</li>`}</ul>
        </article>`;
    })
    .join("");
}

function showToast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 5200);
}

async function manualScan() {
  if (USE_STATIC) {
    await browserLiveScan();
    return;
  }
  const btn = $("#manualScanBtn");
  btn.disabled = true;
  showToast(t("scanning"));
  try {
    await api("/api/scan/manual", { method: "POST" });
    Object.keys(cache).forEach((k) => (cache[k] = null));
    showToast(t("scanOk"));
    await refreshAll();
  } catch (e) {
    if (e.status === 501 || e.status === 429 || e.status === 409) {
      const d = e.data?.detail;
      const msg =
        typeof d === "object"
          ? currentLang === "zh"
            ? d.message_zh
            : d.message_en
          : e.status === 429
            ? t("scanCooldown")
            : t("scanBusy");
      showToast(msg || t("scanCooldown"), true);
    } else {
      showToast(String(e.message || "Error"), true);
    }
  } finally {
    await loadKpis();
  }
}

function tickClock() {
  const now = new Date();
  const s = now.toLocaleString(currentLang === "zh" ? "zh-TW" : "en-US", {
    timeZone: "Asia/Taipei",
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  $("#clock").textContent = s + " TST";
}

async function refreshAll() {
  try {
    // bust static cache on refresh cycle
    if (USE_STATIC) Object.keys(cache).forEach((k) => (cache[k] = null));
    await loadKpis();
    const active = $(".tab.active")?.dataset.view || "overview";
    if (active === "overview") await loadOverview();
    if (active === "intel") await loadIntelStream();
    if (active === "tw") await loadTw();
    if (active === "zone-tw") await loadZoneTw();
    if (active === "zone-ot") await loadZoneOt();
    if (active === "zone-dark") await loadZoneDark();
    if (active === "zone-kev") await loadZoneKev();
    if (active === "finance") await loadFinance();
    if (active === "microsoft") await loadMicrosoft();
    if (active === "layers") await loadLayers();
  } catch (e) {
    console.error(e);
  }
}

window.refreshAll = refreshAll;

function setupTabs() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", async () => {
      $$(".tab").forEach((x) => x.classList.remove("active"));
      tab.classList.add("active");
      const view = tab.dataset.view;
      $$(".view").forEach((v) => v.classList.remove("active"));
      $(`#view-${view}`)?.classList.add("active");
      if (view === "overview") await loadOverview();
      if (view === "intel") await loadIntelStream();
      if (view === "tw") await loadTw();
      if (view === "zone-tw") await loadZoneTw();
      if (view === "zone-ot") await loadZoneOt();
      if (view === "zone-dark") await loadZoneDark();
      if (view === "zone-kev") await loadZoneKev();
      if (view === "finance") await loadFinance();
      if (view === "microsoft") await loadMicrosoft();
      if (view === "layers") await loadLayers();
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  setupTabs();
  fillWatchLists();
  $("#langToggle").addEventListener("click", () => toggleLang());
  $("#manualScanBtn").addEventListener("click", () => manualScan());
  $("#applyFilters")?.addEventListener("click", () => loadIntelStream());
  $("#filterQ")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadIntelStream();
  });
  $("#scanModalClose")?.addEventListener("click", () => {
    $("#scanModal")?.classList.add("hidden");
  });
  tickClock();
  setInterval(tickClock, 1000);
  await detectMode();
  await refreshAll();
  setInterval(refreshAll, 120000);
});
