/* global t, applyI18n, toggleLang, currentLang */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

/** Live API when backend is present; otherwise GitHub Pages static JSON. */
let USE_STATIC = false;
const STATIC_BASE = "data";

const cache = {
  intel: null,
  intelHigh: null,
  tw: null,
  finance: null,
  microsoft: null,
  layers: null,
  kpis: null,
  scan: null,
  reviewQueue: null,
  ruleAccuracy: null,
  preemptive: null,
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
  if (item.is_tw_industry) tags.push(`<span class="pill tw">TW</span>`);
  if (item.is_finance) tags.push(`<span class="pill fin">FIN</span>`);
  if (item.is_microsoft) tags.push(`<span class="pill ms">MS</span>`);
  if (item.admiralty)
    tags.push(
      `<span class="pill admiralty" title="Admiralty">${escapeHtml(item.admiralty)}</span>`
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

  const metaChips = [];
  if (item.cve_id) {
    metaChips.push(cveCopyChip(item.cve_id));
  }
  if (item.source_name) {
    metaChips.push(
      metaChip("source", t("sources"), item.source_name, "meta-source")
    );
  }
  if (item.layer_id) {
    metaChips.push(
      metaChip("layer", t("layer"), item.layer_id, "meta-layer")
    );
  }
  if (item.epss != null) {
    const epssPct = Number(item.epss) * 100;
    const epssTier =
      epssPct >= 70 ? "epss-high" : epssPct >= 50 ? "epss-mid" : "epss-low";
    metaChips.push(
      metaChip(
        "epss",
        t("metaEpss"),
        `${epssPct.toFixed(1)}%`,
        `meta-epss ${epssTier}`
      )
    );
  }

  // Time always top-right: prefer date_added, else fetched_at
  const dateVal = item.date_added
    ? String(item.date_added)
    : item.fetched_at
      ? formatTs(item.fetched_at)
      : "";
  const timeHtml = dateVal
    ? `<time class="card-time" datetime="${escapeHtml(String(item.date_added || item.fetched_at || ""))}" title="${escapeHtml(t("metaDate"))}">${escapeHtml(dateVal)}</time>`
    : `<span class="card-time card-time-empty" aria-hidden="true"></span>`;

  // XSS-safe: only allow http/https; reject javascript:/data:/etc.
  const safeUrl = safeHref(item.url);
  const link = safeUrl
    ? `<a class="meta-link" href="${safeUrl}" target="_blank" rel="noopener noreferrer">${t("openLink")} ↗</a>`
    : "";

  return `
    <article class="${classes.join(" ")}">
      <div class="card-top">
        <div class="card-tags">${tags.join("")}</div>
        ${timeHtml}
      </div>
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
        ${metaChips.join("")}
        ${link}
      </div>
    </article>
  `;
}

/** Labeled meta chip for card footer (source / layer / EPSS). */
function metaChip(kind, label, value, extraClass = "") {
  const k = escapeHtml(String(label));
  const v = escapeHtml(String(value));
  return `<span class="meta-chip ${extraClass}" data-kind="${escapeHtml(kind)}" title="${k}: ${v}"><span class="meta-k">${k}</span><span class="meta-v">${v}</span></span>`;
}

/** Clickable CVE chip — one-click copy to clipboard. */
function cveCopyChip(cveId) {
  const v = escapeHtml(String(cveId));
  const tip = escapeHtml(t("copyCve"));
  return `<button type="button" class="meta-chip meta-cve meta-cve-btn" data-copy-cve="${v}" title="${tip}" aria-label="${tip}: ${v}"><span class="meta-k">${escapeHtml(t("metaCve"))}</span><span class="meta-v">${v}</span><span class="meta-copy-icon" aria-hidden="true">⎘</span></button>`;
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

function setupCardActions() {
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-copy-cve]");
    if (!btn) return;
    e.preventDefault();
    const cve = btn.getAttribute("data-copy-cve");
    if (!cve) return;
    try {
      await copyText(cve);
      btn.classList.add("copied");
      const label = btn.querySelector(".meta-copy-icon");
      if (label) label.textContent = "✓";
      showToast(t("cveCopied").replace("{cve}", cve));
      setTimeout(() => {
        btn.classList.remove("copied");
        if (label) label.textContent = "⎘";
      }, 1400);
    } catch {
      showToast(t("cveCopyFail"), true);
    }
  });
}

const WATCH_BIG5 = [
  "廣達 2382 Quanta",
  "仁寶 2324 Compal",
  "英業達 2356 Inventec",
  "緯創 3231 Wistron",
  "和碩 4938 Pegatron",
];

const WATCH_SEMI = [
  "台積電 2330 TSMC",
  "聯電 2303 UMC",
  "日月光 3711 ASE",
  "聯發科 2454 MediaTek",
  "聯詠 3034 Novatek",
  "瑞昱 2379 Realtek",
  "南亞科 2408 Nanya",
  "力積電 6770 Powerchip",
  "世界先進 5347 VIS",
  "力成 6239 PSMC",
  "京元電 2449 KYEC",
  "頎邦 6147 Chipbond",
  "華邦電 2344 Winbond",
  "旺宏 2337 Macronix",
  "矽品 2325 SPIL",
  "金士頓 Kingston",
  "創意 3443 GlobalUnichip",
  "祥碩 5269 ASMedia",
];
const WATCH_EMS = [
  "鴻海 2317 Foxconn",
  "光寶 2301 Lite-On",
  "台達電 2308 Delta",
  "華碩 2357 ASUS",
  "宏碁 2353 Acer",
  "技嘉 2376 Gigabyte",
  "微星 2377 MSI",
  "友達 2409 AUO",
  "群創 3481 Innolux",
  "研華 2395 Advantech",
  "可成 2474 Catcher",
  "鴻準 2354 Foxconn Precision",
  "正崴 2392 Foxlink",
  "和勤 1580",
  "新金寶 2312 Cal-Comp",
  "緯穎 6669 Wiwynn",
  "健鼎 3044 Tripod",
  "欣興 3037 Unimicron",
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

function goToView(view) {
  const tab = $(`.tab[data-view="${view}"]`);
  if (tab) tab.click();
}

async function ensureIntel() {
  if (USE_STATIC) {
    if (!cache.intel) cache.intel = await loadStaticJson("intel.json");
    return cache.intel.items || [];
  }
  const d = await api("/api/intel?limit=300");
  return d.items || [];
}

/** Escape HTML special chars. Use string concat so editors cannot auto-decode entities. */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;")
    .replace(/"/g, "&" + "quot;")
    .replace(/'/g, "&#39;");
}

/**
 * XSS-safe href: only allow http: and https: schemes.
 * Rejects javascript:, data:, vbscript:, blob:, and malformed URLs.
 * Returns attribute-escaped absolute URL, or empty string if unsafe.
 */
function safeHref(url) {
  const raw = String(url || "").trim();
  if (!raw) return "";
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return escapeHtml(u.href);
  } catch {
    return "";
  }
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
  if (path.startsWith("/api/preemptive-brief")) {
    if (!cache.preemptive) cache.preemptive = await loadStaticJson("preemptive-brief.json");
    return cache.preemptive;
  }
  if (path.startsWith("/api/ot-catalog")) {
    if (!cache.otCatalog) cache.otCatalog = await loadStaticJson("ot-catalog.json");
    return cache.otCatalog;
  }
  if (path.startsWith("/api/review-queue")) {
    if (!cache.reviewQueue)
      cache.reviewQueue = await loadStaticJson("review-queue.json");
    return cache.reviewQueue;
  }
  if (path.startsWith("/api/rule-accuracy")) {
    if (!cache.ruleAccuracy)
      cache.ruleAccuracy = await loadStaticJson("rule-accuracy.json");
    return cache.ruleAccuracy;
  }
  if (path.startsWith("/api/intel")) {
    const u = new URL(path, "http://local");
    // First paint only needs P0/P1, which ships as its own small file — the
    // full stream is several MB and is fetched only when a view needs it.
    const wantsPriority = u.searchParams.get("priority");
    const highRiskOnly = wantsPriority === "P0" || wantsPriority === "P1";
    if (highRiskOnly && !cache.intel) {
      if (!cache.intelHigh) {
        try {
          cache.intelHigh = await loadStaticJson("intel-highrisk.json");
        } catch {
          cache.intelHigh = null; // older export without the split
        }
      }
      if (cache.intelHigh) {
        const items = (cache.intelHigh.items || []).filter(
          (i) => i.priority === wantsPriority
        );
        const limit = parseInt(u.searchParams.get("limit") || "150", 10);
        return { count: items.length, items: items.slice(0, limit) };
      }
    }
    if (!cache.intel) cache.intel = await loadStaticJson("intel.json");
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

/** Taipei hour, independent of the viewer's own timezone. */
function taipeiHour() {
  return parseInt(
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Taipei",
      hour: "2-digit",
      hour12: false,
    }).format(new Date()),
    10
  );
}

/**
 * On-duty operator panel.
 *
 * Shift boundaries follow the harvest schedule (07:00 / 15:00 Asia/Taipei), so
 * "who is on" lines up with when the data was last refreshed. The status line
 * is derived from live KPIs rather than being decorative: an operator opening
 * the dashboard should see the outstanding work before the charts.
 */
function renderDuty(k) {
  const panel = $("#dutyPanel");
  if (!panel || !k) return;

  const h = taipeiHour();
  const shiftKey = h >= 7 && h < 15 ? "dutyShiftDay" : "dutyShiftNight";
  const p0 = k.p0_count ?? 0;
  const p1 = k.p1_count ?? 0;
  const review = k.review_queue_count ?? 0;
  const health = k.source_health_pct ?? 0;

  const set = (sel, v) => {
    const el = $(sel);
    if (el) el.textContent = v;
  };
  set("#dutyP0", p0);
  set("#dutyP1", p1);
  set("#dutyReview", review);
  set("#dutyHealth", health);
  set("#dutyShift", `${t(shiftKey)} · ${t("dutyOnDuty")}`);

  // Most urgent true statement wins, so the line never overstates the state.
  let state = "clear";
  let say = t("dutySayClear");
  if (p0 > 0) {
    state = "alert";
    say = t("dutySayP0").replace("{n}", p0);
  } else if (health < 80) {
    state = "warn";
    say = t("dutySayHealth").replace("{n}", health);
  } else if (review > 0) {
    state = "review";
    say = t("dutySayReview").replace("{n}", review);
  }
  panel.dataset.state = state;
  set("#dutySay", say);
}

/** Use the operator's own artwork when dropped in at assets/kano.png. */
function upgradeDutyAvatar() {
  const img = $("#dutyAvatar");
  if (!img) return;
  const probe = new Image();
  probe.onload = () => {
    img.src = "assets/kano.png";
    img.classList.add("duty-avatar-photo");
  };
  probe.src = "assets/kano.png";
}

async function loadKpis() {
  const k = await api("/api/kpis");
  cache.kpis = k;

  // 營運概況四卡：P0 / P1 / 核實度 / 完整度
  if ($("#opsP0")) $("#opsP0").textContent = k.p0_count ?? 0;
  if ($("#opsP1")) $("#opsP1").textContent = k.p1_count ?? 0;
  const totalItems =
    (k.p0_count || 0) +
    (k.p1_count || 0) +
    (k.p2_count || 0) +
    (k.p3_count || 0);
  // 核實度 = (已證實 + 可信) / 全部 ≈ 1 − 未核實 / 全部
  const unv = k.unverified_count ?? 0;
  const denom = Math.max(totalItems, 1);
  const vPct = Math.min(100, Math.max(0, Math.round(100 * (1 - unv / denom))));
  if ($("#opsVerify")) $("#opsVerify").textContent = Number.isFinite(vPct) ? vPct : 0;
  if ($("#opsVerifyHint")) {
    $("#opsVerifyHint").textContent =
      currentLang === "zh"
        ? `已證實+可信／全部 · 未核實 ${unv}`
        : `Confirmed+Credible / all · unverified ${unv}`;
  }
  const health = k.source_health_pct ?? 0;
  if ($("#opsComplete")) $("#opsComplete").textContent = health;
  if ($("#opsCompleteHint")) {
    $("#opsCompleteHint").textContent =
      currentLang === "zh"
        ? `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} 來源正常`
        : `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} sources OK`;
  }

  // 專區導覽磚件數
  if ($("#tileTw")) $("#tileTw").textContent = k.tw_industry_count ?? 0;
  if ($("#tileEms"))
    $("#tileEms").textContent = k.ems_count ?? k.tw_industry_count ?? 0;
  if ($("#tileFin")) $("#tileFin").textContent = k.finance_count ?? 0;
  if ($("#tileMs")) $("#tileMs").textContent = k.microsoft_count ?? 0;
  if ($("#tileHigh"))
    $("#tileHigh").textContent = (k.p0_count ?? 0) + (k.p1_count ?? 0);
  if ($("#tileDark"))
    $("#tileDark").textContent =
      k.ransomware_count ?? k.breach_count ?? 0;
  if ($("#tileSrc")) $("#tileSrc").textContent = health;

  renderDuty(k);

  const scan = await api("/api/scan/status");
  const parts = [
    `${t("lastSched")}: ${formatTs(scan.last_scheduled_scan)}`,
    `${t("lastManual")}: ${formatTs(scan.last_manual_scan)}`,
  ];
  if (USE_STATIC) {
    parts.push(
      currentLang === "zh"
        ? "靜態站 · 可瀏覽器即時巡檢"
        : "Static · browser live scan OK"
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
  await loadKpis();
  // OT tile count
  const items = await ensureIntel();
  const otN = items.filter((i) => isOtItem(i)).length;
  if ($("#tileOt")) $("#tileOt").textContent = otN;
  try {
    const brief = cache.preemptive || (await api("/api/preemptive-brief"));
    const st = brief.stats || {};
    if ($("#tilePre")) $("#tilePre").textContent = (st.p0 ?? 0) + (st.p1 ?? 0);
  } catch {
    /* tile stays 0 */
  }

  // 最新高風險 P0+P1 前 8（P0 優先）
  const high = items
    .filter((i) => i.priority === "P0" || i.priority === "P1")
    .sort((a, b) => {
      if (a.priority !== b.priority) return a.priority === "P0" ? -1 : 1;
      return 0;
    })
    .slice(0, 8);
  renderList($("#overviewHighList"), high, 8);
}

async function loadHighRisk() {
  const [p0, p1] = await Promise.all([
    api("/api/intel?priority=P0&limit=80"),
    api("/api/intel?priority=P1&limit=80"),
  ]);
  renderList($("#highP0List"), p0.items, 80);
  renderList($("#highP1List"), p1.items, 80);
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

async function loadTaiwan() {
  const data = await api("/api/intel?tw=true&limit=100");
  const items = [...(data.items || [])].sort((a, b) => {
    if (a.is_ransomware && !b.is_ransomware) return -1;
    if (!a.is_ransomware && b.is_ransomware) return 1;
    return 0;
  });
  renderList($("#taiwanList"), items, 80);
}

async function loadEms() {
  fillWatchLists();
  const data = await api("/api/tw-dashboard");
  if ($("#emsHitTotal")) $("#emsHitTotal").textContent = data.stats?.tw_total ?? 0;
  if ($("#emsHitRansom")) $("#emsHitRansom").textContent = data.stats?.tw_ransomware ?? 0;
  renderEntityChips($("#entityChips"), data.entity_counts);
  renderList($("#emsRansomList"), data.tw_ransomware, 40);
  renderList($("#emsOtherList"), data.tw_other, 40);
}

function isFinanceItem(item) {
  if (item?.is_finance) return true;
  const blob = [
    item?.title,
    item?.title_en,
    item?.summary,
    item?.summary_en,
    item?.vendor,
    item?.product,
    item?.source_name,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  // 避開 CISA ICS 關鍵基礎設施「Financial Services」列舉誤判
  const scrubbed = blob
    .replace(/financial services\s*[;/|]/gi, " ")
    .replace(/[;/|]\s*financial services\b/gi, " ")
    .replace(
      /\b(commercial facilities|communications|critical manufacturing|financial services|healthcare and public health|government facilities|information technology)\b/gi,
      " "
    );
  // 組織／產業訊號，避免「financial documents」「partial credit card data」等外洩內容誤判
  const noLeakBoiler = scrubbed.replace(
    /\bfinancial\s+(documents?|data|information|records?|files?|reporting|accounting|planning|statements?)\b/gi,
    " "
  );
  return /(?<![a-z])(banks?|banking|fintech|insurance|assurance|reinsurance|financi[eè]re|neobank)(?![a-z])|金融|銀行|金控|壽險|產險|證交所|證券商|電子支付|支付機構|swift network|credit union|stock exchange|crypto exchange|payment processor|paypal|mastercard|jpmorgan|hsbc|citibank|中國信託|國泰世華|富邦銀行|玉山銀行|兆豐|合作金庫|街口支付/.test(
    noLeakBoiler
  );
}

async function loadFinance() {
  let data = {};
  try {
    data = await api("/api/finance-dashboard");
  } catch (e) {
    console.warn("finance-dashboard", e);
  }

  // 以 dashboard 為主；若過舊／過少，改從全庫 is_finance + 前端關鍵字後援
  let items = [...(data.items || [])];
  if (items.length < 3) {
    try {
      const fin = await api("/api/intel?finance=true&limit=200");
      items = fin.items || items;
    } catch {
      /* keep */
    }
  }
  if (items.length < 3) {
    const all = await ensureIntel();
    items = all.filter(isFinanceItem);
  }

  // 去重
  const seen = new Set();
  items = items.filter((i) => {
    const k = i.id || i.url || i.title;
    if (!k || seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const ransom = items.filter((i) => i.is_ransomware);
  const kev = items.filter(
    (i) =>
      (i.source_name && /kev/i.test(i.source_name)) ||
      (i.tags && /kev/i.test(String(i.tags))) ||
      (Array.isArray(i.tags) && i.tags.some((t) => /kev/i.test(t)))
  );
  const kevIds = new Set(kev.map((i) => i.id || i.url || i.title));
  const other = items.filter(
    (i) => !i.is_ransomware && !kevIds.has(i.id || i.url || i.title)
  );

  if ($("#finHitTotal")) $("#finHitTotal").textContent = items.length;
  if ($("#finHitRansom")) $("#finHitRansom").textContent = ransom.length;
  if ($("#finHitKev")) $("#finHitKev").textContent = kev.length;
  if ($("#tileFin")) $("#tileFin").textContent = items.length;

  const chips = $("#watchFinance");
  if (chips) {
    const wl = data.watchlist || [];
    chips.innerHTML = wl.length
      ? wl
          .map((w) => {
            const label = typeof w === "string" ? w : w.key || w.name || "";
            const tier = w && w.tier ? ` · ${w.tier}` : "";
            return `<span>${escapeHtml(label)}${escapeHtml(tier)}</span>`;
          })
          .join("")
      : `<span>${t("empty")}</span>`;
  }

  const entityCounts = data.entity_counts && Object.keys(data.entity_counts).length
    ? data.entity_counts
    : {};
  if (!Object.keys(entityCounts).length) {
    for (const it of items) {
      let ents = it.finance_entities;
      if (typeof ents === "string") {
        try {
          ents = JSON.parse(ents);
        } catch {
          ents = [];
        }
      }
      for (const e of ents || []) {
        const k = e.key || e.matched || "finance";
        entityCounts[k] = (entityCounts[k] || 0) + 1;
      }
    }
  }
  renderEntityChips($("#finEntityChips"), entityCounts);
  renderList($("#finRansomList"), ransom, 40);
  renderList($("#finKevList"), kev, 40);
  renderList($("#finOtherList"), other, 60);
}

/** Microsoft zone — backed by /api/microsoft-dashboard (ms_dashboard.py buckets). */
async function loadMicrosoft() {
  let data = {};
  try {
    data = await api("/api/microsoft-dashboard");
  } catch (e) {
    console.warn("microsoft-dashboard", e);
  }

  // Fallback: dashboard unavailable/empty → query the flagged items directly
  let items = [...(data.items || [])];
  if (items.length < 3) {
    try {
      const ms = await api("/api/intel?microsoft=true&limit=200");
      items = ms.items || items;
    } catch {
      /* keep */
    }
  }
  if (items.length < 3) {
    const all = await ensureIntel();
    items = all.filter((i) => i.is_microsoft);
  }

  const stats = data.stats || {};
  const isKev = (i) =>
    (i.source_name && /kev/i.test(i.source_name)) ||
    (Array.isArray(i.tags) && i.tags.some((t) => /kev|in-the-wild/i.test(t)));
  const kev = data.kev_items || items.filter(isKev);
  const p1 = data.p1_items || items.filter((i) => i.priority === "P1");
  const ransom = data.ransomware || items.filter((i) => i.is_ransomware);

  const setNum = (sel, n) => {
    const el = $(sel);
    if (el) el.textContent = n;
  };
  setNum("#msHitTotal", stats.total ?? items.length);
  setNum("#msHitKev", stats.kev ?? kev.length);
  setNum("#msHitP1", stats.p1 ?? p1.length);
  setNum("#msHitRansom", stats.ransomware ?? ransom.length);
  setNum("#tileMs", stats.total ?? items.length);

  const chips = $("#watchMicrosoft");
  if (chips) {
    const wl = data.watchlist || [];
    chips.innerHTML = wl.length
      ? wl
          .map((w) => {
            const label = typeof w === "string" ? w : w.key || w.name || "";
            const tier = w && w.tier ? ` · ${w.tier}` : "";
            return `<span>${escapeHtml(label)}${escapeHtml(tier)}</span>`;
          })
          .join("")
      : `<span>${t("empty")}</span>`;
  }

  let entityCounts = data.entity_counts || {};
  if (!Object.keys(entityCounts).length) {
    entityCounts = {};
    for (const it of items) {
      let ents = it.ms_entities;
      if (typeof ents === "string") {
        try {
          ents = JSON.parse(ents);
        } catch {
          ents = [];
        }
      }
      for (const e of ents || []) {
        const k = e.key || e.matched || "microsoft";
        entityCounts[k] = (entityCounts[k] || 0) + 1;
      }
    }
  }
  renderEntityChips($("#msEntityChips"), entityCounts);

  renderList($("#msKevList"), kev, 40);
  renderList($("#msP1List"), p1, 40);
  renderList($("#msRansomList"), ransom, 40);
  renderList($("#msWindowsList"), data.windows_os || [], 40);
  renderList($("#msEnterpriseList"), data.enterprise_platform || [], 40);
  renderList($("#msTiList"), data.threat_intel || [], 40);
  renderList($("#msConfirmedList"), data.confirmed_items || [], 40);
  renderList($("#msOtherList"), data.other || [], 40);
}

function briefCardHTML(it) {
  const p = it.priority || "P3";
  const classes = ["card", "pre-card", String(p).toLowerCase()];
  if (it.org_related) classes.push("pre-org");
  if (it.status_upgrade) classes.push("pre-up");
  const ev = it.evidence || "unverified";
  const evClass =
    ev === "confirmed" ? "v-confirmed" : ev === "third_party" ? "v-credible" : "v-unverified";
  const evLabel =
    ev === "confirmed"
      ? t("vConfirmed")
      : ev === "third_party"
        ? t("preThirdParty")
        : t("vUnverified");
  const sig = it.signals || {};
  const epss =
    sig.epss == null ? "—" : Number(sig.epss).toFixed(3);
  const cvss =
    sig.cvss == null ? "—" : `${Number(sig.cvss).toFixed(1)} (${sig.cvss_version || "v3.1"})`;
  const safeUrl = safeHref(it.url);
  const link = safeUrl
    ? `<a class="meta-link" href="${safeUrl}" target="_blank" rel="noopener noreferrer">${t("openLink")} ↗</a>`
    : "";
  const tags = [
    `<span class="pill ${String(p).toLowerCase()}">${escapeHtml(p)}</span>`,
    `<span class="pill ${evClass}">${escapeHtml(evLabel)}</span>`,
  ];
  if (it.org_related)
    tags.push(
      `<span class="pill org-hit">${escapeHtml(t("preOrgHits"))}</span>`
    );
  if (it.status_upgrade)
    tags.push(`<span class="pill p2">${escapeHtml(t("preUpgrade"))}</span>`);
  const cve = it.cve_id ? cveCopyChip(it.cve_id) : "";
  return `
    <article class="${classes.join(" ")}">
      <div class="card-top"><div class="card-tags">${tags.join("")}</div></div>
      <h4>${escapeHtml(it.cve_id || it.title || "")}</h4>
      <p>${escapeHtml(it.title && it.cve_id && it.title !== it.cve_id ? it.title : it.so_what || "")}</p>
      <div class="card-rationale"><strong>${t("preSoWhat")}</strong> ${escapeHtml(it.so_what || "")}</div>
      ${
        it.action
          ? `<div class="card-ops"><span><b>${t("preAction")}</b> ${escapeHtml(it.action)}</span>
             <span><b>${t("preDeadline")}</b> ${escapeHtml(it.deadline || "—")}</span>
             <span><b>${t("preOwner")}</b> ${escapeHtml(it.owner || "—")}</span></div>`
          : ""
      }
      ${
        it.trigger && (it.section === "watch" || p === "P3")
          ? `<div class="card-assets"><b>${t("preTrigger")}</b> ${escapeHtml(it.trigger)}</div>`
          : ""
      }
      <div class="card-meta">
        ${cve}
        ${metaChip("epss", "EPSS", epss, "meta-epss")}
        ${metaChip("cvss", "CVSS", cvss, "meta-layer")}
        ${it.source_name ? metaChip("source", t("sources"), it.source_name, "meta-source") : ""}
        ${link}
      </div>
    </article>`;
}

// 「顯示 N／共 M」 next to a section heading. `total` comes from the brief
// payload's section_counts, i.e. how many rows the classifier actually put in
// that section before the composer's cap trimmed it.
function setSectionCount(key, shown, total) {
  const el = document.querySelector(`.sec-count[data-count="${key}"]`);
  if (!el) return;
  const m = Number.isFinite(total) ? total : shown;
  const truncated = m > shown;
  el.textContent = truncated
    ? t("preShownOf").replace("{n}", shown).replace("{m}", m)
    : t("preTotalOf").replace("{m}", m);
  el.classList.toggle("is-truncated", truncated);
  if (truncated) el.title = t("preTruncHint");
  else el.removeAttribute("title");
}

// Renders every row the payload carries. The old form re-truncated to 8/6/10 on
// top of the composer's own caps, so a section could hold 101 items, ship 20 and
// show 10 — three numbers, none of them stated anywhere in the UI.
function renderBriefList(el, items, key, counts) {
  const rows = items || [];
  setSectionCount(key, rows.length, (counts || {})[key]?.total);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="empty">${t("empty")}</div>`;
    return;
  }
  el.innerHTML = rows.map(briefCardHTML).join("");
}

async function loadPreemptive() {
  let data = {};
  try {
    data = await api("/api/preemptive-brief");
  } catch (e) {
    console.warn("preemptive-brief", e);
  }
  cache.preemptive = data;
  const stats = data.stats || {};
  const set = (sel, v) => {
    const el = $(sel);
    if (el) el.textContent = v;
  };
  set("#preP0", stats.p0 ?? 0);
  set("#preP1", stats.p1 ?? 0);
  set("#preOrg", stats.org_hits ?? 0);
  set("#tilePre", (stats.p0 ?? 0) + (stats.p1 ?? 0));

  const meta = $("#preMeta");
  if (meta) {
    const dec = data.needs_exec_decision ? t("preNeedsDecision") : t("preNoDecision");
    meta.textContent = [
      `${data.date || "—"} ${data.weekday_zh || ""}`,
      data.coverage || "",
      data.generated_at_taipei || data.generated_at || "",
      dec,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  const exec = $("#preExec");
  if (exec) {
    const lines = data.exec_summary || [];
    exec.innerHTML = lines.length
      ? `<h3 data-i18n="none">${escapeHtml(currentLang === "zh" ? "一、管理階層摘要" : "1. Executive summary")}</h3>` +
        lines.map((l) => `<p>${escapeHtml(l)}</p>`).join("")
      : `<p class="empty">${t("empty")}</p>`;
  }

  const counts = data.section_counts || {};

  const mustEl = $("#preMust");
  {
    const must = data.must_do || [];
    // 「Top 3」 is a deliberate cap, but the reader still needs to know it was
    // picked out of 125 P0/P1 items rather than being the whole list.
    setSectionCount("must_do", must.length, counts.must_do?.total);
    if (mustEl) {
      mustEl.innerHTML = must.length
        ? must
            .map((it, i) => {
              const card = briefCardHTML(it);
              return `<div class="pre-must-item"><div class="pre-rank">${i + 1}</div>${card}</div>`;
            })
            .join("")
        : `<div class="empty">${t("preNoMust")}</div>`;
    }
  }

  const body = $("#preKevBody");
  {
    const rows = data.kev_epss || [];
    setSectionCount("kev_epss", rows.length, counts.kev_epss?.total);
    if (body)
      body.innerHTML = rows.length
      ? rows
          .map((it) => {
            const sig = it.signals || {};
            const epss = sig.epss == null ? "—" : Number(sig.epss).toFixed(3);
            const cvss =
              sig.cvss == null
                ? "—"
                : `${Number(sig.cvss).toFixed(1)} ${sig.cvss_version || ""}`;
            const url = safeHref(it.url);
            const cve = escapeHtml(it.cve_id || "—");
            const cveCell = url
              ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${cve}</a>`
              : cve;
            return `<tr>
              <td>${cveCell}</td>
              <td>${escapeHtml(((it.vendor || "") + " " + (it.product || "")).trim() || "—")}</td>
              <td>${escapeHtml(cvss)}</td>
              <td>${escapeHtml(epss)}</td>
              <td>${sig.kev ? "●" : "—"}</td>
              <td>${it.org_related ? "●" : "—"}</td>
              <td>${escapeHtml(it.source_name || "—")}</td>
            </tr>`;
          })
          .join("")
      : `<tr><td colspan="7">${escapeHtml(t("empty"))}</td></tr>`;
  }

  renderBriefList($("#preExpList"), data.exposure, "exposure", counts);
  renderBriefList($("#preOtList"), data.ot_ics, "ot_ics", counts);
  renderBriefList($("#prePsirtList"), data.psirt, "psirt", counts);
  renderBriefList($("#preMktList"), data.market, "market", counts);
  renderBriefList($("#preWatchList"), data.watch, "watch", counts);

  const src = $("#preSources");
  {
    const rows = data.sources || [];
    setSectionCount("sources", rows.length, counts.sources?.total);
    if (src)
      src.innerHTML = rows.length
      ? rows
          .map((s) => {
            const url = safeHref(s.url);
            const name = escapeHtml(s.name || "");
            const st = s.status && s.status !== "ok" ? ` · ${escapeHtml(s.status)}` : "";
            const link = url
              ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${name}</a>`
              : name;
            return `<li>${link}${st} <time>${escapeHtml(s.published || "")}</time></li>`;
          })
          .join("")
      : `<li>${t("empty")}</li>`;
  }
}

function setupPreemptiveActions() {
  const copyBtn = $("#preCopyMd");
  const dlBtn = $("#preDlMd");
  copyBtn?.addEventListener("click", async () => {
    const md = cache.preemptive?.markdown || cache.preemptive?.exec_markdown || "";
    if (!md) {
      showToast(t("empty"), true);
      return;
    }
    try {
      await copyText(md);
      showToast(t("preCopied"));
    } catch {
      showToast(t("preCopyFail"), true);
    }
  });
  dlBtn?.addEventListener("click", () => {
    const md = cache.preemptive?.markdown || "";
    if (!md) return;
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    const date = cache.preemptive?.date || "brief";
    a.href = URL.createObjectURL(blob);
    a.download = `daily_${date}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

/** Review queue + rule accuracy — the analyst feedback loop (2.9). */
async function loadReview() {
  const hint = $("#reviewModeHint");
  if (hint) hint.textContent = USE_STATIC ? t("reviewStaticHint") : t("reviewLiveHint");

  let acc = {};
  try {
    acc = await api("/api/rule-accuracy");
  } catch (e) {
    console.warn("rule-accuracy", e);
  }
  const body = $("#ruleAccuracyBody");
  if (body) {
    const dims = acc.dimensions || {};
    const rows = Object.entries(dims);
    body.innerHTML = rows.length
      ? rows
          .map(([name, d]) => {
            const pct =
              d.precision == null
                ? `<span class="muted">—</span>`
                : `<b class="${d.precision >= 0.8 ? "acc-good" : d.precision >= 0.5 ? "acc-mid" : "acc-bad"}">${Math.round(d.precision * 100)}%</b>`;
            return `<tr>
              <td>${escapeHtml(name)}</td>
              <td>${d.total ?? 0}</td>
              <td>${d.reviewed ?? 0}</td>
              <td>${d.true_positive ?? 0}</td>
              <td>${d.false_positive ?? 0}</td>
              <td>${pct}</td>
            </tr>`;
          })
          .join("")
      : `<tr><td colspan="6">${escapeHtml(t("accNoData"))}</td></tr>`;
  }

  let queue = { items: [] };
  try {
    queue = await api("/api/review-queue?limit=100");
  } catch (e) {
    console.warn("review-queue", e);
  }
  const list = $("#reviewList");
  if (!list) return;
  const items = queue.items || [];
  if (!items.length) {
    list.innerHTML = `<p class="empty">${escapeHtml(t("empty"))}</p>`;
    return;
  }
  list.innerHTML = items
    .map((item) => {
      const card = cardHTML(item);
      if (USE_STATIC) return card;
      const id = escapeHtml(String(item.id || ""));
      const buttons = `
        <div class="verdict-bar" data-verdict-for="${id}">
          <button type="button" class="btn verdict-btn v-tp" data-verdict="true_positive">${escapeHtml(t("markTp"))}</button>
          <button type="button" class="btn verdict-btn v-fp" data-verdict="false_positive">${escapeHtml(t("markFp"))}</button>
          <button type="button" class="btn verdict-btn v-unk" data-verdict="unknown">${escapeHtml(t("markUnknown"))}</button>
        </div>`;
      return card.replace("</article>", `${buttons}</article>`);
    })
    .join("");
}

/** Delegated handler so verdict buttons keep working after re-render. */
function setupVerdictActions() {
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest?.(".verdict-btn");
    if (!btn) return;
    const bar = btn.closest("[data-verdict-for]");
    const id = bar?.getAttribute("data-verdict-for");
    if (!id) return;
    bar.querySelectorAll(".verdict-btn").forEach((b) => (b.disabled = true));
    try {
      await api(`/api/intel/${encodeURIComponent(id)}/verdict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verdict: btn.dataset.verdict }),
      });
      bar.innerHTML = `<span class="verdict-done">✓ ${escapeHtml(t("verdictSaved"))}</span>`;
      cache.ruleAccuracy = null;
      cache.reviewQueue = null;
    } catch (e) {
      bar.querySelectorAll(".verdict-btn").forEach((b) => (b.disabled = false));
      // Same reason as manualScan(): a fail-closed 401 must say what to set.
      showToast(e.status === 401 ? t("scanAuth") : t("verdictFailed"), true);
    }
  });
}

function isOtItem(i) {
  const tags = Array.isArray(i.tags)
    ? i.tags
    : typeof i.tags === "string"
      ? (() => {
          try {
            return JSON.parse(i.tags);
          } catch {
            return [];
          }
        })()
      : [];
  if (
    tags.some((t) =>
      /^(ot|ot-gov|ot-it|ot-vendor|ot-research|ot-media|ics|icsma|scada|plc|claroty|nozomi|dragos|sans-ics)$/i.test(
        String(t)
      )
    )
  ) {
    return true;
  }
  if (i.layer_id === "L7") return true;
  const blob = `${i.title || ""} ${i.summary || ""} ${i.source_name || ""}`;
  return /cisa ics|icsma|icsa-|dragos|claroty|nozomi|sans ics|industrial cyber|scada|\bot\b|industrial control|plc |jpcert|ncsc|twcert|acsc|cccs|cert-eu|\bbsi\b|nsa csa|cis advisory|official-gov|securityweek ics|dark reading ics/i.test(
    blob
  );
}

function otSortRank(i) {
  const blob = `${(i.tags || []).join(" ")} ${i.source_name || ""} ${i.title || ""}`.toLowerCase();
  if (/official-gov|ot-gov|cisa ics|cisa kev|twcert|ics advisory/.test(blob)) return 0;
  if (/ot-research|dragos|claroty|nozomi|sans ics|sansics/.test(blob)) return 1;
  if (/ot-media|securityweek|industrial cyber|dark reading|thn ics|infosec/.test(blob))
    return 2;
  return 3;
}

async function loadOtCatalog() {
  const el = $("#otCatalog");
  if (!el) return;
  let data = null;
  try {
    data = await api("/api/ot-catalog");
  } catch {
    data = null;
  }
  if (!data || !data.categories) {
    el.innerHTML = "";
    return;
  }
  const zh = currentLang === "zh";
  const catTitle = (c) => (zh ? c.name_zh : c.name_en);
  const role = (s) => (zh ? s.role_zh : s.role_en);
  const usage = (s) => (zh ? s.usage_zh : s.usage_en);
  const parts = [`<h3 class="ot-cat-heading">${t("otCatalogTitle")}</h3>`];
  for (const c of data.categories) {
    const srcs = (data.by_category && data.by_category[String(c.id)]) || [];
    parts.push(`<details class="ot-cat-block" ${c.id === 1 ? "open" : ""}>`);
    parts.push(`<summary><strong>${escapeHtml(catTitle(c))}</strong> · ${srcs.length}</summary>`);
    if (c.note_zh || c.note_en) {
      parts.push(
        `<p class="ot-cat-note">${escapeHtml(zh ? c.note_zh || "" : c.note_en || "")}</p>`
      );
    }
    parts.push(`<ul class="ot-cat-list">`);
    for (const s of srcs) {
      const safeUrl = safeHref(s.url);
      const nameEsc = escapeHtml(s.name || "");
      const link = safeUrl
        ? `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${nameEsc}</a>`
        : nameEsc;
      const badge = s.ingest === "reference" || s.priority === "framework"
        ? `<span class="pill p3">ref</span>`
        : s.priority === "daily_must"
          ? `<span class="pill p0">must</span>`
          : s.ingest
            ? `<span class="pill p2">${escapeHtml(String(s.ingest))}</span>`
            : "";
      parts.push(
        `<li>${badge} ${link}` +
          `<div class="ot-cat-role">${escapeHtml(role(s) || "")}</div>` +
          (usage(s)
            ? `<div class="ot-cat-usage"><span class="muted">${t("otUsage")}:</span> ${escapeHtml(usage(s))}</div>`
            : "") +
          `</li>`
      );
    }
    parts.push(`</ul></details>`);
  }
  parts.push(`<h3 class="ot-cat-heading">${t("otLiveFeed")}</h3>`);
  el.innerHTML = parts.join("");
}

async function loadOt() {
  await loadOtCatalog();
  const items = await ensureIntel();
  const ot = items.filter((i) => isOtItem(i)).sort((a, b) => {
    const ar = otSortRank(a);
    const br = otSortRank(b);
    if (ar !== br) return ar - br;
    if (a.priority !== b.priority) {
      const order = { P0: 0, P1: 1, P2: 2, P3: 3 };
      return (order[a.priority] ?? 9) - (order[b.priority] ?? 9);
    }
    return 0;
  });
  renderList($("#otList"), ot, 80);
}

async function loadDark() {
  const all = await ensureIntel();
  const dark = all.filter((i) => {
    const src = `${i.source_name || ""} ${i.title || ""}`.toLowerCase();
    if (src.includes("cisa kev") && !src.includes("ransom")) return false;
    return /ransomlook|ransomware\.live|threatfox|hibp|databreach|dark web|x @|leak-site|indirect dark/i.test(
      src
    );
  });
  // 單一列表：雙源在前，單源 P3 在後
  dark.sort((a, b) => {
    const ad =
      a.verification === "credible" || (a.sources || []).length >= 2 ? 0 : 1;
    const bd =
      b.verification === "credible" || (b.sources || []).length >= 2 ? 0 : 1;
    if (ad !== bd) return ad - bd;
    return 0;
  });
  renderList($("#darkList"), dark, 80);
}

async function loadSources() {
  await loadLayers();
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

  /**
   * Fetch the first reachable mirror. Reports one outcome per *source* rather
   * than per attempt: a failed first mirror followed by a working one is a
   * success, and showing both made the panel look broken when it was not.
   */
  async function fetchFirst(urls) {
    let lastErr;
    for (const u of urls) {
      try {
        const r = await fetch(u, { cache: "no-store" });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return { data: await r.json(), url: u };
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error("no mirror reachable");
  }

  // 1) KEV — GitHub mirror first: it sends Access-Control-Allow-Origin, while
  // cisa.gov does not, so from a browser the direct feed can only ever fail.
  const kevUrls = [
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  ];
  let kevN = 0;
  {
    try {
      const { data, url: u } = await fetchFirst(kevUrls);
      const vulns = (data.vulnerabilities || [])
        .sort((a, b) => (b.dateAdded || "").localeCompare(a.dateAdded || ""))
        .slice(0, 40);
      kevN = vulns.length;
      results.push({
        name: "CISA KEV",
        state: "ok",
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
    } catch (e) {
      results.push({ name: "CISA KEV", state: "bad", detail: String(e.message || e) });
    }
  }

  // 2) RansomLook — serves no CORS header, so a browser can never read it.
  // Reported as unavailable-in-static rather than as a failure: nothing is
  // broken, this source simply needs the Actions run.
  let lookTitles = new Set();
  let lookReachable = false;
  try {
    const r = await fetch("https://www.ransomlook.io/api/recent", { cache: "no-store" });
    const data = await r.json();
    const rows = Array.isArray(data) ? data.slice(0, 30) : [];
    lookReachable = true;
    results.push({ name: "RansomLook", state: "ok", detail: `${rows.length} posts` });
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
  } catch {
    results.push({ name: "RansomLook", state: "blocked", detail: t("scanNoCors") });
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
      // Only claim a dual-source count when the other tracker was actually
      // read. "dual≈0" with RansomLook unreachable reads as "cross-checked,
      // no matches" when nothing was cross-checked at all.
      results.push({
        name: "Ransomware.live",
        state: "ok",
        detail: lookReachable
          ? `${rows.length} victims · dual≈${dual}`
          : `${rows.length} victims · ${t("scanNoDual")}`,
      });
    } else {
      results.push({ name: "Ransomware.live", state: "bad", detail: `HTTP ${r.status}` });
    }
  } catch (e) {
    results.push({
      name: "Ransomware.live",
      state: "blocked",
      detail: String(e.message || e),
    });
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
    const cls = { ok: "ok", bad: "bad", blocked: "info" };
    const rows = results
      .map(
        (r) =>
          `<li class="${cls[r.state] || "bad"}"><b>${escapeHtml(r.name)}</b> — ${escapeHtml(
            r.detail || ""
          )}</li>`
      )
      .join("");
    const anyBlocked = results.some((r) => r.state === "blocked");
    list.innerHTML =
      rows +
      (anyBlocked
        ? `<li class="scan-note">${escapeHtml(t("scanBlockedNote"))}</li>`
        : "");
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
  if (badge) {
    badge.textContent =
      currentLang === "zh"
        ? data.schedule?.description_zh || ""
        : data.schedule?.description_en || "";
  }

  const grid = $("#layersGrid");
  if (!grid) return;
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
          const lat = s.latency_ms != null ? ` · ${s.latency_ms}ms` : "";
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
          <div class="layer-hint">${escapeHtml(L.schedule_hint || "")}</div>
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
    // 401 is now the default posture with no SOC_CTI_API_KEY set, so it has to
    // reach the analyst as an explanation rather than as a bare "api_error".
    if (e.status === 401 || e.status === 501 || e.status === 429 || e.status === 409) {
      const d = e.data?.detail;
      const fallback =
        e.status === 429
          ? t("scanCooldown")
          : e.status === 401
            ? t("scanAuth")
            : t("scanBusy");
      const msg =
        typeof d === "object"
          ? currentLang === "zh"
            ? d.message_zh
            : d.message_en
          : fallback;
      showToast(msg || fallback, true);
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

async function loadView(view) {
  if (view === "overview") await loadOverview();
  if (view === "highrisk") await loadHighRisk();
  if (view === "taiwan") await loadTaiwan();
  if (view === "ot") await loadOt();
  if (view === "dark") await loadDark();
  if (view === "ems") await loadEms();
  if (view === "finance") await loadFinance();
  if (view === "microsoft") await loadMicrosoft();
  if (view === "preemptive") await loadPreemptive();
  if (view === "review") await loadReview();
  if (view === "sources") await loadSources();
}

async function refreshAll() {
  try {
    if (USE_STATIC) Object.keys(cache).forEach((k) => (cache[k] = null));
    const active = $(".tab.active")?.dataset.view || "overview";
    await loadView(active);
  } catch (e) {
    console.error(e);
  }
}

window.refreshAll = refreshAll;

function activateTab(tab) {
  $$(".tab").forEach((x) => {
    x.classList.remove("active");
    x.setAttribute("aria-selected", "false");
  });
  tab.classList.add("active");
  tab.setAttribute("aria-selected", "true");
  const view = tab.dataset.view;
  $$(".view").forEach((v) => v.classList.remove("active"));
  $(`#view-${view}`)?.classList.add("active");
  syncBottomNav(view);
  return view;
}

/**
 * Mirror the active view onto the phone shortcut bar.
 *
 * Called from activateTab rather than from the bar's own click handler, so
 * the highlight is right however the view changed — top tab, zone tile, the
 * "view all" button, or the bar itself. Six of the eleven zones have no
 * shortcut here; when one of those is open, nothing is highlighted, which is
 * the truth rather than a stale mark left on the last shortcut used.
 */
function syncBottomNav(view) {
  $$(".bnav-item").forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "true");
    else b.removeAttribute("aria-current");
  });
}

function setupTabs() {
  const tabs = $$(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", async () => {
      await loadView(activateTab(tab));
    });
    // Arrow-key navigation, as expected of role="tablist"
    tab.addEventListener("keydown", async (ev) => {
      const step =
        ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
      if (!step) return;
      ev.preventDefault();
      const i = tabs.indexOf(tab);
      const next = tabs[(i + step + tabs.length) % tabs.length];
      next.focus();
      await loadView(activateTab(next));
    });
  });
  $$(".nav-tile").forEach((tile) => {
    tile.addEventListener("click", () => {
      const v = tile.dataset.goto;
      if (v) goToView(v);
    });
  });
  $("#btnViewAllHigh")?.addEventListener("click", () => goToView("highrisk"));

  // The shortcut bar routes through goToView, i.e. it clicks the real tab, so
  // loading and state changes stay on one path instead of a parallel one.
  $$(".bnav-item").forEach((b) => {
    b.addEventListener("click", () => {
      const v = b.dataset.view;
      if (v) goToView(v);
    });
  });
  // The first view is marked active in the HTML, so activateTab has not run
  // yet and the bar would start with nothing highlighted.
  syncBottomNav($(".tab.active")?.dataset.view);
}

document.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  setupTabs();
  setupCardActions();
  setupVerdictActions();
  setupPreemptiveActions();
  upgradeDutyAvatar();
  $("#langToggle")?.addEventListener("click", () => toggleLang());
  $("#manualScanBtn")?.addEventListener("click", () => manualScan());
  $("#scanModalClose")?.addEventListener("click", () => {
    $("#scanModal")?.classList.add("hidden");
  });
  tickClock();
  setInterval(tickClock, 1000);
  await detectMode();
  await refreshAll();
  setInterval(refreshAll, 120000);
});
