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
  const classes = ["card", p.toLowerCase()];
  if (ransom) classes.push("ransom-glow");
  const tags = [];
  tags.push(`<span class="pill ${p.toLowerCase()}">${p}</span>`);
  tags.push(
    `<span class="pill ${verClass(item.verification)}">${verLabel(item.verification)}</span>`
  );
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
      `<span class="pill" style="background:#1a1a2e;border-color:#555;color:#ccc">${item.admiralty}</span>`
    );

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
      <div class="card-meta">
        ${meta.map((m) => `<span>${escapeHtml(String(m))}</span>`).join("")}
        ${link}
      </div>
    </article>
  `;
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
      ? `KEV 總收錄（本庫）${k.kev_total ?? 0}`
      : `KEV in DB ${k.kev_total ?? 0}`;
  $("#kpiTw").textContent = `${k.tw_industry_count ?? 0} / ${k.tw_ransomware_count ?? 0}`;
  $("#kpiHealth").textContent = `${k.source_health_pct ?? 0}%`;
  $("#kpiHealthHint").textContent =
    currentLang === "zh"
      ? `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} 來源正常`
      : `${k.sources_healthy ?? 0}/${k.sources_total ?? 0} sources OK`;

  const scan = await api("/api/scan/status");
  const parts = [
    `${t("lastSched")}: ${formatTs(scan.last_scheduled_scan)}`,
    `${t("lastManual")}: ${formatTs(scan.last_manual_scan)}`,
  ];
  if (USE_STATIC) {
    parts.push(currentLang === "zh" ? "模式：GitHub Pages 靜態" : "Mode: GitHub Pages static");
  } else if (!scan.manual_scan_allowed) {
    const m = Math.ceil((scan.cooldown_remaining_sec || 0) / 60);
    parts.push(`${t("nextCooldown")}: ${m}m`);
  }
  $("#scanMeta").textContent = parts.join(" · ");

  const btn = $("#manualScanBtn");
  if (btn) {
    btn.disabled = USE_STATIC ? false : !scan.manual_scan_allowed || scan.harvest_running;
    if (USE_STATIC) {
      btn.title =
        currentLang === "zh"
          ? "靜態站：將提示用 GitHub Actions 更新"
          : "Static site: prompts to use GitHub Actions";
    }
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

async function loadLayers() {
  const data = await api("/api/layers");
  const badge = $("#scheduleBadge");
  badge.textContent =
    currentLang === "zh" ? data.schedule?.description_zh : data.schedule?.description_en;

  const grid = $("#layersGrid");
  grid.innerHTML = (data.layers || [])
    .map((L) => {
      const name = currentLang === "zh" ? L.name_zh : L.name_en;
      const srcs = (L.sources || [])
        .map(
          (s) => `
        <li>
          <span class="src-name">${escapeHtml(s.name)}</span>
          <span>
            <span class="status-dot ${escapeHtml(s.status || "unknown")}"></span>
            ${escapeHtml(s.status || "—")}
            ${s.item_count != null ? ` · ${s.item_count}` : ""}
          </span>
        </li>`
        )
        .join("");
      return `
        <article class="layer-card">
          <h3>
            <span class="layer-id">${escapeHtml(L.id)}</span>
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
  const btn = $("#manualScanBtn");
  btn.disabled = true;
  showToast(t("scanning"));
  try {
    await api("/api/scan/manual", { method: "POST" });
    // clear static cache after live scan
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
      if (view === "finance") await loadFinance();
      if (view === "microsoft") await loadMicrosoft();
      if (view === "layers") await loadLayers();
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  setupTabs();
  $("#langToggle").addEventListener("click", () => toggleLang());
  $("#manualScanBtn").addEventListener("click", () => manualScan());
  $("#applyFilters").addEventListener("click", () => loadIntelStream());
  $("#filterQ").addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadIntelStream();
  });
  tickClock();
  setInterval(tickClock, 1000);
  await detectMode();
  await refreshAll();
  setInterval(refreshAll, 120000);
});
