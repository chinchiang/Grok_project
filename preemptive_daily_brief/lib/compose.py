"""Compose the 8-section Traditional Chinese daily brief + JSON payload."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from .classify import PRIO_RANK, classify_item, promote_if_upgrade
from .state import ReportedState

TZ = ZoneInfo("Asia/Taipei")
WEEKDAY_ZH = "一二三四五六日"

EVIDENCE_ZH = {
    "confirmed": "【已證實】",
    "third_party": "【第三方評論】",
    "unverified": "【尚未證實】",
}

SECTION_TITLES = {
    "must_do": "二、今日必辦 Top 3（P0/P1 行動項）",
    "kev_epss": "三、新增 KEV 與高 EPSS 訊號",
    "exposure": "四、曝險與攻擊面訊號（EASM/憑證外洩/品牌仿冒域名/供應鏈）",
    "ot_ics": "五、OT/ICS 專區",
    "psirt": "六、產品資安／供應鏈（PSIRT・SBOM・CRA）",
    "market": "七、先制式技術與市場動態（CTEM/AEV/EAP/AMTD/欺敵/預測式 DNS）",
    "watch": "八、觀察與尚未證實（追蹤清單）",
}

EMPTY_ZH = "本日無重大更新"

# Rows carried in the JSON payload per section. Caps bound the payload size; they
# are published in payload["section_counts"] so the UI and the Markdown can say
# 「顯示 N／共 M」 instead of silently dropping the tail.
SECTION_CAPS = {
    "must_do": 3,
    "kev_epss": 40,
    "exposure": 20,
    "ot_ics": 20,
    "psirt": 20,
    "market": 15,
    "watch": 20,
    "sources": 80,
}

# The Markdown edition prints fewer rows than the payload carries, so it is a
# second truncation layer on top of SECTION_CAPS. Both are reported.
MD_LIMITS = {
    "kev_epss": 25,
    "exposure": 12,
    "ot_ics": 12,
    "psirt": 12,
    "market": 12,
    "watch": 12,
}


def _now_taipei() -> datetime:
    return datetime.now(TZ)


def _weekday_zh(dt: datetime) -> str:
    return f"週{WEEKDAY_ZH[dt.weekday()]}"


def _fmt_epss(epss: float | None, percentile: float | None = None, delta: float | None = None) -> str:
    if epss is None:
        return "—"
    pct = f"{epss:.3f}"
    extra = []
    if percentile is not None:
        extra.append(f"p{percentile:.1f}")
    if delta is not None:
        sign = "+" if delta >= 0 else ""
        extra.append(f"24h {sign}{delta:.3f}")
    return f"{pct}" + (f"（{'；'.join(extra)}）" if extra else "")


def _fmt_cvss(cvss: float | None, version: str | None = None) -> str:
    if cvss is None:
        return "—"
    ver = version or "v3.1"
    return f"{cvss:.1f}（{ver}）"


def _so_what(item: dict[str, Any]) -> str:
    """Concrete org implication — templated from real fields, never invented."""
    assets = "、".join(a.get("matched") or a.get("key") or "" for a in item.get("org_assets") or [])
    product = item.get("product") or item.get("vendor") or "相關資產"
    if item.get("section") == "ot_ics":
        zone = item.get("iec62443") or "zone/conduit"
        return (
            f"若產線存在 {product}，屬 IEC 62443 {zone} 曝險；"
            f"僅能在受控變更窗口驗證，禁止主動掃描。"
            + (f"命中關鍵字：{assets}。" if assets else "")
        )
    if item.get("section") == "psirt":
        return (
            f"可能影響出貨產品之上游元件（{product}）。"
            "請以 SBOM 比對；若屬 CRA 涵蓋產品且已出貨，評估 24 小時通報義務。"
        )
    if item.get("org_related"):
        return f"〔本組織相關〕堆疊命中 {assets or product}，優先納入今日修補／虛擬修補清單。"
    if item.get("in_kev"):
        return f"{item.get('cve_id') or product} 已在 CISA KEV，視為在野利用，須納入緊急修補節奏。"
    if item.get("is_ransomware"):
        return "勒索活動訊號：核對監控名單與供應鏈第三方，未雙源核實不得單獨開立 IR 工單。"
    return f"列入觀察：{product}。確認本組織是否持有受影響版本後再升級為必辦。"


def _action(item: dict[str, Any]) -> tuple[str, str, str]:
    """Return (action, deadline, owner).

    OT never includes an active-scan or unapproved-automation instruction
    (CLAUDE.md §7), but urgency must still track priority. This used to branch
    on section before priority, so any P0 that routed to OT/ICS was handed
    「下次 CAB 窗口（建議 7 日內排程）」 instead of a 24-hour deadline — a
    misrouted item was silently *de-prioritised* below a correctly routed one.
    Priority now selects the deadline and OT only constrains the method.
    """
    owner = item.get("owner_unit") or "IT"
    priority = item.get("brief_priority")
    if item.get("section") == "ot_ics":
        if priority == "P0":
            return (
                "被動盤點受影響型號與韌體；召開緊急 CAB，於受控窗口套用原廠緩解，"
                "過渡期以網段／conduit 隔離與加強監控降險。禁止主動掃描或未核准自動化補救。",
                "24 小時內召開緊急 CAB 並完成緩解決議",
                "OT",
            )
        if priority == "P1":
            return (
                "被動盤點受影響型號與韌體；完成緩解評估並提交 CAB 排入最近受控窗口。"
                "禁止主動掃描或未核准自動化補救。",
                "72 小時內提交 CAB 決議",
                "OT",
            )
        return (
            "被動盤點受影響型號與韌體；經 OT 工程與 CAB 核定後，於受控窗口套用原廠緩解。禁止主動掃描或未核准自動化補救。",
            "下次 CAB 窗口（建議 7 日內排程）",
            "OT",
        )
    if priority == "P0":
        return ("套用原廠修補；無法立即修補則虛擬修補／WAF／邊界封鎖。", "24 小時", owner)
    if priority == "P1":
        return ("確認資產持有後於變更窗口修補；過渡期採虛擬修補。", "72 小時", owner)
    if item.get("section") == "psirt":
        return ("SBOM 比對受影響元件；PSIRT 準備客戶問答與 CRA 通報評估。", "48 小時", "PSIRT")
    return ("持續觀察；若進入 KEV、EPSS≥0.5 或 PoC 公開則升級為必辦。", "列入週追蹤", owner)


def _trigger(item: dict[str, Any]) -> str:
    cve = item.get("cve_id") or "該項目"
    return f"若 {cve} 進入 KEV、EPSS 跨越 0.5、公開 PoC，或本組織資產盤點命中，則升級為必辦。"


def _signals(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "kev": bool(item.get("in_kev")),
        "epss": item.get("epss"),
        "epss_delta": item.get("epss_delta"),
        "epss_percentile": item.get("epss_percentile"),
        "cvss": item.get("cvss"),
        "cvss_version": item.get("cvss_version"),
    }


def _slim(item: dict[str, Any]) -> dict[str, Any]:
    action, deadline, owner = _action(item)
    title = item.get("title") or item.get("cve_id") or "（無標題）"
    return {
        "id": item.get("id") or item.get("cve_id") or title,
        "title": title,
        "cve_id": item.get("cve_id"),
        "product": item.get("product") or "",
        "vendor": item.get("vendor") or "",
        "priority": item.get("brief_priority"),
        "dashboard_priority": item.get("priority"),
        "evidence": item.get("evidence_grade"),
        "evidence_zh": EVIDENCE_ZH.get(item.get("evidence_grade") or "", "【尚未證實】"),
        "org_related": bool(item.get("org_related")),
        "org_assets": item.get("org_assets") or [],
        "signals": _signals(item),
        "so_what": _so_what(item),
        "action": action,
        "deadline": deadline,
        "owner": owner,
        "url": item.get("url") or "",
        "source_name": item.get("source_name") or "",
        "published_at": item.get("published_at") or item.get("date_added") or item.get("fetched_at") or "",
        "section": item.get("section"),
        "status_upgrade": bool(item.get("status_upgrade")),
        "upgrade_reason": item.get("upgrade_reason") or "",
        "poc": bool(item.get("poc")),
        "trigger": _trigger(item),
        "iec62443": item.get("iec62443") or "",
    }


def _neg(value: Any) -> float:
    """Sort helper: higher score first, unscored last."""
    return -float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 1.0


def _rank_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        PRIO_RANK.get(item.get("brief_priority") or "P3", 9),
        0 if item.get("org_related") else 1,
        0 if item.get("status_upgrade") else 1,
        0 if item.get("in_kev") else 1,
        _neg(item.get("epss")),
        _neg(item.get("cvss")),
    )


def _exec_summary(must: list[dict], stats: dict[str, Any], dt: datetime) -> list[str]:
    n_p0, n_p1 = stats["p0"], stats["p1"]
    org = stats["org_hits"]
    if n_p0 == 0 and n_p1 == 0:
        return [
            f"{dt.strftime('%Y-%m-%d')} 先制式曝險態勢：過去 24–48 小時無新增 P0／P1 必辦項，攻擊鏈第一環目前無需緊急切斷。",
            f"本組織技術堆疊命中 {org} 件，皆未達必辦門檻，維持觀察與既有修補節奏即可。",
            "今日不需管理階層決策；若稍後有項目進入 KEV 或 EPSS 跨越 0.5，再升級呈報。",
        ]
    lead = must[0] if must else {}
    target = lead.get("cve_id") or lead.get("product") or lead.get("title") or "高優先項目"
    lines = [
        f"{dt.strftime('%Y-%m-%d')} 先制式曝險態勢：新增 {n_p0} 件 P0、{n_p1} 件 P1；"
        f"今日須先切斷的第一環是「{target}」。",
    ]
    if lead:
        lines.append(f"最優先動作：{lead.get('action')}（時限 {lead.get('deadline')}，負責 {lead.get('owner')}）。")
    if org:
        lines.append(f"其中 {org} 件命中本組織資產關鍵字，已升一級並標〔本組織相關〕。")
    else:
        lines.append("目前條目尚未直接命中本組織資產關鍵字，仍依 KEV／高 EPSS 節奏處理。")
    if n_p0:
        lines.append("P0 已達緊急門檻，建議管理階層確認修補窗口與產線 CAB 是否需提前召開。")
    else:
        lines.append("無 P0，管理階層無需額外決策；IT／OT／PSIRT 依時限執行即可。")
    return lines[:5]


def compose_brief(
    items: list[dict[str, Any]],
    *,
    failed_sources: list[dict[str, str]] | None = None,
    reported: ReportedState | None = None,
    now: datetime | None = None,
    config_dir: str | None = None,
) -> dict[str, Any]:
    """Classify, section, and write the 8-section brief. Does not invent CVEs or scores."""
    dt = now or _now_taipei()
    failed_sources = failed_sources or []
    classified: list[dict[str, Any]] = []
    for raw in items:
        item = classify_item(raw, config_dir=config_dir)
        prev = reported.lookup(item) if reported else None
        item = promote_if_upgrade(item, prev)
        classified.append(item)

    # Priority first, then org relevance / upgrade, then the raw signals. The
    # signal tie-break matters because every section is capped: without it, the
    # rows that survive truncation inside one priority band are whichever the
    # feeds happened to return first.
    classified.sort(key=_rank_key)

    must_src = [i for i in classified if i.get("brief_priority") in ("P0", "P1")]

    sections: dict[str, list[dict[str, Any]]] = {
        "kev_epss": [],
        "exposure": [],
        "ot_ics": [],
        "psirt": [],
        "market": [],
        "watch": [],
    }
    for i in classified:
        key = i.get("section") or "watch"
        if key not in sections:
            key = "watch"
        sections[key].append(_slim(i))

    # Section 3 is a cross-section KEV / EPSS / CVE table (unique by CVE or id).
    # The predicate matches classify.assign_section's kev_epss predicate: a row
    # scored well enough to be routed here must be renderable here. The old
    # `epss >= 0.1` form silently dropped every KEV-adjacent CVE whose EPSS was
    # low or absent — and EPSS is null on 97% of real rows.
    kev_src: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i in classified:
        if not (i.get("in_kev") or i.get("epss") is not None or i.get("cve_id")):
            continue
        uid = str(i.get("cve_id") or i.get("id") or i.get("title"))
        if uid in seen:
            continue
        seen.add(uid)
        kev_src.append(_slim(i))

    stats = {
        "p0": sum(1 for i in classified if i.get("brief_priority") == "P0"),
        "p1": sum(1 for i in classified if i.get("brief_priority") == "P1"),
        "p2": sum(1 for i in classified if i.get("brief_priority") == "P2"),
        "p3": sum(1 for i in classified if i.get("brief_priority") == "P3"),
        "org_hits": sum(1 for i in classified if i.get("org_related")),
        "total": len(classified),
        "failed_sources": failed_sources,
    }
    all_sources = _collect_sources(classified, failed_sources, dt)

    section_counts: dict[str, dict[str, int]] = {}

    def _cap(key: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cap = SECTION_CAPS[key]
        section_counts[key] = {"shown": min(len(rows), cap), "total": len(rows), "cap": cap}
        return rows[:cap]

    must = _cap("must_do", [_slim(i) for i in must_src])
    exec_lines = _exec_summary(must, stats, dt)
    payload = {
        "date": dt.strftime("%Y-%m-%d"),
        "weekday_zh": _weekday_zh(dt),
        "coverage": "前 24–48h",
        "generated_at": dt.isoformat(),
        "generated_at_utc": dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "generated_at_taipei": dt.strftime("%Y-%m-%d %H:%M TST"),
        "stats": stats,
        "exec_summary": exec_lines,
        "must_do": must,
        "kev_epss": _cap("kev_epss", kev_src),
        "exposure": _cap("exposure", sections["exposure"]),
        "ot_ics": _cap("ot_ics", sections["ot_ics"]),
        "psirt": _cap("psirt", sections["psirt"]),
        "market": _cap("market", sections["market"]),
        "watch": _cap("watch", sections["watch"]),
        "sources": _cap("sources", all_sources),
        "needs_exec_decision": stats["p0"] > 0,
    }
    payload["section_counts"] = section_counts
    # Honest coverage: how many of the classified items a reader can actually
    # reach. must_do rows are re-listed in their own section, so count uniques.
    reachable = {
        str(it.get("id"))
        for key in ("must_do", "kev_epss", "exposure", "ot_ics", "psirt", "market", "watch")
        for it in payload[key]
    }
    stats["rendered"] = len(reachable)
    stats["truncated"] = max(0, len(classified) - len(reachable))
    payload["markdown"] = render_markdown(payload)
    payload["exec_markdown"] = render_exec_markdown(payload)
    return payload


def compose_from_intel(
    intel_items: list[dict[str, Any]],
    *,
    failed_sources: list[dict[str, str]] | None = None,
    reported: ReportedState | None = None,
    now: datetime | None = None,
    config_dir: str | None = None,
) -> dict[str, Any]:
    """Adapter: dashboard intel rows → brief. Pass-through; no new CVE invented."""
    return compose_brief(
        intel_items,
        failed_sources=failed_sources,
        reported=reported,
        now=now,
        config_dir=config_dir,
    )


def _collect_sources(items: list[dict[str, Any]], failed: list[dict[str, str]], dt: datetime) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for i in items:
        url = (i.get("url") or "").strip()
        name = i.get("source_name") or "unknown"
        key = url or name
        if key in seen:
            continue
        seen.add(key)
        ts = i.get("published_at") or i.get("date_added") or i.get("fetched_at") or dt.isoformat()
        out.append(
            {
                "name": name,
                "url": url,
                "published": str(ts),
                "status": "ok",
            }
        )
    for f in failed:
        out.append(
            {
                "name": f.get("name") or f.get("id") or "unknown",
                "url": f.get("url") or "",
                "published": dt.isoformat(),
                "status": "來源今日無法存取",
                "error": f.get("error") or "",
            }
        )
    # Not truncated here — compose_brief caps it and records the true total so
    # the appendix can state 「顯示 N／共 M」.
    return out


def _md_item(it: dict[str, Any], *, action: bool = False) -> str:
    ev = it.get("evidence_zh") or ""
    up = " ⬆ 狀態升級" + (f"（{it['upgrade_reason']}）" if it.get("upgrade_reason") else "") if it.get("status_upgrade") else ""
    org = "〔本組織相關〕" if it.get("org_related") else ""
    sig = it.get("signals") or {}
    sig_txt = (
        f"KEV={'是' if sig.get('kev') else '否'}｜"
        f"EPSS={_fmt_epss(sig.get('epss'), sig.get('epss_percentile'), sig.get('epss_delta'))}｜"
        f"CVSS={_fmt_cvss(sig.get('cvss'), sig.get('cvss_version'))}"
    )
    src = it.get("source_name") or ""
    url = it.get("url") or ""
    cite = f"{src} {url}".strip()
    lines = [
        f"- {ev}{org}{up} **{it.get('cve_id') or it.get('title')}**（{it.get('priority')}）",
        f"  - 產品：{it.get('vendor') or '—'} {it.get('product') or ''}".rstrip(),
        f"  - 訊號：{sig_txt}",
        f"  - So what：{it.get('so_what')}",
    ]
    if action:
        lines.append(f"  - 建議動作：{it.get('action')}")
        lines.append(f"  - 時限：{it.get('deadline')}｜負責：{it.get('owner')}")
    if it.get("section") == "watch":
        lines.append(f"  - 升級觸發：{it.get('trigger')}")
    if cite:
        lines.append(f"  - 來源：{cite}")
    return "\n".join(lines)


def _count_note(p: dict[str, Any], key: str, shown: int) -> str:
    """「顯示 N／共 M 件」 for one section.

    ``shown`` is what this renderer actually prints, ``total`` is how many rows
    the classifier put in the section before SECTION_CAPS and MD_LIMITS trimmed
    it. Truncating without saying so reads as 「今天只有這幾件」.
    """
    counts = (p.get("section_counts") or {}).get(key) or {}
    total = int(counts.get("total", shown))
    if total > shown:
        return f"（顯示 {shown}／共 {total} 件；完整清單見儀表板或 JSON 輸出）"
    return f"（共 {total} 件）"


def render_markdown(p: dict[str, Any]) -> str:
    date = p["date"]
    stats = p.get("stats") or {}
    parts = [
        "# 先制式資安日報 Preemptive Cybersecurity Daily Brief",
        f"日期：{date}（{p['weekday_zh']}）｜資料涵蓋：{p['coverage']}｜產出：全球資安管理處 情報分析代理",
        f"產出時間：{p.get('generated_at_utc')} ／ {p.get('generated_at_taipei')}",
        "證據標記：【已證實】【第三方評論】【尚未證實】｜⬆＝既有項目狀態升級",
        f"本日分類 {stats.get('total', 0)} 件，其中 {stats.get('rendered', 0)} 件列入本報告"
        + (
            f"；{stats.get('truncated', 0)} 件因版面上限未列出（各分區標題已註明「顯示 N／共 M」）。"
            if stats.get("truncated")
            else "。"
        ),
        "",
        "## 一、管理階層摘要（3–5 句）",
        *[line if line.endswith("。") else line + "。" for line in p["exec_summary"]],
        "",
        "## 二、今日必辦 Top 3（P0/P1 行動項）"
        + _count_note(p, "must_do", len(p["must_do"])),
    ]
    if p["must_do"]:
        for i, it in enumerate(p["must_do"], 1):
            parts.append(f"### 必辦 {i}")
            parts.append(_md_item(it, action=True))
            parts.append("")
    else:
        parts.append(EMPTY_ZH)
        parts.append("")

    kev_rows = (p.get("kev_epss") or [])[: MD_LIMITS["kev_epss"]]
    parts += [
        f"## {SECTION_TITLES['kev_epss']}" + _count_note(p, "kev_epss", len(kev_rows)),
        "",
    ]
    if kev_rows:
        parts.append("| CVE | 產品 | CVSS | EPSS | KEV | PoC/利用 | 本組織相關 | 來源 |")
        parts.append("|---|---|---|---|---|---|---|---|")
        for it in kev_rows:
            sig = it.get("signals") or {}
            parts.append(
                "| {cve} | {prod} | {cvss} | {epss} | {kev} | {poc} | {org} | {src} |".format(
                    cve=it.get("cve_id") or "—",
                    prod=(f"{it.get('vendor','')} {it.get('product','')}").strip() or "—",
                    cvss=_fmt_cvss(sig.get("cvss"), sig.get("cvss_version")),
                    epss=_fmt_epss(sig.get("epss"), sig.get("epss_percentile"), sig.get("epss_delta")),
                    kev="是" if sig.get("kev") else "否",
                    poc="有" if it.get("poc") else "未公開／未知",
                    org="是" if it.get("org_related") else "否",
                    src=it.get("source_name") or "—",
                )
            )
        parts.append("")
    else:
        parts.append(EMPTY_ZH)
        parts.append("")

    def _sec(key: str, extra: str = "") -> None:
        rows = (p.get(key) or [])[: MD_LIMITS[key]]
        parts.append(f"## {SECTION_TITLES[key]}" + _count_note(p, key, len(rows)))
        if extra:
            parts.append(extra)
        if not rows:
            parts.append(EMPTY_ZH)
        else:
            for it in rows:
                parts.append(_md_item(it, action=key in ("ot_ics", "psirt", "exposure")))
        parts.append("")

    _sec("exposure")
    _sec(
        "ot_ics",
        extra="原則：OT 只做被動探索與受控窗口驗證；任何緩解建議須經 OT 工程與變更管制（CAB）。",
    )
    _sec("psirt")
    _sec("market", extra="此區多為【第三方評論】，不得重製付費報告內文。")
    _sec("watch")

    parts += [
        "## 附錄：今日全部來源清單（URL＋時間戳）"
        + _count_note(p, "sources", len(p.get("sources") or [])),
        "",
    ]
    if p.get("sources"):
        for s in p["sources"]:
            st = s.get("status") or "ok"
            ts = s.get("published") or ""
            url = s.get("url") or ""
            err = f" — {s['error']}" if s.get("error") else ""
            parts.append(f"- {s.get('name')}｜{st}｜{ts}｜{url}{err}")
    else:
        parts.append(EMPTY_ZH)
    parts.append("")
    return "\n".join(parts).strip() + "\n"


def render_exec_markdown(p: dict[str, Any]) -> str:
    """One-page executive edition: sections 1–2 only."""
    parts = [
        "# 先制式資安日報（主管版）",
        f"日期：{p['date']}（{p['weekday_zh']}）｜涵蓋：{p['coverage']}",
        "",
        "## 一、管理階層摘要",
        *p["exec_summary"],
        "",
        "## 二、今日必辦 Top 3" + _count_note(p, "must_do", len(p["must_do"])),
    ]
    if p["must_do"]:
        for i, it in enumerate(p["must_do"], 1):
            parts.append(f"### 必辦 {i}")
            parts.append(_md_item(it, action=True))
            parts.append("")
    else:
        parts.append(EMPTY_ZH)
    return "\n".join(parts).strip() + "\n"
