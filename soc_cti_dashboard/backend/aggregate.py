"""Cross-source event aggregation (2.5).

Every collector wrote its items with ``source_count=1``, because each one only
knows about its own feed. The "multi-source credible" and "≥2 independent
sources" rules therefore almost never fired outside the two purpose-built
dual-source passes: five outlets reporting one breach stayed five separate
single-source P3s.

This pass runs after ingestion and looks across the whole recent window. It
deliberately does **not** merge records — analysts want to open each outlet's
article — it records that an item is corroborated, then re-derives verification
and priority from the corrected evidence count.

Corroboration requires all of:

* a shared event key — the same CVE, or titles similar enough by token overlap;
* a genuinely different source name; and
* a different link domain, so two Google News mirrors of one article (or a feed
  and its own fallback mirror) cannot corroborate each other.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

from .database import apply_aggregation, items_for_aggregation
from .ops import explain_priority
from .priority import assign_priority, assign_verification

# Similarity required between two titles before they count as the same event.
TITLE_JACCARD_MIN = 0.55
# Candidate pairs must share at least this many distinctive tokens.
BLOCKING_MIN_SHARED = 2
MIN_TOKENS = 4

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CJK_RE = re.compile(r"[㐀-鿿]")

# Classification prefixes and source badges the UI adds to titles; they would
# otherwise make unrelated items look similar.
_TITLE_NOISE = re.compile(
    r"^(?:[🇹🇼💰🪟🔐📰🔬📚🚨🏥🛡️⚙️🌑]+\s*)+|"
    r"^\[(?:KEV|即時\s*LIVE|LIVE|未核實)\]\s*|"
    r"(?:金融相關|微軟相關|勒索受害|勒索受駭)｜",
)

_STOPWORDS = frozenset(
    """
    the a an and or of for to in on at by with from into over after new news
    report reports reported say says said via amid as is are was were be been
    this that these those its it their his her they them we you your our
    security cyber cybersecurity attack attacks hack hacked hacker hackers
    vulnerability vulnerabilities flaw flaws bug bugs issue issues update
    updates patch patched fix fixes fixed release released advisory advisories
    warns warning warned alert alerts data
    """.split()
)


def _clean_title(title: str) -> str:
    t = _TITLE_NOISE.sub(" ", title or "")
    t = re.sub(r"https?://\S+", " ", t)
    return t


def title_tokens(title: str) -> set[str]:
    """Distinctive tokens of a headline.

    Generic security vocabulary is dropped — otherwise every advisory looks
    like every other advisory. CJK headlines have no spaces, so they are cut
    into bigrams instead.
    """
    text = _clean_title(title).lower()
    tokens = {t for t in re.findall(r"[a-z0-9][a-z0-9\-.]{3,}", text) if t not in _STOPWORDS}
    cjk = "".join(_CJK_RE.findall(text))
    tokens |= {cjk[i : i + 2] for i in range(len(cjk) - 1)}
    return tokens


def event_cves(item: dict[str, Any]) -> set[str]:
    found = set()
    if item.get("cve_id"):
        found.add(str(item["cve_id"]).upper())
    for field in ("title", "title_en", "summary"):
        found.update(m.upper() for m in _CVE_RE.findall(str(item.get(field) or "")))
    return found


def link_domain(url: str) -> str:
    s = (url or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s).split("/")[0]
    s = re.sub(r"^www\d?\.", "", s)
    # Google News proxies the real publisher; treat all of them as one domain so
    # a site feed and its own GNews mirror never corroborate each other.
    return s


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _independent(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Two items corroborate only if they are really separate reports."""
    if a.get("id") == b.get("id"):
        return False
    sa = (a.get("source_name") or "").strip().lower()
    sb = (b.get("source_name") or "").strip().lower()
    if not sa or not sb or sa == sb:
        return False
    da, db_ = link_domain(a.get("url") or ""), link_domain(b.get("url") or "")
    if da and db_ and da == db_:
        return False
    return True


def find_corroborations(items: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map item id → set of ids that independently report the same event."""
    by_cve: dict[str, list[dict]] = defaultdict(list)
    by_token: dict[str, list[dict]] = defaultdict(list)
    tokens: dict[str, set[str]] = {}

    for item in items:
        iid = item.get("id")
        if not iid:
            continue
        for cve in event_cves(item):
            by_cve[cve].append(item)
        tok = title_tokens(
            f"{item.get('title') or ''} {item.get('title_en') or ''}"
        )
        tokens[iid] = tok
        if len(tok) >= MIN_TOKENS:
            for t in tok:
                by_token[t].append(item)

    linked: dict[str, set[str]] = defaultdict(set)

    # Same CVE — the strongest and cheapest signal.
    for group in by_cve.values():
        if len(group) < 2:
            continue
        for a in group:
            for b in group:
                if _independent(a, b):
                    linked[a["id"]].add(b["id"])

    # Similar headlines, blocked on shared distinctive tokens.
    for item in items:
        iid = item.get("id")
        if not iid or len(tokens.get(iid, ())) < MIN_TOKENS:
            continue
        shared_counts: dict[str, int] = defaultdict(int)
        for t in tokens[iid]:
            for other in by_token.get(t, ()):
                oid = other.get("id")
                if oid and oid != iid:
                    shared_counts[oid] += 1
        for oid, shared in shared_counts.items():
            if shared < BLOCKING_MIN_SHARED or oid in linked[iid]:
                continue
            other = next((x for x in items if x.get("id") == oid), None)
            if other is None or not _independent(item, other):
                continue
            if _jaccard(tokens[iid], tokens[oid]) >= TITLE_JACCARD_MIN:
                linked[iid].add(oid)

    return {k: v for k, v in linked.items() if v}


def _source_names(items: Iterable[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for it in items:
        name = (it.get("source_name") or "").strip()
        if name and name not in seen:
            seen.append(name)
    return seen


async def aggregate_cross_source_events(
    *, window_days: int = 14, limit: int = 1200
) -> dict[str, Any]:
    """Re-score recent items that turn out to be independently corroborated."""
    items = await items_for_aggregation(days=window_days, limit=limit)
    by_id = {i["id"]: i for i in items if i.get("id")}
    linked = find_corroborations(items)

    upgraded = 0
    priority_changes: dict[str, int] = defaultdict(int)

    for iid, partners in linked.items():
        item = by_id.get(iid)
        if not item:
            continue
        partner_items = [by_id[p] for p in partners if p in by_id]
        if not partner_items:
            continue

        sources = _source_names([item, *partner_items])
        source_count = len(sources)
        if source_count < 2:
            continue

        layer_id = item.get("layer_id") or "L6"
        in_kev = "kev" in (item.get("source_name") or "").lower()
        is_darkweb = "darkweb-indirect" in (item.get("tags") or [])

        verification, admiralty = assign_verification(
            in_kev=in_kev,
            layer_id=layer_id,
            source_count=source_count,
            is_darkweb_indirect=is_darkweb,
        )
        priority = assign_priority(
            in_kev=in_kev,
            known_ransomware_campaign=bool(item.get("known_ransomware_campaign")),
            is_ransomware=bool(item.get("is_ransomware")),
            is_tw_industry=bool(item.get("is_tw_industry")),
            epss=item.get("epss"),
            source_count=source_count,
            layer_id=layer_id,
            # Corroboration is exactly the condition that lifts the single-source
            # review hold, so force_p3_review is not re-applied here.
            verification=verification,
        )

        old_priority = item.get("priority")
        old_verification = item.get("verification")
        if (
            priority == old_priority
            and verification == old_verification
            and len(item.get("sources") or []) == source_count
        ):
            continue

        rz, re_ = explain_priority(
            priority=priority,
            in_kev=in_kev,
            is_ransomware=bool(item.get("is_ransomware")),
            is_tw_industry=bool(item.get("is_tw_industry")),
            epss=item.get("epss"),
            source_count=source_count,
            dual_verified=source_count >= 2,
            verification=verification,
        )
        others = ", ".join(s for s in sources if s != item.get("source_name"))
        rz = f"{rz}；跨來源佐證：{source_count} 個獨立來源（{others}）"
        re_ = f"{re_}; cross-source corroboration: {source_count} independent sources ({others})"

        await apply_aggregation(
            iid,
            sources=sources,
            priority=priority,
            verification=verification,
            admiralty=admiralty,
            rationale_zh=rz,
            rationale_en=re_,
            corroborated_by=[s for s in sources if s != item.get("source_name")],
        )
        upgraded += 1
        if priority != old_priority:
            priority_changes[f"{old_priority}->{priority}"] += 1

    return {
        "ok": True,
        "window_days": window_days,
        "examined": len(items),
        "clustered": len(linked),
        "rescored": upgraded,
        "priority_changes": dict(priority_changes),
    }
