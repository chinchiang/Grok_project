"""L4 — external attack surface via Shodan InternetDB/API and Censys."""

from __future__ import annotations

import json
import re
import time
from typing import Any
import httpx
from ..config import (
    CENSYS_API_ID,
    CENSYS_API_SECRET,
    CENSYS_HOST_API,
    EASM_MAX_TARGETS,
    EASM_WATCH_HOSTS,
    EASM_WATCH_IPS,
    SHODAN_API_HOST,
    SHODAN_API_KEY,
    SHODAN_INTERNETDB_URL,
    USER_AGENT,
    HTTP_TIMEOUT,
)
from ..database import now_iso, upsert_intel, upsert_source_health
from ..priority import assign_priority, assign_verification, enrich_flags

from ._base import _client, _id, _mark


def _resolve_easm_targets() -> list[str]:
    """Merge configured IPs + DNS-resolved hostnames (unique, capped)."""
    import socket

    targets: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        ip = (ip or "").strip()
        if not ip or ip in seen:
            return
        # basic IPv4/IPv6 sanity
        if re.match(r"^[\d.:a-fA-F]+$", ip) is None:
            return
        seen.add(ip)
        targets.append(ip)

    for ip in EASM_WATCH_IPS:
        add(ip)

    for host in EASM_WATCH_HOSTS:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                add(info[4][0])
        except Exception:
            continue

    return targets[:EASM_MAX_TARGETS]

async def _upsert_easm_finding(
    *,
    source_id: str,
    source_name: str,
    ip: str,
    ports: list[Any],
    hostnames: list[str],
    vulns: list[str],
    cpes: list[str],
    tags: list[str],
    extra_summary: str = "",
    url: str = "",
) -> None:
    ports_s = ", ".join(str(p) for p in ports[:40]) if ports else "—"
    host_s = ", ".join(hostnames[:12]) if hostnames else "—"
    vuln_s = ", ".join(vulns[:20]) if vulns else "—"
    cpe_s = ", ".join(cpes[:12]) if cpes else "—"
    tag_s = ", ".join(tags[:12]) if tags else "—"

    title_zh = f"[EASM] {ip} 對外暴露端口 {len(ports) if ports else 0}"
    if vulns:
        title_zh = f"[EASM] {ip} 暴露且關聯 {len(vulns)} 個 CVE"
    title_en = title_zh

    summary_zh = (
        f"IP：{ip}\n主機名：{host_s}\n端口：{ports_s}\n"
        f"CVE/漏洞：{vuln_s}\nCPE：{cpe_s}\n標籤：{tag_s}\n"
        f"{extra_summary}"
    )
    summary_en = (
        f"IP: {ip}\nHostnames: {host_s}\nPorts: {ports_s}\n"
        f"Vulns: {vuln_s}\nCPEs: {cpe_s}\nTags: {tag_s}\n"
        f"{extra_summary}"
    )

    flags = enrich_flags(title_zh, summary_en, " ".join(hostnames), " ".join(cpes))
    cve_id = None
    if vulns:
        m = re.findall(r"CVE-\d{4}-\d{4,7}", " ".join(vulns), re.I)
        cve_id = m[0].upper() if m else None

    verification, admiralty = assign_verification(
        in_kev=False,
        layer_id="L4",
        source_count=1,
        is_darkweb_indirect=False,
    )
    priority = assign_priority(
        in_kev=False,
        known_ransomware_campaign=False,
        is_ransomware=flags["is_ransomware"],
        is_tw_industry=flags["is_tw_industry"],
        epss=None,
        source_count=1,
        layer_id="L4",
        verification=verification,
    )
    # Open risky ports or known vulns → at least P2
    risky_ports = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
    open_set = {int(p) for p in ports if str(p).isdigit()}
    if vulns or (open_set & risky_ports):
        if priority == "P3":
            priority = "P2"

    await upsert_intel(
        {
            "id": _id("easm", source_id, ip, ",".join(str(p) for p in (ports or [])[:8])),
            "title": title_zh,
            "title_en": title_en,
            "summary": summary_zh,
            "summary_en": summary_en,
            "priority": priority,
            "verification": verification,
            "layer_id": "L4",
            "source_name": source_name,
            "sources_json": json.dumps([source_name]),
            "cve_id": cve_id,
            "product": host_s if host_s != "—" else ip,
            "vendor": "EASM",
            "is_ransomware": 1 if flags["is_ransomware"] else 0,
            "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
            "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
            "is_finance": 1 if flags["is_finance"] else 0,
            "finance_entities_json": json.dumps(
                flags["finance_entities"], ensure_ascii=False
            ),
            "is_microsoft": 1 if flags["is_microsoft"] else 0,
            "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
            "known_ransomware_campaign": 0,
            "epss": None,
            "cvss": None,
            "date_added": now_iso()[:10],
            "published_at": now_iso()[:10],
            "fetched_at": now_iso(),
            "url": url or f"https://www.shodan.io/host/{ip}",
            "admiralty": admiralty,
            "raw_json": json.dumps(
                {
                    "ip": ip,
                    "ports": ports[:50] if ports else [],
                    "vulns": vulns[:30] if vulns else [],
                    "hostnames": hostnames[:20] if hostnames else [],
                },
                ensure_ascii=False,
            )[:4000],
            "tags_json": json.dumps(
                ["easm", "attack-surface"]
                + (["has-vulns"] if vulns else [])
                + (["tw-industry"] if flags["is_tw_industry"] else [])
            ),
        }
    )

async def collect_shodan_easm() -> int:
    """
    L4 Shodan:
      1) Free InternetDB (no key) for EASM_WATCH_IPS / resolved EASM_WATCH_HOSTS
      2) Optional SHODAN_API_KEY for deeper host enrichment
    """
    t0 = time.perf_counter()
    targets = _resolve_easm_targets()
    count = 0

    if not targets and not SHODAN_API_KEY:
        await upsert_source_health(
            {
                "source_id": "shodan",
                "layer_id": "L4",
                "name": "Shodan InternetDB / API",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "免金鑰可用 InternetDB：設定 EASM_WATCH_IPS=x.x.x.x "
                    "或 EASM_WATCH_HOSTS=edge.example.com；"
                    "進階可設 SHODAN_API_KEY"
                ),
            }
        )
        return 0

    try:
        async with await _client() as client:
            # Prefer InternetDB for each target (free)
            for ip in targets:
                try:
                    r = await client.get(
                        f"{SHODAN_INTERNETDB_URL}/{ip}",
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                    )
                    if r.status_code == 404:
                        # no data in InternetDB
                        continue
                    r.raise_for_status()
                    data = r.json()
                    ports = data.get("ports") or []
                    hostnames = data.get("hostnames") or []
                    vulns = data.get("vulns") or []
                    cpes = data.get("cpes") or []
                    tags = data.get("tags") or []
                    if not ports and not vulns and not hostnames:
                        continue
                    await _upsert_easm_finding(
                        source_id="shodan-idb",
                        source_name="Shodan InternetDB",
                        ip=ip,
                        ports=ports,
                        hostnames=hostnames,
                        vulns=vulns,
                        cpes=cpes,
                        tags=tags,
                        extra_summary="來源：Shodan InternetDB（免 API 金鑰）\n",
                        url=f"https://www.shodan.io/host/{ip}",
                    )
                    count += 1
                except Exception:
                    continue

                # Optional API enrichment
                if SHODAN_API_KEY:
                    try:
                        hr = await client.get(
                            f"{SHODAN_API_HOST}/{ip}",
                            params={"key": SHODAN_API_KEY},
                            headers={"User-Agent": USER_AGENT},
                        )
                        if hr.status_code == 200:
                            h = hr.json()
                            ports2 = h.get("ports") or ports
                            hostnames2 = h.get("hostnames") or hostnames
                            vulns2 = list(h.get("vulns") or vulns or [])
                            await _upsert_easm_finding(
                                source_id="shodan-api",
                                source_name="Shodan API",
                                ip=ip,
                                ports=ports2,
                                hostnames=hostnames2,
                                vulns=vulns2,
                                cpes=cpes,
                                tags=tags,
                                extra_summary=(
                                    f"org={h.get('org') or '—'}; "
                                    f"isp={h.get('isp') or '—'}; "
                                    f"os={h.get('os') or '—'}\n"
                                    "來源：Shodan Host API\n"
                                ),
                                url=f"https://www.shodan.io/host/{ip}",
                            )
                            count += 1
                    except Exception:
                        pass

        ms = int((time.perf_counter() - t0) * 1000)
        mode = []
        mode.append("internetdb")
        if SHODAN_API_KEY:
            mode.append("api-key")
        await _mark(
            "shodan",
            "L4",
            "Shodan InternetDB / API",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"targets={len(targets)}; modes={'+'.join(mode)}; findings={count}"
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "shodan",
            "L4",
            "Shodan InternetDB / API",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0

async def collect_censys_easm() -> int:
    """
    L4 Censys host lookup for watch IPs.
    Requires CENSYS_API_ID + CENSYS_API_SECRET (free tier host lookup supported).
    """
    t0 = time.perf_counter()
    targets = _resolve_easm_targets()

    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        await upsert_source_health(
            {
                "source_id": "censys",
                "layer_id": "L4",
                "name": "Censys host lookup",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "需 CENSYS_API_ID + CENSYS_API_SECRET（免費帳號可申請），"
                    "並設定 EASM_WATCH_IPS 或 EASM_WATCH_HOSTS"
                ),
            }
        )
        return 0

    if not targets:
        await upsert_source_health(
            {
                "source_id": "censys",
                "layer_id": "L4",
                "name": "Censys host lookup",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "金鑰已設定，但未設定監控目標："
                    "EASM_WATCH_IPS / EASM_WATCH_HOSTS"
                ),
            }
        )
        return 0

    count = 0
    try:
        auth = (CENSYS_API_ID, CENSYS_API_SECRET)
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            for ip in targets:
                try:
                    r = await client.get(f"{CENSYS_HOST_API}/{ip}", auth=auth)
                    if r.status_code in (404, 422):
                        continue
                    if r.status_code == 401:
                        raise RuntimeError("Censys auth failed (check API ID/Secret)")
                    r.raise_for_status()
                    body = r.json()
                    result = body.get("result") or body
                    services = result.get("services") or []
                    ports = []
                    for s in services:
                        p = s.get("port")
                        if p is not None:
                            ports.append(p)
                    dns = result.get("dns") or {}
                    hostnames = []
                    if isinstance(dns, dict):
                        names = dns.get("names") or dns.get("reverse_dns") or []
                        if isinstance(names, dict):
                            hostnames = list(names.keys())[:20]
                        elif isinstance(names, list):
                            hostnames = [str(n) for n in names[:20]]
                    # Censys v2 may put names at top-level
                    for n in result.get("name") and [result.get("name")] or []:
                        if n and n not in hostnames:
                            hostnames.append(n)

                    vulns: list[str] = []
                    for s in services:
                        for v in s.get("vulns") or []:
                            if isinstance(v, str):
                                vulns.append(v)
                            elif isinstance(v, dict) and v.get("id"):
                                vulns.append(str(v["id"]))

                    await _upsert_easm_finding(
                        source_id="censys",
                        source_name="Censys",
                        ip=ip,
                        ports=ports,
                        hostnames=hostnames,
                        vulns=vulns,
                        cpes=[],
                        tags=[],
                        extra_summary=(
                            f"services={len(services)}; "
                            f"autonomous_system="
                            f"{(result.get('autonomous_system') or {}).get('name') or '—'}\n"
                            "來源：Censys Host API\n"
                        ),
                        url=f"https://search.censys.io/hosts/{ip}",
                    )
                    count += 1
                except Exception:
                    continue

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "censys",
            "L4",
            "Censys host lookup",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"targets={len(targets)}; findings={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "censys",
            "L4",
            "Censys host lookup",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0
