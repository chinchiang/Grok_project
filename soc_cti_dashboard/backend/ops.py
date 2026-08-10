"""Operational enrichment: SOP playbooks, owners, SLA, priority rationale."""

from __future__ import annotations

from typing import Any

# SOP T-01 ~ T-08 初動處置建議
SOP_CATALOG: dict[str, dict[str, str]] = {
    "T-01": {
        "zh": "T-01 KEV 緊急修補：資產盤點 → 套用修補／緩解 → 驗證",
        "en": "T-01 KEV emergency patch: inventory → patch/mitigate → verify",
        "owner": "Vuln Mgmt",
        "sla_hours": 24,
    },
    "T-02": {
        "zh": "T-02 勒索應變：隔離主機 → 保全日誌 → 啟動 IR 戰情",
        "en": "T-02 Ransomware IR: isolate → preserve logs → stand up war-room",
        "owner": "IR Lead",
        "sla_hours": 4,
    },
    "T-03": {
        "zh": "T-03 台灣產業受駭：確認供應鏈曝險 → 通報 SOC/BU → 強化監控",
        "en": "T-03 TW industry hit: supply-chain check → notify SOC/BU → heighten monitoring",
        "owner": "SOC L2",
        "sla_hours": 8,
    },
    "T-04": {
        "zh": "T-04 OT/ICS：協調 OT 維運 → 分段隔離 → 變更窗口修補",
        "en": "T-04 OT/ICS: coordinate OT ops → segment → patch in change window",
        "owner": "OT Security",
        "sla_hours": 48,
    },
    "T-05": {
        "zh": "T-05 外洩／憑證：強制重設 → MFA 稽核 → 暗網監控追蹤",
        "en": "T-05 Breach/creds: force reset → MFA audit → dark-web watch",
        "owner": "IAM / SOC",
        "sla_hours": 12,
    },
    "T-06": {
        "zh": "T-06 微軟生態：WSUS/Intune 推送 → Defender 全掃 → 身分防護",
        "en": "T-06 Microsoft estate: WSUS/Intune → Defender full scan → identity hardening",
        "owner": "Endpoint / Cloud Sec",
        "sla_hours": 48,
    },
    "T-07": {
        "zh": "T-07 未核實暗網：雙源複核佇列 → 不得單獨開立工單",
        "en": "T-07 Unverified dark-web: dual-source review queue — no ticket alone",
        "owner": "CTI Analyst",
        "sla_hours": 72,
    },
    "T-08": {
        "zh": "T-08 一般監控：EPSS/多源追蹤 → 週期複評優先級",
        "en": "T-08 Monitor: track EPSS/multi-source → periodic re-priority",
        "owner": "CTI Analyst",
        "sla_hours": 168,
    },
}


def pick_sop(
    *,
    priority: str,
    in_kev: bool = False,
    is_ransomware: bool = False,
    is_tw_industry: bool = False,
    is_microsoft: bool = False,
    is_ot: bool = False,
    is_breach: bool = False,
    verification: str = "unverified",
    is_darkweb: bool = False,
) -> dict[str, Any]:
    if is_darkweb and verification == "unverified":
        sid = "T-07"
    elif is_ransomware and priority in ("P0", "P1"):
        sid = "T-02"
    elif is_tw_industry and (is_ransomware or in_kev):
        sid = "T-03"
    elif in_kev or priority == "P1":
        sid = "T-01"
    elif is_ot:
        sid = "T-04"
    elif is_breach:
        sid = "T-05"
    elif is_microsoft:
        sid = "T-06"
    elif priority in ("P0", "P1"):
        sid = "T-01"
    else:
        sid = "T-08"
    cat = SOP_CATALOG[sid]
    return {
        "sop_id": sid,
        "sop_zh": cat["zh"],
        "sop_en": cat["en"],
        "owner": cat["owner"],
        "sla_hours": cat["sla_hours"],
    }


def explain_priority(
    *,
    priority: str,
    in_kev: bool = False,
    known_ransomware_campaign: bool = False,
    is_ransomware: bool = False,
    is_tw_industry: bool = False,
    epss: float | None = None,
    source_count: int = 1,
    dual_verified: bool = False,
    forced_p3_review: bool = False,
    verification: str = "unverified",
) -> tuple[str, str]:
    """Return (rationale_zh, rationale_en) for card display 判定依據."""
    if forced_p3_review:
        return (
            "判定依據：單一來源未核實（X OSINT／暗網間接／洩漏站）→ 強制 P3 人工複核佇列；"
            "即使命中台灣監控名單＋勒索關鍵字亦不得單獨升 P0",
            "Rationale: single-source Unverified (X OSINT / dark-web / leak-site) → "
            "forced P3 human review; TW watchlist + ransomware keywords alone cannot auto-P0",
        )
    if priority == "P0":
        if in_kev and known_ransomware_campaign:
            return (
                "判定依據：CISA KEV 且 knownRansomwareCampaignUse=Known（一票升級 P0）",
                "Rationale: CISA KEV + known ransomware campaign use (auto P0)",
            )
        if is_tw_industry and is_ransomware:
            return (
                "判定依據：台灣電子／半導體監控名單命中 + 勒索相關，且核實狀態為已證實／可信 → P0",
                "Rationale: TW electronics/semi watchlist hit + ransomware AND verification confirmed/credible → P0",
            )
        if is_tw_industry and in_kev:
            return (
                "判定依據：台灣產業監控名單 + KEV 在野利用 → P0",
                "Rationale: TW industry watchlist + KEV in-the-wild → P0",
            )
        return ("判定依據：P0 規則命中", "Rationale: P0 rule matched")
    if priority == "P1":
        return (
            "判定依據：列入 CISA KEV（已證實在野利用）且未達 P0 → 固定 P1，不混入其他級",
            "Rationale: In CISA KEV (confirmed ITW) and not P0 → exclusive P1",
        )
    if priority == "P2":
        if epss is not None and epss >= 0.5:
            return (
                f"判定依據：非 KEV，EPSS={epss:.3f} ≥ 0.5 → P2 預測利用",
                f"Rationale: not KEV, EPSS={epss:.3f} ≥ 0.5 → P2 predictive",
            )
        if dual_verified or source_count >= 2:
            return (
                "判定依據：多來源／雙源核實可信情資 → P2",
                "Rationale: multi-source / dual-verified credible intel → P2",
            )
        return ("判定依據：P2 規則命中", "Rationale: P2 rule matched")
    # P3 — surface why TW+ransomware did not elevate when verification insufficient
    if is_tw_industry and is_ransomware and verification not in ("confirmed", "credible"):
        return (
            "判定依據：台灣監控名單＋勒索關鍵字命中，但核實狀態未達已證實／可信 → 維持 P3（需雙源或官方佐證後再升 P0）",
            "Rationale: TW watchlist + ransomware keywords hit, but verification not confirmed/credible → stay P3 (need dual-source or official corroboration for P0)",
        )
    return (
        "判定依據：未達 P0–P2 → P3 監控／人工複核",
        "Rationale: below P0–P2 thresholds → P3 monitor/review",
    )


def guess_assets(item_flags: dict[str, Any], vendor: str = "", product: str = "") -> list[str]:
    assets: list[str] = []
    if item_flags.get("is_microsoft") or (vendor or "").lower().startswith("microsoft"):
        assets.append("Windows / M365 / Entra estate")
    if item_flags.get("is_tw_industry"):
        for e in item_flags.get("tw_entities") or []:
            assets.append(f"TW watch: {e.get('key')}")
    if item_flags.get("is_finance"):
        assets.append("Finance / payment systems")
    if product:
        assets.append(f"Product: {product[:80]}")
    if vendor and not assets:
        assets.append(f"Vendor: {vendor[:80]}")
    if not assets:
        assets.append("Enterprise perimeter / endpoints (generic)")
    return assets[:6]
