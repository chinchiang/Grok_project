"""Multi-layer OSINT collectors with health reporting.

Split from a single 3.8k-line module into one file per source family.
Every name the old module exposed is re-exported here, so
``from .collectors import run_full_harvest`` and the tests' imports of
the private victim-matching helpers keep working unchanged.
"""

from __future__ import annotations

from ._base import _id, _client, _mark, _strip_html, _parse_rss_entries
from .rss import collect_rss_layer, collect_registered_intel_feeds
from .kev import collect_cisa_kev, _fetch_epss_batch, collect_epss_top_scores
from .ics import collect_cisa_ics, _collect_cisa_ics_from_github_csv
from .easm import _resolve_easm_targets, _upsert_easm_finding, collect_shodan_easm, collect_censys_easm
from .breaches import collect_hibp_breaches
from .iocs import collect_threatfox, collect_otx_pulses
from .ransom import _LEGAL_SUFFIXES, _victim_domain, _victim_name_key, _group_key, _victim_day, _ransom_match, _upsert_ransom_victim_item, collect_ransomware_live, collect_ransomlook, dual_source_ransom_trackers
from .osint import collect_x_osint_accounts, collect_x_darkweb_accounts, dual_source_darkweb_verify
from .harvest import run_full_harvest

__all__ = [
    "_id",
    "_client",
    "_mark",
    "_strip_html",
    "_parse_rss_entries",
    "collect_rss_layer",
    "collect_registered_intel_feeds",
    "collect_cisa_kev",
    "_fetch_epss_batch",
    "collect_epss_top_scores",
    "collect_cisa_ics",
    "_collect_cisa_ics_from_github_csv",
    "_resolve_easm_targets",
    "_upsert_easm_finding",
    "collect_shodan_easm",
    "collect_censys_easm",
    "collect_hibp_breaches",
    "collect_threatfox",
    "collect_otx_pulses",
    "_LEGAL_SUFFIXES",
    "_victim_domain",
    "_victim_name_key",
    "_group_key",
    "_victim_day",
    "_ransom_match",
    "_upsert_ransom_victim_item",
    "collect_ransomware_live",
    "collect_ransomlook",
    "dual_source_ransom_trackers",
    "collect_x_osint_accounts",
    "collect_x_darkweb_accounts",
    "dual_source_darkweb_verify",
    "run_full_harvest",
]
