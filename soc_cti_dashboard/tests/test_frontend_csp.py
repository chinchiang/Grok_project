"""The document-delivered CSP has to keep matching the code it governs.

The dashboard is served two ways — FastAPI locally and GitHub Pages publicly —
and Pages cannot set response headers, so the policy lives in a <meta> in
index.html. That makes it a static asset that silently drifts: nothing at
runtime complains when app.js gains a feed the policy does not allow (the live
scan just reports the source as unreachable), and nothing complains when a
style="..." attribute creeps back in and quietly needs 'unsafe-inline'.

Both directions are pinned here.
"""

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")
APP_JS = (FRONTEND / "app.js").read_text(encoding="utf-8")

CSP_META = re.compile(
    r"""<meta\s+http-equiv=["']Content-Security-Policy["']\s+content=["'](.*?)["']\s*/?>""",
    re.IGNORECASE | re.DOTALL,
)


def _policy() -> dict[str, list[str]]:
    m = CSP_META.search(INDEX)
    assert m, "index.html must carry a Content-Security-Policy <meta>"
    out: dict[str, list[str]] = {}
    for directive in m.group(1).split(";"):
        parts = directive.split()
        if parts:
            out[parts[0].lower()] = parts[1:]
    return out


def test_policy_is_present_and_parses():
    policy = _policy()
    assert policy["default-src"] == ["'none'"], "start from deny-all"
    for directive in ("script-src", "style-src", "img-src", "font-src", "connect-src"):
        assert directive in policy, f"{directive} must be stated, not inherited"


def test_policy_precedes_every_subresource():
    """A meta policy only governs what is fetched after it is parsed."""
    csp_at = INDEX.lower().index("http-equiv")
    for tag in ("<link", "<script", "<img"):
        first = INDEX.lower().find(tag)
        if first != -1:
            assert csp_at < first, f"{tag} appears before the CSP meta"


@pytest.mark.parametrize("directive", ["script-src", "style-src", "default-src"])
def test_no_unsafe_escape_hatches(directive):
    """app.js builds cards with innerHTML from feed text. 'unsafe-inline' would
    turn any escapeHtml() gap into script execution or a full restyle."""
    values = _policy().get(directive, [])
    assert "'unsafe-inline'" not in values
    assert "'unsafe-eval'" not in values
    assert not any(v == "*" or v.startswith("*.") for v in values), values


def test_script_src_is_exactly_self():
    assert _policy()["script-src"] == ["'self'"]


def test_no_wildcard_on_any_directive():
    for name, values in _policy().items():
        assert "*" not in values, name
        assert not any(v.startswith("*.") for v in values), name


def test_injection_sinks_are_closed():
    policy = _policy()
    assert policy.get("object-src") == ["'none'"]
    assert policy.get("base-uri") == ["'none'"], "a stray <base> would repoint every relative fetch"
    assert policy.get("form-action") == ["'none'"], "the UI has no forms; keep exfil via <form> shut"


def test_inline_styles_are_gone_from_the_document_and_the_renderer():
    """These are what forced 'unsafe-inline' into style-src before."""
    assert "<style" not in INDEX.lower(), "move the rules into styles.css"
    for name, text in (("index.html", INDEX), ("app.js", APP_JS)):
        assert 'style="' not in text, f"{name} still builds a style attribute"


def test_no_inline_event_handlers_or_script_bodies():
    for handler in ("onclick=", "onload=", "onerror=", "onmouseover="):
        assert handler not in INDEX.lower(), f"inline {handler} cannot run under script-src 'self'"
    # <script src="..."> only — no inline bodies.
    for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", INDEX, re.DOTALL | re.IGNORECASE):
        assert not tag.strip(), "inline script bodies are blocked by script-src 'self'"


# --- the drift guard --------------------------------------------------------

# https:// literals on a line that assigns a `url:`/`href` field are link
# targets the analyst clicks, i.e. navigations, not fetches: connect-src has no
# say over them.
_LINK_FIELD = re.compile(r"""(url|href)\s*[:=]""")


def _fetched_hosts() -> set[str]:
    hosts = set()
    for line in APP_JS.splitlines():
        for url in re.findall(r"https://([a-z0-9.\-]+)", line, re.IGNORECASE):
            if not _LINK_FIELD.search(line):
                hosts.add(url.lower())
    return hosts


def _connect_hosts() -> set[str]:
    return {
        v.split("://", 1)[1].rstrip("/").lower()
        for v in _policy()["connect-src"]
        if "://" in v
    }


def test_every_host_app_js_fetches_is_allowed_by_connect_src():
    """Add a live feed, forget the policy, and browserLiveScan() reports the
    source as unreachable with no hint that the browser refused it."""
    missing = sorted(_fetched_hosts() - _connect_hosts())
    assert not missing, f"connect-src is missing: {missing}"


def test_connect_src_grants_nothing_app_js_stopped_using():
    """The reverse drift: a retired feed leaves a standing grant behind."""
    stale = sorted(_connect_hosts() - _fetched_hosts())
    assert not stale, f"connect-src still allows unused hosts: {stale}"


def test_font_hosts_match_the_stylesheet_link():
    """Google Fonts is a two-host arrangement: the CSS comes from googleapis,
    the woff2 files it @imports come from gstatic. Allowing one without the
    other renders the page in a fallback face."""
    policy = _policy()
    if "fonts.googleapis.com" in INDEX:
        assert "https://fonts.googleapis.com" in policy["style-src"]
        assert "https://fonts.gstatic.com" in policy["font-src"]


def test_img_src_still_permits_the_inline_data_uris():
    """The favicon and the mascot are data: URIs; 'self' alone hides both."""
    assert "data:" in _policy()["img-src"]
    assert "data:image" in INDEX
