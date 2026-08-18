"""index.html and styles.css must actually be the page, not a stub.

Both files were replaced by placeholder text — `SEE_ARTIFACTS_STYLES`, 20
bytes — and four deploys went green and published an unstyled dashboard. The
sanity gate ran `node --check` on the JavaScript and pytest on the backend,
so nothing looked at the two files that make up everything a user sees. The
index.html stub was eventually caught, but only because test_frontend_csp.py
happens to parse index.html and could not find the CSP meta; styles.css had
no guard at all.

These tests are that guard. They are deliberately shallow — they cannot tell
good design from bad — but they fail loudly when a file stops being a real
stylesheet or a real document.
"""

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
INDEX = FRONTEND / "index.html"
STYLES = FRONTEND / "styles.css"

# Well under the real sizes (~34 KB each) but far above any stub. The point
# is to catch truncation, not to freeze the files at a size.
MIN_BYTES = 8_000

# Text a placeholder commit left behind. Listed explicitly so the failure
# message names the actual failure mode rather than just "file too small".
PLACEHOLDER_MARKERS = (
    "SEE_ARTIFACTS",
    "PLACEHOLDER",
    "WILL_BE_REPLACED",
    "FULL_CONTENT",
    "TODO_REPLACE",
)


@pytest.mark.parametrize("path", [INDEX, STYLES], ids=["index.html", "styles.css"])
def test_asset_is_not_a_stub(path):
    raw = path.read_text(encoding="utf-8")
    assert len(raw.encode("utf-8")) >= MIN_BYTES, (
        f"{path.name} is {len(raw.encode('utf-8'))} bytes — it has been "
        f"truncated or replaced by a placeholder"
    )
    upper = raw.upper()
    found = [m for m in PLACEHOLDER_MARKERS if m in upper]
    assert not found, f"{path.name} still contains placeholder text: {found}"


def test_index_is_a_document_with_the_shell_the_app_drives():
    html = INDEX.read_text(encoding="utf-8")
    assert html.lstrip().upper().startswith("<!DOCTYPE HTML"), "not an HTML document"
    for needed in ('<link rel="stylesheet" href="styles.css"', 'src="app.js"'):
        assert needed in html, f"index.html no longer loads {needed}"
    # The shell app.js writes into. A stub would have none of these.
    for el in ('id="clock"', 'class="tabs"', 'role="tabpanel"', 'id="view-overview"'):
        assert el in html, f"index.html is missing {el}"


def test_styles_defines_the_tokens_and_the_layout():
    css = STYLES.read_text(encoding="utf-8")
    assert ":root" in css, "no token block"
    # The load-bearing rules. Without these the page renders as unstyled text,
    # which is exactly what shipped.
    for sel in (".topbar", ".tabs", ".tab", ".card", ".kpi", "main"):
        assert re.search(rf"(^|[,\s}}]){re.escape(sel)}[\s,{{:]", css, re.M), (
            f"styles.css defines no rule for {sel}"
        )


def test_no_stylesheet_uses_an_undefined_token():
    """A var(--x) with no definition silently renders as nothing — an
    invisible border, a transparent background — which is hard to spot in
    review and easy to introduce when renaming a token."""
    css = STYLES.read_text(encoding="utf-8")
    defined = set(re.findall(r"^\s*(--[a-z0-9-]+)\s*:", css, re.M))
    used = set(re.findall(r"var\(\s*(--[a-z0-9-]+)", css))
    # var(--x, fallback) is fine even when --x is absent.
    with_fallback = set(re.findall(r"var\(\s*(--[a-z0-9-]+)\s*,", css))
    missing = sorted(used - defined - with_fallback)
    assert missing == [], f"styles.css uses undefined tokens: {missing}"


def test_phone_layout_exists():
    """The dashboard is opened on phones. Without a narrow breakpoint the
    desktop grid is what a phone gets."""
    css = STYLES.read_text(encoding="utf-8")
    narrow = re.findall(r"@media[^{]*max-width:\s*(\d+)px", css)
    assert narrow, "no max-width media query at all"
    assert min(int(w) for w in narrow) <= 640, (
        f"narrowest breakpoint is {min(int(w) for w in narrow)}px — nothing "
        f"targets phone widths"
    )


def test_every_i18n_key_used_in_the_page_exists_in_both_languages():
    """A data-i18n key with no entry renders as the raw key or as whatever
    static fallback happens to be in the HTML, so the two drift apart
    silently — which is how tab labels ended up showing their emoji twice."""
    html = INDEX.read_text(encoding="utf-8")
    i18n = (FRONTEND / "i18n.js").read_text(encoding="utf-8")

    used = set(re.findall(r'data-i18n="([\w.]+)"', html))
    # i18n.js is `{ zh: {...}, en: {...} }`; check each block separately.
    blocks = re.split(r"^\s{2}(zh|en):\s*\{", i18n, flags=re.M)
    tables = {}
    for name, body in zip(blocks[1::2], blocks[2::2]):
        tables[name] = set(re.findall(r"^\s*(\w+):", body, re.M))
    assert {"zh", "en"} <= set(tables), "could not find both language tables"

    for lang, keys in tables.items():
        missing = sorted(used - keys)
        assert missing == [], f"{lang} is missing keys used in index.html: {missing}"
