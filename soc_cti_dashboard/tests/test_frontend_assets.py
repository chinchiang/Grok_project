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


def test_reduced_motion_is_honoured():
    """Two commit messages claimed `prefers-reduced-motion` support and
    neither delivered it, so it gets a guard rather than trust.

    The page runs three infinite animations (two status-dot pulses and the
    RANSOM pill blink). A viewer who has asked their OS to reduce motion
    must not get them.
    """
    css = STYLES.read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css, (
        "the page animates indefinitely and offers no way to opt out"
    )

    block = re.search(
        r"@media[^{]*prefers-reduced-motion:\s*reduce[^{]*\{(.*?)\n\}\s*$",
        css,
        re.S,
    )
    assert block, "could not isolate the reduced-motion block"
    body = block.group(1)
    assert re.search(r"animation:\s*none", body), (
        "reduced-motion block does not stop the animations"
    )
    assert "transition-duration" in body, (
        "reduced-motion block does not shorten transitions"
    )


def test_every_infinite_animation_is_inside_the_reduced_motion_sweep():
    """The sweep uses a universal selector, so a new animation is covered
    automatically — unless someone adds one with !important, which would win
    over it. This fails if that ever happens."""
    css = STYLES.read_text(encoding="utf-8")
    forced = [
        line.strip()
        for line in css.splitlines()
        if re.search(r"animation[^;]*infinite[^;]*!important", line)
    ]
    assert forced == [], f"animation outruns the reduced-motion sweep: {forced}"


# --- phone shortcut bar --------------------------------------------------------

BNAV_VIEWS = ["overview", "highrisk", "preemptive", "review", "sources"]


def test_bottom_nav_targets_are_real_views():
    """A shortcut pointing at a view that does not exist is a dead button.
    Both ends are in index.html, so they can drift in one edit."""
    html = INDEX.read_text(encoding="utf-8")
    shortcuts = re.findall(r'class="bnav-item"[^>]*data-view="(\w+)"', html)
    assert shortcuts == BNAV_VIEWS, f"unexpected shortcut set: {shortcuts}"
    for view in shortcuts:
        assert f'data-view="{view}"' in html and f'id="view-{view}"' in html, (
            f"shortcut {view} has no matching tab or panel"
        )


def test_bottom_nav_does_not_pose_as_a_second_tablist():
    """The buttons drive the same panels as the tablist above. Marking them
    role="tab" would tell a screen reader there are two sets of tabs for one
    set of panels; they are navigation, and carry aria-current instead."""
    html = INDEX.read_text(encoding="utf-8")
    bar = re.search(r'<nav class="bottom-nav".*?</nav>', html, re.S)
    assert bar, "bottom nav markup missing"
    assert 'role="tab"' not in bar.group(0), "shortcut bar claims to be a tablist"
    assert "aria-label=" in bar.group(0), "shortcut bar has no accessible name"
    app = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert "aria-current" in app, "active shortcut is never announced"


def test_bottom_nav_is_phone_only_and_content_clears_it():
    """Fixed to the bottom edge, it covers the end of the page unless main
    reserves the space — and on iOS it needs the safe-area inset or the home
    indicator sits on top of it."""
    css = STYLES.read_text(encoding="utf-8")
    assert re.search(r"\.bottom-nav\s*\{\s*display:\s*none", css), (
        "the bar is not hidden by default, so it would show on desktop too"
    )
    # There is more than one 640px block; the bar only has to live in one.
    phone_blocks = re.findall(
        r"@media \(max-width: 640px\) \{(.*?)\n\}", css, re.S
    )
    assert phone_blocks, "no phone breakpoint at all"
    assert any(".bottom-nav" in b for b in phone_blocks), (
        "the bar is never shown at phone widths"
    )
    assert "safe-area-inset-bottom" in css, "no safe-area inset for the home indicator"
    assert re.search(r"main\s*\{\s*padding-bottom:\s*calc\(", css), (
        "main does not reserve space for the fixed bar"
    )


def test_bottom_nav_highlight_is_driven_by_the_shared_activate_path():
    """If the bar tracked its own clicks instead, opening a zone from a tile
    or the tab strip would leave a stale highlight."""
    app = (FRONTEND / "app.js").read_text(encoding="utf-8")
    activate = re.search(r"function activateTab\(tab\) \{(.*?)\n\}", app, re.S)
    assert activate, "activateTab not found"
    assert "syncBottomNav" in activate.group(1), (
        "activateTab does not sync the shortcut bar, so the highlight can go stale"
    )


def test_colours_come_only_from_tokens():
    """Converting the sheet from dark to light exposed why this matters:
    the hex literals were easy to find and fix, but a dozen `rgba(...)`
    values picked for a dark background survived the sweep and turned into
    dark chips with dark ink on a white page. The invariant that prevents a
    repeat is simple — every colour is declared once, in :root.

    Neutral shadows and overlays are exempt: they are black or white at low
    alpha and work on any background.
    """
    css = STYLES.read_text(encoding="utf-8")
    root = re.search(r":root\s*\{(.*?)\n\}", css, re.S)
    assert root, "no :root block"
    body = css[root.end():]

    literals = []
    for lineno, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("/*", "*")):
            continue
        for m in re.finditer(r"#[0-9a-fA-F]{3,8}\b", stripped):
            literals.append(f"{stripped[:70]}  ({m.group(0)})")
        for m in re.finditer(r"rgba?\(([^)]*)\)", stripped):
            nums = [n.strip() for n in m.group(1).split(",")]
            # black / white at any alpha is theme-neutral
            if len(nums) >= 3 and (
                all(n == "0" for n in nums[:3]) or all(n == "255" for n in nums[:3])
            ):
                continue
            literals.append(f"{stripped[:70]}  ({m.group(0)})")

    assert literals == [], (
        "colours declared outside :root — these do not follow the theme:\n  "
        + "\n  ".join(literals[:10])
    )


def test_zone_tiles_divide_evenly_into_their_column_counts():
    """The tile row is laid out at 3 or 9 columns because nine tiles divide
    evenly by both, which is what makes every row full and every tile the
    same width. A six-column grid left three orphans and half a row of white
    space; a flex row that grew the last line filled the width but wrapped to
    7 + 2 at ~1024px with two tiles stretched to triple width.

    Add or remove a zone and neither count works any more, so this fails and
    the column counts have to be chosen again.
    """
    html = INDEX.read_text(encoding="utf-8")
    css = STYLES.read_text(encoding="utf-8")

    tiles = len(re.findall(r'class="nav-tile[ "]', html))
    assert tiles, "no zone tiles found"

    counts = {int(n) for n in re.findall(r"\.nav-tiles\s*\{[^}]*?repeat\((\d+), 1fr\)", css)}
    counts |= {
        int(n)
        for n in re.findall(
            r"@media[^{]*\{\s*\.nav-tiles\s*\{[^}]*?repeat\((\d+), 1fr\)", css
        )
    }
    assert counts, "the tile grid declares no fixed column count"

    bad = sorted(c for c in counts if tiles % c)
    assert bad == [], (
        f"{tiles} zone tiles do not divide evenly into column count(s) {bad} — "
        f"the last row will be ragged"
    )
