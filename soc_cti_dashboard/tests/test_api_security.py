"""API surface hardening tests: manual-scan auth (R3-7) and CORS (R3-6).

These deliberately avoid the app lifespan (no TestClient context manager), so
no database is created and no harvest is kicked off: rejection happens in the
dependency before any handler runs, and CORS is resolved in middleware before
routing. That keeps the suite fast and network-free in CI.
"""

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import main as app_main
from backend.config import CORS_ORIGINS

SCAN = "/api/scan/manual"
KEY = "s3cr3t-key"

client = TestClient(app_main.app)


@pytest.fixture
def with_key(monkeypatch):
    monkeypatch.setattr(app_main, "API_KEY", KEY)
    return KEY


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-API-Key": "wrong"},
        {"X-API-Key": ""},
        {"X-API-Key": KEY[:-1]},                      # near miss
        {"Authorization": "Bearer wrong"},
        {"Authorization": "wrong"},                   # bare token form
        {"X-API-Key": "café".encode("latin-1")},      # raw high bytes
        {"X-API-Key": "金鑰".encode("utf-8")},
    ],
)
def test_manual_scan_rejects_bad_credentials(with_key, headers):
    r = client.post(SCAN, headers=headers)
    assert r.status_code == 401, f"expected 401, got {r.status_code}"


def test_bad_credentials_never_500(with_key):
    """compare_digest() raises on non-ASCII str; a hostile header must not
    turn that into a server error."""
    r = client.post(SCAN, headers={"X-API-Key": bytes([0xC3, 0xA9, 0xFF])})
    assert r.status_code == 401


@pytest.mark.parametrize("key", [KEY, "金鑰-secret"])
def test_correct_key_is_accepted(monkeypatch, key):
    """Both header forms accept the configured key — including a non-ASCII one,
    which ASGI hands over latin-1 decoded."""
    monkeypatch.setattr(app_main, "API_KEY", key)
    # No exception == accepted; the dependency returns None on success.
    asyncio.run(app_main.require_api_key(x_api_key=key, authorization=None))
    asyncio.run(
        app_main.require_api_key(x_api_key=None, authorization=f"Bearer {key}")
    )


def test_no_key_configured_fails_closed(monkeypatch):
    """No key configured ⇒ writes are disabled, not open.

    Loopback binding is not an authentication boundary: a cross-origin POST from
    any page the analyst has open still executes the handler, since CORS
    withholds the *response*, not the write.
    """
    monkeypatch.setattr(app_main, "API_KEY", "")
    monkeypatch.setattr(app_main, "ALLOW_UNAUTHENTICATED_WRITES", False)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(app_main.require_api_key(x_api_key=None, authorization=None))
    assert exc.value.status_code == 401
    assert "SOC_CTI_API_KEY" in exc.value.detail["message_en"]
    assert client.post(SCAN).status_code == 401


def test_unauthenticated_override_is_explicit_and_opt_in(monkeypatch):
    """The old permissive behaviour survives only behind a deliberate env flag."""
    monkeypatch.setattr(app_main, "API_KEY", "")
    monkeypatch.setattr(app_main, "ALLOW_UNAUTHENTICATED_WRITES", True)
    asyncio.run(app_main.require_api_key(x_api_key=None, authorization=None))
    assert app_main.writes_require_key() is False


def test_health_reports_the_real_posture(monkeypatch):
    monkeypatch.setattr(app_main, "API_KEY", "")
    monkeypatch.setattr(app_main, "ALLOW_UNAUTHENTICATED_WRITES", False)
    assert app_main.writes_require_key() is True
    monkeypatch.setattr(app_main, "API_KEY", KEY)
    assert app_main.writes_require_key() is True


def test_comparison_is_constant_time(monkeypatch, with_key):
    """Timing-safety cannot be observed from responses, so assert the mechanism:
    a plain `==` would pass every other test in this file while leaking the
    matching prefix through response latency."""
    calls: list[tuple] = []
    real = app_main.secrets.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(app_main.secrets, "compare_digest", spy)
    client.post(SCAN, headers={"X-API-Key": "wrong"})
    assert calls, "credential check must go through secrets.compare_digest()"
    assert all(
        isinstance(a, bytes) and isinstance(b, bytes) for a, b in calls
    ), "compare_digest() must receive bytes — it raises on non-ASCII str"


# --- CORS (R3-6) ------------------------------------------------------------

def test_cors_default_targets_the_served_port():
    """run.py serves 8787; a default allowlist naming another port is a trap."""
    assert any("8787" in o for o in CORS_ORIGINS)


def test_cors_allowlist_has_no_wildcard():
    """'*' with allow_credentials is rejected by browsers and widens the surface."""
    assert "*" not in CORS_ORIGINS


def test_preflight_from_unlisted_origin_is_denied():
    r = client.options(
        SCAN,
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.headers.get("access-control-allow-origin") is None


def test_preflight_from_allowed_origin_is_permitted():
    origin = CORS_ORIGINS[0]
    r = client.options(
        SCAN,
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )
    assert r.headers.get("access-control-allow-origin") == origin


def test_security_headers_are_set_on_api_responses():
    r = client.options(
        SCAN,
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    csp = r.headers.get("content-security-policy") or ""
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
