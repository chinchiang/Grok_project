"""Real HTTP/1.1 regression gate for the Uvicorn upgrade; no external feeds."""
import http.client
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import time

import pytest
import uvicorn
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=[None, ""])
def server(request, tmp_path):
    env = os.environ.copy()
    for key in ("FORWARDED_ALLOW_IPS", "API_KEY", "SOC_CTI_API_KEY",
                "SOC_CTI_ALLOW_UNAUTHENTICATED", "SOC_CTI_BIND"):
        env.pop(key, None)
    env.update(SOC_CTI_BIND="127.0.0.1", SOC_CTI_ALLOW_UNAUTHENTICATED="0",
               SMOKE_DATA_DIR=str(tmp_path / "db"),
               PYTHONPATH=os.pathsep.join((str(ROOT), str(ROOT.parent))))
    if request.param is not None:
        env["FORWARDED_ALLOW_IPS"] = request.param
    output = tmp_path / "server.log"
    with output.open("w") as log:
        proc = subprocess.Popen([sys.executable, str(ROOT / "tests/uvicorn_smoke_server.py")],
                                cwd=ROOT, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            info = None
            while time.monotonic() < deadline:
                text = output.read_text()
                for line in text.splitlines():
                    if line.startswith('{"port":'):
                        info = json.loads(line)
                if info and "Application startup complete" in text:
                    break
                assert proc.poll() is None, text
                time.sleep(0.05)
            else:
                pytest.fail("Uvicorn startup timeout: " + output.read_text())
            assert info["http2"] is False
            assert info["trusted"] == ("127.0.0.1" if request.param is None else "")
            yield info["port"], request.param
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                    pytest.fail("Uvicorn failed to shut down")
        # POSIX termination exercises the real ASGI lifespan shutdown.
        if os.name != "nt":
            assert "Application shutdown complete" in output.read_text()
            assert proc.returncode in (0, -15), output.read_text()


def test_live_startup_auth_proxy_and_keepalive(server):
    port, trust = server
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        for path in ("/", "/api/health"):
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read()
            assert response.status == 200
            if path == "/api/health":
                assert json.loads(body)["write_endpoints_enabled"] is False
            assert conn.sock is not None
            if path == "/":
                original_socket = conn.sock
            else:
                assert conn.sock is original_socket
        conn.request("POST", "/api/scan/manual")
        response = conn.getresponse()
        response.read()
        assert response.status == 401
        conn.request("GET", "/_transport", headers={
            "X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"})
        response = conn.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == (
            {"client": "203.0.113.7", "scheme": "https"} if trust is None else
            {"client": "127.0.0.1", "scheme": "http"})
    finally:
        conn.close()


def test_connection_close_mixed_case_token_list(server):
    port, _ = server
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n"
                     b"Connection: keep-alive, ClOsE\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 200
        assert json.loads(response.read())["status"] == "ok"
        # A timeout is a failure: the server must close, not just send a header.
        assert sock.recv(1) == b""


@pytest.mark.asyncio
@pytest.mark.parametrize("allow,expected", [(None, "::1"), ("127.0.0.1,::1", "203.0.113.7")])
async def test_ipv6_proxy_requires_explicit_opt_in(monkeypatch, allow, expected):
    # Synthetic ASGI peer avoids relying on IPv6 availability on CI runners.
    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    if allow is not None:
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", allow)
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kw))
    runpy.run_path(str(ROOT / "run.py"), run_name="__main__")
    seen = {}

    async def app(scope, receive, send):
        seen.update(scope)

    middleware = ProxyHeadersMiddleware(app, trusted_hosts=captured["forwarded_allow_ips"])
    await middleware({"type": "http", "scheme": "http", "client": ("::1", 1234),
                      "headers": [(b"x-forwarded-for", b"203.0.113.7"),
                                  (b"x-forwarded-proto", b"https")]}, None, None)
    assert seen["client"][0] == expected
    assert seen["scheme"] == ("http" if allow is None else "https")
