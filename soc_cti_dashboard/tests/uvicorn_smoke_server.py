"""Subprocess-only fixture; never imported by production code."""
import json
import os
from pathlib import Path
import runpy
import socket

import uvicorn
from fastapi import Request
from backend import database, main

database.DATA_DIR = Path(os.environ["SMOKE_DATA_DIR"])
database.DB_PATH = database.DATA_DIR / "cti.db"
main.SCHEDULE_HOURS = ()


async def no_bootstrap():
    pass


def deny_outbound(*args, **kwargs):
    raise AssertionError("Smoke server must not make outbound connections")


main._bootstrap = no_bootstrap
socket.socket.connect = deny_outbound
socket.socket.connect_ex = deny_outbound


@main.app.get("/_transport")
async def transport(request: Request):
    return {"client": request.client.host, "scheme": request.url.scheme}


# The production static mount at '/' would otherwise consume this test route.
main.app.router.routes.insert(0, main.app.router.routes.pop())


def serve(app, **kwargs):
    # Use the real entrypoint's options, changing only the test port and app
    # reference (the app above has isolated storage and test-only diagnostics).
    kwargs["port"] = 0
    config = uvicorn.Config(main.app, **kwargs)
    sock = config.bind_socket()
    print(json.dumps({"port": sock.getsockname()[1],
                      "http2": config.http2,
                      "trusted": config.forwarded_allow_ips}), flush=True)
    try:
        uvicorn.Server(config).run(sockets=[sock])
    finally:
        sock.close()


uvicorn.run = serve
runpy.run_path(str(Path(__file__).resolve().parents[1] / "run.py"), run_name="__main__")
