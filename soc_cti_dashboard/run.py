"""Launch SOC CTI Dashboard:  python run.py"""

from __future__ import annotations

import os

import uvicorn

# GET /api/intel is unauthenticated and includes raw_json. Binding 0.0.0.0
# would publish the whole CTI DB on the LAN. Override only when you mean to:
#   SOC_CTI_BIND=0.0.0.0 python run.py
BIND_HOST = (os.environ.get("SOC_CTI_BIND") or "127.0.0.1").strip() or "127.0.0.1"


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=BIND_HOST,
        port=8787,
        reload=False,
        log_level="info",
    )
