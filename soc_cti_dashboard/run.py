"""Launch SOC CTI Dashboard:  python run.py"""

from __future__ import annotations

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8787,
        reload=False,
        log_level="info",
    )
