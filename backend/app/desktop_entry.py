from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("NETBOT_HOST", "127.0.0.1")
    port = int(os.environ.get("NETBOT_PORT", "8765"))
    uvicorn.run("backend.app.main:app", host=host, port=port, log_level=os.environ.get("NETBOT_LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
