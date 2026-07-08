from __future__ import annotations

import json
import os
import sys

CAPTURE_DISCOVERY_ARG = "--capture-discovery-json"


def _trace(message: str) -> None:
    if os.environ.get("NETBOT_BOOT_TRACE") != "1":
        return
    print(f"[desktop-entry] {message}", file=sys.stderr, flush=True)


def _emit_capture_discovery_payload() -> int:
    _trace("capture discovery starting")
    from core.netbotpro_sniffer_core.interfaces import list_capture_interfaces

    json.dump(list_capture_interfaces(), sys.stdout)
    sys.stdout.flush()
    _trace("capture discovery complete")
    return 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    _trace("entrypoint starting")
    if CAPTURE_DISCOVERY_ARG in argv:
        raise SystemExit(_emit_capture_discovery_payload())

    _trace("importing uvicorn")
    import uvicorn

    _trace("importing backend app")
    from backend.app.main import app

    host = os.environ.get("NETBOT_HOST", "127.0.0.1")
    port = int(os.environ.get("NETBOT_PORT", "8765"))
    _trace(f"starting uvicorn on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("NETBOT_LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
