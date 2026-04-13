from __future__ import annotations

import json
import os
import sys

CAPTURE_DISCOVERY_ARG = "--capture-discovery-json"


def _emit_capture_discovery_payload() -> int:
    from core.netbotpro_sniffer_core.interfaces import list_capture_interfaces

    json.dump(list_capture_interfaces(), sys.stdout)
    sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if CAPTURE_DISCOVERY_ARG in argv:
        raise SystemExit(_emit_capture_discovery_payload())

    import uvicorn

    host = os.environ.get("NETBOT_HOST", "127.0.0.1")
    port = int(os.environ.get("NETBOT_PORT", "8765"))
    uvicorn.run("backend.app.main:app", host=host, port=port, log_level=os.environ.get("NETBOT_LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
