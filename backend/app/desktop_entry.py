from __future__ import annotations

import json
import os
import sys

CAPTURE_BACKEND_PROBE_ARG = "--capture-backend-probe"
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


def _probe_capture_backend() -> int:
    _trace("capture backend probe starting")
    from scapy.config import conf  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.sendrecv import sniff  # type: ignore  # noqa: F401

    conf.use_pcap = True
    conf.l2types.register(1, Ether)
    print("ok", file=sys.stdout, flush=True)
    _trace("capture backend probe complete")
    return 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    _trace("entrypoint starting")
    if CAPTURE_BACKEND_PROBE_ARG in argv:
        raise SystemExit(_probe_capture_backend())
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
