from __future__ import annotations

import json
import os
import sys

CAPTURE_BACKEND_PROBE_ARG = "--capture-backend-probe"
CAPTURE_DISCOVERY_ARG = "--capture-discovery-json"
EXPORT_PROBE_ARG = "--export-runtime-probe"
ML_PROBE_ARG = "--ml-runtime-probe"


def _probe_ml_runtime() -> int:
    from core.ids_ml import MLIDS
    model = MLIDS(sample_rate=1, min_train_size=50)
    for index in range(55):
        model.analyze_packet({"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP",
                              "sport": 51000, "dport": 443, "length": 120 + index, "ttl": 64})
    if not model._trained or not model._ml_available:
        raise RuntimeError("Packaged ML training failed")
    print(json.dumps({"ml_available": True, "trained": True, "synthetic_samples": 55}))
    return 0


def _probe_export_runtime() -> int:
    import tempfile
    from pathlib import Path
    import zipfile
    with tempfile.TemporaryDirectory() as directory:
        os.environ["NETBOT_DATA_DIR"] = directory
        os.environ["NETBOT_LOG_DIR"] = directory
        from backend.app.services import export_service
        export_service.LOG_DIR = Path(directory)
        service = export_service.ExportService()
        results = {}
        for kind in ("csv", "xlsx", "pdf", "html", "zip"):
            result = service.export_session(kind, [], [], [])
            path = Path(directory) / result["path"]
            if not path.exists() or not path.stat().st_size:
                raise RuntimeError("Empty export: " + kind)
            if kind in ("xlsx", "zip"):
                with zipfile.ZipFile(path) as archive:
                    if archive.testzip() is not None:
                        raise RuntimeError("Corrupt export: " + kind)
            if kind == "pdf" and not path.read_bytes().startswith(b"%PDF"):
                raise RuntimeError("Invalid PDF")
            results[kind] = "ok"
        print(json.dumps(results))
    return 0


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
    if ML_PROBE_ARG in argv:
        raise SystemExit(_probe_ml_runtime())
    if EXPORT_PROBE_ARG in argv:
        raise SystemExit(_probe_export_runtime())
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
    import multiprocessing
    multiprocessing.freeze_support()
    main()
