from __future__ import annotations

from hashlib import sha256
from typing import Any

from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text


def reconstruct_stream(
    packets: list[dict[str, Any]],
    *,
    flow_id: str = "",
    protocol: str = "UNKNOWN",
    capture_mode: str = "metadata",
) -> dict[str, Any]:
    ordered = sorted(packets, key=lambda item: str(item.get("ts") or item.get("timestamp") or ""))
    chunks = []
    for packet in ordered:
        direction = "server_to_client" if str(packet.get("direction") or "").upper() == "INCOMING" else "client_to_server"
        preview = redact_sensitive_text(str(packet.get("payload_ascii") or packet.get("summary") or ""))
        chunks.append({
            "timestamp": packet.get("ts") or packet.get("timestamp"),
            "direction": direction,
            "length": int(packet.get("length") or 0),
            "preview_redacted": preview if capture_mode in {"full", "forensic"} else "",
            "packet_id": packet.get("id"),
            "redacted": True,
        })
    tls = str(protocol).upper() == "TLS"
    return redact_sensitive_data({
        "stream_id": "stream-" + sha256((flow_id or repr(ordered)).encode()).hexdigest()[:16],
        "flow_id": flow_id or None,
        "mode": "metadata" if capture_mode == "metadata" else "redacted_text",
        "protocol": protocol,
        "chunks": chunks,
        "warnings": [
            "TLS content remains encrypted; no decryption or key extraction is performed."
            if tls else
            "Stream previews are redacted and may omit sensitive content."
        ],
    })
