from __future__ import annotations

import binascii
import logging
from typing import Any

from .tls import tls_fingerprints

logger = logging.getLogger(__name__)


def safe_bytes_preview(payload: bytes, max_len: int = 64) -> dict[str, Any]:
    if not payload:
        return {"payload_len": 0, "payload_hex": "", "payload_ascii": ""}

    preview = payload[:max_len]
    hex_text = binascii.hexlify(preview).decode("ascii")
    hex_text = " ".join(hex_text[index : index + 2] for index in range(0, len(hex_text), 2))
    ascii_text = "".join(chr(value) if 32 <= value < 127 else "." for value in preview)
    return {
        "payload_len": len(payload),
        "payload_hex": hex_text,
        "payload_ascii": ascii_text,
    }


def extract_payload(pkt: Any, layers: Any) -> bytes:
    try:
        if layers.TCP in pkt:
            return bytes(pkt[layers.TCP].payload)
        if layers.UDP in pkt:
            return bytes(pkt[layers.UDP].payload)
    except Exception:
        logger.debug("transport payload extraction failed", exc_info=True)
    return b""


def extract_layer7(pkt: Any, payload: bytes, layers: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "l7": None,
        "dns_qname": None,
        "dns_qtype": None,
        "dns_rcode": None,
        "http_method": None,
        "http_host": None,
        "http_path": None,
        "http_user_agent": None,
        "tls_version": None,
        "tls_sni": None,
        "tls_alpn": [],
        "ja3": None,
        "ja3_str": None,
        "ja4": None,
        "sni": None,
        "alpn": [],
    }

    if layers.DNS in pkt and pkt.haslayer(layers.DNSQR):
        try:
            query = pkt[layers.DNSQR]
            qname = query.qname.decode(errors="ignore") if isinstance(query.qname, bytes) else str(query.qname)
            data.update(
                {
                    "dns_qname": qname,
                    "dns_qtype": int(getattr(query, "qtype", 0) or 0),
                    "dns_rcode": int(getattr(pkt[layers.DNS], "rcode", 0) or 0),
                    "l7": f"DNS {qname}",
                }
            )
        except Exception:
            logger.debug("DNS extraction failed", exc_info=True)

    if data["l7"] is None and payload:
        try:
            raw_text = payload[:1024].decode("utf-8", errors="ignore")
            lines = raw_text.splitlines()
            line0 = lines[0] if lines else ""
            if line0.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")):
                parts = line0.split()
                http_method = parts[0] if len(parts) > 0 else None
                http_path = parts[1] if len(parts) > 1 else None
                http_host = None
                http_user_agent = None
                for line in lines[1:50]:
                    lower = line.lower()
                    if lower.startswith("host:"):
                        http_host = line.split(":", 1)[1].strip()
                    elif lower.startswith("user-agent:"):
                        http_user_agent = line.split(":", 1)[1].strip()
                data.update(
                    {
                        "http_method": http_method,
                        "http_path": http_path,
                        "http_host": http_host,
                        "http_user_agent": http_user_agent,
                        "l7": f"HTTP {http_method or ''} {http_path or ''}".strip(),
                    }
                )
        except Exception:
            logger.debug("HTTP extraction failed", exc_info=True)

    if payload:
        tls_info = tls_fingerprints(payload)
        if tls_info.get("ja3") or tls_info.get("ja4") or tls_info.get("tls_sni") or tls_info.get("tls_alpn"):
            data.update(tls_info)
            data["sni"] = tls_info.get("tls_sni")
            data["alpn"] = list(tls_info.get("tls_alpn") or [])
            if data["l7"] is None:
                data["l7"] = "TLS"

    return data
