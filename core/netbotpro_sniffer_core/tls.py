from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def tls_version_to_str(version: int) -> str:
    return {
        0x0304: "TLS1.3",
        0x0303: "TLS1.2",
        0x0302: "TLS1.1",
        0x0301: "TLS1.0",
        0x0300: "SSL3.0",
    }.get(version, f"0x{version:04x}")


def _tls_version_to_ja4(version: int) -> str:
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
    }.get(version, "00")


def _sha256_12(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def parse_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    try:
        if not payload or len(payload) < 9:
            return None

        content_type = payload[0]
        if content_type != 22:
            return None

        record_ver = (payload[1] << 8) | payload[2]
        rec_len = (payload[3] << 8) | payload[4]
        if len(payload) < 5 + rec_len:
            return None

        handshake = payload[5 : 5 + rec_len]
        if len(handshake) < 4 or handshake[0] != 1:
            return None

        hs_len = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3]
        body = handshake[4 : 4 + hs_len]
        if len(body) < 34:
            return None

        offset = 0
        client_ver = (body[offset] << 8) | body[offset + 1]
        offset += 2
        offset += 32

        session_id_len = body[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(body):
            return None

        cipher_len = (body[offset] << 8) | body[offset + 1]
        offset += 2
        ciphers: list[int] = []
        for i in range(0, cipher_len, 2):
            if offset + i + 1 >= len(body):
                break
            cipher = (body[offset + i] << 8) | body[offset + i + 1]
            if not is_grease(cipher):
                ciphers.append(cipher)
        offset += cipher_len
        if offset >= len(body):
            return {
                "record_ver": record_ver,
                "client_ver": client_ver,
                "ciphers": ciphers,
                "extensions": [],
                "sni": None,
                "alpn": [],
                "groups": [],
                "ecpf": [],
                "supported_versions": [],
            }

        comp_len = body[offset]
        offset += 1 + comp_len
        if offset + 2 > len(body):
            return {
                "record_ver": record_ver,
                "client_ver": client_ver,
                "ciphers": ciphers,
                "extensions": [],
                "sni": None,
                "alpn": [],
                "groups": [],
                "ecpf": [],
                "supported_versions": [],
            }

        ext_total = (body[offset] << 8) | body[offset + 1]
        offset += 2
        end = min(len(body), offset + ext_total)

        extensions: list[int] = []
        groups: list[int] = []
        ecpf: list[int] = []
        sni: str | None = None
        alpn: list[str] = []
        supported_versions: list[int] = []

        while offset + 4 <= end:
            ext_type = (body[offset] << 8) | body[offset + 1]
            ext_len = (body[offset + 2] << 8) | body[offset + 3]
            offset += 4
            ext_value = body[offset : offset + ext_len]
            offset += ext_len

            if is_grease(ext_type):
                continue
            extensions.append(ext_type)

            if ext_type == 0 and len(ext_value) >= 5:
                try:
                    list_len = (ext_value[0] << 8) | ext_value[1]
                    if 2 + list_len <= len(ext_value):
                        pos = 2
                        while pos + 3 <= 2 + list_len:
                            name_type = ext_value[pos]
                            name_len = (ext_value[pos + 1] << 8) | ext_value[pos + 2]
                            pos += 3
                            name = ext_value[pos : pos + name_len]
                            pos += name_len
                            if name_type == 0:
                                sni = name.decode("utf-8", errors="ignore")
                                break
                except Exception:
                    logger.debug("failed to parse TLS SNI", exc_info=True)

            elif ext_type == 16 and len(ext_value) >= 3:
                try:
                    list_len = (ext_value[0] << 8) | ext_value[1]
                    pos = 2
                    end_pos = min(len(ext_value), 2 + list_len)
                    while pos < end_pos:
                        proto_len = ext_value[pos]
                        pos += 1
                        proto = ext_value[pos : pos + proto_len].decode("ascii", errors="ignore")
                        pos += proto_len
                        if proto:
                            alpn.append(proto)
                except Exception:
                    logger.debug("failed to parse TLS ALPN", exc_info=True)

            elif ext_type == 10 and len(ext_value) >= 2:
                try:
                    list_len = (ext_value[0] << 8) | ext_value[1]
                    pos = 2
                    end_pos = min(len(ext_value), 2 + list_len)
                    while pos + 1 < end_pos:
                        groups.append((ext_value[pos] << 8) | ext_value[pos + 1])
                        pos += 2
                except Exception:
                    logger.debug("failed to parse TLS groups", exc_info=True)

            elif ext_type == 11 and len(ext_value) >= 1:
                try:
                    list_len = ext_value[0]
                    pos = 1
                    end_pos = min(len(ext_value), 1 + list_len)
                    while pos < end_pos:
                        ecpf.append(ext_value[pos])
                        pos += 1
                except Exception:
                    logger.debug("failed to parse TLS point formats", exc_info=True)

            elif ext_type == 43 and len(ext_value) >= 1:
                try:
                    list_len = ext_value[0]
                    pos = 1
                    end_pos = min(len(ext_value), 1 + list_len)
                    while pos + 1 < end_pos:
                        supported_versions.append((ext_value[pos] << 8) | ext_value[pos + 1])
                        pos += 2
                except Exception:
                    logger.debug("failed to parse TLS supported versions", exc_info=True)

        return {
            "record_ver": record_ver,
            "client_ver": client_ver,
            "ciphers": ciphers,
            "extensions": extensions,
            "sni": sni,
            "alpn": alpn,
            "groups": [value for value in groups if not is_grease(value)],
            "ecpf": ecpf,
            "supported_versions": [value for value in supported_versions if not is_grease(value)],
        }
    except Exception:
        logger.debug("TLS ClientHello parsing failed", exc_info=True)
        return None


def calc_ja3(client_hello: dict[str, Any]) -> tuple[str | None, str | None]:
    try:
        version = client_hello.get("client_ver") or client_hello.get("record_ver")
        ciphers = [c for c in (client_hello.get("ciphers") or []) if not is_grease(c)]
        extensions = [e for e in (client_hello.get("extensions") or []) if not is_grease(e)]
        groups = [g for g in (client_hello.get("groups") or []) if not is_grease(g)]
        ecpf = list(client_hello.get("ecpf") or [])

        ja3_string = ",".join(
            [
                str(int(version) if version is not None else 0),
                "-".join(str(value) for value in ciphers),
                "-".join(str(value) for value in extensions),
                "-".join(str(value) for value in groups),
                "-".join(str(value) for value in ecpf),
            ]
        )
        return ja3_string, _md5_hex(ja3_string)
    except Exception:
        logger.debug("JA3 generation failed", exc_info=True)
        return None, None


def calc_ja4(client_hello: dict[str, Any]) -> str | None:
    try:
        supported_versions = list(client_hello.get("supported_versions") or [])
        version = max(supported_versions) if supported_versions else (client_hello.get("client_ver") or client_hello.get("record_ver") or 0)
        version_part = _tls_version_to_ja4(int(version))

        sni = client_hello.get("sni") or ""
        sni_flag = "d" if ("." in sni and len(sni) >= 3) else "i"

        alpn = list(client_hello.get("alpn") or [])
        alpn_first = alpn[0] if alpn else ""
        if len(alpn_first) >= 2:
            alpn_part = alpn_first[:2]
        elif len(alpn_first) == 1:
            alpn_part = alpn_first + "0"
        else:
            alpn_part = "00"

        ciphers = sorted({c for c in (client_hello.get("ciphers") or []) if not is_grease(c)})
        all_extensions = [e for e in (client_hello.get("extensions") or []) if not is_grease(e)]
        extensions = sorted({e for e in all_extensions if e not in (0, 16)})

        ja4_a = f"t{version_part}{sni_flag}{len(ciphers):02d}{len(all_extensions):02d}{alpn_part}"
        cipher_hash = _sha256_12(",".join(f"{cipher:04x}" for cipher in ciphers))
        extension_hash = _sha256_12(",".join(f"{extension:04x}" for extension in extensions))
        return f"{ja4_a}_{cipher_hash}_{extension_hash}"
    except Exception:
        logger.debug("JA4 generation failed", exc_info=True)
        return None


def tls_fingerprints(payload: bytes) -> dict[str, Any]:
    client_hello = parse_tls_client_hello(payload)
    if not client_hello:
        return {}

    ja3_string, ja3 = calc_ja3(client_hello)
    ja4 = calc_ja4(client_hello)
    supported_versions = list(client_hello.get("supported_versions") or [])
    version = max(supported_versions) if supported_versions else (client_hello.get("client_ver") or client_hello.get("record_ver"))

    return {
        "tls_version": tls_version_to_str(int(version) if version is not None else 0),
        "tls_sni": client_hello.get("sni"),
        "tls_alpn": list(client_hello.get("alpn") or []),
        "ja3_str": ja3_string,
        "ja3": ja3,
        "ja4": ja4,
    }
