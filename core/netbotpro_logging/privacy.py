from __future__ import annotations

from typing import Any

import pandas as pd

from core.redaction import redact_sensitive_text


def _redacted(value: Any) -> Any:
    if value is None:
        return value
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def packet_rows_to_df(rows: list[dict[str, Any]]) -> pd.DataFrame:
    cols = [
        "ts",
        "src",
        "dst",
        "proto",
        "sport",
        "dport",
        "length",
        "direction",
        "summary",
        "country",
        "country_code",
        "country_name",
        "city",
        "org",
        "asn",
        "inside_outside",
        "pid",
        "process_name",
        "l7",
        "tls_version",
        "sni",
        "alpn",
        "ja3",
        "ja3s",
        "ja4",
        "ja4s",
    ]
    if not rows:
        return pd.DataFrame(columns=cols)
    normalized = []
    for row in rows:
        normalized.append(
            {
                "ts": row.get("ts") or row.get("timestamp"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "proto": row.get("proto"),
                "sport": row.get("sport"),
                "dport": row.get("dport"),
                "length": row.get("length") or row.get("len"),
                "direction": row.get("direction"),
                "summary": _redacted(row.get("summary")),
                "country": row.get("country"),
                "country_code": row.get("country_code"),
                "country_name": row.get("country_name"),
                "city": row.get("city"),
                "org": row.get("org"),
                "asn": row.get("asn"),
                "inside_outside": row.get("inside_outside"),
                "pid": row.get("pid"),
                "process_name": row.get("process_name"),
                "l7": _redacted(row.get("l7")),
                "tls_version": row.get("tls_version"),
                "sni": row.get("sni"),
                "alpn": row.get("alpn"),
                "ja3": row.get("ja3"),
                "ja3s": row.get("ja3s"),
                "ja4": row.get("ja4"),
                "ja4s": row.get("ja4s"),
            }
        )
    df = pd.DataFrame(normalized)
    for col in cols:
        if col not in df.columns:
            df[col] = ""
    return df[cols]


def alert_rows_to_df(rows: list[dict[str, Any]]) -> pd.DataFrame:
    cols = ["ts", "src", "dst", "proto", "dport", "attack", "score", "engine", "detail"]
    if not rows:
        return pd.DataFrame(columns=cols)
    normalized = []
    for row in rows:
        normalized.append(
            {
                "ts": row.get("ts") or row.get("timestamp"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "proto": row.get("proto"),
                "dport": row.get("dport"),
                "attack": row.get("attack") or row.get("attack_type"),
                "score": row.get("score"),
                "engine": row.get("engine"),
                "detail": _redacted(row.get("detail") or row.get("info") or ""),
            }
        )
    df = pd.DataFrame(normalized)
    for col in cols:
        if col not in df.columns:
            df[col] = ""
    return df[cols]


def traceroute_rows_to_df(rows: list[dict[str, Any]]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(
            columns=["hop", "ip", "rtt", "country", "city", "org", "asn", "route"]
        )
    return pd.DataFrame(
        [
            {
                "hop": row.get("hop"),
                "ip": row.get("ip"),
                "rtt": row.get("rtt"),
                "country": row.get("country"),
                "city": row.get("city"),
                "org": row.get("org"),
                "asn": row.get("asn"),
                "route": row.get("route"),
            }
            for row in rows
        ]
    )
