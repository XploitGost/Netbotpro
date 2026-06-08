from __future__ import annotations

import re
import shlex
from typing import Any


class DisplayFilterError(ValueError):
    pass


_OPERATORS = {"==", "!=", "contains", "startswith", "endswith", ">", ">=", "<", "<="}
_ALIASES = {
    "ip.src": "src",
    "ip.dst": "dst",
    "tcp.src_port": "sport",
    "tcp.dst_port": "dport",
    "udp.src_port": "sport",
    "udp.dst_port": "dport",
    "dns.qry.name": "dns_query",
    "http.host": "http_host",
    "http.method": "http_method",
    "tls.sni": "tls_sni",
    "protocol": "proto",
    "transport": "proto",
    "risk": "risk_score",
    "alert.severity": "severity",
}


def _tokens(expression: str) -> list[str]:
    prepared = re.sub(r"(>=|<=|==|!=|>|<)", r" \1 ", expression.strip())
    try:
        return shlex.split(prepared)
    except ValueError as exc:
        raise DisplayFilterError(f"Invalid display filter: {exc}") from exc


def _value(row: dict[str, Any], field: str) -> Any:
    if field in {"tcp.port", "udp.port"}:
        return [row.get("sport"), row.get("dport")]
    key = _ALIASES.get(field, field)
    current: Any = row
    for part in key.split("."):
        current = current.get(part) if isinstance(current, dict) else None
    return current


def _compare(actual: Any, operator: str, expected: str) -> bool:
    if isinstance(actual, list):
        return any(_compare(item, operator, expected) for item in actual)
    if operator in {">", ">=", "<", "<="}:
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right}[operator]
    left, right = str(actual or "").lower(), str(expected).lower()
    return {
        "==": left == right,
        "!=": left != right,
        "contains": right in left,
        "startswith": left.startswith(right),
        "endswith": left.endswith(right),
    }[operator]


def compile_display_filter(expression: str):
    tokens = _tokens(expression)
    if not tokens:
        return lambda row: True
    position = 0

    def parse_atom():
        nonlocal position
        negate = position < len(tokens) and tokens[position].lower() == "not"
        if negate:
            position += 1
        if position >= len(tokens):
            raise DisplayFilterError("Expected a field or search term after 'not'")
        field = tokens[position]
        position += 1
        if field.lower() == "contains":
            if position >= len(tokens):
                raise DisplayFilterError("Expected a safe text value after 'contains'")
            term = tokens[position].lower()
            position += 1
            predicate = lambda row: term in " ".join(
                str(row.get(key) or "") for key in ("summary", "src", "dst", "proto", "app_protocol")
            ).lower()
            return (lambda row: not predicate(row)) if negate else predicate
        if position < len(tokens) and tokens[position].lower() in _OPERATORS:
            operator = tokens[position].lower()
            position += 1
            if position >= len(tokens):
                raise DisplayFilterError(f"Expected a value after '{operator}'")
            expected = tokens[position]
            position += 1
            predicate = lambda row: _compare(_value(row, field), operator, expected)
        else:
            term = field.lower()
            predicate = lambda row: term in " ".join(
                str(row.get(key) or "") for key in ("summary", "src", "dst", "proto", "app_protocol")
            ).lower()
        return (lambda row: not predicate(row)) if negate else predicate

    groups = [[parse_atom()]]
    while position < len(tokens):
        connector = tokens[position].lower()
        position += 1
        if connector not in {"and", "or"}:
            raise DisplayFilterError(f"Expected 'and' or 'or', got '{connector}'")
        atom = parse_atom()
        if connector == "and":
            groups[-1].append(atom)
        else:
            groups.append([atom])

    return lambda row: any(all(predicate(row) for predicate in group) for group in groups)


def apply_display_filter(items: list[dict[str, Any]], expression: str) -> list[dict[str, Any]]:
    predicate = compile_display_filter(expression)
    return [item for item in items if predicate(item)]


def filter_help() -> dict[str, Any]:
    return {
        "operators": sorted(_OPERATORS),
        "boolean": ["and", "or", "not"],
        "fields": sorted(set(_ALIASES) | {"app_protocol", "risk", "contains"}),
        "examples": [
            "ip.src == 10.0.0.5",
            "tcp.port == 443 and protocol == TCP",
            'dns.qry.name contains "example"',
            "risk >= 60",
            'contains "login"',
        ],
        "safety": "Filters run only against redacted packet and flow metadata. Python eval is not used.",
    }
