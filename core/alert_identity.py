"""Versioned detection-occurrence keys; no payload or mutable-score hashing."""
import hashlib
import json
import re

from core.capture.identity import valid_capture_event_id


_RULE = re.compile(r'[a-z0-9_.:-]{1,160}', re.ASCII)
_VERSION = re.compile(r'[a-zA-Z0-9_.-]{1,32}', re.ASCII)
_ALERT = re.compile(r'alert-v1:[0-9a-f]{64}', re.ASCII)


def valid_alert_event_id(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) == 73 and _ALERT.fullmatch(value) else None


def alert_occurrence_id(packet_event: object, rule: object, version: object, ordinal: int) -> str | None:
    if (valid_capture_event_id(packet_event) is None
            or not isinstance(rule, str) or not _RULE.fullmatch(rule)
            or not isinstance(version, str) or not _VERSION.fullmatch(version)
            or type(ordinal) is not int or not 0 <= ordinal <= 65535):
        return None
    encoded = json.dumps([packet_event, rule, version, ordinal], ensure_ascii=True,
                         separators=(',', ':')).encode('ascii')
    return 'alert-v1:' + hashlib.sha256(encoded).hexdigest()


def custom_rule_key(family: str, position: int, name: str, source: str,
                    port: int, window: int, threshold: int) -> str:
    # Position separates identical user rules; effective configuration scopes edits.
    encoded = json.dumps([position, str(name), source, port, window, threshold],
                         ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return family + ':' + hashlib.sha256(encoded).hexdigest()
