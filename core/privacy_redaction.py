from __future__ import annotations

import re
import os

try:
    from core._privacy_walk import redact as _native_redact
except ImportError:
    _native_redact = None

SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)([^\r\n]*)"
)
SENSITIVE_TOKEN_RE = re.compile(r"(?i)\b(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]+")
SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|api_key|apikey|auth|authorization|code|password|passwd|pwd|secret|session|sessionid|token)=)[^&#\s]+"
)
SENSITIVE_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|api_key|apikey|secret|session|sessionid|jwt)\s*[:=]\s*[^&\s;,]+"
)
JWT_LIKE_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
SENSITIVE_CANDIDATE_PATTERN = (
    r"authorization|cookie|x-api-key|x-auth-token|basic|bearer|access_token|"
    r"refresh_token|api_key|apikey|auth|code|password|passwd|pwd|secret|session|token|jwt|eyj"
)
SENSITIVE_CANDIDATE_RE = re.compile(SENSITIVE_CANDIDATE_PATTERN, re.IGNORECASE)
SENSITIVE_ASCII_CANDIDATE_RE = re.compile(SENSITIVE_CANDIDATE_PATTERN)
SENSITIVE_ASCII_FAST_RE = re.compile(r"auth|cookie|basic|bearer|token|api|code|pass|pwd|secret|session|jwt|eyj")
SENSITIVE_ASCII_MARKERS = tuple(SENSITIVE_CANDIDATE_PATTERN.split("|"))
SENSITIVE_KEYS = frozenset({
    "authorization", "proxy_authorization", "cookie", "set_cookie",
    "password", "passwd", "token", "access_token", "refresh_token",
    "api_key", "apikey", "secret", "session", "sessionid", "jwt",
})


def redact_sensitive_text(value: str) -> str:
    text = str(value or "")
    # Every full redaction pattern contains one of these literal markers.
    if text.isascii():
        lowered = text.lower()
        candidate = SENSITIVE_ASCII_FAST_RE.search(lowered)
    else:
        candidate = SENSITIVE_CANDIDATE_RE.search(text)
    if not candidate:
        return text
    text = SENSITIVE_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = SENSITIVE_TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    text = SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", text)
    text = SENSITIVE_KV_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = JWT_LIKE_RE.sub("[REDACTED_JWT]", text)
    return text


def redact_http_path(value: str | None) -> str | None:
    if value is None:
        return None
    return redact_sensitive_text(str(value))


def redact_sensitive_data(value, *, empty_fields=frozenset()):
    # This bounded memo lives only for one traversal, never across packets.
    if _native_redact is not None and os.environ.get('NETBOT_NATIVE_REDACTION', '1') != '0':
        return _native_redact(value, redact_sensitive_text, _redact_sensitive_data,
                              SENSITIVE_KEYS, empty_fields, SENSITIVE_ASCII_FAST_RE.pattern)
    return _redact_sensitive_data(value, {}, empty_fields, {})


def redaction_backend() -> str:
    return 'native' if _native_redact is not None and os.environ.get('NETBOT_NATIVE_REDACTION', '1') != '0' else 'python'


def _redact_sensitive_data(value, text_memo, empty_fields, key_memo):
    if isinstance(value, str):
        if value in text_memo:
            return text_memo[value]
        result = redact_sensitive_text(value)
        if len(text_memo) < 256:
            text_memo[value] = result
        return result
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            classification = key_memo.get(key)
            if classification is None:
                lowered = str(key).lower()
                classification = 2 if lowered in empty_fields else int(lowered.replace("-", "_") in SENSITIVE_KEYS)
                if len(key_memo) < 128:
                    key_memo[key] = classification
            if classification == 2:
                redacted[key] = ""
                continue
            if classification == 1:
                redacted[key] = "[REDACTED]"
            elif item is None or type(item) in (int, float, bool):
                redacted[key] = item
            else:
                redacted[key] = _redact_sensitive_data(item, text_memo, empty_fields, key_memo)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_data(item, text_memo, empty_fields, key_memo) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive_data(item, text_memo, empty_fields, key_memo) for item in value]
    return value
