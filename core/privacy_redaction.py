from __future__ import annotations

import re

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


def redact_sensitive_text(value: str) -> str:
    text = str(value or "")
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


def redact_sensitive_data(value):
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {
                "authorization",
                "proxy_authorization",
                "cookie",
                "set_cookie",
                "password",
                "passwd",
                "token",
                "access_token",
                "refresh_token",
                "api_key",
                "apikey",
                "secret",
                "session",
                "sessionid",
                "jwt",
            }:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_data(item) for item in value]
    return value
