# geoip_tools.py
# -*- coding: utf-8 -*-
"""Lightweight GeoIP helper for NetBotPRO."""

from __future__ import annotations

import functools
import ipaddress
import threading
import time
from typing import Optional, Dict, Any

import requests


_MAX_HTTP_LOOKUPS = 500
_http_lookups_done = 0
_HTTP_TIMEOUT = 0.7
_RATE_LIMIT_RESET_AT = 0.0
_LOCK = threading.Lock()
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "NetBotPRO/1.0"})


_EMPTY_RESP: Dict[str, Any] = {
    "country": None,
    "country_name": None,
    "city": None,
    "org": None,
    "isp": None,
    "route": None,
    "asn": None,
    "lat": None,
    "lon": None,
}


def _is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _should_skip_http_lookup() -> bool:
    with _LOCK:
        if _http_lookups_done >= _MAX_HTTP_LOOKUPS:
            return True
        if _RATE_LIMIT_RESET_AT > time.time():
            return True
        return False


def _mark_rate_limit(response: requests.Response) -> None:
    global _RATE_LIMIT_RESET_AT
    remaining = response.headers.get("X-Rl")
    ttl = response.headers.get("X-Ttl")
    try:
        if remaining == "0" and ttl is not None:
            _RATE_LIMIT_RESET_AT = time.time() + max(1, int(ttl))
    except Exception:
        return


@functools.lru_cache(maxsize=4096)
def _geoip_http(ip: str) -> Dict[str, Any]:
    global _http_lookups_done
    if _should_skip_http_lookup():
        return dict(_EMPTY_RESP)

    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,country,countryCode,city,org,isp,as,asname,lat,lon,query"
    )
    try:
        response = _SESSION.get(url, timeout=_HTTP_TIMEOUT)
    except Exception:
        return dict(_EMPTY_RESP)

    _mark_rate_limit(response)
    if response.status_code != 200:
        return dict(_EMPTY_RESP)

    try:
        data = response.json()
    except Exception:
        return dict(_EMPTY_RESP)

    if data.get("status") != "success":
        return dict(_EMPTY_RESP)

    with _LOCK:
        _http_lookups_done += 1

    country_code = data.get("countryCode")
    country_name = data.get("country")
    city = data.get("city")
    org = data.get("org") or data.get("asname") or data.get("as")
    isp = data.get("isp")
    route = data.get("as") or data.get("asname")
    asn = None
    if isinstance(data.get("as"), str):
        parts = data["as"].split()
        for part in parts:
            if part.upper().startswith("AS") and len(part) > 2:
                asn = part
                break

    return {
        "country": country_code,
        "country_name": country_name,
        "city": city,
        "org": org,
        "isp": isp,
        "route": route,
        "asn": asn,
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }


def geoip_lookup(ip: str) -> Dict[str, Any]:
    if not ip or _is_private_ip(ip):
        return dict(_EMPTY_RESP)

    try:
        data = _geoip_http(ip)
    except Exception:
        data = dict(_EMPTY_RESP)

    result = dict(_EMPTY_RESP)
    result.update({k: data.get(k) for k in _EMPTY_RESP.keys()})
    return result
