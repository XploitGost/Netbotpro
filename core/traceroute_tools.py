# traceroute_tools.py
# -*- coding: utf-8 -*-
"""Traceroute helper (Windows + Linux/Kali)

Changes in this patch:
- Supports mode selection on Linux: ICMP / UDP / TCP
- Supports timeout / max_hops / queries / port
- Supports cancel_event (best-effort) for UI Stop/Cancel button
- More robust parsing for Linux traceroute output, including '* * *'
"""

import platform
import subprocess
import re
import shutil
import time
from typing import List, Dict, Any, Optional

from core.geoip_tools import geoip_lookup


def _parse_rtt_ms(txt: str) -> Optional[float]:
    """
    متن مثل "<1 ms" یا "181 ms" را به float برمی‌گرداند.
    اگر نشد → None
    """
    if not txt:
        return None
    m = re.search(r"(\d+)\s*ms", txt)
    if not m:
        return None
    try:
        return float(m.group(1))
    except Exception:
        return None


def _safe_float(x: str) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def run_traceroute(
    target: str,
    mode: str = "UDP",
    timeout: float = 1.5,
    max_hops: int = 30,
    queries: int = 1,
    port: int = 443,
    cancel_event=None,
) -> List[Dict[str, Any]]:
    """
    خروجی: list[
      {
        hop: int|None,
        ip: str,
        rtt_ms: float|None,
        rtt1_ms: float|None,
        rtt2_ms: float|None,
        rtt3_ms: float|None,
        country_code: str|None,
        country_name: str|None,
        city: str|None,
        org: str|None,
        isp: str|None,
        route: str|None,
        asn: str|None,
      }
    ]

    NOTE:
    - Windows: uses tracert (no TCP/UDP selection)
    - Linux: uses traceroute with -I / -T / UDP default
    - cancel_event: threading.Event-like (must have is_set()).
    """
    target = (target or "").strip()
    if not target:
        return []

    # sanitize numeric params
    try:
        timeout_f = float(timeout)
    except Exception:
        timeout_f = 1.5
    timeout_f = max(0.2, min(10.0, timeout_f))

    try:
        mh = int(max_hops)
    except Exception:
        mh = 30
    mh = max(1, min(64, mh))

    try:
        q = int(queries)
    except Exception:
        q = 1
    q = max(1, min(5, q))

    try:
        p = int(port)
    except Exception:
        p = 443
    p = max(1, min(65535, p))

    system = platform.system().lower()
    if system == "windows":
        traceroute_bin = shutil.which("tracert")
        if not traceroute_bin:
            return []
        # tracert: -d no DNS, -h hops, -w timeout(ms)
        cmd = [traceroute_bin, "-d", "-h", str(mh), "-w", str(int(timeout_f * 1000)), target]
    else:
        traceroute_bin = shutil.which("traceroute")
        if not traceroute_bin:
            return []
        m_upper = (mode or "UDP").strip().upper()
        cmd = [
            traceroute_bin,
            "-n",
            "-m",
            str(mh),
            "-w",
            str(timeout_f),
            "-q",
            str(q),
        ]
        if m_upper.startswith("ICMP") or m_upper in ("I", "ICMP"):
            cmd.append("-I")
        elif m_upper.startswith("TCP") or m_upper in ("T", "TCP"):
            cmd.append("-T")
            cmd += ["-p", str(p)]
        else:
            # UDP default
            cmd += ["-p", str(p)]
        cmd.append(target)

    # ---- Run process with streaming output (cancel-able) ----
    output_lines: List[str] = []
    max_runtime = min(140.0, max(20.0, mh * timeout_f * q * 1.8))
    t0 = time.time()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as e:
        return [{
            "hop": 0,
            "ip": f"ERROR: {e}",
            "rtt_ms": None,
            "rtt1_ms": None,
            "rtt2_ms": None,
            "rtt3_ms": None,
            "country_code": None,
            "country_name": None,
            "city": None,
            "org": None,
            "isp": None,
            "route": None,
            "asn": None,
        }]

    try:
        while True:
            # cancel
            try:
                if cancel_event is not None and hasattr(cancel_event, "is_set") and cancel_event.is_set():
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
            except Exception:
                pass

            # timeout
            if time.time() - t0 > max_runtime:
                try:
                    proc.kill()
                except Exception:
                    pass
                break

            if proc.stdout is None:
                break

            line = proc.stdout.readline()
            if line:
                output_lines.append(line)
                continue

            if proc.poll() is not None:
                break

            time.sleep(0.03)
    finally:
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass

    output = "".join(output_lines)

    # ---- Parse output (reuse structure expected by UI) ----
    hops: List[Dict[str, Any]] = []
    system_is_windows = (system == "windows")

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        hop_no: Optional[int] = None
        ip = ""
        rtt1 = rtt2 = rtt3 = None

        if system_is_windows:
            # مثال: "  1    90 ms    92 ms    88 ms  192.168.1.1"
            m = re.match(
                r"(\d+)\s+([\d<\sms*]+)\s+([\d<\sms*]+)\s+([\d<\sms*]+)\s+(\S+)",
                line,
            )
            if not m:
                if "Request timed out" in line:
                    hops.append({
                        "hop": None,
                        "ip": "Request timed out",
                        "rtt_ms": None,
                        "rtt1_ms": None,
                        "rtt2_ms": None,
                        "rtt3_ms": None,
                        "country_code": None,
                        "country_name": None,
                        "city": None,
                        "org": None,
                        "isp": None,
                        "route": None,
                        "asn": None,
                    })
                continue

            hop_no = int(m.group(1))
            ip = m.group(5)
            rtt1 = _parse_rtt_ms(m.group(2))
            rtt2 = _parse_rtt_ms(m.group(3))
            rtt3 = _parse_rtt_ms(m.group(4))

        else:
            # Linux traceroute -n lines:
            # 1  192.168.1.1  1.234 ms  1.111 ms  1.098 ms
            # 2  * * *
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue
            hop_no = int(parts[0])

            if len(parts) >= 2 and parts[1] == "*":
                ip = "*"
                rtt1 = rtt2 = rtt3 = None
            else:
                ip = parts[1] if len(parts) >= 2 else ""
                ms_vals = [_safe_float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
                ms_vals = [v for v in ms_vals if v is not None]
                rtt1 = ms_vals[0] if len(ms_vals) > 0 else None
                rtt2 = ms_vals[1] if len(ms_vals) > 1 else None
                rtt3 = ms_vals[2] if len(ms_vals) > 2 else None

        rtts = [v for v in (rtt1, rtt2, rtt3) if v is not None]
        rtt_avg = sum(rtts) / len(rtts) if rtts else None

        country_code = country_name = city = org = isp = route = asn = None
        if ip and ip[0].isdigit():
            try:
                g = geoip_lookup(ip)
                if g:
                    country_code = g.get("country_code")
                    country_name = g.get("country_name")
                    city = g.get("city")
                    org = g.get("org")
                    isp = g.get("isp")
                    route = g.get("route")
                    asn = g.get("asn")
            except Exception:
                pass

        hops.append(
            {
                "hop": hop_no,
                "ip": ip,
                "rtt_ms": rtt_avg,
                "rtt1_ms": rtt1,
                "rtt2_ms": rtt2,
                "rtt3_ms": rtt3,
                "country_code": country_code,
                "country_name": country_name,
                "city": city,
                "org": org,
                "isp": isp,
                "route": route,
                "asn": asn,
            }
        )

    return hops
