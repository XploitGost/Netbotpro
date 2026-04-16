# -*- coding: utf-8 -*-
from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess

logger = logging.getLogger(__name__)


def block_ip(ip: str) -> bool:
    """
    Add a system firewall rule to block a remote IP.
    """
    if not ip:
        return False

    try:
        parsed = ipaddress.ip_address(ip)
    except Exception:
        logger.warning("firewall block rejected invalid ip=%s", ip)
        return False
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        logger.warning("firewall block rejected unsupported ip=%s", ip)
        return False

    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=NetBotPRO_Block_{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ]
        elif system == "linux":
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            logger.info("firewall block unsupported on system=%s ip=%s", system, ip)
            return False

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            text=True,
        )
        if proc.returncode != 0:
            logger.warning("firewall block failed ip=%s system=%s stderr=%s", ip, system, (proc.stderr or "").strip())
            return False
        logger.info("firewall block applied ip=%s system=%s", ip, system)
        return True
    except Exception:
        logger.exception("firewall block exception ip=%s", ip)
        return False
