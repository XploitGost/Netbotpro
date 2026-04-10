# core_sniffer.py
# -*- coding: utf-8 -*-
"""
Backward-compatible NetSniffer entrypoint.

This module keeps the old import path alive:
    from core_sniffer import NetSniffer

The implementation now lives in the netbotpro_sniffer_core package to keep
capture lifecycle, packet parsing, layer-7 extraction, and enrichment logic
separated and testable.
"""

from __future__ import annotations

from core.core_sniffer import NetSniffer, PacketCallback

__all__ = ["NetSniffer", "PacketCallback"]
