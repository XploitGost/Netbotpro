from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from .interfaces import ensure_capture_backend, interface_local_ips, recommended_interface_name, resolve_capture_interface
from .packet_parser import PacketLayers, PacketMetadataBuilder

logger = logging.getLogger(__name__)

PacketCallback = Callable[[dict[str, Any]], None]


class NetSniffer:
    def __init__(
        self,
        packet_callback: PacketCallback,
        enable_geoip: bool = True,
        enable_mac_vendor: bool = True,
        geoip_provider: Any | None = None,
        mac_vendor_provider: Any | None = None,
        process_mapper: Any | None = None,
        sniff_func: Callable[..., Any] | None = None,
        sniff_poll_seconds: float = 1.0,
        iface_resolver: Callable[[], str | None] | None = None,
        candidate_resolver: Callable[[str | None], str | None] | None = None,
    ) -> None:
        self.packet_callback = packet_callback
        self.enable_geoip = enable_geoip
        self.enable_mac_vendor = enable_mac_vendor
        self._sniff_func = sniff_func
        self._iface_resolver = iface_resolver or self._default_iface_resolver
        self._candidate_resolver = candidate_resolver or resolve_capture_interface
        self._poll_seconds = max(0.2, float(sniff_poll_seconds))
        self._geoip_provider = geoip_provider
        self._mac_vendor_provider = mac_vendor_provider
        self._process_mapper = process_mapper
        self._layers: PacketLayers | None = None
        self._builder: PacketMetadataBuilder | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False
        self._stop_event = threading.Event()
        self._iface: str | None = None

    def start(self, iface: str | None = None, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            iface = self._resolve_iface(iface, args, kwargs)
            if self._running:
                return
            self._iface = iface
            self._builder = None
            self._running = True
            self._stop_event.clear()
            logger.info("starting sniffer on iface=%s", iface or "<scapy-default>")
            self._thread = threading.Thread(
                target=self._sniff_loop,
                kwargs={"iface": iface},
                daemon=True,
                name="NetSnifferLoop",
            )
            self._thread.start()

    def start_sniffer(self, iface: str | None = None, *args: Any, **kwargs: Any) -> None:
        self.start(iface=iface, *args, **kwargs)

    def run(self, iface: str | None = None, *args: Any, **kwargs: Any) -> None:
        self.start(iface=iface, *args, **kwargs)

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None
        if thread and thread.is_alive():
            thread.join(timeout=max(3.0, self._poll_seconds + 1.0))

    def selected_iface(self) -> str | None:
        with self._lock:
            return self._iface

    def _sniff_loop(self, iface: str | None) -> None:
        try:
            sniff_func = self._sniff_callable()
            while self._should_run():
                sniff_func(
                    iface=iface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=self._poll_seconds,
                    stop_filter=lambda _pkt: self._stop_event.is_set(),
                )
        except Exception:
            logger.exception("sniff loop crashed")
        finally:
            with self._lock:
                self._running = False
                self._stop_event.set()

    def _sniff_callable(self) -> Callable[..., Any]:
        if self._sniff_func is not None:
            return self._sniff_func

        ensure_capture_backend()
        from scapy.config import conf  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.sendrecv import sniff  # type: ignore

        conf.l2types.register(1, Ether)
        self._sniff_func = sniff
        return sniff

    def _handle_packet(self, pkt: Any) -> None:
        if not self._should_run():
            return
        try:
            meta = self._packet_builder().build(pkt)
            self.packet_callback(meta)
        except Exception:
            logger.exception("packet callback pipeline failed")

    def _should_run(self) -> bool:
        with self._lock:
            return self._running and not self._stop_event.is_set()

    def _resolve_iface(self, iface: str | None, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
        if iface is None and args:
            try:
                iface = args[0]
            except Exception:
                iface = None
        if iface is None:
            iface = kwargs.get("interface") or kwargs.get("ifname") or kwargs.get("dev") or kwargs.get("device")
        if iface in ("iface=default", "default", "", None):
            resolved = self._iface_resolver()
            if resolved:
                return resolved
            return None
        candidate = str(iface).strip()
        resolved = self._candidate_resolver(candidate)
        if resolved:
            return resolved
        logger.warning("invalid capture interface requested: %s; falling back to recommended", candidate)
        fallback = self._iface_resolver()
        return fallback or None

    @staticmethod
    def _default_iface_resolver() -> str | None:
        return recommended_interface_name()

    def _packet_builder(self) -> PacketMetadataBuilder:
        if self._builder is not None:
            return self._builder

        from scapy.layers.dns import DNS, DNSQR  # type: ignore
        from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore

        self._layers = PacketLayers(
            Ether=Ether,
            IP=IP,
            TCP=TCP,
            UDP=UDP,
            ICMP=ICMP,
            DNS=DNS,
            DNSQR=DNSQR,
        )
        self._builder = PacketMetadataBuilder(
            layers=self._layers,
            enable_geoip=self.enable_geoip,
            enable_mac_vendor=self.enable_mac_vendor,
            local_ips=interface_local_ips(self.selected_iface()),
            geoip_provider=self._geoip_provider,
            mac_vendor_provider=self._mac_vendor_provider,
            process_mapper=self._process_mapper,
        )
        return self._builder
