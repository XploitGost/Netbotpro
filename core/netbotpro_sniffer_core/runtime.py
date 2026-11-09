from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Callable

from .interfaces import capture_target, ensure_capture_backend, interface_local_ips, recommended_interface_name, resolve_capture_interface
from .packet_parser import PacketLayers, PacketMetadataBuilder
from .pcap_session import DriverStats, PcapBinding
from .deferred_enrichment import default_deferred_provider
from .route_probe import RouteProbe

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
        self._started_at: float | None = None
        self._last_error = ""
        self._capture_filter: str | None = None
        self._auto_interface = True
        self._route_warning = ""
        self._route_switches = 0
        self._route_candidate: str | None = None
        self._route_candidate_hits = 0
        self._driver_stats = DriverStats()
        self._pcap_binding = None
        self._last_raw_buffers = []
        self._callback_failures = 0
        self._owned_enrichment = []
        self._last_enrichment_stats = {}
        self._capture_packets = 0
        self._capture_timings = deque(maxlen=256)

    def start(self, iface: str | None = None, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            if self._running:
                return
            requested = iface if iface is not None else (args[0] if args else None)
            if requested is None:
                requested = kwargs.get("interface") or kwargs.get("ifname") or kwargs.get("dev") or kwargs.get("device")
            self._auto_interface = requested in ("iface=default", "default", "", None)
            iface = self._resolve_iface(iface, args, kwargs)
            self._sniff_callable()
            selected = iface
            iface, self._capture_filter = self._capture_binding(iface)
            self._iface = selected
            self._builder = None
            self._running = True
            self._started_at = time.time()
            self._last_error = ""
            self._route_warning = ""
            self._route_switches = 0
            self._route_candidate = None
            self._route_candidate_hits = 0
            self._driver_stats = DriverStats()
            self._callback_failures = 0
            self._capture_packets = 0
            self._capture_timings.clear()
            self._last_enrichment_stats = {}
            self._last_raw_buffers = []
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
            # The child must not close its journal while accepted raw frames drain.
            thread.join()

    def selected_iface(self) -> str | None:
        with self._lock:
            return self._iface

    def is_running(self) -> bool:
        with self._lock:
            return self._running and self._thread is not None and self._thread.is_alive()

    def capture_status(self) -> dict[str, Any]:
        with self._lock:
            running = self._running and self._thread is not None and self._thread.is_alive()
            driver = self._driver_stats.snapshot()
            if running and not driver['active_handles']:
                driver['coverage_complete'] = False
            raw = self._pcap_binding.raw_status() if self._pcap_binding is not None else self._last_raw_buffers
            raw_pressure = any(item['queued_bytes'] >= item['capacity_bytes']*.8 or
                               item['queued_frames'] >= item['capacity_frames']*.8 for item in raw)
            return {"running": running, "capture_started_at": self._started_at,
                    "elapsed_seconds": max(0.0, time.time() - self._started_at) if running and self._started_at else 0.0,
                    "capture_error": self._last_error,
                    "selected_iface": self._iface,
                    "auto_interface": self._auto_interface,
                    "route_switches": self._route_switches,
                    "route_warning": self._route_warning,
                    "driver_stats": driver,
                    "raw_buffers": raw, "raw_buffer_pressure": raw_pressure,
                    "capture_callback_errors": self._callback_failures,
                    "optional_enrichment": self._enrichment_stats_locked(),
                    "capture_profile": self._capture_profile_locked(),
                    "health": "critical" if self._last_error else "degraded" if running and (raw_pressure or self._route_warning or self._callback_failures or driver['buffer_dropped_reported']) else "healthy" if running else "idle"}

    def _close_enrichment(self):
        with self._lock:
            providers = [(name, getattr(self, name)) for name in self._owned_enrichment]
            self._owned_enrichment.clear()
            for name, provider in providers:
                setattr(self, name, None)
        results = {}
        for name, provider in providers:
            results[name.lstrip('_')] = provider.stats()
            provider.close()
        with self._lock:
            self._last_enrichment_stats = results

    def _enrichment_stats_locked(self):
        current = {name.lstrip('_'): getattr(self, name).stats() for name in self._owned_enrichment}
        return current or {key: dict(value) for key, value in self._last_enrichment_stats.items()}

    def _capture_profile_locked(self):
        cutoff = time.monotonic()-60
        samples = [item for item in self._capture_timings if item[0] >= cutoff]
        result = dict(sample_every=127, seen_packets=self._capture_packets, samples=len(samples))
        for index, label in ((1, 'metadata'), (2, 'emit')):
            values = sorted(item[index] for item in samples)
            result[label + '_p50_ms'] = round(values[len(values)//2], 3) if values else None
            result[label + '_p95_ms'] = round(values[min(len(values)-1, int(len(values)*.95))], 3) if values else None
            result[label + '_max_ms'] = round(values[-1], 3) if values else None
        return result

    def _close_binding(self):
        binding = self._pcap_binding
        if binding is not None:
            try:
                binding.drain(lambda packet: self._handle_packet(packet, draining=True))
            finally:
                self._last_raw_buffers = binding.raw_status()
                binding.close()
                self._pcap_binding = None

    def _capture_binding(self, selected):
        target, capture_filter = capture_target(selected)
        if self._sniff_func is not None and self._sniff_func.__module__.startswith("scapy"):
            from scapy.interfaces import resolve_iface
            target = [resolve_iface(item).network_name for item in target] if isinstance(target, list) else resolve_iface(target).network_name
        return target, capture_filter

    def _refresh_capture_target(self, current):
        return self._apply_capture_observation(current, self._observe_capture_target())

    def _observe_capture_target(self):
        selected = None
        try:
            selected = self._iface_resolver() if self._auto_interface else self.selected_iface()
            if not selected:
                raise ValueError("No active network route; waiting for connection")
            target, capture_filter = self._capture_binding(selected)
            return selected, target, capture_filter, ''
        except Exception as exc:
            return selected, None, None, "Waiting for capture adapter: " + type(exc).__name__ + ": " + str(exc)

    def _apply_capture_observation(self, current, observation):
        selected, target, capture_filter, error = observation
        try:
            # Two consecutive observations avoid following a transient VPN route.
            if self._auto_interface and selected and selected != self.selected_iface():
                if selected != self._route_candidate:
                    self._route_candidate, self._route_candidate_hits = selected, 1
                else:
                    self._route_candidate_hits += 1
                if self._route_candidate_hits < 2:
                    return current, True
            else:
                self._route_candidate, self._route_candidate_hits = None, 0
            if error:
                with self._lock:
                    self._route_warning = error
                self._route_candidate, self._route_candidate_hits = None, 0
                return current, False
            changed = selected != self._iface or target != current or capture_filter != self._capture_filter
            if changed:
                self._close_binding()
            with self._lock:
                if changed:
                    self._route_switches += 1
                    self._iface = selected
                    self._capture_filter = capture_filter
                    self._builder = None
                    logger.info("capture rebound to iface=%s", selected)
                self._route_warning = ""
            return target, True
        except Exception as exc:
            with self._lock:
                self._route_warning = "Waiting for capture adapter: " + type(exc).__name__ + ": " + str(exc)
            self._route_candidate, self._route_candidate_hits = None, 0
            return current, False

    def _sniff_loop(self, iface: str | None) -> None:
        route_probe = None
        try:
            sniff_func = self._sniff_callable()
            if sniff_func.__module__.startswith('scapy'):
                route_probe = RouteProbe(self._observe_capture_target)
            next_route_check = time.monotonic() + 2.0
            ready = True
            while self._should_run():
                if route_probe is not None:
                    observation = route_probe.take()
                    if observation is not None:
                        iface, ready = self._apply_capture_observation(iface, observation)
                elif time.monotonic() >= next_route_check:
                    next_route_check = time.monotonic() + 2.0
                    iface, ready = self._refresh_capture_target(iface)
                if not ready:
                    self._close_binding()
                    self._stop_event.wait(.2)
                    continue
                try:
                    arguments = {'iface': iface, **({'filter': self._capture_filter} if self._capture_filter else {})}
                    if sniff_func.__module__.startswith('scapy'):
                        if self._pcap_binding is None or not self._pcap_binding.matches(iface, self._capture_filter):
                            self._close_binding()
                            # Imports and adapter discovery must finish before the
                            # driver starts buffering traffic, not on packet one.
                            self._packet_builder()
                            self._pcap_binding = PcapBinding(iface, self._capture_filter, self._driver_stats)
                        arguments = self._pcap_binding.sniff_arguments()
                    sniff_func(
                        **arguments,
                        prn=lambda packet: self._handle_packet(packet, draining=True),
                        store=False,
                        timeout=self._poll_seconds,
                        stop_filter=lambda _pkt: self._stop_event.is_set(),
                    )
                    if self._pcap_binding is not None:
                        self._pcap_binding.sample()
                        if self._pcap_binding.is_closed():
                            raise OSError('Capture driver closed its socket')
                    with self._lock:
                        self._route_warning = ""
                except Exception as exc:
                    from scapy.error import Scapy_Exception
                    if not self._auto_interface or not isinstance(exc, (OSError, ValueError, Scapy_Exception)):
                        raise
                    with self._lock:
                        self._route_warning = "Capture adapter reconnecting: " + type(exc).__name__ + ": " + str(exc)
                    self._builder = None
                    self._close_binding()
                    ready = False
                    self._stop_event.wait(.2)
        except Exception as exc:
            with self._lock:
                self._last_error = type(exc).__name__ + ": " + str(exc)
            logger.exception("sniff loop crashed")
        finally:
            if route_probe is not None:
                route_probe.close()
            try:
                self._close_binding()
            except Exception as exc:
                with self._lock:
                    self._last_error = 'Capture drain failed: ' + type(exc).__name__
            self._close_enrichment()
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

    def _handle_packet(self, pkt: Any, *, draining=False) -> None:
        if not draining and not self._should_run():
            return
        try:
            self._capture_packets += 1
            # Coprime with the32-record writer batch: avoid sampling only flushes.
            sample = self._capture_packets % 127 == 0
            started = time.perf_counter() if sample else 0
            meta = self._packet_builder().build(pkt)
            built = time.perf_counter() if sample else 0
            self.packet_callback(meta)
            if sample:
                end = time.perf_counter()
                with self._lock:
                    self._capture_timings.append((time.monotonic(), (built-started)*1000, (end-built)*1000))
        except Exception:
            with self._lock:
                self._callback_failures += 1
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
        raise ValueError("Capture interface is unavailable: " + candidate)

    @staticmethod
    def _default_iface_resolver() -> str | None:
        return recommended_interface_name()

    def _packet_builder(self) -> PacketMetadataBuilder:
        if self._builder is not None:
            return self._builder

        for name in ('_geoip_provider', '_mac_vendor_provider', '_process_mapper'):
            with self._lock:
                if getattr(self, name) is None:
                    enabled = self.enable_geoip if name == '_geoip_provider' else self.enable_mac_vendor if name == '_mac_vendor_provider' else True
                    setattr(self, name, default_deferred_provider(name, enabled=enabled))
                    self._owned_enrichment.append(name)

        from scapy.layers.dns import DNS, DNSQR  # type: ignore
        from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
        from scapy.layers.inet6 import IPv6, _ICMPv6
        from scapy.layers.l2 import Ether, ARP  # type: ignore

        self._layers = PacketLayers(
            Ether=Ether,
            IP=IP,
            TCP=TCP,
            UDP=UDP,
            ICMP=ICMP,
            DNS=DNS,
            DNSQR=DNSQR,
            IPv6=IPv6, ARP=ARP, ICMPv6=_ICMPv6,
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
