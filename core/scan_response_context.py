"""Bounded request/reply hints for scan evidence, not a TCP state machine."""
from collections import OrderedDict
from datetime import timedelta


class ScanResponseContext:
    def __init__(self, max_flows=8192, idle_seconds=60):
        self.max_flows = max(1, int(max_flows))
        self.idle_seconds = max(1, int(idle_seconds))
        self._flows = OrderedDict()
        self.correlated_total = 0
        self.evictions_total = 0

    def reset(self):
        self._flows.clear()
        self.correlated_total = self.evictions_total = 0

    def expire(self, now):
        cutoff = now - timedelta(seconds=self.idle_seconds)
        for key, (_, last) in list(self._flows.items()):
            if last < cutoff:
                del self._flows[key]

    def observe(self, packet, now, flags):
        proto = packet.get('proto')
        if proto != 'TCP':
            return False
        src, dst = str(packet.get('src') or ''), str(packet.get('dst') or '')
        scope = str(packet.get('iface') or packet.get('interface') or '')
        if not src or not dst or max(len(src), len(dst)) > 128 or len(scope) > 256:
            return False
        try:
            sport, dport = int(packet['sport']), int(packet['dport'])
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
            return False
        key = (proto, src, sport, dst, dport, scope)
        reverse = (proto, dst, dport, src, sport, scope)
        cutoff = now - timedelta(seconds=self.idle_seconds)
        known = self._flows.get(key)
        response_flags = 'A' in flags or 'R' in flags
        is_response = bool(response_flags and known and known[0] <= now and known[1] >= cutoff)
        if is_response:
            self._flows[key] = (known[0], max(known[1], now))
            self._flows.move_to_end(key)
            self.correlated_total += 1
        if 'R' in flags:
            self._flows.pop(key, None)
            self._flows.pop(reverse, None)
            return is_response and not ('S' in flags and 'A' not in flags)
        # Reverse traffic is a hint, not a validated TCP connection. A probe
        # remains evidence; its RST response must not exempt subsequent probes.
        initial_syn = 'S' in flags and 'A' not in flags
        if 'R' not in flags:
            previous = self._flows.get(reverse)
            if previous and previous[1] >= cutoff:
                self._flows[reverse] = (min(previous[0], now), max(previous[1], now))
            else:
                self._flows[reverse] = (now, now)
            self._flows.move_to_end(reverse)
            while len(self._flows) > self.max_flows:
                self._flows.popitem(last=False)
                self.evictions_total += 1
        return is_response and not initial_syn

    def stats(self):
        return {'tracked_flows': len(self._flows), 'max_flows': self.max_flows,
                'idle_seconds': self.idle_seconds,
                'correlated_responses_total': self.correlated_total,
                'capacity_evictions_total': self.evictions_total}
