"""Lossless, internal JSON compression; never deserializes executable objects."""
from collections import Counter
import json
import math
import zlib

DETAIL_FIELDS = frozenset({'timeline', 'related_alert_ids', 'sample_packets',
                           'metadata', 'service_attribution', 'alert_counts'})
PACKED_FIELD = '_cold_details_zlib'
ALERT_COUNT_FIELD = '_cold_alert_count'
RAW_BYTES_FIELD = '_cold_json_bytes'


def _json_tree(value, depth=0):
    if depth > 64:
        return False
    kind = type(value)
    if value is None or kind in (str, int, bool):
        return True
    if kind is float:
        return math.isfinite(value)
    if kind is list:
        return all(_json_tree(item, depth + 1) for item in value)
    if kind is dict:
        return all(type(key) is str and _json_tree(item, depth + 1)
                   for key, item in value.items())
    return False


def pack_flow(flow):
    source = dict(flow)
    source['alert_counts'] = dict(source.get('alert_counts') or {})
    if not _json_tree(source):
        raise ValueError('Flow contains noncanonical JSON values')
    raw = json.dumps(source, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    return zlib.compress(raw, level=1), len(raw)


def expand_flow(flow):
    if PACKED_FIELD not in flow:
        return flow
    restored = json.loads(zlib.decompress(flow[PACKED_FIELD]))
    restored['alert_counts'] = Counter(restored.get('alert_counts') or {})
    return restored


def alert_count(flow):
    return flow[ALERT_COUNT_FIELD] if PACKED_FIELD in flow else len(flow.get('related_alert_ids') or [])
