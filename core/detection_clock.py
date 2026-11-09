"""Use captured event time only for the ordered journal replay path."""
from datetime import datetime, timezone
import os


def detection_time(packet, fallback):
    if os.environ.get('NETBOT_CAPTURE_JOURNAL', '') != '1':
        return fallback
    value = packet.get('ts')
    if value is None or value == '':
        value = packet.get('timestamp')
    try:
        if type(value) in (int, float):
            return datetime.fromtimestamp(value, timezone.utc)
        if isinstance(value, str) and ('T' in value or ' ' in value):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    return fallback
