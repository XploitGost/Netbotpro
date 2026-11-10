"""Versioned journal occurrence identity, not content hashing or a trust certificate."""
import re


_EVENT_ID = re.compile(r'cap-v1:[0-9a-f]{32}:[1-9][0-9]*:[0-9]+', re.ASCII)


def valid_capture_event_id(value: object) -> str | None:
    if isinstance(value, str) and len(value) <= 96 and _EVENT_ID.fullmatch(value):
        return value
    return None
