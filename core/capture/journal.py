"""Windows-user-encrypted bounded metadata journal; batches acknowledged after analysis."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from functools import lru_cache
import json
import os
from pathlib import Path
import sqlite3
import threading
import zlib


class JournalFull(RuntimeError):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


@lru_cache(maxsize=1)
def _dpapi_functions():
    if os.name != 'nt':
        raise RuntimeError('Capture journal requires Windows DPAPI; plaintext fallback forbidden')
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    protect = crypt.CryptProtectData
    protect.argtypes = [ctypes.POINTER(_Blob), ctypes.c_wchar_p, ctypes.c_void_p,
                        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    protect.restype = wintypes.BOOL
    unprotect = crypt.CryptUnprotectData
    unprotect.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    unprotect.restype = wintypes.BOOL
    return protect, unprotect, kernel.LocalFree


def _protect(data: bytes, decrypt=False) -> bytes:
    protect, unprotect, free = _dpapi_functions()
    memory = ctypes.create_string_buffer(data)
    source = _Blob(len(data), ctypes.cast(memory, ctypes.POINTER(ctypes.c_ubyte)))
    destination = _Blob()
    if decrypt:
        ok = unprotect(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination))
    else:
        ok = protect(ctypes.byref(source), 'NetBotPro capture metadata', None, None, None, 1, ctypes.byref(destination))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(destination.data, destination.size)
    finally:
        free(ctypes.cast(destination.data, ctypes.c_void_p))


class CaptureJournal:
    def __init__(self, path, *, max_bytes=1024*1024*1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max(1, int(max_bytes))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY AUTOINCREMENT, count INTEGER NOT NULL, payload BLOB NOT NULL)')
        self._db.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL, records INTEGER NOT NULL)')
        self._db.execute('INSERT OR IGNORE INTO budget VALUES (1,0,0)')
        self._db.commit()

    def append(self, packets):
        if not packets:
            return
        payload = _protect(zlib.compress(json.dumps(packets, ensure_ascii=True).encode(), 1))
        with self._lock:
            try:
                self._db.execute('BEGIN IMMEDIATE')
                size = self._db.execute('SELECT bytes FROM budget WHERE id=1').fetchone()[0]
                if size + len(payload) > self.max_bytes:
                    raise JournalFull('Encrypted capture journal is full; capture must stop')
                self._db.execute('INSERT INTO batches(count,payload) VALUES (?,?)', (len(packets), payload))
                self._db.execute('UPDATE budget SET bytes=bytes+?, records=records+? WHERE id=1', (len(payload), len(packets)))
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def first(self):
        with self._lock:
            row = self._db.execute('SELECT id,payload FROM batches ORDER BY id LIMIT 1').fetchone()
        return (row[0], json.loads(zlib.decompress(_protect(row[1], decrypt=True)))) if row else None

    def acknowledge(self, identifier):
        with self._lock, self._db:
            row = self._db.execute('SELECT length(payload), count FROM batches WHERE id=?', (identifier,)).fetchone()
            if row:
                self._db.execute('DELETE FROM batches WHERE id=?', (identifier,))
                self._db.execute('UPDATE budget SET bytes=bytes-?,records=records-? WHERE id=1', row)

    def stats(self):
        with self._lock:
            size, count = self._db.execute('SELECT bytes,records FROM budget WHERE id=1').fetchone()
        return dict(journal_pending_records=count, journal_pending_bytes=size,
                    journal_max_payload_bytes=self.max_bytes)

    def close(self):
        with self._lock:
            self._db.close()
