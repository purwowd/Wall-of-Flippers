#!/usr/bin/python3
"""Atomic persistence and in-memory archive for Flipper.json."""

import json
import os
import time

try:
    import fcntl
except ImportError:
    fcntl = None

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(_PROJECT_ROOT, "db")
FLIPPER_PATH = os.path.join(DB_DIR, "Flipper.json")
BACKUP_PATH = os.path.join(DB_DIR, "Backup.json")

_archive_cache = None
_last_flush = 0


def ensure_db():
    os.makedirs(DB_DIR, exist_ok=True)
    if not os.path.isfile(FLIPPER_PATH):
        _atomic_write(FLIPPER_PATH, [])
    if not os.path.isfile(BACKUP_PATH):
        _atomic_write(BACKUP_PATH, [])


def _atomic_write(path, data):
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        json.dump(data, handle, indent=4)
        handle.flush()
        os.fsync(handle.fileno())
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    os.replace(temp_path, path)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            return json.load(handle)
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_archive(force=False):
    global _archive_cache
    if _archive_cache is not None and not force:
        return _archive_cache
    ensure_db()
    try:
        _archive_cache = _read_json(FLIPPER_PATH)
    except (OSError, json.JSONDecodeError):
        try:
            _archive_cache = _read_json(BACKUP_PATH)
            _atomic_write(FLIPPER_PATH, _archive_cache)
        except (OSError, json.JSONDecodeError):
            _archive_cache = []
    return _archive_cache


def get_archive():
    return load_archive()


def flush_archive(force=False, flush_interval=30):
    global _last_flush, _archive_cache
    if _archive_cache is None:
        return
    now = time.time()
    if not force and (now - _last_flush) < flush_interval:
        return
    ensure_db()
    _atomic_write(FLIPPER_PATH, _archive_cache)
    _atomic_write(BACKUP_PATH, _archive_cache)
    _last_flush = now


def find_existing(mac, name):
    for entry in get_archive():
        if entry.get("MAC") == mac and entry.get("Name") == name:
            return entry
    return None


def persist_flipper(record, flush_interval=30):
    """Upsert flipper record; preserve unixFirstSeen from archive."""
    global _archive_cache
    archive = get_archive()
    mac = record["MAC"]
    name = record["Name"]
    existing = find_existing(mac, name)
    if existing:
        first_seen = existing.get("unixFirstSeen", record.get("unixFirstSeen"))
        existing.update({
            "RSSI": str(record["RSSI"]),
            "Detection Type": record["Detection Type"],
            "unixLastSeen": record["unixLastSeen"],
            "Name": name,
            "Type": record.get("Type", existing.get("Type", "Unknown")),
            "Trust": record.get("Trust", existing.get("Trust", "Unknown")),
        })
        if "UID" in record:
            existing["UID"] = record["UID"]
    else:
        archive.append({
            "Name": name,
            "RSSI": str(record["RSSI"]),
            "MAC": mac,
            "Detection Type": record["Detection Type"],
            "unixLastSeen": record["unixLastSeen"],
            "unixFirstSeen": record.get("unixFirstSeen", record["unixLastSeen"]),
            "Type": record.get("Type", "Unknown"),
            "UID": record.get("UID", ""),
            "Trust": record.get("Trust", "Unknown"),
        })
    flush_archive(force=False, flush_interval=flush_interval)
    return existing is None
