#!/usr/bin/python3
"""Thread-safe state for the web dashboard."""

import threading
import time
from collections import deque

_lock = threading.Lock()
_snapshot = {
    "ts": 0,
    "platform": "—",
    "scanning": False,
    "stats": {"online": 0, "offline": 0, "spam_packets": 0},
    "online": [],
    "offline": [],
    "spam": [],
    "nearby_wof": [],
}
_events = deque(maxlen=100)
_worker_running = False
_last_error = None


def set_snapshot(data):
    global _snapshot
    with _lock:
        _snapshot = data


def get_snapshot():
    with _lock:
        return dict(_snapshot)


def push_event(event_type, payload=None):
    entry = {
        "ts": int(time.time()),
        "event": event_type,
        **(payload or {}),
    }
    with _lock:
        _events.append(entry)
    return entry


def get_events_since(ts=0):
    with _lock:
        return [e for e in list(_events) if e.get("ts", 0) > ts]


def set_worker_running(running):
    global _worker_running
    with _lock:
        _worker_running = running


def is_worker_running():
    with _lock:
        return _worker_running


def set_last_error(msg):
    global _last_error
    with _lock:
        _last_error = msg


def get_status():
    with _lock:
        return {
            "worker_running": _worker_running,
            "last_error": _last_error,
            "snapshot_ts": _snapshot.get("ts", 0),
        }
