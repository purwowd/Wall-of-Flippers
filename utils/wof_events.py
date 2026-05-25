#!/usr/bin/python3
"""JSON-lines event output for automation."""

import json
import time

import utils.wof_cache as cache
import utils.wof_logging as wof_log


def emit(event_type, payload=None):
    payload = payload or {}
    event = {
        "ts": int(time.time()),
        "event": event_type,
        **payload,
    }
    line = json.dumps(event, ensure_ascii=False)
    if cache.wof_data.get("json_lines_mode"):
        print(line, flush=True)
    wof_log.info(f"{event_type} {payload}")
    if cache.wof_data.get("dashboard_mode"):
        try:
            from web import state as web_state
            web_state.push_event(event_type, payload)
        except ImportError:
            pass
