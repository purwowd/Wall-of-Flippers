#!/usr/bin/python3
"""In-memory RSSI time series for web charts."""

import time

import utils.wof_cache as cache

# mac -> list of {ts, rssi, name}
_history = {}


def record_scan(devices):
    """Append RSSI samples from scan_ble_devices list."""
    global _history
    now = int(time.time())
    scan_seq = cache.wof_data.get("scan_seq", 0)
    max_points = cache.wof_data.get("rssi_history_max_points", 40)
    max_devices = cache.wof_data.get("rssi_history_max_devices", 50)

    for device in devices:
        mac = device.get("mac")
        rssi = device.get("rssi")
        if not mac or not isinstance(rssi, (int, float)):
            continue
        if mac not in _history:
            if len(_history) >= max_devices:
                oldest = min(_history.keys(), key=lambda m: _history[m][-1]["seq"] if _history[m] else 0)
                del _history[oldest]
            _history[mac] = []
        series = _history[mac]
        if series and series[-1]["seq"] == scan_seq:
            series[-1]["rssi"] = int(rssi)
            series[-1]["name"] = device.get("name", series[-1].get("name", ""))
            series[-1]["ts"] = now
        else:
            series.append({
                "seq": scan_seq,
                "ts": now,
                "rssi": int(rssi),
                "name": device.get("name", ""),
            })
        if len(series) > max_points:
            _history[mac] = series[-max_points:]


def get_history(mac=None):
    if mac:
        return {mac: list(_history.get(mac, []))}
    return {m: list(s) for m, s in _history.items()}


def get_chart_series(limit=8):
    """Top devices by most recent RSSI for multi-line chart."""
    ranked = []
    for mac, series in _history.items():
        if not series:
            continue
        ranked.append((mac, series[-1]["rssi"], series))
    ranked.sort(key=lambda x: x[1], reverse=True)
    out = []
    for mac, _rssi, series in ranked[:limit]:
        out.append({
            "mac": mac,
            "name": series[-1].get("name") or mac,
            "points": series,
        })
    return out


def clear():
    global _history
    _history = {}
