#!/usr/bin/python3
"""CSV export helpers for the web dashboard."""

import csv
import io

import utils.wof_storage as storage
from web import state as web_state


def snapshot_to_csv_rows():
    snap = web_state.get_snapshot()
    rows = []

    rows.append(["# Wall of Flippers export"])
    rows.append(["timestamp", snap.get("ts", "")])
    rows.append(["platform", snap.get("platform", "")])
    rows.append([])

    rows.append(["## BLE devices (last scan)"])
    rows.append(["name", "mac", "role", "rssi", "trust", "is_flipper"])
    for d in snap.get("ble_devices_all") or snap.get("ble_devices") or []:
        rows.append([
            d.get("name", ""),
            d.get("mac", ""),
            d.get("role", ""),
            d.get("rssi", ""),
            d.get("trust", ""),
            d.get("is_flipper", False),
        ])
    rows.append([])

    rows.append(["## Flippers online"])
    rows.append(["name", "mac", "trust", "rssi", "detection", "last_seen"])
    for d in snap.get("online") or []:
        rows.append([
            d.get("name"), d.get("mac"), d.get("trust"),
            d.get("rssi"), d.get("detection"), d.get("last_seen"),
        ])
    rows.append([])

    rows.append(["## Flippers offline (archive)"])
    rows.append(["name", "mac", "trust", "type", "first_seen", "last_seen"])
    for d in snap.get("offline") or []:
        rows.append([
            d.get("name"), d.get("mac"), d.get("trust"),
            d.get("type"), d.get("first_seen"), d.get("last_seen"),
        ])
    rows.append([])

    rows.append(["## Spam / suspicious"])
    rows.append(["type", "mac", "rssi", "packet"])
    for s in snap.get("spam") or []:
        rows.append([s.get("type"), s.get("mac"), s.get("rssi"), s.get("packet")])
    rows.append([])

    rows.append(["## Full flipper archive (db)"])
    rows.append(["name", "mac", "type", "trust", "detection", "rssi", "first_seen", "last_seen"])
    for entry in storage.get_archive():
        rows.append([
            entry.get("Name"),
            entry.get("MAC"),
            entry.get("Type"),
            entry.get("Trust"),
            entry.get("Detection Type"),
            entry.get("RSSI"),
            entry.get("unixFirstSeen"),
            entry.get("unixLastSeen"),
        ])

    return rows


def generate_csv_string():
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in snapshot_to_csv_rows():
        writer.writerow(row)
    return buffer.getvalue()
