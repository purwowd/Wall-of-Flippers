#!/usr/bin/python3
"""Scan cycle and dashboard snapshot for CLI and web."""

import time

import utils.wof_cache as cache
import utils.wof_library as library
import utils.wof_scanner as wof_scanner
import utils.wof_storage as storage
import utils.wof_platform as wof_platform
import utils.wof_rssi_history as rssi_history
import utils.wof_rssi_geo as rssi_geo


def clear_cycle_buffers():
    cache.wof_data["forbidden_packets_found"] = []
    cache.wof_data["all_packets_found"] = []
    cache.wof_data["duplicated_packets"] = []
    cache.wof_data["nearbyWof"] = []
    cache.wof_data["scan_ble_devices"] = []
    cache.wof_data["live_flippers"] = []


def _ble_devices_for_snapshot():
    """All BLE devices seen in the last scan cycle."""
    rows = []
    tx_power = cache.wof_data.get("ble_tx_power_dbm", -59)
    path_loss_n = cache.wof_data.get("ble_path_loss_n", 2.2)
    for device in cache.wof_data.get("scan_ble_devices", []):
        raw_mac = device.get("mac", "")
        rssi = device.get("rssi")
        rows.append({
            "name": device.get("name", "Unknown"),
            "mac": library.format_mac(raw_mac),
            "mac_raw": raw_mac,
            "rssi": rssi,
            "rssi_num": rssi if isinstance(rssi, (int, float)) else None,
            "is_flipper": device.get("is_flipper", False),
            "role": device.get("role", "BLE"),
            "trust": device.get("trust", "—"),
            "est_distance_m": rssi_geo.rssi_to_distance_m(rssi, tx_power, path_loss_n),
            "bearing_deg": rssi_geo.mac_bearing_deg(raw_mac),
        })
    rows.sort(
        key=lambda row: (
            0 if row.get("is_flipper") else 1,
            -(row["rssi"] if isinstance(row.get("rssi"), (int, float)) else -999),
        ),
    )
    return rows


def _flipper_row(entry, online):
    mac = library.format_mac(entry.get("MAC", ""))
    raw_mac = entry.get("MAC", "")
    unix_last = int(entry.get("unixLastSeen", 0) or 0)
    rssi = entry.get("RSSI", "—")
    rssi_num = rssi if isinstance(rssi, (int, float)) else None
    now = int(time.time())
    return {
        "name": entry.get("Name", "UNK").replace("Flipper ", "")[:15],
        "mac": mac,
        "mac_raw": raw_mac,
        "type": entry.get("Type", "?"),
        "trust": entry.get("Trust", "?"),
        "detection": entry.get("Detection Type", "?"),
        "rssi": rssi,
        "rssi_num": rssi_num,
        "first_seen": library.unix2text(entry.get("unixFirstSeen", 0)),
        "last_seen": library.unix2text(entry.get("unixLastSeen", 0)),
        "last_seen_unix": unix_last,
        "last_seen_ago_sec": max(0, now - unix_last) if unix_last else None,
        "online": online,
    }


def build_snapshot(scan_meta=None):
    """Build JSON-serializable dashboard state from cache + archive."""
    scan_meta = scan_meta or {}
    archive = list(storage.get_archive())
    cache.wof_data["base_flippers"] = archive

    live_keys = {(f["MAC"], f["Name"]) for f in cache.wof_data["live_flippers"]}
    online = []
    offline = []

    for entry in archive:
        if "Type" not in entry:
            entry["Type"] = "Unknown"
        if "Trust" not in entry:
            entry["Trust"] = "Unknown"
        key = (entry["MAC"], entry["Name"])
        row = _flipper_row(entry, key in live_keys)
        if key in live_keys:
            online.append(row)
        else:
            offline.append(row)

    online.sort(key=lambda r: r.get("last_seen", ""), reverse=True)
    offline.sort(key=lambda r: r.get("last_seen", ""), reverse=True)

    spam = []
    for item in cache.wof_data["forbidden_packets_found"][: cache.wof_data["max_ble_packets"]]:
        spam.append({
            "type": item.get("Type", "?"),
            "mac": library.format_mac(item.get("MAC", "")),
            "rssi": str(item.get("RSSI", "N/A")),
            "packet": str(item.get("PCK", ""))[:80],
        })

    platform_kind = cache.wof_data.get("platform_kind") or wof_platform.get_platform_kind()
    ratelimit_remaining = max(0, int(cache.wof_data["last_ratelimit"] - time.time()))
    ble_all = _ble_devices_for_snapshot()
    ble_devices = ble_all[: cache.wof_data.get("max_ble_devices_display", 30)]
    flipper_price = cache.wof_data["flipper_volume_price"]
    archive_total = len(online) + len(offline)

    spam_types = sorted({s["type"] for s in spam if s.get("type")})

    return {
        "ts": int(time.time()),
        "platform": wof_platform.platform_display_name(platform_kind),
        "platform_kind": platform_kind,
        "scanning": cache.wof_data["bool_isScanning"],
        "ratelimited": cache.wof_data["is_ratelimited"],
        "ratelimit_seconds_left": ratelimit_remaining if cache.wof_data["is_ratelimited"] else 0,
        "stats": {
            "online": len(online),
            "offline": len(offline),
            "ble_devices": len(cache.wof_data.get("scan_ble_devices", [])),
            "spam_packets": len(cache.wof_data["forbidden_packets_found"]),
            "ble_packets": len(cache.wof_data["all_packets_found"]),
            "nearby_wof": len(cache.wof_data["nearbyWof"]),
            "archive_est_usd": archive_total * flipper_price,
            "flipper_unit_price": flipper_price,
        },
        "online": online[: cache.wof_data["max_online"]],
        "offline": offline[: cache.wof_data["max_offline"]],
        "ble_devices": ble_devices,
        "ble_devices_all": ble_all,
        "spam": spam,
        "spam_types": spam_types,
        "nearby_wof": list(cache.wof_data["nearbyWof"]),
        "rssi_charts": rssi_history.get_chart_series(),
        "scan": scan_meta,
    }


def run_scan_cycle(hci_device=0):
    """Run one BLE scan cycle; return dashboard snapshot dict."""
    cache.wof_data["bool_isScanning"] = True
    cache.wof_data["scan_seq"] = cache.wof_data.get("scan_seq", 0) + 1
    scan_meta = {"ok": True, "message": None, "seq": cache.wof_data["scan_seq"]}
    try:
        platform_kind = cache.wof_data["platform_kind"]
        packets = wof_scanner.scan_ble(platform_kind, hci_device)
        (
            any_found,
            _found_list,
            latest,
            total_new,
            ratelimited,
        ) = library.ble2Sort(packets)

        if ratelimited:
            scan_meta["ok"] = True
            scan_meta["ratelimited"] = True
            scan_meta["message"] = (
                f"Ratelimit: {total_new}+ new flippers — possible spoofing"
            )
        elif any_found and latest:
            scan_meta["latest"] = {
                "name": latest.get("Name"),
                "mac": library.format_mac(latest.get("MAC", "")),
                "trust": latest.get("Trust"),
            }

        rssi_history.record_scan(cache.wof_data.get("scan_ble_devices", []))
        snapshot = build_snapshot(scan_meta)
        clear_cycle_buffers()
        return snapshot
    except Exception as err:
        scan_meta["ok"] = False
        scan_meta["message"] = str(err)
        snapshot = build_snapshot(scan_meta)
        clear_cycle_buffers()
        return snapshot
    finally:
        cache.wof_data["bool_isScanning"] = False
