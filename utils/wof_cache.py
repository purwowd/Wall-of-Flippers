#!/usr/bin/python3

import os
import random
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_ascii(filename):
    path = os.path.join(_PROJECT_ROOT, "ascii", filename)
    with open(path, "r", encoding="utf-8") as ascii_file:
        return ascii_file.read().encode("ascii", "ignore").decode("ascii")


wof_data = {
    "bool_isScanning": False,
    "system_type": None,
    "platform_kind": None,
    "config_path": None,
    "signatures_path": None,
    "found_flippers": [],
    "base_flippers": [],
    "live_flippers": [],
    "display_live": [],
    "display_offline": [],
    "cachedMessages": [],
    "narrow_mode": False,
    "badge_mode": False,
    "toggle_advertiser": False,
    "toggle_adveriser": False,
    "forbidden_packets_found": [],
    "all_packets_found": [],
    "duplicated_packets": [],
    "nearbyWof": [],
    "scan_ble_devices": [],
    "scan_seq": 0,

    "scan_interval_seconds": 5,
    "loop_sleep_seconds": 0.5,
    "archive_flush_interval_seconds": 30,
    "max_session_flippers": 200,
    "no_clear": False,
    "quiet_mode": False,
    "json_lines_mode": False,
    "anonymize_mac": False,
    "export_path": None,

    "narrow_mode_limit": 100,
    "max_online": 15,
    "max_offline": 15,
    "flipper_volume_price": 169,

    "max_flippers_ratelimited": 3,
    "ratelimit_seconds": 5,
    "last_ratelimit": time.time(),
    "is_ratelimited": False,

    "wof_advertiser": (0x1E, 0xFF, 0x2C, 0x22, 0x22, 0x22, 0x22, 0x22),
    "wof_advertiserName": f"WoF-{random.randint(1000, 9999)}",
    "wof_advertiserRaw": "2c2222222222",

    "wof_blechatAdvertiser": (0x1E, 0xFF, 0x2C, 0x22, 0x22, 0x24, 0x24, 0x24),
    "wof_bleAdvertiserRaw": "2c2222242424",
    "wof_displayName": "WoF-Guest",

    "flipper_types": {
        "00003081-0000-1000-8000-00805f9b34fb": "B",
        "00003082-0000-1000-8000-00805f9b34fb": "W",
        "00003083-0000-1000-8000-00805f9b34fb": "T",
    },

    "forbidden_packets": [],
    "max_ble_packets": 10,
    "max_ble_devices_display": 30,
    "rssi_history_max_points": 40,
    "rssi_history_max_devices": 50,
    "min_byte_length": 3,
    "max_byte_length": 450,
    "ble_threshold": 25,

    "dolphin_thinking": [
        "Let's hunt some flippers",
        "Ya'll like war driving flippers?",
        "Skid detector 9000",
        "macOS + Linux + Windows via Bleak",
        "Detection only — this does not stop attacks",
        "Hack the planet!",
        "WallofFlippers.py -h for headless flags",
    ],
    "init_directory_options": [
        {"option": "1", "action": "Wall of Flippers", "description": "Terminal wall (Default)", "return": "wall_of_flippers"},
        {"option": "2", "action": "Web Dashboard", "description": "FastAPI + Tailwind UI", "return": "web_dashboard"},
        {"option": "3", "action": "BLE Chat", "description": "Chat via BLE (Linux only)", "return": "wall_of_talking"},
        {"option": "4", "action": "Auto-Install", "description": "Install dependencies", "return": "install_dependencies"},
        {"option": "5", "action": "Exit", "description": "....", "return": "exit"},
    ],
    "ascii_normal": _load_ascii("normal.txt"),
    "ascii_small": _load_ascii("small.txt"),
}
