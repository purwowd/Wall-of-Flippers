#!/usr/bin/python3
"""Load config/signatures and merge into runtime cache."""

import json
import os

import utils.wof_cache as cache

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(_PROJECT_ROOT, "config", "wof.defaults.json")
DEFAULT_SIGNATURES = os.path.join(_PROJECT_ROOT, "config", "signatures.json")

_CONFIG_KEYS = {
    "scan_interval_seconds",
    "loop_sleep_seconds",
    "archive_flush_interval_seconds",
    "max_session_flippers",
    "max_flippers_ratelimited",
    "ratelimit_seconds",
    "ble_threshold",
    "max_online",
    "max_offline",
    "anonymize_mac",
    "flipper_volume_price",
    "max_ble_devices_display",
    "rssi_history_max_points",
    "rssi_history_max_devices",
    "max_ble_packets",
    "min_byte_length",
    "max_byte_length",
    "narrow_mode_limit",
    "badge_mode",
    "toggle_advertiser",
}


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_signatures(path=None):
    sig_path = path or DEFAULT_SIGNATURES
    if os.path.isfile(sig_path):
        cache.wof_data["forbidden_packets"] = _load_json(sig_path)
        cache.wof_data["signatures_path"] = sig_path


def apply_config(config_path=None):
    """Merge defaults + user config into wof_data."""
    merged = {}
    if os.path.isfile(DEFAULT_CONFIG):
        merged.update(_load_json(DEFAULT_CONFIG))
    if config_path and os.path.isfile(config_path):
        merged.update(_load_json(config_path))
        cache.wof_data["config_path"] = config_path

    for key, value in merged.items():
        if key in _CONFIG_KEYS:
            cache.wof_data[key] = value
        if key == "toggle_adveriser":
            cache.wof_data["toggle_advertiser"] = value

    sig_override = merged.get("signatures_path")
    load_signatures(sig_override)
    if "forbidden_packets" not in cache.wof_data or not cache.wof_data["forbidden_packets"]:
        load_signatures()

    # Legacy typo support
    if cache.wof_data.get("toggle_adveriser") and not cache.wof_data.get("toggle_advertiser"):
        cache.wof_data["toggle_advertiser"] = cache.wof_data["toggle_adveriser"]
