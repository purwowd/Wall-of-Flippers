#!/usr/bin/python3
"""RSSI → distance / pseudo-bearing helpers for radar UI (single-antenna estimate)."""


def rssi_to_distance_m(rssi, tx_power=-59, path_loss_n=2.2):
    """
    Log-distance path loss: d ≈ 10^((TxPower - RSSI) / (10*n)).
    Returns meters clamped 0.3–40 (approximate, not trilateration).
    """
    if not isinstance(rssi, (int, float)):
        return None
    try:
        exponent = (float(tx_power) - float(rssi)) / (10.0 * path_loss_n)
        dist = 10 ** exponent
        return round(max(0.3, min(40.0, dist)), 1)
    except (ValueError, OverflowError):
        return None


def mac_bearing_deg(mac):
    """Stable pseudo-bearing 0–360° (no AoA — spreads contacts on radar)."""
    h = 0
    for ch in str(mac or ""):
        h = ((h << 5) - h + ord(ch)) & 0xFFFFFFFF
    return float(h % 360)
