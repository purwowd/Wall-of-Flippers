#!/usr/bin/python3
"""Heuristic trust / spoof scoring for Flipper detections."""

import utils.wof_platform as platform


def trust_score(device_name, device_mac, device_uid, detection_type, device_color):
    """
    Returns: High | Medium | Low | Spoof?
    """
    score = 0

    if device_uid and device_uid != "UNK":
        score += 2
    if device_color in ("B", "W", "T"):
        score += 2
    elif device_color == "SPF":
        score -= 2

    if detection_type == "Name":
        score += 3
    elif detection_type == "Address":
        score += 2
    elif detection_type == "Identifier":
        score += 1

    if device_mac and device_mac.startswith(platform.FLIPPER_MAC_PREFIXES):
        score += 2

    if device_name and device_name.lower().startswith("flipper"):
        score += 1
    elif device_name and device_name != "UNK":
        score -= 1

    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 2:
        return "Low"
    return "Spoof?"
