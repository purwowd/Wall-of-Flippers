#!/usr/bin/python3
"""Platform detection and capability flags for Wall of Flippers."""

import os
import sys

PLATFORM_LINUX = "linux"
PLATFORM_DARWIN = "darwin"
PLATFORM_WINDOWS = "windows"

FLIPPER_MAC_PREFIXES = ("80:e1:26", "80:e1:27", "0c:fa:22")


def get_platform_kind() -> str:
    if sys.platform.startswith("linux"):
        return PLATFORM_LINUX
    if sys.platform == "darwin":
        return PLATFORM_DARWIN
    if os.name == "nt" or sys.platform == "win32":
        return PLATFORM_WINDOWS
    return PLATFORM_LINUX


def uses_bleak(platform_kind=None) -> bool:
    kind = platform_kind or get_platform_kind()
    return kind in (PLATFORM_DARWIN, PLATFORM_WINDOWS)


def uses_bluepy(platform_kind=None) -> bool:
    return (platform_kind or get_platform_kind()) == PLATFORM_LINUX


def requires_root(platform_kind=None) -> bool:
    return uses_bluepy(platform_kind)


def requires_linux_venv(platform_kind=None) -> bool:
    return (platform_kind or get_platform_kind()) == PLATFORM_LINUX


def supports_ble_advertiser(platform_kind=None) -> bool:
    return uses_bluepy(platform_kind)


def supports_ble_chat(platform_kind=None) -> bool:
    return uses_bluepy(platform_kind)


def supports_ble_attack_detection(platform_kind=None) -> bool:
    kind = platform_kind or get_platform_kind()
    return kind in (PLATFORM_LINUX, PLATFORM_DARWIN, PLATFORM_WINDOWS)


def platform_display_name(platform_kind=None) -> str:
    names = {
        PLATFORM_LINUX: "Linux",
        PLATFORM_DARWIN: "macOS",
        PLATFORM_WINDOWS: "Windows",
    }
    return names.get(platform_kind or get_platform_kind(), "Unknown")
