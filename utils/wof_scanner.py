#!/usr/bin/python3
"""Unified BLE scanning for Linux (bluepy), macOS, and Windows (bleak)."""

import asyncio

import utils.wof_cache as cache
import utils.wof_library as library
import utils.wof_platform as platform

_bleak_loop = None


def _scan_timeout():
    return float(cache.wof_data.get("scan_interval_seconds", 5))


def _get_bleak_loop():
    global _bleak_loop
    if _bleak_loop is None or _bleak_loop.is_closed():
        _bleak_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_bleak_loop)
    return _bleak_loop


def scan_ble(platform_kind, hci_device=0):
    if platform.uses_bluepy(platform_kind):
        return _scan_linux(hci_device)
    return _scan_bleak()


def _scan_linux(hci_device):
    from bluepy.btle import Scanner

    hci = library.normalize_hci(hci_device)
    scanner = Scanner(hci)
    devices = scanner.scan(int(_scan_timeout()))
    ble_packets = []
    if devices:
        for device in devices:
            ble_packets.append(library.flipper2Validation(device, platform.PLATFORM_LINUX))
    return ble_packets


def _scan_bleak():
    loop = _get_bleak_loop()
    return loop.run_until_complete(_scan_bleak_async())


async def _scan_bleak_async():
    from bleak import BleakScanner

    ble_packets = []
    timeout = _scan_timeout()
    try:
        discovered = await BleakScanner.discover(timeout=timeout, return_adv=True)
    except TypeError:
        devices = await BleakScanner.discover(timeout=timeout)
        for device in devices:
            ble_packets.append(library.flipper2Validation_bleak(device, None))
        return ble_packets

    if not discovered:
        return ble_packets

    for _addr, (device, adv_data) in discovered.items():
        ble_packets.append(library.flipper2Validation_bleak(device, adv_data))
    return ble_packets
