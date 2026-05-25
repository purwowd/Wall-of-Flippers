#!/usr/bin/python3

import json
import shutil

import utils.wof_cache as cache
import utils.wof_library as library
import utils.wof_platform as wof_platform
import utils.wof_storage as storage


def isLive(mac, string):
    for key in cache.wof_data['live_flippers']:
        if key['MAC'] == mac and key['Name'] == string:
            return True
    return False


def _export_snapshot():
    export_path = cache.wof_data.get("export_path")
    if not export_path:
        return
    snapshot = {
        "platform": cache.wof_data.get("platform_kind"),
        "online": cache.wof_data['display_live'],
        "offline": cache.wof_data['display_offline'],
        "spam": cache.wof_data['forbidden_packets_found'],
        "nearby_wof": cache.wof_data['nearbyWof'],
    }
    with open(export_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2)


def display(custom_text=None):
    if cache.wof_data.get("quiet_mode") or cache.wof_data.get("json_lines_mode"):
        if custom_text:
            print(custom_text, flush=True)
        storage.flush_archive(
            force=False,
            flush_interval=cache.wof_data.get("archive_flush_interval_seconds", 30),
        )
        return

    cache.wof_data['base_flippers'] = list(storage.get_archive())

    for key in cache.wof_data['base_flippers']:
        if 'Type' not in key:
            key['Type'] = "Unknown"
        if 'Trust' not in key:
            key['Trust'] = "Unknown"
        is_online = isLive(key['MAC'], key['Name'])
        key['Name'] = key['Name'].replace("Flipper ", "")[:15]
        display_mac = library.format_mac(key['MAC'])
        row = dict(key)
        row['MAC'] = display_mac
        if is_online:
            cache.wof_data['display_live'].append(row)
        else:
            cache.wof_data['display_offline'].append(row)

    t_allignment = 8
    ble_spamming_macs = []
    number_of_total_blacklisted_packets = len(cache.wof_data['forbidden_packets_found'])
    number_of_total_ble_packets = len(cache.wof_data['all_packets_found'])
    number_of_flippers_online = len(cache.wof_data['display_live'])
    number_of_flippers_offline = len(cache.wof_data['display_offline'])

    if shutil.get_terminal_size().columns < cache.wof_data['narrow_mode_limit']:
        cache.wof_data['narrow_mode'] = True
    else:
        cache.wof_data['narrow_mode'] = False

    if custom_text is None or custom_text == "":
        library.print_ascii_art(None)
    else:
        library.print_ascii_art(custom_text)

    platform_kind = cache.wof_data.get("platform_kind") or wof_platform.get_platform_kind()
    bleak_limited = platform_kind in (wof_platform.PLATFORM_DARWIN, wof_platform.PLATFORM_WINDOWS)
    print(f"Platform.........................: {wof_platform.platform_display_name(platform_kind)}")

    if wof_platform.supports_ble_attack_detection(platform_kind):
        if not cache.wof_data['badge_mode']:
            mode_note = " (Bleak — some packets may be missed)" if bleak_limited else ""
            print(
                f"Latest Forbidden Advertisements..: {number_of_total_blacklisted_packets}\n"
                f"Latest Advertisements............: {number_of_total_ble_packets}{mode_note}"
            )
            if len(cache.wof_data['all_packets_found']) > 0:
                packet_counts = {}
                addrs = []
                for packet in cache.wof_data['all_packets_found']:
                    packet_value = packet['PCK']
                    packet_counts[packet_value] = packet_counts.get(packet_value, 0) + 1
                most_common_packet = max(packet_counts, key=packet_counts.get)
                for packet in cache.wof_data['all_packets_found']:
                    if packet['PCK'] == most_common_packet:
                        if packet['MAC'] not in addrs:
                            addrs.append(packet['MAC'])
                    if len(packet['PCK']) > cache.wof_data['max_byte_length']:
                        cache.wof_data['forbidden_packets_found'].append({
                            "MAC": library.format_mac(packet['MAC']),
                            "PCK": packet['PCK'],
                            "Type": f"SUSPICIOUS_PACKET (+{cache.wof_data['max_byte_length']} bytes)",
                        })
                print(
                    f"Most Common Advertisement........: {most_common_packet} "
                    f"({packet_counts[most_common_packet]} packets) ({len(addrs)} unique addresses)"
                )
                if len(addrs) > 5:
                    cache.wof_data['forbidden_packets_found'].append({
                        "MAC": str(len(addrs)) + " Unique Addresses",
                        "PCK": most_common_packet,
                        "Type": "SUSPICIOUS_ADVERTISEMENT",
                    })
            else:
                print("Most Common Advertisement........: None")
            if len(cache.wof_data['forbidden_packets_found']) > 0:
                t_packets = 0
                print(
                    "\n\n[!] Wall of Flippers >> These packets may not be related to the Flipper Zero.\n"
                    "[NAME]\t\t\t\t\t[RSSI]\t[ADDR]\t\t   [PACKET]"
                )
                print(shutil.get_terminal_size().columns * "-")
                for key in cache.wof_data['forbidden_packets_found']:
                    if ble_spamming_macs.count(key['MAC']) == 0:
                        ble_spamming_macs.append(key['MAC'])
                        t_packets += 1
                        if t_packets <= cache.wof_data['max_ble_packets']:
                            rssi_value = str(key.get('RSSI', 'N/A'))
                            mac_show = library.format_mac(key['MAC'])
                            print(
                                f"{key['Type'].ljust(t_allignment)}\t\t"
                                f"{rssi_value.ljust(t_allignment)}{mac_show.ljust(t_allignment)}  "
                                f"{str(key['PCK']).ljust(t_allignment)}"
                            )
                if number_of_total_blacklisted_packets > cache.wof_data['ble_threshold']:
                    print(
                        f"------------------ Bluetooth Low Energy (BLE) Attacks Detected "
                        f"({number_of_total_blacklisted_packets} Advertisements) --------------------"
                    )

    print(
        f"\nTotal Online.....................: {number_of_flippers_online}\n"
        f"Total Offline....................: {number_of_flippers_offline}"
    )
    archive_est = (number_of_flippers_online + number_of_flippers_offline) * cache.wof_data['flipper_volume_price']
    ble_nearby = len(cache.wof_data.get('scan_ble_devices', []))
    print(f"BLE devices (this scan)..........: {ble_nearby}")
    print(
        f"Archive est. value...............: ${archive_est} "
        f"({number_of_flippers_online + number_of_flippers_offline} × ${cache.wof_data['flipper_volume_price']} meme stat)"
    )
    print(f"WoF Instances Nearby.............: {cache.wof_data['nearbyWof']}")

    if cache.wof_data['narrow_mode']:
        print("\n\nFlipper, Address, First Seen, Last Seen, RSSI, Detection, Trust")
    else:
        print(
            f"\n\n[FLIPPER]{''.ljust(t_allignment)}[ADDR]{''.ljust(t_allignment)}\t\t"
            f"[FIRST]{''.ljust(t_allignment)}[LAST]{''.ljust(t_allignment)}[RSSI]\t[DETECTION] [TRUST]"
        )
    print("-" * shutil.get_terminal_size().columns)

    if number_of_flippers_online > 0:
        t_live = 0
        cache.wof_data['display_live'] = sorted(
            cache.wof_data['display_live'], key=lambda k: k['unixLastSeen'], reverse=True
        )
        for key in cache.wof_data['display_live']:
            t_live += 1
            if t_live <= cache.wof_data['max_online']:
                key['RSSI'] = f"{key['RSSI']} dBm"
                trust_val = key.get('Trust', '?')
                if cache.wof_data['narrow_mode']:
                    print(
                        f"{key['Name']}, {key['MAC']}, {library.unix2text(key['unixFirstSeen'])}, "
                        f"{library.unix2text(key['unixLastSeen'])}, {key['RSSI']}, "
                        f"{key['Detection Type']} ({key['Type']}) [{trust_val}]"
                    )
                else:
                    print(
                        f"{key['Name'].ljust(t_allignment)}\t{key['MAC'].ljust(t_allignment)}\t"
                        f"{library.unix2text(key['unixFirstSeen']).ljust(t_allignment)}\t"
                        f"{library.unix2text(key['unixLastSeen']).ljust(t_allignment)}     "
                        f"{str(key['RSSI']).ljust(t_allignment)}\t{key['Detection Type']} "
                        f"({key['Type']}) [{trust_val}]"
                    )
            if t_live > cache.wof_data['max_online']:
                t_left_over = number_of_flippers_online - cache.wof_data['max_online']
                print(f"Too many <online> devices to display. ({t_left_over} devices)")
                break

    if number_of_flippers_offline > 0 and not cache.wof_data['badge_mode']:
        t_offline = 0
        print("\033[2m".center(shutil.get_terminal_size().columns))
        cache.wof_data['display_offline'] = sorted(
            cache.wof_data['display_offline'], key=lambda k: k['unixLastSeen'], reverse=True
        )
        for key in cache.wof_data['display_offline']:
            t_offline += 1
            if t_offline <= cache.wof_data['max_offline']:
                key['RSSI'] = "Offline"
                trust_val = key.get('Trust', '?')
                if cache.wof_data['narrow_mode']:
                    print(
                        f"{key['Name']}, {key['MAC']}, {library.unix2text(key['unixFirstSeen'])}, "
                        f"{library.unix2text(key['unixLastSeen'])}, {key['RSSI']}, "
                        f"{key['Detection Type']} ({key['Type']}) [{trust_val}]"
                    )
                else:
                    print(
                        f"{key['Name'].ljust(t_allignment)}\t{key['MAC'].ljust(t_allignment)}\t"
                        f"{library.unix2text(key['unixFirstSeen']).ljust(t_allignment)}\t"
                        f"{library.unix2text(key['unixLastSeen']).ljust(t_allignment)}     "
                        f"{str(key['RSSI']).ljust(t_allignment)}\t{key['Detection Type']} "
                        f"({key['Type']}) [{trust_val}]"
                    )
            if t_offline > cache.wof_data['max_offline']:
                t_left_over = number_of_flippers_offline - cache.wof_data['max_offline']
                print(f"\033[0mToo many <offline> devices to display. ({t_left_over} devices)\033[0m")
                break
        print("\033[0m")

    if number_of_flippers_offline == 0 and number_of_flippers_online == 0:
        print("No devices detected, scanning...".center(shutil.get_terminal_size().columns))

    _export_snapshot()
    storage.flush_archive(
        force=False,
        flush_interval=cache.wof_data.get("archive_flush_interval_seconds", 30),
    )

    cache.wof_data['display_live'] = []
    cache.wof_data['display_offline'] = []
    cache.wof_data['live_flippers'] = []
    cache.wof_data['forbidden_packets_found'] = []
    cache.wof_data['all_packets_found'] = []
    cache.wof_data['duplicated_packets'] = []
    cache.wof_data['nearbyWof'] = []
