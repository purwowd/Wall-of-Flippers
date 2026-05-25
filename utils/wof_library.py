#!/usr/bin/python3

#                               YAao,                            
#                                 Y8888b,                        Created By: Kiyomi & Jbohack
#                               ,oA8888888b,                     Kiyomi: https://ko-fi.com/k3yomi
#                         ,aaad8888888888888888bo,               Jbohack: https://ko-fi.com/jbohack
#                      ,d888888888888888888888888888b,               
#                    ,888888888888888888888888888888888b,            
#                   d8888888888888888888888888888888888888,                   
#                  d888888888888888888888888888888888888888b             
#                 d888888P'                    `Y88888888Ꙩ \,          
#                 88888P'                    Ybaaaa888888  Ꙩ l          
#                a8888'                      `Y8888P' `V888888    
#              d8888888a                                `Y8888           
#             AY/'' `\Y8b                                 ``Y8b
#             Y'      `YP                                    ~~
#     _       __      ____         ____   _________                           
#    | |     / /___ _/ / /  ____  / __/  / ____/ (_)___  ____  ___  __________
#    | | /| / / __ `/ / /  / __ \/ /_   / /_  / / / __ \/ __ \/ _ \/ ___/ ___/
#    | |/ |/ / /_/ / / /  / /_/ / __/  / __/ / / / /_/ / /_/ /  __/ /  (__  )
#    |__/|__/\__,_/_/_/   \____/_/    /_/   /_/_/ .___/ .___/\___/_/  /____/
#                                              /_/   /_/

# Standard library Imports
import os
import sys
import shutil
import random
import time
import json


# Wall of Flippers "library" for important functions and classes :3
import utils.wof_cache as cache
import utils.wof_platform as platform
import utils.wof_storage as storage
import utils.wof_trust as trust
import utils.wof_events as events


def log(s_table):
    """Backward-compatible alias for persist_flipper."""
    persist_flipper(s_table)


def persist_flipper(s_table):
    interval = cache.wof_data.get("archive_flush_interval_seconds", 30)
    return storage.persist_flipper(s_table, flush_interval=interval)


def format_mac(mac):
    if not mac or not cache.wof_data.get("anonymize_mac"):
        return mac
    parts = mac.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3]) + ":xx:xx:xx"
    return mac


def required2files():
    storage.ensure_db()
    storage.load_archive()
    cache.wof_data["base_flippers"] = list(storage.get_archive())
    

def unix2text(unix_timestamp:int):
    """converts a unix timestamp to a human readable format."""
    current_timestamp = int(time.time())
    t_different = current_timestamp - unix_timestamp
    t_minutes, t_seconds = divmod(t_different, 60)
    if t_minutes > 1000:
        t_hours, t_minutes = divmod(t_minutes, 60)
        if t_hours > 24:
            t_days, t_hours = divmod(t_hours, 24)
            if t_days > 1000:
                t_years, t_days = divmod(t_days, 365)
                return f"1Year+"
            return f"{t_days}d {t_hours}h"
        return f"{t_hours}h {t_minutes}m"
    return f"{t_minutes}m {t_seconds}s"

def ble2Sort(packets:list): # Sorts BLE packets and updates the list/cache
    """Sorts the BLE packets based on the type of packet"""
    any_flippers_discovered = False
    flippers_discovered_list = []
    latest_discovered_list = []
    suspiciousFlippers = []
    forbidden_packets_list = cache.wof_data['forbidden_packets']
    wof_advertiserRaw = cache.wof_data['wof_advertiserRaw']
    totalNewFound = 0
    totalNewFound = sum(1 for advertisement in packets if advertisement[0]["flipper"] and not any(flipper['MAC'] == advertisement[0]["address"] for flipper in cache.wof_data['base_flippers']))
    totalNewFoundArray = [advertisement[0] for advertisement in packets if advertisement[0]["flipper"] and not any(flipper['MAC'] == advertisement[0]["address"] for flipper in cache.wof_data['base_flippers'])]
    for advertisement in totalNewFoundArray: suspiciousFlippers.append(advertisement["address"])
    if (totalNewFound >= cache.wof_data['max_flippers_ratelimited'] and not cache.wof_data['is_ratelimited']):
        cache.wof_data['is_ratelimited'] = True 
        cache.wof_data['last_ratelimit'] = int(time.time()) + cache.wof_data['ratelimit_seconds']

    seen_ble_macs = set()
    cache.wof_data['scan_ble_devices'] = []
    for advertisement in packets:
        advertisement = advertisement[0]
        adv_name = advertisement["name"]
        adv_type = advertisement["color"]
        adv_rssi = advertisement["rssi"]
        adv_address = advertisement["address"]
        adv_packets = advertisement["packets"]
        adv_uid = advertisement["uid"]
        adv_isFlipper = advertisement["flipper"]
        adv_detection = advertisement["detection"]
        adv_trust = advertisement.get("trust", "—")
        if adv_address in suspiciousFlippers and cache.wof_data['is_ratelimited']:
            adv_isFlipper = False
        if adv_address and adv_address not in seen_ble_macs:
            seen_ble_macs.add(adv_address)
            if adv_name and adv_name != "UNK":
                display_name = adv_name
            else:
                short_mac = adv_address.replace(":", "")[-6:]
                display_name = f"BLE ···{short_mac}"
            cache.wof_data['scan_ble_devices'].append({
                "name": display_name,
                "mac": adv_address,
                "rssi": adv_rssi,
                "is_flipper": adv_isFlipper,
                "role": "Flipper" if adv_isFlipper else "BLE",
                "trust": adv_trust,
            })
        for packet in adv_packets:
            for forbidden_packet in forbidden_packets_list:
                if all(p1 == p2 or p2 == "_" for p1, p2 in zip(packet, forbidden_packet['PCK'])):
                    int_get_non_underscore = len(forbidden_packet['PCK'].replace("_", ""))
                    int_total_found = sum(p != "_" for p in packet)
                    if int_total_found >= int_get_non_underscore:
                        cache.wof_data['forbidden_packets_found'].append(
                            {"Type": forbidden_packet['TYPE'], "PCK": packet, "MAC": adv_address, "RSSI": adv_rssi}
                        )
            if len(packet) > cache.wof_data['min_byte_length']:
                cache.wof_data['all_packets_found'].append({"PCK": packet, "MAC": adv_address})
            if str(packet).startswith(wof_advertiserRaw):
                try:
                    decodedAdvertiser = bytes.fromhex(
                        packet.replace(wof_advertiserRaw, "")
                    ).decode("utf-8", errors="ignore").replace("\x00", "")
                    if decodedAdvertiser and decodedAdvertiser not in cache.wof_data['nearbyWof']:
                        cache.wof_data['nearbyWof'].append(decodedAdvertiser)
                except (ValueError, UnicodeDecodeError):
                    pass
        if adv_isFlipper:
            int_recorded = int(time.time())
            existing = storage.find_existing(adv_address, adv_name)
            first_seen = existing["unixFirstSeen"] if existing else int_recorded
            trust_label = trust.trust_score(adv_name, adv_address, adv_uid, adv_detection, adv_type)
            t_data = {
                "Name": adv_name,
                "RSSI": adv_rssi,
                "MAC": adv_address,
                "Detection Type": adv_detection,
                "unixLastSeen": int_recorded,
                "unixFirstSeen": first_seen,
                "Type": adv_type,
                "UID": adv_uid,
                "Trust": trust_label,
            }
            mac_key = adv_address.lower()
            is_new_session = True
            for flipper in cache.wof_data['found_flippers']:
                if flipper['MAC'].lower() == mac_key:
                    flipper.update({
                        "RSSI": adv_rssi,
                        "unixLastSeen": int_recorded,
                        "Trust": trust_label,
                    })
                    if adv_name and adv_name != "UNK" and flipper.get("Name") in (None, "", "UNK"):
                        flipper["Name"] = adv_name
                        t_data["Name"] = adv_name
                    is_new_session = False
                    break
            if is_new_session:
                cache.wof_data['found_flippers'].append(t_data)
                max_session = cache.wof_data.get("max_session_flippers", 200)
                if len(cache.wof_data['found_flippers']) > max_session:
                    cache.wof_data['found_flippers'] = cache.wof_data['found_flippers'][-max_session:]
                is_new = persist_flipper(t_data)
                cache.wof_data['base_flippers'] = list(storage.get_archive())
                events.emit("flipper_seen", {
                    "mac": format_mac(adv_address),
                    "name": adv_name if adv_name and adv_name != "UNK" else t_data.get("Name", "?"),
                    "trust": trust_label,
                    "new": is_new,
                })
            cache.wof_data['live_flippers'].append(t_data)
            any_flippers_discovered = True
            flippers_discovered_list.append(t_data)
            latest_discovered_list = t_data
    if (cache.wof_data['last_ratelimit'] < int(time.time())) and cache.wof_data['is_ratelimited']:
        cache.wof_data['is_ratelimited'] = False
    return any_flippers_discovered, flippers_discovered_list, latest_discovered_list, totalNewFound, cache.wof_data['is_ratelimited']

def _match_flipper_uid(value):
    """Return (uid, color, matched_known_type)."""
    if not value:
        return "UNK", "UNK", False
    normalized = value.lower()
    for key, color in cache.wof_data['flipper_types'].items():
        if key.lower() in normalized or normalized == key.lower():
            return key, color, True
    if normalized.startswith("0000308") and normalized.endswith("0000-1000-8000-00805f9b34fb"):
        return value, "SPF", True
    return "UNK", "UNK", False


def _classify_flipper(device_name, device_mac, device_uid):
    if device_uid == "UNK":
        return False, "Unknown"
    if device_name and device_name.lower().startswith("flipper"):
        return True, "Name"
    if device_mac and device_mac.startswith(platform.FLIPPER_MAC_PREFIXES):
        return True, "Address"
    return True, "Identifier"


def _build_device_record(
    device_name,
    device_mac,
    device_rssi,
    device_packets,
    device_uid,
    device_manufacturer,
    device_color,
    device_formatted,
    is_flipper,
    detection_type,
):
    return [{
        "name": device_name or "UNK",
        "address": device_mac or "UNK",
        "rssi": device_rssi,
        "packets": device_packets,
        "uid": device_uid,
        "manufacturer": device_manufacturer,
        "color": device_color,
        "genericdata": device_formatted,
        "detection": detection_type,
        "flipper": is_flipper,
    }]


def flipper2Validation_bleak(device, adv_data=None):
    """Validate a Bleak device (macOS / Windows)."""
    device_packets = []
    device_formatted = []
    device_name = device.name or "UNK"
    device_manufacturer = "UNK"
    device_uid = "UNK"
    device_color = "UNK"
    device_mac = str(device.address).lower()
    device_rssi = getattr(device, "rssi", None) or -100

    uids_blob = ""
    if adv_data is not None:
        if adv_data.local_name:
            device_name = adv_data.local_name
        if getattr(adv_data, "rssi", None) is not None:
            device_rssi = adv_data.rssi
        for uuid in adv_data.service_uuids or []:
            uids_blob += uuid.lower()
            device_packets.append(uuid.lower())
            uid, color, matched = _match_flipper_uid(uuid)
            if matched:
                device_uid = uid
                device_color = color
        for company_id, mfg_bytes in (adv_data.manufacturer_data or {}).items():
            hex_packet = f"{company_id:04x}{mfg_bytes.hex()}"
            device_packets.append(hex_packet)
            device_formatted.append({
                "ADTYPE": "mfg",
                "Description": "Manufacturer",
                "Value": hex_packet,
            })
        for service_uuid, svc_bytes in (adv_data.service_data or {}).items():
            hex_packet = f"{service_uuid.lower()}{svc_bytes.hex()}"
            device_packets.append(hex_packet)
            uid, color, matched = _match_flipper_uid(service_uuid)
            if matched:
                device_uid = uid
                device_color = color
    else:
        metadata = device.metadata or {}
        uids_blob = str(metadata.get("uuids", "")).replace("['", "").replace("']", "").lower()
        for uuid in metadata.get("uuids") or []:
            device_packets.append(str(uuid).lower())
            uid, color, matched = _match_flipper_uid(str(uuid))
            if matched:
                device_uid = uid
                device_color = color

    if device_uid == "UNK" and uids_blob:
        device_uid, device_color, _ = _match_flipper_uid(uids_blob)

    is_flipper, detection_type = _classify_flipper(device_name, device_mac, device_uid)
    trust_label = trust.trust_score(device_name, device_mac, device_uid, detection_type, device_color)
    records = _build_device_record(
        device_name,
        device_mac,
        device_rssi,
        device_packets,
        device_uid,
        device_manufacturer,
        device_color,
        device_formatted,
        is_flipper,
        detection_type,
    )
    records[0]["trust"] = trust_label
    return records


def flipper2Validation(data, platform_kind):
    """Validate a bluepy device (Linux)."""
    device_packets = []
    device_name = "UNK"
    device_manufacturer = "UNK"
    device_uid = "UNK"
    device_color = "UNK"
    device_formatted = []
    device_mac = data.addr.lower()
    device_rssi = data.rssi
    is_flipper = False
    detection_type = "Unknown"

    scan_list = data.getScanData()
    for scan_list_item in scan_list:
        device_formatted.append({
            "ADTYPE": scan_list_item[0],
            "Description": scan_list_item[1],
            "Value": scan_list_item[2],
        })

    for i_data in device_formatted:
        value = i_data["Value"]
        if i_data["Description"] == "Complete Local Name":
            device_name = value
        if i_data["Description"] == "Manufacturer":
            device_manufacturer = value
        uid, color, matched = _match_flipper_uid(value)
        if matched:
            device_uid = uid
            device_color = color
        device_packets.append(value)

    is_flipper, detection_type = _classify_flipper(device_name, device_mac, device_uid)
    records = _build_device_record(
        device_name,
        device_mac,
        device_rssi,
        device_packets,
        device_uid,
        device_manufacturer,
        device_color,
        device_formatted,
        is_flipper,
        detection_type,
    )
    records[0]["trust"] = trust.trust_score(device_name, device_mac, device_uid, detection_type, device_color)
    return records


def normalize_hci(device_arg):
    """Map hci0 / 0 / empty to HCI index integer."""
    if device_arg is None or device_arg == "":
        return 0
    value = str(device_arg).strip().lower()
    if value.startswith("hci"):
        return int(value[3:])
    return int(value)


def adapter2Selection(device_args=None):
    if not platform.uses_bluepy(cache.wof_data.get("platform_kind")):
        return 0

    if not os.path.isdir("/sys/class/bluetooth"):
        print("[!] Wall of Flippers >> No Bluetooth adapters found (/sys/class/bluetooth).")
        return 0

    ble_adapters = [
        adapter for adapter in os.listdir("/sys/class/bluetooth/") if adapter.startswith("hci")
    ]
    ble_adapters.sort()

    if device_args is None:
        print("\n\n[#]\t[HCI DEVICE]\n" + "-" * shutil.get_terminal_size().columns)
        for index, adapter in enumerate(ble_adapters):
            print(f"{index}".ljust(8) + f"{adapter}".ljust(34))
        selection = input("[?] Wall of Flippers >> ")
    else:
        selection = device_args

    if selection == "":
        return 0

    selection_str = str(selection).strip().lower()
    if selection_str.startswith("hci"):
        return normalize_hci(selection_str)

    if selection_str.isdigit() and int(selection_str) < len(ble_adapters):
        return normalize_hci(ble_adapters[int(selection_str)])

    return normalize_hci(selection_str)

def is_in_venv():
    """Returns True if the user is in a virtual environment, otherwise returns False"""
    return sys.prefix != sys.base_prefix

def print_ascii_art(custom_text=None):
    """Displays ASCII art in the terminal with the custom text if provided, otherwise displays a random quote"""
    if not cache.wof_data.get("no_clear"):
        os.system('cls' if os.name == 'nt' else 'clear')
    r_quote = random.choice(cache.wof_data['dolphin_thinking']) if not custom_text else custom_text
    # selecting adequate ASCII art based on the terminal size and if the user is in narrow mode
    print("\033[0;94m")
    if cache.wof_data['narrow_mode']:
        print(f"{cache.wof_data['ascii_small']}\n\"{r_quote}\"\n".center(50) + "\033[0m")
    else:
        ascii_art = cache.wof_data['ascii_normal']

        if cache.wof_data['badge_mode']:
           # shorten ascii art by 10 lines
            ascii_art = "\n".join(ascii_art.split("\n")[:-7])
            print(f"{ascii_art.replace('[RANDOM_QUOTE]', r_quote)}\n\033[0m")
        else:
            print(f"{ascii_art.replace('[RANDOM_QUOTE]', r_quote)}\n\033[0m")

def init():
    """Initial Selection Box (Upon starup)
    This init() function allows the user to select what action they would like to preform (cached options stored in utils/wof_cache.py)
    returns: the action the user selected (str)
    """
    # check terminal size to set narrow mode (false by default)
    if shutil.get_terminal_size().columns < cache.wof_data['narrow_mode_limit']: # if the terminal size is less than *narrow_mode_limit* columns (default: 100)
        cache.wof_data['narrow_mode'] = True

    dialogue_options = cache.wof_data['init_directory_options']
    dialogue_options_dict = {option['option']: option['return'] for option in dialogue_options}
    print_ascii_art("Please Select an option to continue")

    #Library dependencies check
    #This checks the bleak, bluepy, and bluetooth python packages and libraries
    #for Wall of Flippers to work properly.

    try:
        import bleak # Universal (Mostly for Windows) BLE Library
        print("[X] Bleak is installed")
    except ImportError:
        print("[ ] Bleak is installed")
    try:
        import bluepy # Linux BLE Library
        print("[X] Bluepy is installed")
    except ImportError:
        print("[ ] Bluepy is installed")
    try:
        import bluetooth # Bluetooth Library
        print("[X] Bluetooth is installed")
    except ImportError:
        print("[ ] Bluetooth is installed")


    #Initial selection box for the user to select what they want to do.
        
    if cache.wof_data['narrow_mode']:
        # dont display the description if the terminal is too narrow
        print("\n\n[#]\t[ACTION]\n" + "-"*shutil.get_terminal_size().columns + "\n" + "\n".join([f"{option['option'].ljust(8)}{option['action']}" for option in dialogue_options]))
    else:
        print("\n\n[#]\t[ACTION]\t\t\t  [DESCRIPTION]\n" + "-"*shutil.get_terminal_size().columns + "\n" + "\n".join([f"{option['option'].ljust(8)}{option['action'].ljust(34)}{option['description']}" for option in dialogue_options]))


    try:
        while True:
            str_input = input("\n[?] Wall of Flippers >> ").strip()
            result = dialogue_options_dict.get(str_input)
            if result is not None:
                if result == "exit":
                    print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
                    print("\n[!] Wall of Flippers >> Exiting...")
                    sys.exit()
                return result
            print("[!] Wall of Flippers >> Invalid option. Please choose from the menu.")
    except KeyboardInterrupt:
        print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
        print("\n[!] Wall of Flippers >> Exiting...")
        sys.exit()
