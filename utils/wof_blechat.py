#!/usr/bin/python3

import sys
import time
import threading

import utils.wof_cache as cache
import utils.wof_library as library
import utils.wof_scanner as wof_scanner


def check_length(string, limit):
    if len(string) > limit:
        print(f"[!] Wall of Flippers >> Message too long (max {limit} characters).")
        return False
    return True


def send_traffic(sock, start, stop):
    from utils.bluetooth_utils import stop_le_advertising

    display_name = cache.wof_data['wof_displayName'] + "::"
    total_chars_left = 31 - len(display_name) - len(cache.wof_data['wof_bleAdvertiserRaw'])

    while True:
        try:
            library.print_ascii_art("You are now broadcasting your messages!")
            for entry in cache.wof_data['cachedMessages'][:20]:
                readable_date = time.strftime('%H:%M:%S', time.localtime(entry['time']))
                print(f"[+] {readable_date} {entry['displayName']} >> {entry['message']}")

            custom_message = input(
                f"[?] Wall of Flippers >> (MAX: {total_chars_left} chars) (Empty = Refresh) >> "
            )
            if custom_message == "":
                continue
            if not check_length(custom_message, total_chars_left):
                continue

            cache.wof_data['cachedMessages'].append({
                "displayName": cache.wof_data['wof_displayName'],
                "message": custom_message,
                "time": int(time.time()),
            })

            for _ in range(0, 10):
                advertisement_data = list(cache.wof_data['wof_blechatAdvertiser'])
                advertisement_data += list(bytes.fromhex(display_name.encode().hex()))
                advertisement_data += list(bytes.fromhex(custom_message.encode().hex()))
                advertisement_data = tuple(advertisement_data)
                advertisement_data += (0x00,) * (31 - len(advertisement_data))
                start(sock, adv_type=0x03, data=advertisement_data)
                time.sleep(0.1)
                stop(sock)
        except KeyboardInterrupt:
            library.print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
            print("\n[!] Wall of Flippers >> Exiting...")
            stop_le_advertising(sock)
            sys.exit(0)


def sort_traffic(ble_packets):
    for advertisement in ble_packets:
        advertisement_packets = advertisement[0]['packets']
        for advertisement_packet in advertisement_packets:
            if str(advertisement_packet).startswith(cache.wof_data['wof_bleAdvertiserRaw']):
                decoded_message = bytes.fromhex(
                    advertisement_packet.replace(cache.wof_data['wof_bleAdvertiserRaw'], "")
                ).decode('utf-8', errors='ignore').replace("\x00", "")
                if "::" not in decoded_message:
                    continue
                decoded_display_name = decoded_message.split("::")[0]
                decoded_display_message = decoded_message.split("::", 1)[1]
                duplicate = any(
                    i['message'] == decoded_display_message and i['displayName'] == decoded_display_name
                    for i in cache.wof_data['cachedMessages']
                )
                if duplicate:
                    continue
                cache.wof_data['cachedMessages'].append({
                    "displayName": decoded_display_name,
                    "message": decoded_display_message,
                    "time": int(time.time()),
                })


def read_traffic(hci_device):
    cache.wof_data['bool_isScanning'] = True
    try:
        ble_packets = wof_scanner.scan_ble(cache.wof_data['platform_kind'], hci_device)
        sort_traffic(ble_packets)
    finally:
        cache.wof_data['bool_isScanning'] = False


def init():
    from utils.bluetooth_utils import toggle_device, start_le_advertising, stop_le_advertising
    import bluetooth._bluetooth as bluez

    hci_device = library.adapter2Selection()
    hci_index = library.normalize_hci(hci_device)
    sock = bluez.hci_open_dev(hci_index)
    toggle_device(hci_index, True)

    display_name_selection = input("[?] Wall of Flippers >> Display name (MAX: 6 chars) >> ")
    if not check_length(display_name_selection, 6):
        sys.exit(1)
    cache.wof_data['wof_displayName'] = display_name_selection

    threading.Thread(
        target=send_traffic,
        args=(sock, start_le_advertising, stop_le_advertising),
        daemon=True,
    ).start()

    try:
        while True:
            time.sleep(0.1)
            if not cache.wof_data['bool_isScanning']:
                read_traffic(hci_device)
    except KeyboardInterrupt:
        library.print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
        print("\n[!] Wall of Flippers >> Exiting...")
        stop_le_advertising(sock)
        sys.exit(0)
