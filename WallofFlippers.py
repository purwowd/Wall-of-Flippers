#!/usr/bin/python3

import os
import sys
import time
import argparse

import utils.wof_cache as cache
import utils.wof_library as library
import utils.wof_display as wall_display
import utils.wof_install as installer
import utils.wof_blechat as blechat
import utils.wof_platform as wof_platform
import utils.wof_scanner as wof_scanner
import utils.wof_config as wof_config
import utils.wof_logging as wof_log
import utils.wof_events as events
import utils.wof_storage as storage

parser = argparse.ArgumentParser(description='Wall of Flippers', prog='WallofFlippers.py')
parser.add_argument('-w', '--wall', action='store_true', help='Wall of Flippers')
parser.add_argument('-i', '--install', action='store_true', help='Install dependencies')
parser.add_argument('-d', '--device', action='store', help='Bluetooth adapter (Linux: hci0 or index)')
parser.add_argument('-b', '--badgemode', action='store_true', help='Toggle badge mode')
parser.add_argument('-a', '--advertise', action='store_true', help='Advertise WoF (Linux only)')
parser.add_argument('-c', '--config', action='store', metavar='PATH', help='JSON config file')
parser.add_argument('--scan-interval', type=float, metavar='SEC', help='BLE scan duration (seconds)')
parser.add_argument('--loop-sleep', type=float, metavar='SEC', help='Delay between scan cycles')
parser.add_argument('--no-clear', action='store_true', help='Do not clear terminal on refresh')
parser.add_argument('--quiet', action='store_true', help='Minimal console output')
parser.add_argument('--json-lines', action='store_true', help='Emit JSON-lines events to stdout')
parser.add_argument('--export', dest='export_path', metavar='PATH', help='Write dashboard snapshot JSON each refresh')
parser.add_argument('--anonymize-mac', action='store_true', help='Mask last 3 bytes of MAC in UI')
parser.add_argument('--web', action='store_true', help='Start FastAPI web dashboard')
parser.add_argument('--web-host', default='127.0.0.1', help='Web dashboard bind host')
parser.add_argument('--web-port', type=int, default=8787, help='Web dashboard port')
args = parser.parse_args()


def _sync_advertiser_flags():
    on = cache.wof_data.get("toggle_advertiser") or cache.wof_data.get("toggle_adveriser")
    cache.wof_data["toggle_advertiser"] = on
    cache.wof_data["toggle_adveriser"] = on


def apply_cli_overrides():
    if args.scan_interval is not None:
        cache.wof_data['scan_interval_seconds'] = args.scan_interval
    if args.loop_sleep is not None:
        cache.wof_data['loop_sleep_seconds'] = args.loop_sleep
    if args.no_clear:
        cache.wof_data['no_clear'] = True
    if args.quiet:
        cache.wof_data['quiet_mode'] = True
    if args.json_lines:
        cache.wof_data['json_lines_mode'] = True
        cache.wof_data['no_clear'] = True
    if args.export_path:
        cache.wof_data['export_path'] = args.export_path
    if args.anonymize_mac:
        cache.wof_data['anonymize_mac'] = True


def show_disclaimer():
    marker = os.path.join(storage.DB_DIR, ".disclaimer_seen")
    if os.path.isfile(marker):
        return
    print(
        "\n[!] Wall of Flippers is for detection and awareness only.\n"
        "    It does NOT block or mitigate Bluetooth attacks.\n"
        "    Use responsibly and comply with local laws.\n"
    )
    os.makedirs(storage.DB_DIR, exist_ok=True)
    with open(marker, "w", encoding="utf-8") as handle:
        handle.write("ok\n")
    wof_log.info("disclaimer_shown")


def resolve_selection():
    if args.badgemode:
        cache.wof_data['badge_mode'] = not cache.wof_data['badge_mode']
    if args.advertise:
        if not wof_platform.supports_ble_advertiser():
            print("[!] Wall of Flippers >> BLE advertise is only available on Linux.")
        else:
            cache.wof_data['toggle_advertiser'] = not cache.wof_data['toggle_advertiser']
            _sync_advertiser_flags()
    if args.wall:
        return 'wall_of_flippers'
    if args.install:
        return 'install_dependencies'
    if args.web:
        return 'web_dashboard'
    if args.device is not None:
        return 'wall_of_flippers'
    return library.init()


def run_detection(hci_device=0):
    import utils.wof_engine as engine

    try:
        snapshot = engine.run_scan_cycle(hci_device)
        scan = snapshot.get("scan", {})
        if scan.get("ratelimited"):
            total_new = 0
            msg = scan.get("message") or "Ratelimit active — possible spoofing"
            events.emit("ratelimit", {"seconds": snapshot.get("ratelimit_seconds_left", 0)})
            wall_display.display(msg)
            return
        if scan.get("latest"):
            latest = scan["latest"]
            wall_display.display(
                f"I've found a wild {latest.get('name')} ({latest.get('mac')})"
            )
        elif not scan.get("ok"):
            if not cache.wof_data.get("json_lines_mode"):
                library.print_ascii_art("Error: Failed to scan for BLE devices")
                print(f"[!] Wall of Flippers >> {scan.get('message')}")
            events.emit("scan_error", {"error": scan.get("message")})
        else:
            wall_display.display(None)
    except Exception as err:
        wof_log.error(f"scan_failed: {err}")
        if not cache.wof_data.get("json_lines_mode"):
            library.print_ascii_art("Error: Failed to scan for BLE devices")
            print(f"[!] Wall of Flippers >> Error: Failed to scan for BLE devices >> {err}")
        events.emit("scan_error", {"error": str(err)})


def run_ble_advertiser(sock, hci_index):
    from utils.bluetooth_utils import start_le_advertising, stop_le_advertising

    for _ in range(0, 10):
        advertisement_data = cache.wof_data['wof_advertiser']
        advertisement_name = tuple(cache.wof_data['wof_advertiserName'].encode())
        advertisement_data += advertisement_name
        advertisement_data += (0x00,) * (31 - len(advertisement_data))
        if len(advertisement_data) > 31:
            print(
                "[!] Wall of Flippers >> Advertisement data too long; "
                "shorten wof_advertiserName in utils/wof_cache.py"
            )
            sys.exit(1)
        start_le_advertising(sock, adv_type=0x03, data=advertisement_data)
        time.sleep(0.1)
        stop_le_advertising(sock)


def run_wall_loop(hci_device):
    platform_kind = cache.wof_data['platform_kind']
    sock = None
    _sync_advertiser_flags()

    if wof_platform.uses_bluepy(platform_kind):
        from bluepy.btle import Scanner  # noqa: F401
        if cache.wof_data['toggle_advertiser']:
            from utils.bluetooth_utils import toggle_device
            import bluetooth._bluetooth as bluez

            hci_index = library.normalize_hci(hci_device)
            sock = bluez.hci_open_dev(hci_index)
            toggle_device(hci_index, True)

    if not cache.wof_data.get("quiet_mode") and not cache.wof_data.get("json_lines_mode"):
        wall_display.display("Thank you for using Wall of Flippers!")
    else:
        events.emit("wall_started", {"platform": platform_kind})

    loop_sleep = float(cache.wof_data.get("loop_sleep_seconds", 0.5))
    while True:
        if cache.wof_data['toggle_advertiser'] and wof_platform.supports_ble_advertiser(platform_kind) and sock:
            run_ble_advertiser(sock, hci_device)
        if not cache.wof_data['bool_isScanning']:
            run_detection(hci_device)
        time.sleep(loop_sleep)


def preflight_checks():
    wof_config.apply_config(args.config)
    apply_cli_overrides()
    _sync_advertiser_flags()
    library.required2files()
    wof_log.setup()

    platform_kind = wof_platform.get_platform_kind()
    cache.wof_data['platform_kind'] = platform_kind
    cache.wof_data['system_type'] = os.name

    if wof_platform.requires_linux_venv(platform_kind):
        if not os.path.exists(".venv/bin/activate"):
            library.print_ascii_art("Virtual environment not found (.venv)")
            print("[!] Wall of Flippers >> Run: python3 -m venv .venv")
            if input("[?] Create .venv now? (Y/N) >> ").lower() == "y":
                os.system("python3 -m venv .venv")
                print("[!] Created .venv — activate it and run again.")
            sys.exit(0)
        if not library.is_in_venv():
            library.print_ascii_art("Activate your virtual environment")
            print("[!] Wall of Flippers >> source .venv/bin/activate  OR  bash wof.sh")
            sys.exit(1)

    if wof_platform.uses_bleak(platform_kind):
        try:
            import bleak  # noqa: F401
        except ImportError:
            library.print_ascii_art("Missing dependency: bleak")
            print(
                f"[!] Install bleak for {wof_platform.platform_display_name(platform_kind)}:\n"
                "\tpip install bleak\n"
                "\tpython3 WallofFlippers.py -i"
            )
            sys.exit(1)


def main():
    if not cache.wof_data.get("no_clear") and not cache.wof_data.get("json_lines_mode"):
        os.system('cls' if os.name == 'nt' else 'clear')

    preflight_checks()
    show_disclaimer()

    selection_box = resolve_selection()
    if selection_box is None:
        print("[!] Wall of Flippers >> No action selected.")
        sys.exit(1)

    if selection_box == 'wall_of_flippers':
        platform_kind = cache.wof_data['platform_kind']

        if wof_platform.requires_root(platform_kind) and not os.geteuid() == 0:
            library.print_ascii_art("Root required on Linux")
            print("[!] Wall of Flippers >> sudo python3 WallofFlippers.py -w")
            sys.exit(1)

        if cache.wof_data['toggle_advertiser'] and not wof_platform.supports_ble_advertiser(platform_kind):
            print("[!] Wall of Flippers >> BLE advertise disabled on this platform.")
            cache.wof_data['toggle_advertiser'] = False
            _sync_advertiser_flags()

        try:
            hci_device = library.adapter2Selection(args.device)
            run_wall_loop(hci_device)
        except KeyboardInterrupt:
            storage.flush_archive(force=True)
            library.print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
            print("\n[!] Wall of Flippers >> Exiting...")
            sys.exit(0)

    elif selection_box == 'install_dependencies':
        installer.init()

    elif selection_box == 'web_dashboard':
        try:
            from web.app import run_server
        except ImportError:
            print("[!] Install web deps: pip install fastapi uvicorn jinja2")
            sys.exit(1)
        platform_kind = cache.wof_data['platform_kind']
        if wof_platform.requires_root(platform_kind) and not os.geteuid() == 0:
            print("[!] Linux web scan needs root: sudo python3 WallofFlippers.py --web")
            sys.exit(1)
        hci = library.normalize_hci(args.device) if args.device is not None else 0
        print(f"[*] Web UI → http://{args.web_host}:{args.web_port}")
        run_server(
            host=args.web_host,
            port=args.web_port,
            config_path=args.config,
            hci_device=hci,
            anonymize_mac=args.anonymize_mac,
        )

    elif selection_box == 'wall_of_talking':
        if not wof_platform.supports_ble_chat():
            print(f"[!] BLE Chat requires Linux (current: {wof_platform.platform_display_name()})")
            sys.exit(1)
        if not os.geteuid() == 0:
            print("[!] Root required for BLE Chat.")
            sys.exit(1)
        blechat.init()


if __name__ == "__main__":
    main()
