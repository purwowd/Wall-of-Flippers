#!/usr/bin/env python3
"""Start the Wall of Flippers web dashboard."""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def main():
    parser = argparse.ArgumentParser(description="Wall of Flippers — Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (0.0.0.0 for LAN)")
    parser.add_argument("--port", type=int, default=8787, help="HTTP port")
    parser.add_argument("-c", "--config", help="JSON config path")
    parser.add_argument("-d", "--device", default="0", help="HCI device (Linux)")
    parser.add_argument("--anonymize-mac", action="store_true")
    args = parser.parse_args()

    try:
        from web.app import bootstrap, run_server
    except ImportError as err:
        print("[!] Install web dependencies: pip install fastapi uvicorn jinja2")
        raise SystemExit(1) from err

    bootstrap(args.config, hci_device=args.device, anonymize_mac=args.anonymize_mac)
    print(f"[*] Wall of Flippers Web → http://{args.host}:{args.port}")
    print("[*] Detection only — does not block BLE attacks.")
    run_server(
        host=args.host,
        port=args.port,
        config_path=args.config,
        hci_device=args.device,
        anonymize_mac=args.anonymize_mac,
    )


if __name__ == "__main__":
    main()
