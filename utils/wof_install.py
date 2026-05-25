#!/usr/bin/python3

import os
import sys
import json
import subprocess

import utils.wof_library as library
import utils.wof_platform as wof_platform


def _run_commands(commands):
    for cmd in commands:
        print(f"[!] Running: {cmd}")
        result = subprocess.run(cmd, shell=True)
        if result.returncode != 0:
            print(f"[!] Command failed ({result.returncode}): {cmd}")


def verify_imports(platform_kind):
    """Smoke-test critical imports after install."""
    ok = True
    if wof_platform.uses_bleak(platform_kind):
        try:
            import bleak  # noqa: F401
            print("[X] bleak import OK")
        except ImportError:
            print("[ ] bleak import FAILED")
            ok = False
    if wof_platform.uses_bluepy(platform_kind):
        try:
            import bluepy  # noqa: F401
            print("[X] bluepy import OK")
        except ImportError:
            print("[ ] bluepy import FAILED")
            ok = False
        try:
            import bluetooth  # noqa: F401
            print("[X] bluetooth import OK")
        except ImportError:
            print("[ ] bluetooth import FAILED")
            ok = False
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        print("[X] fastapi/uvicorn import OK (web UI)")
    except ImportError:
        print("[ ] fastapi/uvicorn not installed (optional web UI)")
    return ok


def init():
    try:
        library.print_ascii_art("Welcome to the easy install process! Please read carefully.")
        platform_kind = wof_platform.get_platform_kind()

        windows_dependencies_cmd = ["pip install bleak", "pip install -r requirements.txt"]
        macos_dependencies_cmd = [
            "python3 -m pip install bleak fastapi uvicorn jinja2",
            "python3 -m pip install -r requirements.txt",
        ]
        web_dependencies_cmd = ["python3 -m pip install fastapi uvicorn jinja2"]
        arch_cmd = [
            "python3 -m pip install git+https://github.com/pybluez/pybluez.git#egg=pybluez",
            "python3 -m pip install bluepy",
            "python3 -m pip install -r requirements.txt",
        ]
        debian_dependencies_cmd = [
            "sudo apt-get install -y libglib2.0-dev python3-bluez",
            "python3 -m pip install bluepy",
            "python3 -m pip install git+https://github.com/pybluez/pybluez.git#egg=pybluez",
            "python3 -m pip install -r requirements.txt",
        ]
        fedora_dependencies_cmd = [
            "sudo dnf install -y glib2-devel python3-bluez",
            "python3 -m pip install bluepy",
            "python3 -m pip install git+https://github.com/pybluez/pybluez.git#egg=pybluez",
            "python3 -m pip install -r requirements.txt",
        ]
        generic_pip_cmd = ["python3 -m pip install -r requirements.txt"]

        if platform_kind == wof_platform.PLATFORM_WINDOWS:
            library.print_ascii_art("Detected Windows")
            print(
                f"[!] Wall of Flippers >> Install commands:\n"
                f"{json.dumps(windows_dependencies_cmd, indent=4)}"
            )
            if input("[?] Wall of Flippers (Y/N) >> ").lower() == "y":
                pip_bin = input("[?] pip executable (pip/pip3) [pip]: ").strip() or "pip"
                commands = [cmd.replace("pip", pip_bin) for cmd in windows_dependencies_cmd]
                _run_commands(commands)
                library.print_ascii_art("Dependencies install finished.")
                verify_imports(platform_kind)
                print("[!] Wall of Flippers >> Verify with: python WallofFlippers.py -w")

        elif platform_kind == wof_platform.PLATFORM_DARWIN:
            library.print_ascii_art("Detected macOS")
            print(
                f"[!] Wall of Flippers >> macOS uses Bleak (Flipper scan + BLE spam hints).\n"
                f"{json.dumps(macos_dependencies_cmd, indent=4)}\n"
                "[!] Grant Bluetooth permission when macOS prompts you."
            )
            if input("[?] Wall of Flippers (Y/N) >> ").lower() == "y":
                _run_commands(macos_dependencies_cmd)
                library.print_ascii_art("Dependencies install finished.")
                if verify_imports(platform_kind):
                    print("[!] Wall of Flippers >> Run: python3 WallofFlippers.py -w")
                else:
                    print("[!] Install incomplete — check pip output above.")

        elif platform_kind == wof_platform.PLATFORM_LINUX:
            library.print_ascii_art("Detected Linux")
            linux_distro = [
                {"name": "debian", "rolling": ["debian", "ubuntu", "kali", "raspbian"]},
                {"name": "fedora", "rolling": ["fedora"]},
                {"name": "arch", "rolling": ["arch", "cachyos"]},
            ]

            def get_like_distro():
                with open("/etc/os-release", "r", encoding="utf-8") as os_file:
                    os_data = os_file.read()
                parsed = {}
                for line in os_data.split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        parsed[key] = value.replace('"', "")
                for distro in linux_distro:
                    name_only = parsed.get("ID", parsed.get("NAME", "")).lower().split(" ")[0]
                    if name_only in distro["rolling"]:
                        return distro["name"]
                return parsed.get("ID", "unknown").lower()

            distro_name = get_like_distro()
            if distro_name == "fedora":
                commands = fedora_dependencies_cmd
            elif distro_name == "arch":
                commands = arch_cmd
            elif distro_name == "debian":
                commands = debian_dependencies_cmd
            else:
                print(f"[!] Unknown distro '{distro_name}', using pip requirements only.")
                commands = generic_pip_cmd

            print(f"[!] Wall of Flippers >> Commands:\n{json.dumps(commands, indent=4)}")
            if input("[?] Wall of Flippers (Y/N) >> ").lower() == "y":
                _run_commands(commands)
                library.print_ascii_art("Dependencies install finished.")
                verify_imports(platform_kind)
                print("[!] Wall of Flippers >> Run: bash wof.sh  or  sudo python3 WallofFlippers.py -w")
        else:
            library.print_ascii_art("Unsupported platform for auto-install")
            print(f"[!] Platform: {sys.platform}")
            _run_commands(generic_pip_cmd)

    except KeyboardInterrupt:
        library.print_ascii_art("Thank you for using Wall of Flippers... Goodbye!")
        print("\n[!] Wall of Flippers >> Exiting...")
        sys.exit(0)
