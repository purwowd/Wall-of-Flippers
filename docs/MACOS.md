# Wall of Flippers on macOS

## Requirements

- Python 3.9+
- Bluetooth enabled
- `bleak` (`pip install bleak`)

## Install

```bash
git clone <your-repo-url>
cd Wall-of-Flippers
python3 -m pip install bleak
python3 WallofFlippers.py -i   # optional guided install
```

Grant **Bluetooth** permission when macOS prompts you (System Settings → Privacy & Security → Bluetooth).

## Run

```bash
python3 WallofFlippers.py -w
./wof.sh -w
```

### Useful flags

```bash
python3 WallofFlippers.py -w --no-clear
python3 WallofFlippers.py -w --json-lines
python3 WallofFlippers.py -w --anonymize-mac
python3 WallofFlippers.py -w -c config/wof.defaults.json
python3 WallofFlippers.py -w --export /tmp/wof-snapshot.json
```

## Linux-only features

These do **not** work on macOS:

- BLE advertiser (`-a`)
- BLE Chat (menu option 2)
- Raw bluepy scan (full advertisement fidelity)

## Web dashboard (FastAPI + Tailwind)

```bash
pip install fastapi uvicorn jinja2
python3 run_web.py --host 127.0.0.1 --port 8787
# or
python3 WallofFlippers.py --web
```

Open http://127.0.0.1:8787 — live updates via Server-Sent Events (SSE).

## Logs

Runtime log file: `logs/wof.log`

Archive database: `db/Flipper.json`
