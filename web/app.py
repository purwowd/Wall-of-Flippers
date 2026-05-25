#!/usr/bin/python3
"""FastAPI web dashboard for Wall of Flippers."""

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import utils.wof_cache as cache
import utils.wof_config as wof_config
import utils.wof_library as library
import utils.wof_logging as wof_log
import utils.wof_platform as wof_platform
import utils.wof_engine as engine
from web import state as web_state
from web.worker import ScanWorker
from web.export_csv import generate_csv_string
import utils.wof_rssi_history as rssi_history

templates = Jinja2Templates(directory=str(ROOT / "web" / "templates"))

_worker = None
_hci_device = 0


def bootstrap(config_path=None, hci_device=0, anonymize_mac=False):
    global _hci_device, _worker
    try:
        _hci_device = library.normalize_hci(hci_device)
    except (ValueError, TypeError):
        _hci_device = 0
    _worker = None
    wof_config.apply_config(config_path)
    if anonymize_mac:
        cache.wof_data["anonymize_mac"] = True
    library.required2files()
    wof_log.setup()
    cache.wof_data["platform_kind"] = wof_platform.get_platform_kind()
    cache.wof_data["system_type"] = os.name
    cache.wof_data["quiet_mode"] = True
    cache.wof_data["dashboard_mode"] = True
    cache.wof_data["no_clear"] = True
    web_state.set_snapshot(engine.build_snapshot({"ok": True, "message": "Ready"}))


def _check_ble_deps():
    kind = cache.wof_data["platform_kind"]
    if wof_platform.uses_bleak(kind):
        import bleak  # noqa: F401
    if wof_platform.requires_root(kind) and not os.geteuid() == 0:
        raise RuntimeError("Linux scan requires root (sudo).")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker
    try:
        _check_ble_deps()
        _worker = ScanWorker(_hci_device)
        _worker.start()
    except Exception as err:
        web_state.set_last_error(str(err))
        web_state.push_event("boot_error", {"error": str(err)})
    yield
    if _worker:
        _worker.stop()


app = FastAPI(
    title="Wall of Flippers",
    description="BLE Flipper & spam detection dashboard",
    version="2.0.0",
    lifespan=lifespan,
)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"title": "Wall of Flippers"},
    )


@app.get("/api/snapshot")
async def api_snapshot():
    return JSONResponse(web_state.get_snapshot())


@app.get("/api/status")
async def api_status():
    return JSONResponse({
        **web_state.get_status(),
        "platform": cache.wof_data.get("platform_kind"),
        "scan_interval": cache.wof_data.get("scan_interval_seconds"),
    })


@app.get("/api/events")
async def api_events(since: int = 0):
    return JSONResponse(web_state.get_events_since(since))


@app.get("/api/rssi-history")
async def api_rssi_history(mac: str = None):
    return JSONResponse(rssi_history.get_history(mac))


@app.get("/api/export.csv")
async def api_export_csv():
    body = generate_csv_string()
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=wall-of-flippers-export.csv"},
    )


@app.post("/api/worker/start")
async def worker_start():
    global _worker
    if _worker is None:
        _worker = ScanWorker(_hci_device)
    _worker.start()
    return {"running": True}


@app.post("/api/worker/stop")
async def worker_stop():
    if _worker:
        _worker.stop()
    return {"running": False}


@app.get("/api/stream")
async def api_stream():
    async def generate():
        last_snap_ts = 0
        last_event_ts = 0
        while True:
            snap = web_state.get_snapshot()
            ts = snap.get("ts", 0)
            if ts != last_snap_ts:
                last_snap_ts = ts
                yield f"data: {json.dumps(snap)}\n\n"
            for ev in web_state.get_events_since(last_event_ts):
                last_event_ts = max(last_event_ts, ev.get("ts", 0))
                yield f"event: log\ndata: {json.dumps(ev)}\n\n"
            await asyncio.sleep(0.4)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def create_app(config_path=None, hci_device=0, anonymize_mac=False):
    bootstrap(config_path, hci_device, anonymize_mac)
    return app


def run_server(host="127.0.0.1", port=8787, config_path=None, hci_device=0, anonymize_mac=False):
    import uvicorn

    bootstrap(config_path, hci_device, anonymize_mac)
    uvicorn.run(app, host=host, port=port, reload=False)
