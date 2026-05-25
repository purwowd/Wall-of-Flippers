#!/usr/bin/python3
"""Background BLE scan worker for the web UI."""

import threading
import time

import utils.wof_cache as cache
import utils.wof_engine as engine
import utils.wof_logging as wof_log

from web import state as web_state


class ScanWorker:
    def __init__(self, hci_device=0):
        self.hci_device = hci_device
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wof-scan-worker", daemon=True)
        self._thread.start()
        web_state.set_worker_running(True)
        web_state.push_event("worker_started", {"hci": self.hci_device})

    def stop(self):
        self._stop.set()
        web_state.set_worker_running(False)
        web_state.push_event("worker_stopped")

    def _run(self):
        loop_sleep = float(cache.wof_data.get("loop_sleep_seconds", 0.5))
        web_state.push_event("scan_loop_started")
        while not self._stop.is_set():
            try:
                snapshot = engine.run_scan_cycle(self.hci_device)
                web_state.set_snapshot(snapshot)
                if snapshot.get("ratelimited"):
                    web_state.push_event("ratelimit", {
                        "seconds": snapshot.get("ratelimit_seconds_left", 0),
                    })
                if not snapshot.get("scan", {}).get("ok"):
                    err = snapshot.get("scan", {}).get("message", "scan failed")
                    web_state.set_last_error(err)
                    web_state.push_event("scan_error", {"error": err})
                else:
                    web_state.set_last_error(None)
            except Exception as err:
                wof_log.error(f"web_worker: {err}")
                web_state.set_last_error(str(err))
                web_state.push_event("scan_error", {"error": str(err)})
            self._stop.wait(loop_sleep)
        web_state.set_worker_running(False)
