"""Continuous Monitoring Mode.

A daemon scheduler that periodically re-runs a saved scan configuration
and diffs the findings (by fingerprint) against the previous run. New or
upgraded findings raise alerts surfaced on the dashboard.
"""
import threading
import time

from config import Config
from .. import database as db
from . import pipeline, vuln_engine


class MonitorManager:
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="sentinel-monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            for mon in db.get_active_monitors():
                if self._stop.is_set():
                    return
                interval = mon["interval_s"] or Config.MONITOR_INTERVAL_S
                due = (mon["last_run"] or 0) + interval <= time.time()
                if not due:
                    continue
                scan = db.get_scan(mon["scan_id"])
                if not scan:
                    continue
                before = db.finding_fingerprints(mon["scan_id"])
                pipeline.run_scan(mon["scan_id"])
                after = db.finding_fingerprints(mon["scan_id"])
                new = [fp for fp in after if fp not in before]
                upgraded = [fp for fp, sev in after.items()
                            if fp in before and _sev_rank(sev) > _sev_rank(before[fp])]
                for fp in new:
                    db.add_alert(mon["scan_id"],
                                 f"Continuous monitoring: NEW vulnerability detected "
                                 f"({after[fp]}) in re-scan of {scan['target']}",
                                 after[fp])
                for fp in upgraded:
                    db.add_alert(mon["scan_id"],
                                 f"Continuous monitoring: finding severity ESCALATED to "
                                 f"{after[fp]} on {scan['target']}",
                                 after[fp])
                db.touch_monitor(mon["scan_id"])
            self._stop.wait(15)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(sev):
    return _SEV_RANK.get(sev, 0)


manager = MonitorManager()
