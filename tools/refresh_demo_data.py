"""Regenerate the GitHub Pages static-demo dataset (docs/js/demo-data.js)
from real scans: one repo scan of the vulnerable fixture project, one
GitHub self-scan, and one API-mode scan of the bundled demo target."""
import io
import json

import requests

BASE = " "  # patched at runtime by caller
BASE = "http://127.0.0.1:5000"
SCAN_IDS = ["664373dcf845", "ef360f151850", "2a6bd4953489"]

scans = [s for s in requests.get(f"{BASE}/api/scans").json()["scans"]
         if s["id"] in SCAN_IDS]
alerts = requests.get(f"{BASE}/api/alerts").json()["alerts"]

data = {"scans": scans, "alerts": alerts, "findings": {}, "tests": {}}
for sid in SCAN_IDS:
    data["findings"][sid] = requests.get(f"{BASE}/api/scans/{sid}/findings").json()["findings"]
    data["tests"][sid] = requests.get(f"{BASE}/api/scans/{sid}/tests").json()["tests"]

with io.open("docs/js/demo-data.js", "w", encoding="utf-8") as fh:
    fh.write("/* Embedded data captured from REAL Sentinel AI scans:\n"
             "   1. static repo scan of the bundled vulnerable fixture project\n"
             "   2. GitHub scan of amrit220/sentinel-ai itself\n"
             "   3. dynamic API scan of the bundled demo target\n"
             "   Powers the static GitHub Pages demo (offline mock API). */\n")
    fh.write("const DEMO_DB = ")
    fh.write(json.dumps(data, separators=(",", ":")))
    fh.write(";\n")

print("scans:", [s["config"]["mode"] for s in scans],
      "| findings:", {k: len(v) for k, v in data["findings"].items()},
      "| alerts:", len(alerts))
