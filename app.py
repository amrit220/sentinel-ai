"""Sentinel AI - Autonomous QA Engineer & Ethical Hacking Platform.

Main Flask application: serves the dashboard SPA and exposes the REST API.

Run:
    python app.py                    # API + dashboard on :5000
    python app.py --with-demo        # also launches the vulnerable demo
                                     # target on :5099 for a full demo
"""
import argparse
import json
import os
import threading

from flask import Flask, jsonify, request, send_from_directory, send_file, abort

from config import Config, REPORT_DIR
from sentinel import database as db
from sentinel.ai_layer import get_ai
from sentinel.engines import perf_engine, pipeline, report_generator, monitor

app = Flask(__name__, static_folder="frontend", static_url_path="")

_ai = get_ai()


# ------------------------------------------------------------- frontend ----
@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")


# ------------------------------------------------------------------ meta ----
@app.get("/api/health")
def health():
    return jsonify({
        "service": "sentinel-ai", "version": "1.0.0",
        "ai_backend": _ai.backend_name, "demo_target": Config.DEMO_TARGET_URL,
    })


@app.get("/api/scans")
def api_list_scans():
    return jsonify({"scans": db.list_scans()})


@app.post("/api/scans")
def api_create_scan():
    data = request.get_json(silent=True) or request.form or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    cfg = {
        "openapi": data.get("openapi") or None,
        "modules": {
            "functional": bool(data.get("functional", True)),
            "attacks": bool(data.get("attacks", True)),
            "performance": bool(data.get("performance", False)),
        },
        "perfConcurrency": int(data.get("perfConcurrency", Config.PERF_CONCURRENCY)),
        "perfDuration": int(data.get("perfDuration", Config.PERF_DURATION_S)),
    }
    scan_id = pipeline.start_scan_async(target, data.get("label"), cfg)
    return jsonify({"scan_id": scan_id}), 201


@app.get("/api/scans/<scan_id>")
def api_get_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    scan["alerts"] = [a for a in db.list_alerts(200) if a["scan_id"] == scan_id][:5]
    return jsonify(scan)


@app.get("/api/scans/<scan_id>/findings")
def api_get_findings(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    findings = db.get_findings(scan_id)
    for f in findings:
        # attach lazily-stored AI data in a tidy shape for the UI
        if f.get("ai_learning"):
            f["ai_analysis"] = {
                "explanation": f.get("ai_explanation"),
                "fix_conceptual": f.get("ai_fix"),
                "learning": f.get("ai_learning"),
            }
    return jsonify({"findings": findings, "counts": (scan.get("summary") or {}).get("counts", {})})


@app.get("/api/scans/<scan_id>/tests")
def api_get_tests(scan_id):
    if not db.get_scan(scan_id):
        return jsonify({"error": "not found"}), 404
    return jsonify({"tests": db.get_tests(scan_id)})


@app.post("/api/scans/<scan_id>/analyze")
def api_analyze_finding(scan_id):
    """On-demand AI deep analysis for a single finding (AI Debug Assistant)."""
    data = request.get_json(silent=True) or {}
    fid = data.get("finding_id")
    finding = db.get_finding(fid) if fid else None
    if not finding or finding["scan_id"] != scan_id:
        return jsonify({"error": "finding not found"}), 404
    analysis = _ai.analyze_finding(finding)
    db.update_finding(fid,
                      ai_explanation=analysis.get("explanation"),
                      ai_fix=analysis.get("fix_conceptual"),
                      ai_learning=analysis.get("learning"),
                      ai_fix_code=analysis.get("fix_code"))
    finding.update(analysis)
    finding["ai_fix_code"] = analysis.get("fix_code")
    return jsonify(finding)


@app.get("/api/scans/<scan_id>/findings/<fid>")
def api_get_finding(scan_id, fid):
    finding = db.get_finding(fid)
    if not finding or finding["scan_id"] != scan_id:
        return jsonify({"error": "not found"}), 404
    return jsonify(finding)


@app.post("/api/scans/<scan_id>/perf")
def api_run_perf(scan_id):
    """Run / re-run the load-test module on demand."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    url = scan["target"].rstrip("/") + (data.get("path") or "/api/health")
    report = perf_engine.run_load_test(
        url, concurrency=data.get("concurrency"), duration_s=data.get("duration"))
    summary = scan.get("summary") or {}
    summary["performance"] = report
    db.update_scan(scan_id, summary=summary)
    return jsonify(report)


@app.get("/api/scans/<scan_id>/report")
def api_download_report(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    fmt = request.args.get("format", "developer")
    findings = db.get_findings(scan_id)
    if fmt == "client":
        path = report_generator.generate_client_report(scan, findings)
    elif fmt == "json":
        path = report_generator.generate_json_export(scan, findings, db.get_tests(scan_id))
    else:
        path = report_generator.generate_dev_report(scan, findings)
    if not os.path.exists(path):
        abort(500)
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))


# ------------------------------------------------------------- AI assistant --
@app.post("/api/ai/assistant")
def api_ai_assistant():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400
    context = data.get("context") or {}
    finding = None
    if data.get("finding_id"):
        finding = db.get_finding(data["finding_id"])
        context = finding or context
    answer = _ai.assistant_chat(question, context or {"topic": "general security"})
    return jsonify({"answer": answer, "backend": _ai.backend_name})


# -------------------------------------------------------------- monitoring --
@app.get("/api/alerts")
def api_alerts():
    unread_only = request.args.get("unread") == "1"
    return jsonify({"alerts": db.list_alerts(50, unread_only)})


@app.post("/api/alerts/read")
def api_alerts_read():
    db.mark_alerts_read()
    return jsonify({"ok": True})


@app.post("/api/monitor/<scan_id>/start")
def api_monitor_start(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    interval = int(request.get_json(silent=True).get("interval", 0) or Config.MONITOR_INTERVAL_S) \
        if request.get_json(silent=True) else Config.MONITOR_INTERVAL_S
    db.upsert_monitor(scan_id, interval)
    monitor.manager.start()
    return jsonify({"monitoring": True, "interval_s": interval})


@app.post("/api/monitor/<scan_id>/stop")
def api_monitor_stop(scan_id):
    db.deactivate_monitor(scan_id)
    return jsonify({"monitoring": False})


@app.get("/api/monitor/<scan_id>")
def api_monitor_status(scan_id):
    return jsonify({"monitor": db.get_monitor(scan_id)})


# ---------------------------------------------------------------- startup --
def launch_demo_target():
    """Start the vulnerable demo app in a daemon thread (port 5099)."""
    import demo_target.vulnerable_app as demo

    t = threading.Thread(
        target=lambda: demo.app.run(host="127.0.0.1", port=5099, threaded=True),
        daemon=True, name="sentinel-demo-target")
    t.start()
    print("[sentinel] demo target live at", Config.DEMO_TARGET_URL)


def main():
    parser = argparse.ArgumentParser(description="Sentinel AI")
    parser.add_argument("--with-demo", action="store_true",
                        help="also launch the vulnerable demo target on :5099")
    args = parser.parse_args()
    if args.with_demo:
        launch_demo_target()
    monitor.manager.start()
    print(f"[sentinel] dashboard: http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, threaded=True)


if __name__ == "__main__":
    main()
