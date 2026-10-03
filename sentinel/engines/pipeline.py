"""Scan Pipeline Orchestrator.

Coordinates the full flow:
  discover -> functional/edge/negative tests -> attack simulation ->
  vulnerability classification -> AI enrichment -> scoring -> summary -> persist.

Runs in a background thread; progress is written to the scans table so the
dashboard can poll it.
"""
import threading

from config import Config
from .. import database as db
from .. import scoring
from ..ai_layer import get_ai
from . import scanner, attack_engine, vuln_engine, perf_engine


def run_scan(scan_id):
    """Entry point - executes a scan synchronously (call inside a thread)."""
    scan = db.get_scan(scan_id)
    if not scan:
        return
    cfg = scan.get("config") or {}
    target = scan["target"]
    base_url = target if target.startswith("http") else "http://" + target
    modules = cfg.get("modules", {})

    # monitoring re-run: wipe previous findings/tests so diffs are meaningful
    if scan.get("status") in ("completed", "failed"):
        db.clear_scan_data(scan_id)

    db.update_scan(scan_id, status="running", stage="discovery", progress=5,
                   started_at=_now())

    try:
        # 1. discovery -----------------------------------------------------
        endpoints, discovery_mode = scanner.discover_endpoints(
            base_url, openapi_text=cfg.get("openapi"))
        if not endpoints:
            endpoints = [scanner.Endpoint("/", ["GET"])]
        db.update_scan(scan_id, stage=f"discovered {len(endpoints)} endpoints "
                                      f"({discovery_mode})", progress=12)

        # 2. functional / edge / negative tests ----------------------------
        test_results, baselines = [], {}
        if modules.get("functional", True):
            db.update_scan(scan_id, stage="running test suite", progress=15)
            def tc(p): db.update_scan(scan_id, progress=15 + int(p * 0.25),
                                      stage=f"tests {p}%")
            test_results, baselines = scanner.full_scan_tests(base_url, endpoints, tc)
            for t in test_results:
                db.add_test(scan_id, t)
            db.update_scan(scan_id, stage=f"tests complete "
                          f"({sum(1 for t in test_results if t['status']=='pass')}/{len(test_results)} passed)",
                          progress=42)

        # 3. attack simulations ---------------------------------------------
        attacks = []
        if modules.get("attacks", True):
            db.update_scan(scan_id, stage="simulating attacks", progress=45)
            def ac(p, name): db.update_scan(scan_id, progress=45 + int(p * 0.2),
                                            stage=f"attack suite: {name}")
            attacks = attack_engine.run_all_attacks(base_url, endpoints, baselines, ac)

        # 4. classification ---------------------------------------------------
        db.update_scan(scan_id, stage="classifying vulnerabilities", progress=68)
        findings = vuln_engine.attacks_to_findings(attacks)
        findings += vuln_engine.test_failures_to_findings(test_results)

        # 5. performance module ----------------------------------------------
        perf_report = None
        if modules.get("performance", False) and endpoints:
            db.update_scan(scan_id, stage="load testing", progress=72)
            ep = endpoints[0]
            perf_report = perf_engine.run_load_test(
                base_url.rstrip("/") + ep.path,
                concurrency=cfg.get("perfConcurrency", Config.PERF_CONCURRENCY),
                duration_s=cfg.get("perfDuration", Config.PERF_DURATION_S))
            db.add_test(scan_id, {
                "name": f"load test {ep.path}", "kind": "performance",
                "endpoint": ep.path, "method": "GET",
                "status": "warn" if perf_report["verdict"] != "healthy" else "pass",
                "expected": "verdict healthy",
                "actual": f"verdict {perf_report['verdict']}, p95={perf_report['latency_p95_ms']}ms",
                "latency_ms": perf_report["latency_p95_ms"],
                "response_snippet": perf_report["bottleneck_analysis"],
            })

        # 6. persistence + AI enrichment --------------------------------------
        db.update_scan(scan_id, stage="AI analysis", progress=78)
        ai = get_ai()
        finding_ids = []
        for f in findings:
            fid = db.add_finding(scan_id, f)
            finding_ids.append((fid, f))

        # enrich top-severity findings with AI content
        enriched = list(findings)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        enriched.sort(key=lambda x: order.get(x.get("severity"), 5))
        for fid, f in finding_ids[:10]:
            analysis = ai.analyze_finding(f)
            f["ai_analysis"] = analysis
            db.update_finding(fid,
                              ai_explanation=analysis.get("explanation"),
                              ai_fix=analysis.get("fix_conceptual"),
                              ai_learning=analysis.get("learning"),
                              ai_fix_code=analysis.get("fix_code"))
        # enrich the rest lazily (kept in DB without AI until requested)
        for fid, f in finding_ids[10:]:
            db.update_finding(fid, ai_fix_code=None)

        # 7. scoring ------------------------------------------------------------
        db.update_scan(scan_id, stage="scoring", progress=90)
        lat = [t.get("latency_ms", 0) for t in test_results if t.get("latency_ms")]
        if perf_report:
            lat.extend([perf_report["latency_p50_ms"]] * 20)
        err_rate = perf_report["error_rate"] if perf_report else \
            (sum(1 for t in test_results if t["status"] == "fail") / max(len(test_results), 1))
        sec = scoring.security_score(findings)
        perf = scoring.performance_score(lat, err_rate)
        qual = scoring.quality_score(test_results)
        ovr = scoring.overall(sec, perf, qual)

        # 8. AI summary -----------------------------------------------------------
        ai_summary = ai.summarize_scan(target, enriched, {
            "overall": ovr, "security": sec, "performance": perf, "quality": qual,
        })

        counts = vuln_engine.severity_counts(findings)
        passed = sum(1 for t in test_results if t["status"] == "pass")
        warned = sum(1 for t in test_results if t["status"] == "warn")
        failed = len(test_results) - passed - warned
        risk, color = scoring.risk_level(ovr)

        summary = {
            "scores": {"overall": ovr, "security": sec, "performance": perf,
                       "quality": qual, "grade": scoring.grade(ovr),
                       "risk": risk, "risk_color": color},
            "counts": counts,
            "endpoints_scanned": len(endpoints),
            "discovery_mode": discovery_mode,
            "attacks_simulated": len(attacks),
            "test_total": len(test_results),
            "test_passed": passed, "test_warned": warned, "test_failed": failed,
            "performance": perf_report,
            "ai_summary": ai_summary,
            "ai_backend": ai.backend_name,
        }
        db.update_scan(scan_id, status="completed", stage="completed", progress=100,
                       summary=summary, finished_at=_now())

        # initial critical findings also raise alerts
        for f in findings:
            if f.get("severity") == "critical":
                db.add_alert(scan_id,
                             f"Critical finding: {f['title']} at {f.get('endpoint')}",
                             "critical")

    except Exception as exc:
        db.update_scan(scan_id, status="failed", stage="failed",
                       error=str(exc), finished_at=_now())


def start_scan_async(target, label=None, config=None):
    """Create the scan record and launch the pipeline in a daemon thread."""
    scan_id = db.create_scan(target, label, config or {})
    threading.Thread(target=run_scan, args=(scan_id,), daemon=True,
                     name=f"sentinel-scan-{scan_id}").start()
    return scan_id


def _now():
    import time
    return time.time()
