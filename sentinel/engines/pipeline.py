"""Scan Pipeline Orchestrator.

Dispatches by scan mode:
  api  : discovery -> functional/edge/negative tests -> attack simulation ->
         classification -> AI enrichment -> scoring -> summary -> persist
  repo : clone/local-read -> static analysis (rule packs, secrets, files,
         CI/Docker, OSV dependency audit) [-> optional Docker runtime ->
         dynamic attack engines] -> AI enrichment -> scoring -> persist

Both modes converge on the same persistence/scoring/AI tail, so reports,
learning mode, monitoring and alerts work identically for both.

Runs in a background thread; progress is written to the scans table so
the dashboard can poll it.
"""
import threading

from config import Config
from .. import database as db
from .. import scoring
from ..ai_layer import get_ai
from . import scanner, attack_engine, vuln_engine, perf_engine, repo_engine


def run_scan(scan_id):
    """Entry point - executes a scan synchronously (call inside a thread)."""
    scan = db.get_scan(scan_id)
    if not scan:
        return
    cfg = scan.get("config") or {}

    # monitoring re-run: wipe previous findings/tests so diffs are meaningful
    if scan.get("status") in ("completed", "failed"):
        db.clear_scan_data(scan_id)

    db.update_scan(scan_id, status="running", stage="starting", progress=3,
                   started_at=_now())

    try:
        if cfg.get("mode", "api") == "repo":
            _run_repo_mode(scan_id, scan, cfg)
        else:
            _run_api_mode(scan_id, scan, cfg)
    except Exception as exc:
        db.update_scan(scan_id, status="failed", stage="failed",
                       error=str(exc), finished_at=_now())


# ================================================================= API mode =
def _run_api_mode(scan_id, scan, cfg):
    target = scan["target"]
    base_url = target if target.startswith("http") else "http://" + target
    modules = cfg.get("modules", {})

    # reachability check -------------------------------------------------
    reach = scanner.http("GET", base_url, timeout=5)
    if reach["status"] == 0:  # 0 = network-level failure (refused/DNS/timeout)
        hint = ""
        if base_url.rstrip("/").endswith(":5099"):
            hint = (" If you intended to scan the bundled demo target, launch Sentinel "
                    "with:  python app.py --with-demo")
        db.update_scan(scan_id, status="failed", stage="unreachable",
                       error=(f"Target {base_url} is unreachable ({reach.get('error')}). "
                              "Verify the URL, that the service is running, and that it "
                              f"is network-reachable from this machine.{hint}"),
                       finished_at=_now())
        return

    # discovery ------------------------------------------------------------
    db.update_scan(scan_id, stage="discovery", progress=6)
    endpoints, discovery_mode = scanner.discover_endpoints(
        base_url, openapi_text=cfg.get("openapi"))
    if not endpoints:
        endpoints = [scanner.Endpoint("/", ["GET"])]
    db.update_scan(scan_id, stage=f"discovered {len(endpoints)} endpoints "
                                  f"({discovery_mode})", progress=12)

    # functional / edge / negative tests ------------------------------------
    test_results, baselines = [], {}
    if modules.get("functional", True):
        db.update_scan(scan_id, stage="running test suite", progress=15)

        def tc(p):
            db.update_scan(scan_id, progress=15 + int(p * 0.25), stage=f"tests {p}%")

        test_results, baselines = scanner.full_scan_tests(base_url, endpoints, tc)
        for t in test_results:
            db.add_test(scan_id, t)
        db.update_scan(scan_id, stage=f"tests complete "
                      f"({sum(1 for t in test_results if t['status']=='pass')}/{len(test_results)} passed)",
                      progress=42)

    # attack simulations ------------------------------------------------------
    attacks = []
    if modules.get("attacks", True):
        db.update_scan(scan_id, stage="simulating attacks", progress=45)

        def ac(p, name):
            db.update_scan(scan_id, progress=45 + int(p * 0.2),
                           stage=f"attack suite: {name}")

        attacks = attack_engine.run_all_attacks(base_url, endpoints, baselines, ac)

    # classification -------------------------------------------------------------
    db.update_scan(scan_id, stage="classifying vulnerabilities", progress=68)
    findings = vuln_engine.attacks_to_findings(attacks)
    findings += vuln_engine.test_failures_to_findings(test_results)

    # performance module ----------------------------------------------------------
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

    # shared tail ------------------------------------------------------------
    lat = [t.get("latency_ms", 0) for t in test_results if t.get("latency_ms")]
    if perf_report:
        lat.extend([perf_report["latency_p50_ms"]] * 20)
    err_rate = perf_report["error_rate"] if perf_report else \
        (sum(1 for t in test_results if t["status"] == "fail") / max(len(test_results), 1))
    _finalize_scan(scan_id, scan, findings, test_results,
                   perf_report=perf_report,
                   extra_summary={
                       "endpoints_scanned": len(endpoints),
                       "discovery_mode": discovery_mode,
                       "attacks_simulated": len(attacks),
                   },
                   latencies=lat, error_rate=err_rate)


# =============================================================== REPO mode =
def _run_repo_mode(scan_id, scan, cfg):
    def cb(stage, pct):
        if stage:
            db.update_scan(scan_id, stage=stage, progress=pct)

    findings, meta = repo_engine.run_repo_scan(cfg, scan_id, cb)
    display = meta.get("display") or scan["target"]

    # optional experimental runtime sandbox --------------------------------
    if cfg.get("repo_modules", {}).get("runtime", False):
        db.update_scan(scan_id, stage="runtime sandbox (experimental)", progress=82)
        base_url, err = repo_engine.try_runtime(meta.get("repo_path", ""))
        if base_url:
            db.update_scan(scan_id, stage="runtime sandbox live — attacking", progress=86)
            endpoints = scanner.probe_common_paths(base_url)
            attacks = attack_engine.run_all_attacks(base_url, endpoints)
            findings += vuln_engine.attacks_to_findings(attacks)
        elif err:
            findings.append({
                "fingerprint": f"runtime-note-{scan_id}",
                "category": "engine_error", "severity": "info",
                "title": "Runtime Sandbox Note",
                "endpoint": "runtime",
                "method": "STATIC",
                "evidence": err, "impact": "",
                "request": {"mode": "static", "file": "runtime"},
                "response": {"status": "source", "body_snippet": err},
                "attack_path": [], "exploit_success": False, "confidence": 1.0,
            })

    _finalize_scan(scan_id, scan, findings, [],
                   perf_report=None,
                   extra_summary={
                       "kind": meta.get("kind"),
                       "repo_display": display,
                       "files_analyzed": meta.get("files"),
                       "text_files_analyzed": meta.get("text_files"),
                       "lines_of_code": meta.get("loc"),
                       "languages": meta.get("languages"),
                       "mode": "repo",
                   },
                   latencies=None, error_rate=None)


# ================================================================ shared ==
_HYGIENE_CATS = {"debug_prod", "weak_crypto", "cors_wildcard", "docker_risk",
                 "unpinned_dependency"}


def _finalize_scan(scan_id, scan, findings, test_results, perf_report,
                   extra_summary, latencies, error_rate):
    """Persist findings, AI-enrich, score, summarize, alert. Shared by modes."""
    is_repo = extra_summary.get("mode") == "repo"

    # persistence + AI enrichment -------------------------------------------
    db.update_scan(scan_id, stage="AI analysis", progress=88)
    ai = get_ai()
    finding_ids = []
    for f in findings:
        fid = db.add_finding(scan_id, f)
        finding_ids.append((fid, f))

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

    # scoring ------------------------------------------------------------------
    db.update_scan(scan_id, stage="scoring", progress=92)
    sec = scoring.security_score(findings)
    if is_repo:
        perf = None  # not measured in static mode
        penalty = sum(4.0 if f.get("severity") == "medium" else 1.5
                      for f in findings if f.get("category") in _HYGIENE_CATS)
        qual = scoring.clamp(100 - penalty, 30, 100)
        ovr = scoring.clamp(sec * 0.75 + qual * 0.25)
    else:
        perf = scoring.performance_score(latencies or [], error_rate or 0)
        qual = scoring.quality_score(test_results)
        ovr = scoring.overall(sec, perf, qual)

    # AI summary ------------------------------------------------------------------
    ai_summary = ai.summarize_scan(scan["target"], enriched, {
        "overall": ovr, "security": sec,
        "performance": perf if perf is not None else "not measured (static analysis)",
        "quality": qual,
    })

    counts = vuln_engine.severity_counts(findings)
    passed = sum(1 for t in test_results if t.get("status") == "pass")
    warned = sum(1 for t in test_results if t.get("status") == "warn")
    failed = len(test_results) - passed - warned
    risk, color = scoring.risk_level(ovr)

    summary = {
        "scores": {"overall": ovr, "security": sec, "performance": perf,
                   "quality": qual, "grade": scoring.grade(ovr),
                   "risk": risk, "risk_color": color},
        "counts": counts,
        "test_total": len(test_results),
        "test_passed": passed, "test_warned": warned, "test_failed": failed,
        "performance": perf_report,
        "ai_summary": ai_summary,
        "ai_backend": ai.backend_name,
        "mode": "repo" if is_repo else "api",
    }
    summary.update(extra_summary)

    db.update_scan(scan_id, status="completed", stage="completed", progress=100,
                   summary=summary, finished_at=_now())

    # critical findings raise alerts
    for f in findings:
        if f.get("severity") == "critical":
            db.add_alert(scan_id,
                         f"Critical finding: {f['title']} at {f.get('endpoint')}",
                         "critical")


def start_scan_async(target, label=None, config=None):
    """Create the scan record and launch the pipeline in a daemon thread."""
    scan_id = db.create_scan(target, label, config or {})
    threading.Thread(target=run_scan, args=(scan_id,), daemon=True,
                     name=f"sentinel-scan-{scan_id}").start()
    return scan_id


def _now():
    import time
    return time.time()
