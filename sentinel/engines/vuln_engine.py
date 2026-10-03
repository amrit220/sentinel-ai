"""Vulnerability Detection Engine.

Consumes raw AttackResults + test results and classifies them into
deduplicated Finding records with severity, confidence and fingerprints
(stable IDs used by continuous monitoring to diff between runs).
"""
import hashlib

from config import Config, SEVERITY_WEIGHTS

SEVERITY_MAP = {
    "sqli":               dict(severity="critical", weight=10.0, cvss="9.8"),
    "command_injection":  dict(severity="critical", weight=10.0, cvss="9.8"),
    "broken_auth":        dict(severity="critical", weight=9.0,  cvss="9.1"),
    "open_endpoint":      dict(severity="critical", weight=9.0,  cvss="8.6"),
    "data_leakage":       dict(severity="critical", weight=8.5,  cvss="8.2"),
    "path_traversal":     dict(severity="critical", weight=8.5,  cvss="7.5"),
    "xss":                dict(severity="high",     weight=7.5,  cvss="7.4"),
    "verbose_error":      dict(severity="high",     weight=6.0,  cvss="6.5"),
    "improper_validation": dict(severity="medium", weight=5.0,  cvss="6.3"),
    "missing_headers":    dict(severity="medium", weight=4.0,  cvss="5.4"),
    "engine_error":       dict(severity="info",    weight=0.0,  cvss="0.0"),
}

TITLES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (Reflected)",
    "broken_auth": "Broken Authentication",
    "open_endpoint": "Open / Unauthenticated Endpoint",
    "data_leakage": "Sensitive Data Exposure",
    "path_traversal": "Path Traversal",
    "command_injection": "OS Command Injection",
    "missing_headers": "Missing Security Headers",
    "verbose_error": "Verbose Error Disclosure",
    "improper_validation": "Improper Input Validation",
    "engine_error": "Engine Internal Notice",
}


def _fingerprint(category, endpoint, payload_label):
    raw = f"{category}|{endpoint}|{payload_label}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def attacks_to_findings(attacks):
    """Convert AttackResults into normalized findings (deduped)."""
    findings, seen = [], set()
    for a in attacks:
        endpoint = (a.request or {}).get("url", "")
        if endpoint:
            endpoint = endpoint.split("://")[-1].split("/", 1)
            endpoint = "/" + (endpoint[1] if len(endpoint) > 1 else "")
        fp = _fingerprint(a.category, endpoint, a.payload_label)
        if fp in seen:
            continue
        seen.add(fp)

        meta = SEVERITY_MAP.get(a.category, dict(severity="medium", weight=4.0, cvss="5.0"))
        findings.append({
            "fingerprint": fp,
            "category": a.category,
            "severity": meta["severity"],
            "title": TITLES.get(a.category, a.category.replace("_", " ").title()),
            "endpoint": endpoint,
            "method": (a.request or {}).get("method", "GET"),
            "evidence": a.evidence,
            "impact": a.impact,
            "request": a.request,
            "response": {
                "status": a.response.get("status"),
                "latency_ms": a.response.get("latency_ms"),
                "headers": a.response.get("headers"),
                "body_snippet": (a.response.get("body") or "")[:Config.MAX_RESPONSE_SNIPPET] if isinstance(a.response, dict) else "",
            },
            "attack_path": a.steps,
            "exploit_success": bool(a.success),
            "confidence": min(0.6 + meta["weight"] * 0.045, 0.99),
            "cvss": meta["cvss"],
        })
    return findings


def test_failures_to_findings(test_results):
    """Convert notable test failures (slow responses, bad error handling)
    into low/medium severity findings."""
    findings = []
    for t in test_results:
        if t["status"] != "fail" and not (t["status"] == "warn" and "slow response" in " ".join(t.get("problems", []))):
            continue
        problems = t.get("problems") or []
        if any("slow response" in p for p in problems) and t["status"] == "warn":
            findings.append({
                "fingerprint": _fingerprint("perf_latency", t["endpoint"], t["name"]),
                "category": "perf_latency",
                "severity": "medium",
                "title": "Performance - Slow Response",
                "endpoint": t["endpoint"],
                "method": t.get("method"),
                "evidence": f"{t['name']}: {t['latency_ms']}ms ({'; '.join(problems)})",
                "impact": "Degraded user experience; possible DoS amplification under load.",
                "request": {"method": t.get("method"), "url": t["endpoint"]},
                "response": {"status": "n/a", "latency_ms": t.get("latency_ms")},
                "attack_path": [
                    {"step": 1, "title": "Latency measurement",
                     "detail": f"Test '{t['name']}' took {t['latency_ms']}ms to respond."},
                    {"step": 2, "title": "Threshold breach",
                     "detail": "Response exceeded the acceptable latency threshold."},
                ],
                "exploit_success": False,
                "confidence": 0.7,
                "cvss": "4.3",
            })
        if t["status"] == "fail":
            findings.append({
                "fingerprint": _fingerprint("error_handling", t["endpoint"], t["name"]),
                "category": "error_handling",
                "severity": "low",
                "title": "Unexpected API Behavior",
                "endpoint": t["endpoint"],
                "method": t.get("method"),
                "evidence": f"{t['name']}: expected {t['expected']}, got {t['actual']} ({'; '.join(problems)})",
                "impact": "Inconsistent API contract; weak error handling confuses clients and hides bugs.",
                "request": {"method": t.get("method"), "url": t["endpoint"]},
                "response": {"status": t["actual"], "body_snippet": t.get("response_snippet")},
                "attack_path": [
                    {"step": 1, "title": "Test execution",
                     "detail": f"Ran '{t['name']}' ({t['kind']} test)."},
                    {"step": 2, "title": "Contract violation",
                     "detail": f"Expected {t['expected']}, received {t['actual']}."},
                ],
                "exploit_success": False,
                "confidence": 0.65,
                "cvss": "3.1",
            })
    return findings


SEVERITY_MAP["perf_latency"] = dict(severity="medium", weight=4.0, cvss="4.3")
SEVERITY_MAP["error_handling"] = dict(severity="low", weight=2.0, cvss="3.1")
TITLES["perf_latency"] = "Performance - Slow Response"
TITLES["error_handling"] = "Unexpected API Behavior"


def severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return counts
