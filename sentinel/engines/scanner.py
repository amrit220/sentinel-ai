"""API Testing Engine.

- Parses OpenAPI/Swagger specs (JSON or YAML) or auto-discovers endpoints.
- Generates functional / edge / negative test cases per endpoint.
- Executes them and validates status codes, response structure, latency
  and error handling.
"""
import json
import re
import time

import requests
import yaml

from config import Config

try:
    from yaml import YAMLError
except ImportError:  # pragma: no cover
    YAMLError = Exception

COMMON_PATHS = [
    "/api/users", "/api/user", "/api/items", "/api/products", "/api/orders",
    "/api/search", "/api/login", "/api/auth", "/api/register", "/api/profile",
    "/api/admin", "/api/admin/secret", "/api/echo", "/api/data", "/api/health",
    "/api/status", "/api/config", "/api/debug", "/api/metrics", "/api/uploads",
    "/api/files", "/api/user/1", "/api/users/1", "/api/ping", "/api/info",
    "/api/error", "/api/fail", "/api/crash", "/api/exception", "/api/logs",
]


class Endpoint:
    def __init__(self, path, methods=None, params=None, has_body=False, description=""):
        self.path = path
        self.methods = methods or ["GET"]
        self.params = params or {}      # name -> {type, required}
        self.has_body = has_body
        self.description = description

    def to_dict(self):
        return {
            "path": self.path,
            "methods": self.methods,
            "params": self.params,
            "has_body": self.has_body,
            "description": self.description,
        }


def http(method, url, timeout=None, **kwargs):
    """Central HTTP helper - never raises, always returns a response dict."""
    timeout = timeout or Config.REQUEST_TIMEOUT
    try:
        r = requests.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:4000] if r.text else "",
            "json": _try_json(r),
            "latency_ms": round(r.elapsed.total_seconds() * 1000, 1),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "headers": {}, "body": "", "json": None,
                "latency_ms": timeout * 1000, "error": "timeout"}
    except requests.exceptions.RequestException as exc:
        return {"status": 0, "headers": {}, "body": "", "json": None,
                "latency_ms": 0, "error": str(exc)}


def _try_json(r):
    try:
        return r.json()
    except (ValueError, TypeError):
        return None


# ------------------------------------------------------------- discovery ----
def parse_openapi(spec_text):
    """Parse an OpenAPI/Swagger document into Endpoint objects."""
    try:
        spec = json.loads(spec_text)
    except ValueError:
        spec = yaml.safe_load(spec_text)
    if not isinstance(spec, dict):
        return []

    endpoints = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        methods, params, has_body = [], {}, False
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            methods.append(method.upper())
            if not isinstance(op, dict):
                continue
            for p in op.get("parameters", []) or []:
                if isinstance(p, dict) and p.get("name"):
                    params[p["name"]] = {
                        "type": (p.get("schema") or {}).get("type") or p.get("type", "string"),
                        "required": bool(p.get("required")),
                    }
            if method.lower() in ("post", "put", "patch"):
                has_body = True
        if methods:
            endpoints.append(Endpoint(path, methods, params, has_body))
    return endpoints


def fetch_openapi_from_target(base_url):
    """Try common spec locations on the target itself."""
    for candidate in ("/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs"):
        res = http("GET", base_url.rstrip("/") + candidate, timeout=4)
        if res["status"] == 200 and res["body"].strip().startswith(("{", "openapi")):
            eps = parse_openapi(res["body"])
            if eps:
                return eps
    return []


def probe_common_paths(base_url):
    """Brute-force a list of common API paths (used when no spec exists)."""
    found = []
    for path in COMMON_PATHS:
        res = http("GET", base_url.rstrip("/") + path, timeout=4)
        if res["status"] in (200, 201, 301, 302, 401, 403, 405, 500):
            if res["status"] == 405:
                found.append(Endpoint(path, ["POST"]))
            else:
                found.append(Endpoint(path, ["GET"]))
    return found


def discover_endpoints(base_url, openapi_text=None):
    """Full discovery: explicit spec -> target-hosted spec -> probing."""
    if openapi_text:
        eps = parse_openapi(openapi_text)
        if eps:
            return eps, "openapi-input"
    eps = fetch_openapi_from_target(base_url)
    if eps:
        return eps, "openapi-discovered"
    return probe_common_paths(base_url), "probed"


# ------------------------------------------------------ test generation -----
class TestCase:
    def __init__(self, name, kind, method, url, params=None, json_body=None,
                 headers=None, expected_status=None, expect_json=None,
                 max_latency_ms=None):
        self.name = name
        self.kind = kind                    # functional | edge | negative
        self.method = method
        self.url = url
        self.params = params or {}
        self.json_body = json_body
        self.headers = headers or {}
        self.expected_status = expected_status
        self.expect_json = expect_json
        self.max_latency_ms = max_latency_ms or Config.VERY_SLOW_REQUEST_MS


def _gen_cases_for(base_url, ep):
    """Generate functional, edge and negative cases for one endpoint."""
    url = base_url.rstrip("/") + ep.path
    cases = []

    # ---- functional: baseline request per method
    for m in ep.methods:
        cases.append(TestCase(
            f"{m} {ep.path} baseline", "functional", m, url,
            params={k: _sample_value(v.get("type")) for k, v in ep.params.items()},
            expected_status=_ok_range(m), expect_json=True,
        ))

    # ---- edge cases on the first query parameter (or path itself)
    if ep.params:
        pname = list(ep.params)[0]
        edge_values = [
            ("empty", ""),
            ("unicode", "Ω≈ç√∫˜µ≤≥Ææſ"),
            ("long-8k", "A" * 8192),
            ("specials", "<>&\"';%$#"),
            ("null-byte", "test%00"),
        ]
        for label, val in edge_values:
            cases.append(TestCase(
                f"edge: {pname}={label}", "edge", "GET", url,
                params={**{k: _sample_value(v.get('type')) for k, v in ep.params.items()},
                        pname: val},
                expected_status=_ok_range("GET"), expect_json=True,
            ))

    # ---- negative tests (a clean rejection is what we expect)
    cases.append(TestCase(
        f"negative: bad method PATCH {ep.path}", "negative", "PATCH", url,
        expected_status=(400, 401, 403, 405, 415, 501),
    ))
    if ep.has_body:
        cases.append(TestCase(
            f"negative: malformed JSON body {ep.path}", "negative", "POST", url,
            headers={"Content-Type": "application/json"},
            expected_status=(400, 401, 403, 415),
        ))
        cases.append(TestCase(
            f"negative: empty body {ep.path}", "negative", "POST", url,
            headers={"Content-Type": "application/json"},
            expected_status=(400, 401, 403, 415),
        ))
    return cases


def _sample_value(ptype):
    return {"integer": "1", "number": "1.5", "boolean": "true"}.get(ptype, "sentinel-test")


def _ok_range(method):
    """Accept 2xx; auth-protected responses (401/403) are also valid behavior."""
    if method in ("POST", "PUT", "PATCH"):
        return (200, 201, 204, 401, 403)
    return (200, 203, 204, 401, 403)


def generate_tests(base_url, endpoints):
    cases = []
    for ep in endpoints:
        cases.extend(_gen_cases_for(base_url, ep))
    return cases


# --------------------------------------------------------- execution --------
def run_test(case):
    """Execute a single TestCase and produce a result dict."""
    kwargs = {"params": case.params or None, "headers": case.headers or None}
    if case.json_body is not None:
        kwargs["data"] = case.json_body
    if case.method == "POST" and case.json_body is None and "Content-Type" in case.headers:
        # deliberately malformed/empty body
        kwargs["data"] = "{not-valid-json!!"

    res = http(case.method, case.url, **kwargs)

    result = {
        "name": case.name,
        "kind": case.kind,
        "endpoint": case.url.replace("http://", "").replace("https://", ""),
        "method": case.method,
        "status": "pass",
        "expected": _fmt_expected(case),
        "actual": f"HTTP {res['status']}" if res["status"] else f"error: {res['error']}",
        "latency_ms": res["latency_ms"],
        "response_snippet": (res["body"] or "")[:400],
    }

    problems = []
    if res["error"]:
        result["status"] = "fail"
        problems.append(res["error"])
    else:
        if case.expected_status and res["status"] not in list(case.expected_status):
            result["status"] = "fail"
            problems.append(f"unexpected status {res['status']}")
        if (case.expect_json and res["json"] is None
                and "json" in (res["headers"].get("Content-Type") or "")):
            result["status"] = "fail"
            problems.append("invalid JSON structure")
        elif case.expect_json and res["json"] is None and case.kind == "functional":
            # baseline returned non-JSON - record as pass but flag
            result["status"] = "warn"
            problems.append("response is not JSON")
        if res["latency_ms"] > Config.VERY_SLOW_REQUEST_MS:
            if result["status"] == "pass":
                result["status"] = "warn"
            problems.append(f"slow response {res['latency_ms']}ms")

    # leak detection: verbose errors / stack traces in response body
    if res["body"] and _looks_like_stack_trace(res["body"]) and case.kind != "negative":
        result["status"] = "fail"
        problems.append("response leaks stack trace / internal details")

    result["problems"] = problems
    return result


def _fmt_expected(case):
    if case.expected_status:
        return f"status in {list(case.expected_status)}"
    return "no crash"


def _looks_like_stack_trace(body):
    markers = ("Traceback (most recent call last)", "at java.", "System.NullReferenceException")
    return any(m in body for m in markers)


def full_scan_tests(base_url, endpoints, progress_cb=None):
    """Generate + run all tests. Returns (results, baseline_responses)."""
    cases = generate_tests(base_url, endpoints)
    results, baselines = [], {}
    for i, case in enumerate(cases):
        if progress_cb:
            progress_cb(int(i / max(len(cases), 1) * 100))
        r = run_test(case)
        results.append(r)
        if "baseline" in case.name:
            key = (case.method, case.url)
            baselines[key] = r
    return results, baselines
