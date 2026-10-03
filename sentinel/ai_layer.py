"""AI Analysis Layer.

Two interchangeable backends:

1. `LLMBackend`    - calls any OpenAI-compatible REST endpoint when
                     OPENAI_API_KEY / SENTINEL_LLM_KEY is configured.
2. `SentinelMind`  - a built-in rule-based security analyst used as a
                     fallback so the prototype works fully offline.

The rest of the system only ever talks to `AILayer`, never to a specific
backend directly (clean substitution point for future models).
"""
import json
import re

import requests

from config import Config

# ===================================================================== LLM ==
class LLMBackend:
    name = "llm"

    def _chat(self, system, user, max_tokens=1200):
        resp = requests.post(
            Config.LLM_BASE_URL.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {Config.LLM_API_KEY}"},
            json={
                "model": Config.LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            },
            timeout=45,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def analyze_finding(self, finding):
        prompt = (
            "You are Sentinel AI, an autonomous security analyst. For the vulnerability "
            "below return STRICT JSON with keys: explanation (what happened, plain language), "
            "root_cause (why), fix_conceptual, fix_code (a short concrete code snippet), "
            "mistake, best_practice, why_it_matters.\n\n"
            + json.dumps({
                "title": finding.get("title"),
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "endpoint": finding.get("endpoint"),
                "evidence": finding.get("evidence"),
            })
        )
        raw = self._chat("Return only valid JSON, no markdown fences.", prompt)
        try:
            data = json.loads(re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.M))
        except ValueError:
            data = {"explanation": raw}
        return {
            "explanation": data.get("explanation", raw),
            "root_cause": data.get("root_cause", ""),
            "fix_conceptual": data.get("fix_conceptual", ""),
            "fix_code": data.get("fix_code", ""),
            "learning": {
                "mistake": data.get("mistake", ""),
                "best_practice": data.get("best_practice", ""),
                "why": data.get("why_it_matters", ""),
            },
        }

    def summarize_scan(self, target, findings, scores):
        prompt = (
            "Summarize this security scan for both a CTO and a junior developer. "
            "Return STRICT JSON: executive_summary (3-4 sentences), top_risks (list of 3 strings), "
            "recommendations (list of 4 strings: middleware, headers, architecture, process).\n\n"
            + json.dumps({
                "target": target,
                "scores": scores,
                "findings": [
                    {"title": f["title"], "severity": f["severity"], "endpoint": f["endpoint"]}
                    for f in findings
                ],
            })
        )
        raw = self._chat("Return only valid JSON, no markdown fences.", prompt)
        try:
            return json.loads(re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.M))
        except ValueError:
            return {"executive_summary": raw, "top_risks": [], "recommendations": []}

    def assistant_chat(self, question, context):
        return self._chat(
            "You are Sentinel AI's debugging assistant. Answer concisely, with concrete "
            "code-level guidance when relevant. Context: " + json.dumps(context)[:3000],
            question,
        )


# ===================================================== SentinelMind (KB) ===
KB = {
    "sqli": {
        "explanation": "The endpoint builds SQL queries by concatenating user input directly into the query string. A specially crafted input changed the meaning of the query, which means an attacker can read, modify or delete the entire database.",
        "root_cause": "User-supplied data is interpolated into SQL text instead of being passed as a bound parameter.",
        "fix_conceptual": "Use parameterized queries / prepared statements so input is always treated as data, never as SQL code. Add a allow-list validator for expected input shapes.",
        "fix_code": "# Vulnerable\nquery = f\"SELECT * FROM users WHERE name LIKE '%{name}%\'\"\ncur.execute(query)\n\n# Fixed\ncur.execute(\"SELECT * FROM users WHERE name LIKE ?\", (f\"%{name}%\",))",
        "learning": {
            "mistake": "Trusting and concatenating raw request parameters into SQL.",
            "best_practice": "Always use parameterized statements (e.g. cursor.execute with '?' placeholders) and an ORM where possible.",
            "why": "SQL injection has repeatedly ranked #1 in OWASP Top 10 because it leads to full database compromise - including credential theft and data destruction.",
        },
    },
    "xss": {
        "explanation": "The API returns user-controlled input back in the response without HTML-encoding it. A script injected through a parameter is reflected verbatim, so any browser rendering this response executes attacker-supplied JavaScript.",
        "root_cause": "Output is not contextually encoded; input is echoed back raw.",
        "fix_conceptual": "Encode output according to context (HTML-escape in HTML, JS-escape inside scripts) and set a strict Content-Security-Policy header.",
        "fix_code": "# Vulnerable (Flask example)\nreturn f\"<h1>Results for {request.args.get('q')}</h1>\"\n\n# Fixed\nfrom markupsafe import escape\nreturn f\"<h1>Results for {escape(request.args.get('q'))}</h1>\"\n# Plus header: Content-Security-Policy: default-src 'self'",
        "learning": {
            "mistake": "Reflecting request data into HTML/JSON responses without escaping.",
            "best_practice": "Escape on output, validate on input, and deploy a Content-Security-Policy as a second line of defense.",
            "why": "XSS lets attackers hijack victim sessions, steal credentials, and deliver malware - it turns your users into the attack surface.",
        },
    },
    "broken_auth": {
        "explanation": "The authentication mechanism accepted default/weak credentials and/or issued a predictable token. That means an attacker can log in without ever brute-forcing anything, and may forge other users' sessions.",
        "root_cause": "Default credentials, no lockout policy, and non-random (static) session tokens.",
        "fix_conceptual": "Enforce strong passwords, rate-limit login attempts, store only salted hashes (bcrypt/argon2), and issue cryptographically random, expiring tokens (JWT with short TTL or opaque session tokens).",
        "fix_code": "# Fixed: strong password hashing + random token\nimport bcrypt, secrets\ntoken = secrets.token_urlsafe(32)          # unpredictable session token\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n# Rate-limit: reject after 5 failed logins per account per 15 minutes",
        "learning": {
            "mistake": "Shipping default accounts, weak password policies, or home-made token generation.",
            "best_practice": "Use battle-tested auth libraries (e.g. flask-login, Auth0, JWT libs), MFA where possible, and secure session management.",
            "why": "Broken authentication is the fastest path to total account takeover - OWASP A07.",
        },
    },
    "open_endpoint": {
        "explanation": "A privileged endpoint (admin/secret/internal) responded successfully to a completely anonymous request. Authorization is missing - authentication is not even being checked.",
        "root_cause": "The route lacks an authorization guard or middleware.",
        "fix_conceptual": "Apply an authorization middleware/guard to every privileged route; default-deny: routes require explicit role checks.",
        "fix_code": "# Fixed (Flask)\nfrom functools import wraps\n\ndef require_role(role):\n    def deco(fn):\n        @wraps(fn)\n        def wrapper(*a, **kw):\n            if current_user.role != role:\n                return {'error': 'forbidden'}, 403\n            return fn(*a, **kw)\n        return wrapper\n    return deco\n\n@app.get('/api/admin/secret')\n@require_role('admin')\ndef secret(): ...",
        "learning": {
            "mistake": "Assuming 'nobody knows the URL' or forgetting the auth check during refactoring.",
            "best_practice": "Default-deny design: every sensitive route explicitly verifies identity AND permission.",
            "why": "Authorization gaps expose admin functions to the entire internet - often the shortest path to data breaches.",
        },
    },
    "data_leakage": {
        "explanation": "Ordinary API responses include sensitive fields (e.g. password hashes, secrets, tokens). Any caller - even unauthenticated - receives credential material.",
        "root_cause": "Serializing full database rows instead of explicit response schemas.",
        "fix_conceptual": "Never serialize raw models. Use explicit response DTOs/schemas that whitelist fields; strip secrets at the API boundary.",
        "fix_code": "# Fixed: explicit schema\n@app.get('/api/profile')\ndef profile():\n    u = get_user()\n    return {'id': u.id, 'username': u.username, 'email': u.email}\n    # note: no password_hash / internal fields",
        "learning": {
            "mistake": "Returning database entities directly (e.g. row.__dict__).",
            "best_practice": "Whitelist serialization - define exactly what each endpoint returns and never more.",
            "why": "One leaked password hash or API key can compromise every user account immediately.",
        },
    },
    "path_traversal": {
        "explanation": "A file-related parameter allowed '../' sequences to escape the intended directory and read system files.",
        "root_cause": "User input is concatenated into filesystem paths without normalization.",
        "fix_conceptual": "Resolve the final path and verify it stays inside the allowed base directory; never trust '..' inputs.",
        "fix_code": "# Fixed\nimport os\nbase = os.path.abspath('uploads')\nreq = os.path.abspath(os.path.join(base, filename))\nif not req.startswith(base + os.sep):\n    abort(400)",
        "learning": {
            "mistake": "Using request parameters in file paths unvalidated.",
            "best_practice": "Canonicalize paths and enforce containment within an allow-listed root.",
            "why": "Path traversal exposes source code, credentials and OS files, and can often be upgraded to RCE via log poisoning.",
        },
    },
    "command_injection": {
        "explanation": "User input reached an OS shell command. Shell metacharacters ('|', ';', '$()') executed attacker commands on the server.",
        "root_cause": "String-concatenated shell calls (os.system, subprocess with shell=True).",
        "fix_conceptual": "Avoid shell=True entirely; pass argument lists and use safe APIs. Strip/validate everything else.",
        "fix_code": "# Vulnerable\nos.system(f'convert {file} out.png')\n\n# Fixed\nsubprocess.run(['convert', file, 'out.png'], shell=False, check=True)",
        "learning": {
            "mistake": "Calling shell commands with unsanitized input.",
            "best_practice": "shell=False with argument lists; keep subprocess calls out of request handlers where possible.",
            "why": "Command injection equals remote code execution - the most severe outcome possible.",
        },
    },
    "missing_headers": {
        "explanation": "Responses lack standard security headers. Without them the app is exposed to clickjacking, MIME-sniffing attacks, and protocol downgrade.",
        "root_cause": "Security headers were never configured at the web-server/middleware level.",
        "fix_conceptual": "Attach a security-header middleware (or configure at the reverse proxy) globally so every response is covered.",
        "fix_code": "# Fixed (Flask)\n@app.after_request\ndef secure(resp):\n    resp.headers['X-Content-Type-Options'] = 'nosniff'\n    resp.headers['X-Frame-Options'] = 'DENY'\n    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n    resp.headers['Referrer-Policy'] = 'no-referrer'\n    return resp",
        "learning": {
            "mistake": "Treating security headers as optional.",
            "best_practice": "Set CSP, nosniff, frame-deny, HSTS and Referrer-Policy globally via middleware - one fix protects every route.",
            "why": "These headers are cheap, one-time defenses that neutralize entire attack classes (clickjacking, sniffing, downgrade).",
        },
    },
    "verbose_error": {
        "explanation": "The API returns full stack traces including framework details and internal file paths. This hands attackers a map of your codebase.",
        "root_cause": "Debug mode leaks through to production or exception handlers dump tracebacks to the client.",
        "fix_conceptual": "Return generic error responses to clients; log the full traceback server-side with a correlation ID.",
        "fix_code": "# Fixed\n@app.errorhandler(Exception)\ndef handle(e):\n    app.logger.exception(e)          # full detail only in server logs\n    return {'error': 'internal error', 'trace_id': uuid4().hex}, 500",
        "learning": {
            "mistake": "Forwarding raw exceptions to API consumers.",
            "best_practice": "Fail loudly in logs, silently to clients. Disable DEBUG in production always.",
            "why": "Verbose errors dramatically reduce attacker effort and reveal injection points, paths and framework quirks.",
        },
    },
    "improper_validation": {
        "explanation": "The endpoint accepted object/serialized data where a scalar was expected. It never type-checked input before using it.",
        "root_cause": "Missing schema validation on request parameters.",
        "fix_conceptual": "Validate every input against an explicit schema (pydantic, marshmallow, JSON Schema) before business logic runs.",
        "fix_code": "# Fixed (pydantic)\nfrom pydantic import BaseModel, conint\nclass Query(BaseModel):\n    q: str = Field(max_length=256)\n    page: conint(gt=0, le=1000) = 1",
        "learning": {
            "mistake": "Using inputs without checking type, length or shape.",
            "best_practice": "Validate at the edge: typed schemas with length/range constraints on every field.",
            "why": "Type confusion enables NoSQL operator injection, memory abuse and logic-bypass attacks.",
        },
    },
    "perf_latency": {
        "explanation": "Responses under normal test load are abnormally slow. This indicates a bottleneck (missing index, N+1 queries, blocking I/O, or cold infrastructure).",
        "root_cause": "Likely unindexed queries, synchronous blocking calls, or per-request external I/O.",
        "fix_conceptual": "Profile the hot path; add DB indexes, batch queries, cache repeated computations, and move slow I/O to background jobs.",
        "fix_code": "# Example: add an index\nCREATE INDEX idx_users_name ON users(name);\n# Example: cache repeated results\n@lru_cache(maxsize=1024)\ndef get_stats(): ...",
        "learning": {
            "mistake": "Shipping hot paths without measuring latency budgets.",
            "best_practice": "Set latency SLOs per endpoint; alert on p95, profile before optimizing.",
            "why": "Latency directly affects conversion and makes the app an easy DoS target under modest load.",
        },
    },
    "error_handling": {
        "explanation": "The API responded outside its documented/expected contract (wrong status code or broken error behavior).",
        "root_cause": "Inconsistent error handling between routes.",
        "fix_conceptual": "Centralize error handling with consistent status codes and error envelope; encode the contract in integration tests.",
        "fix_code": "# Fixed: uniform error envelope\n@app.errorhandler(HTTPException)\ndef err(e):\n    return {'error': e.description, 'status': e.code}, e.code",
        "learning": {
            "mistake": "Ad-hoc exception handling per route.",
            "best_practice": "One global error handler, consistent {\"error\": ...} envelope, contract tests in CI.",
            "why": "Predictable APIs are testable, monitorable, and hide less information from attackers.",
        },
    },
}


class SentinelMindBackend:
    """Offline rule-based analyst - instant, deterministic, zero-cost."""

    name = "sentinel-mind"

    def analyze_finding(self, finding):
        entry = KB.get(finding.get("category"), KB["error_handling"])
        return {
            "explanation": entry["explanation"],
            "root_cause": entry["root_cause"],
            "fix_conceptual": entry["fix_conceptual"],
            "fix_code": entry["fix_code"],
            "learning": dict(entry["learning"]),
        }

    def summarize_scan(self, target, findings, scores):
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev[f.get("severity", "low")] = sev.get(f.get("severity", "low"), 0) + 1
        if sev["critical"]:
            verdict = (f"The scan of {target} uncovered {sev['critical']} critical, "
                       f"{sev['high']} high and {sev['medium']} medium severity issues. "
                       "Critical findings are directly exploitable and must be remediated before "
                       "any release. The system in its current state should NOT be exposed to "
                       "untrusted networks.")
        elif sev["high"]:
            verdict = (f"{target} shows {sev['high']} high-severity weaknesses that are "
                       "realistic attack vectors. Prioritize authentication, injection and "
                       "header fixes this sprint.")
        elif sev["medium"] or sev["low"]:
            verdict = (f"{target} is in reasonable shape, with {sev['medium'] + sev['low']} "
                       "lower-severity issues remaining. Harden the API before production.")
        else:
            verdict = f"{target} passed all simulated attack classes with no confirmed findings."
        top = [
            f"{f['title']} at {f.get('endpoint', 'n/a')}"
            for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))[:3]
        ] or ["No risks detected in this run."]
        recs = [
            "Middleware: add a global security-header + rate-limiting middleware (one change protects every route).",
            "Headers: deploy CSP, nosniff, frame-deny and HSTS at the edge; verify with each deploy.",
            "Architecture: centralize input validation (typed schemas) and authorization (default-deny guards).",
            "Process: integrate Sentinel AI into CI/CD so every build is scanned before release, and enable continuous monitoring for regressions.",
        ]
        return {"executive_summary": verdict, "top_risks": top, "recommendations": recs}

    def assistant_chat(self, question, context):
        cat = context.get("category", "")
        entry = KB.get(cat)
        base = f"Context: {context.get('title', 'general question')}."
        if entry:
            return (f"{base}\n\n{entry['explanation']}\n\nHow to fix: {entry['fix_conceptual']}\n\n"
                    f"Code:\n{entry['fix_code']}\n\nBest practice: {entry['learning']['best_practice']}")
        return (f"{base}\nGeneral guidance: validate all inputs, enforce authorization on every "
                "route, never trust client data, and add security headers globally.")


class AILayer:
    """Facade selecting the best available backend; caches per finding."""

    def __init__(self):
        self.backend = LLMBackend() if Config.LLM_API_KEY else SentinelMindBackend()
        self._cache = {}

    @property
    def backend_name(self):
        return self.backend.name

    def analyze_finding(self, finding):
        key = finding.get("fingerprint") or finding.get("id")
        if key in self._cache:
            return self._cache[key]
        try:
            result = self.backend.analyze_finding(finding)
        except Exception:
            result = SentinelMindBackend().analyze_finding(finding)
        self._cache[key] = result
        return result

    def summarize_scan(self, target, findings, scores):
        try:
            return self.backend.summarize_scan(target, findings, scores)
        except Exception:
            return SentinelMindBackend().summarize_scan(target, findings, scores)

    def assistant_chat(self, question, context):
        try:
            return self.backend.assistant_chat(question, context)
        except Exception:
            return SentinelMindBackend().assistant_chat(question, context)


_ai = AILayer()


def get_ai():
    return _ai
