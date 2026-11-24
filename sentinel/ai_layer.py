"""AI Analysis Layer.

Two interchangeable backends:

1. `LLMBackend`    - calls any OpenAI-compatible REST endpoint when
                     OPENAI_API_KEY / SENTINEL_LLM_KEY is configured.
2. `SentinelMind`  - a built-in rule-based security analyst used as a
                     fallback so the prototype works fully offline.
The rest of the system only ever talks to `AILayer`, never to a specific
backend directly (clean substitution point for future models).
"""
import collections
import contextlib
import json
import re
import threading
import time

import requests

from config import Config


# ============================================================ rate limiting ==
class RateLimiter:
    """Thread-safe sliding-window limiter with a global cooldown.

    Keeps every LLM call (analysis, verification batches, assistant chat)
    under the provider's requests-per-minute quota — e.g. the NVIDIA NIM
    free tier allows 40 RPM; SENTINEL_LLM_RPM defaults to 28 for headroom.
    Callers block politely instead of getting 429-stormed.

    The quota is frequently shared with other tooling (an assistant, CI, a
    second service). When the provider says "429", the limiter parks *every*
    worker for the advertised Retry-After window instead of letting each one
    burn its own retry — one saturated minute must not turn into an
    avalanche of doomed requests.
    """

    def __init__(self, max_calls, window_s=60.0, max_concurrent=1):
        self.max_calls = max(1, int(max_calls))
        self.window = float(window_s)
        self._times = collections.deque()
        self._lock = threading.Lock()
        self._paused_until = 0.0
        self._quota_streak = 0
        # Concurrency gate. Measured on the NVIDIA NIM free tier: four
        # simultaneous requests on one key answer once and reject the other
        # three with 429 — the practical limit is *in-flight requests*, not
        # just requests-per-minute. Every provider call goes through this
        # slot, so parallel workers queue instead of colliding.
        self._slots = threading.Semaphore(max(1, int(max_concurrent)))

    @contextlib.contextmanager
    def slot(self):
        """Hold the provider's concurrency slot for the duration of a call."""
        self._slots.acquire()
        try:
            yield
        finally:
            self._slots.release()

    def pause(self, seconds):
        """Park every caller after a 429. The pause grows with each
        consecutive rate-limit — a quota shared with other tools can stay
        saturated for a while, and a fixed short pause would just walk
        into the same wall again."""
        with self._lock:
            self._quota_streak += 1
            scaled = min(60.0, max(5.0, float(seconds)) * (2 ** (self._quota_streak - 1)))
            self._paused_until = max(self._paused_until, time.time() + scaled)
            self._times.clear()

    def note_success(self):
        """A call went through — the provider is responsive again."""
        with self._lock:
            self._quota_streak = 0

    def acquire(self):
        while True:
            with self._lock:
                now = time.time()
                if now < self._paused_until:
                    wait = self._paused_until - now
                else:
                    while self._times and now - self._times[0] > self.window:
                        self._times.popleft()
                    if len(self._times) < self.max_calls:
                        self._times.append(now)
                        return
                    wait = self.window - (now - self._times[0]) + 0.05
            time.sleep(max(wait, 0.05))


_limiter = None
_limiter_lock = threading.Lock()


def get_limiter():
    global _limiter
    if _limiter is None:
        with _limiter_lock:
            if _limiter is None:
                _limiter = RateLimiter(
                    getattr(Config, "LLM_RPM_LIMIT", 28),
                    max_concurrent=getattr(Config, "LLM_MAX_CONCURRENCY", 1))
    return _limiter


def _extract_json(raw, want="object"):
    """Best-effort JSON extraction from an LLM reply.

    Chatty / reasoning-style models often wrap the payload in prose or
    markdown fences. Tries, in order: direct parse, fence-stripped parse,
    then the outermost {...} (or [...]) substring. Returns None when no
    valid payload exists — callers treat that as "model failed" and fall
    back to the offline analyst (never surface raw monologue to users)."""
    txt = re.sub(r"^```(json)?|```$", "", (raw or "").strip(), flags=re.M).strip()
    expected = dict if want == "object" else list
    for candidate in (txt,):
        try:
            data = json.loads(candidate)
            if isinstance(data, expected):
                return data
        except ValueError:
            pass
    open_c, close_c = ("{", "}") if want == "object" else ("[", "]")
    start, end = txt.find(open_c), txt.rfind(close_c)
    if start != -1 and end > start:
        try:
            data = json.loads(txt[start:end + 1])
            if isinstance(data, expected):
                return data
        except ValueError:
            pass
    return None


def _salvage_objects(raw):
    """Recover complete JSON objects from a truncated reply.

    Reasoning models can run out of token budget mid-array. Rather than
    throwing away the whole batch, scan for balanced `{...}` blocks and keep
    the ones that parse — a partial verdict set still beats no verdict set.
    """
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(raw or ""):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(raw[start:i + 1])
                    if isinstance(obj, dict):
                        out.append(obj)
                except ValueError:
                    pass
                start = None
    return out


# ===================================================================== LLM ==
class LLMBudgetExceeded(RuntimeError):
    """Raised when a scan's provider time budget is spent.

    The key is often shared with other tooling, so the quota can be
    saturated when a scan starts. Rather than queueing behind that wall
    forever, the scan gives up on further provider calls and falls back
    to the offline analyst.
    """


class LLMBackend:
    name = "llm"

    # --- circuit breaker: a queued/dead endpoint must degrade fast --------
    _fail_streak = 0
    _open_until = 0.0
    BREAKER_STREAK = 2          # consecutive exhausted calls to trip
    BREAKER_COOLDOWN = 60.0     # seconds to stay open before retrying

    def _tripped(self):
        return time.time() < self._open_until

    def __init__(self):
        self._fail_streak = 0
        self._open_until = 0.0
        self._diag_lock = threading.Lock()
        self._local = threading.local()
        self.diag = {"calls": 0, "ok": 0, "http_429": 0, "http_5xx": 0,
                     "timeouts": 0, "truncated": 0, "empty": 0,
                     "breaker_skipped": 0, "unusable": 0, "salvaged": 0,
                     "quota_pauses": 0, "budget_exceeded": 0}

    def _record_failure(self):
        self._fail_streak += 1
        if self._fail_streak >= self.BREAKER_STREAK:
            self._open_until = time.time() + self.BREAKER_COOLDOWN
            self._fail_streak = 0

    def _record_success(self):
        self._fail_streak = 0
        self._open_until = 0.0

    # --- diagnostics -------------------------------------------------------
    # One scan must tell the whole story: how many calls went out, how many
    # were rate-limited, timed out, truncated or came back unusable. Exposed
    # through the health endpoint and the scan summary so no extra probing
    # (which would burn the same shared RPM quota) is ever needed.
    def _diag(self, **kw):
        with self._diag_lock:
            for k, v in kw.items():
                self.diag[k] = self.diag.get(k, 0) + v

    def _diag_snapshot(self):
        with self._diag_lock:
            return dict(self.diag)

    def _chat(self, system, user, max_tokens=1200, deadline=None):
        """Single throttled choke point for every LLM call: respects the
        provider RPM budget, retries 429/5xx with backoff (honoring
        Retry-After), raises after the final attempt or when the circuit
        breaker is open (endpoint queueing/dead).

        `deadline` is a wall-clock cutoff for the scan that owns this
        call. Past it the call is abandoned (LLMBudgetExceeded) instead
        of queueing behind a saturated shared quota.
        """
        if self._tripped():
            self._diag(breaker_skipped=1)
            raise RuntimeError(
                "LLM circuit breaker open (endpoint repeatedly timed out) — "
                "using fallback analyst until cooldown")
        payload = {
            "model": Config.LLM_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        url = Config.LLM_BASE_URL.rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {Config.LLM_API_KEY}"}
        attempts = 4
        timeouts = 0            # network timeouts get a tighter budget: a
        rate_limited = 0        # 429s get one retry — the quota is shared,
        last_error = None       # so hammering it only steals it from others
        for attempt in range(attempts):
            if deadline and time.time() > deadline:
                # the scan's provider budget is spent — stop now
                # instead of waiting out a saturated shared quota
                self._diag(budget_exceeded=1)
                raise LLMBudgetExceeded("scan LLM time budget exhausted")
            get_limiter().acquire()
            try:
                with get_limiter().slot():
                    if deadline and time.time() > deadline:
                        # we queued for the slot while the budget ran out
                        self._diag(budget_exceeded=1)
                        raise LLMBudgetExceeded("scan LLM time budget exhausted")
                    self._diag(calls=1)
                    resp = requests.post(url, headers=headers, json=payload,
                                         timeout=getattr(Config, "LLM_TIMEOUT", 60))
            except requests.RequestException as exc:
                last_error = exc
                timeouts += 1
                self._diag(timeouts=1)
                if attempt == attempts - 1 or timeouts >= 2:
                    self._record_failure()
                    raise
                time.sleep(min(2 ** attempt, 10))
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                self._diag(http_429=1 if resp.status_code == 429 else 0,
                           http_5xx=1 if resp.status_code >= 500 else 0)
                last_error = requests.HTTPError(
                    f"LLM endpoint returned HTTP {resp.status_code}", response=resp)
                retry_after = resp.headers.get("Retry-After", "")
                try:
                    delay = float(retry_after)
                except ValueError:
                    delay = 2 ** (attempt + 1)
                if resp.status_code == 429:
                    # shared quota: park every worker, don't just this one.
                    # Not a breaker trip — the endpoint is healthy, the
                    # budget is simply spent; the pause is the remedy.
                    rate_limited += 1
                    if rate_limited >= 2:
                        raise last_error
                    delay = min(max(delay, 5.0), 60.0)
                    get_limiter().pause(delay)
                    self._diag(quota_pauses=1)
                else:
                    self._record_failure()
                    if attempt == attempts - 1:
                        raise last_error
                time.sleep(min(max(delay, 1.0), 60.0))
                continue
            resp.raise_for_status()
            self._record_success()
            get_limiter().note_success()
            body = resp.json()
            choice = (body.get("choices") or [{}])[0]
            msg = (choice.get("message") or {})
            finish = choice.get("finish_reason")
            # thinking-style models may leave `content` empty and stream
            # their answer through reasoning_content — never return None
            content = msg.get("content") or msg.get("reasoning_content") or ""
            self._local.finish_reason = finish
            self._local.content_len = len(msg.get("content") or "")
            self._local.reasoning_len = len(msg.get("reasoning_content") or "")
            if finish == "length":
                self._diag(truncated=1)
            elif not content.strip():
                self._diag(empty=1)
            else:
                self._diag(ok=1)
            return content
        raise last_error or RuntimeError("LLM request failed")

    def analyze_finding(self, finding, deadline=None):
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
        raw = self._chat(
            "You are a JSON API. Do not think out loud, do not explain, do not use "
            "markdown fences. Reply with ONLY the JSON object — the first character "
            "of your reply must be '{'.",
            prompt, max_tokens=3000, deadline=deadline)
        data = _extract_json(raw, "object")
        if data is None or not data.get("explanation"):
            # chatty model failed to produce a payload -> clean offline fallback
            raise ValueError("LLM reply contained no usable JSON")
        return {
            "explanation": data.get("explanation", ""),
            "root_cause": data.get("root_cause", ""),
            "fix_conceptual": data.get("fix_conceptual", ""),
            "fix_code": data.get("fix_code", ""),
            "learning": {
                "mistake": data.get("mistake", ""),
                "best_practice": data.get("best_practice", ""),
                "why": data.get("why_it_matters", ""),
            },
        }

    def summarize_scan(self, target, findings, scores, deadline=None):
        prompt = (
            "Summarize this security scan for both a CTO and a junior developer. "
            "Return STRICT JSON: executive_summary (3-4 sentences), top_risks (list of 3 strings), "
            "recommendations (list of 4 strings: middleware, headers, architecture, process).\n\n"
            + json.dumps({
                "target": target,
                "scores": scores,
                # the executive summary needs the shape of the report, not
                # every row — a long tail of findings bloats the prompt
                # (and the reasoning model's answer) for no extra signal
                "findings": [
                    {"title": f["title"], "severity": f["severity"], "endpoint": f["endpoint"]}
                    for f in findings[:25]
                ],
            })
        )
        raw = self._chat(
            "You are a JSON API. Do not think out loud, do not explain, do not use "
            "markdown fences. Reply with ONLY the JSON object — the first character "
            "of your reply must be '{'.",
            prompt, max_tokens=2500, deadline=deadline)
        data = _extract_json(raw, "object")
        if data is None or not data.get("executive_summary"):
            # unparseable reply -> clean offline summary instead of raw prose
            raise ValueError("LLM reply contained no usable JSON")
        return data

    def assistant_chat(self, question, context):
        return self._chat(
            "You are Sentinel AI's debugging assistant. Answer concisely, with concrete "
            "code-level guidance when relevant. Context: " + json.dumps(context)[:3000],
            question,
        )

    def verify_batch(self, items, deadline=None):
        """Verification agent: re-review regex-flagged candidates in real
        code context. `items` = [{id,title,category,severity,rule,line,
        evidence,code}]. Returns a list of verdict dicts, or [] when the
        model produced no usable payload (batch stays unverified)."""
        prompt = (
            "You are Sentinel AI's verification agent. A regex-based static scanner "
            "flagged the candidate issues below in one or more source files. For EACH "
            "item, read the code snippet provided with it and decide whether it is a "
            "REAL, exploitable issue in THIS codebase — not test data, not a "
            "docstring/comment example, not internal constants, not a safe or "
            "unreachable pattern. Adjust severity if the context makes it more or "
            "less severe.\n\n"
            "Return STRICT JSON: a bare array, one object per input, each with keys:\n"
            '  id, verdict ("confirmed" | "false_positive" | "uncertain"),\n'
            "  severity (critical|high|medium|low — your adjusted rating),\n"
            "  confidence (0-1), reasoning (max 2 sentences, cite the code),\n"
            "  fix_conceptual (one sentence; empty for false positives),\n"
            "  fix_code (short concrete corrected snippet; empty for false positives),\n"
            "  lesson (one-sentence best practice; empty for false positives).\n\n"
            "Keep every string short — the whole array must fit in one reply.\n\n"
            + json.dumps(items)
        )
        raw = self._chat(
            "You are a JSON API. Do not think out loud, do not explain, do not use "
            "markdown fences. Reply with ONLY the JSON array — the first character "
            "of your reply must be '['.",
            prompt, max_tokens=4000, deadline=deadline)
        data = _extract_json(raw, "array")
        if data is None:  # tolerate {"results": [...]} wrappers
            wrapped = _extract_json(raw, "object")
            if isinstance(wrapped, dict):
                data = wrapped.get("results") or wrapped.get("verdicts")
        if not isinstance(data, list):
            # reply was cut short (reasoning models love to over-think) —
            # salvage the verdict objects that did make it through
            data = _salvage_objects(raw)
            if data:
                self._diag(salvaged=1)
        if not isinstance(data, list) or not data:
            self._diag(unusable=1)
            return []
        return data


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
    # ================= static / repo-scan categories =================
    "hardcoded_secret": {
        "explanation": "A credential (password, API key or token) is written directly into the source code. Anyone with repository access — including ex-employees, CI logs, forks, and anyone who ever received the code — holds a working key.",
        "root_cause": "Secrets stored in code because no external configuration system was in place.",
        "fix_conceptual": "Move every credential to environment variables or a secrets manager, load it at runtime, and rotate the leaked value immediately — removing it from current code is not enough, it stays in git history.",
        "fix_code": "# Vulnerable\nAPI_KEY = 'sk_live_EXAMPLE_KEY'\n\n# Fixed: read from environment / secret manager\nimport os\nAPI_KEY = os.environ['PAYMENT_API_KEY']\n# and rotate the old key NOW - it is burned",
        "learning": {
            "mistake": "Typing real credentials into a file that gets committed.",
            "best_practice": "Secrets live in a vault (AWS Secrets Manager, Doppler, .env excluded via .gitignore). Add secret scanning (gitleaks) as a pre-commit hook.",
            "why": "Leaked keys are the #1 cause of account takeovers and cryptomining bills; git history means 'deleting' the line never removes it.",
        },
    },
    "unsafe_eval": {
        "explanation": "The code evaluates dynamically-built strings as program code (eval/exec/new Function). If any part of that string comes from user input, attackers can execute arbitrary logic inside your process.",
        "root_cause": "eval() used for quick config/templating/math instead of a safe parser.",
        "fix_conceptual": "Replace eval with explicit parsers: ast.literal_eval for literals, json.loads for data, template engines for strings, and calculated dispatch tables instead of dynamic code.",
        "fix_code": "# Vulnerable: eval(user_expr)\nresult = eval(request.args.get('expr'))\n\n# Fixed\nimport ast\nresult = ast.literal_eval(user_input)      # data only, never code\n# or a real expression parser: `simpleeval`, `asteval`",
        "learning": {
            "mistake": "Using eval() to 'save time' parsing dynamic input.",
            "best_practice": "Never eval strings influenced by external data; pick a safe, purpose-built parser.",
            "why": "eval turns any injection bug into instant remote code execution with zero additional effort for the attacker.",
        },
    },
    "unsafe_deserialize": {
        "explanation": "The code deserializes data with a format that can carry executable payloads (pickle) or loads YAML with a permissive loader. A crafted payload here is one of the most reliable paths to remote code execution.",
        "root_cause": "Using pickle/yaml.load where JSON would do, or accepting serialized objects from untrusted sources.",
        "fix_conceptual": "Use JSON for anything crossing a trust boundary; if pickle is unavoidable, sign/HMAC the payload. Use yaml.safe_load always.",
        "fix_code": "# Vulnerable\nobj = pickle.loads(request.data)\ncfg = yaml.load(text)                 # allows !!python/object tags\n\n# Fixed\nobj = json.loads(request.data)\ncfg = yaml.safe_load(text)",
        "learning": {
            "mistake": "Deserializing whatever arrives without questioning the format's power.",
            "best_practice": "JSON between trust boundaries; pickle only for your own signed, trusted data.",
            "why": "Unpickling untrusted data is equivalent to giving the sender code execution rights on your server.",
        },
    },
    "tls_verify_off": {
        "explanation": "Outgoing HTTPS requests are made with certificate verification disabled (verify=False / rejectUnauthorized:false). That makes every connection silently vulnerable to man-in-the-middle interception.",
        "root_cause": "Verification disabled to 'fix' self-signed certificate errors during development, then shipped.",
        "fix_conceptual": "Never disable verification globally. For internal CAs, add the internal root certificate to the trust store instead.",
        "fix_code": "# Vulnerable\nrequests.post(url, verify=False)\n\n# Fixed (internal CA)\nrequests.post(url, verify='/etc/ssl/certs/internal-ca.pem')\n# or: add the CA to the OS trust store once",
        "learning": {
            "mistake": "Turning off TLS verification to silence an error message.",
            "best_practice": "Fix the certificate chain, not the check; gate verify=False from production config in CI.",
            "why": "With verification off, an attacker on the network path can read and rewrite all 'encrypted' traffic including credentials.",
        },
    },
    "weak_crypto": {
        "explanation": "The code uses a broken primitive (MD5/SHA1) or a non-cryptographic RNG (random) for security purposes like passwords or tokens. These can be brute-forced or guessed quickly.",
        "root_cause": "Convenience primitives reused for security jobs.",
        "fix_conceptual": "Use a modern slow KDF for passwords (bcrypt/argon2), SHA-256+ for integrity, and the secrets module for tokens.",
        "fix_code": "# Vulnerable\nh = hashlib.md5(password).hexdigest()\ntoken = random.random()\n\n# Fixed\nimport bcrypt, secrets\nh = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\ntoken = secrets.token_urlsafe(32)",
        "learning": {
            "mistake": "Reaching for familiar functions (md5, random) in security contexts.",
            "best_practice": "Passwords: bcrypt/argon2. Tokens: secrets. Integrity: SHA-256 family.",
            "why": "Weak hashing turns a database leak into instant password recovery; predictable tokens break session security entirely.",
        },
    },
    "debug_prod": {
        "explanation": "Debug mode is enabled in the code path. In production this exposes the interactive debugger, stack traces, and configuration — which frequently allows remote code execution via the debugger console.",
        "root_cause": "Development settings committed without an environment switch.",
        "fix_conceptual": "Drive debug/development flags from environment configuration, defaulting to OFF.",
        "fix_code": "# Vulnerable\napp.run(debug=True)\n\n# Fixed\napp.run(debug=os.environ.get('FLASK_ENV') == 'development')",
        "learning": {
            "mistake": "Hardcoding debug=True.",
            "best_practice": "All environment knobs read from config/env vars; debug defaults off even for local runs.",
            "why": "Flask's debug console alone allows arbitrary code execution if the port is reachable.",
        },
    },
    "cors_wildcard": {
        "explanation": "The API answers with a wildcard CORS policy, letting any website read responses from authenticated user sessions — a direct path to cross-site data theft.",
        "root_cause": "CORS configured to '*' to make dev integration easy.",
        "fix_conceptual": "Whitelist the exact origins that need API access.",
        "fix_code": "# Vulnerable\nCORS(app, origins='*')\n\n# Fixed\nCORS(app, origins=['https://app.yourdomain.com'])",
        "learning": {
            "mistake": "Copying permissive CORS config from tutorials.",
            "best_practice": "Explicit origin allow-list; never wildcard with credentials.",
            "why": "Wildcard CORS converts any victim's browser into a proxy that reads your API with their cookies.",
        },
    },
    "dependency_cve": {
        "explanation": "The project pins a dependency version with at least one published, known vulnerability (matched via OSV.dev). Exploitation difficulty varies, but public exploit code usually exists.",
        "root_cause": "Dependencies installed long ago and never audited or updated.",
        "fix_conceptual": "Upgrade to a fixed release immediately, then automate: enable Dependabot/Renovate and add dependency audits to CI.",
        "fix_code": "# requirements.txt - bump to the fixed release, then\npip install -r requirements.txt\n\n# CI: fail the build on known-vulnerable deps\n# pip-audit / npm audit --audit-level=high",
        "learning": {
            "mistake": "Treating third-party packages as trusted black boxes.",
            "best_practice": "Automated update PRs (Dependabot) + CI audit gates + minimal dependency trees.",
            "why": "Attackers scan for vulnerable library fingerprints before targeting your code — it is the cheapest way in.",
        },
    },
    "exposed_file": {
        "explanation": "A sensitive file — an environment file, a private key, or a database — is committed to the repository. Everyone with repo access has the credential, and it remains in git history forever.",
        "root_cause": "Files created locally during development, then committed by accident.",
        "fix_conceptual": "Add .gitignore rules for secret files, remove them from the entire history (git filter-repo), and rotate everything exposed.",
        "fix_code": "# .gitignore\n.env\n*.pem\nid_rsa*\n*.sqlite\n\n# purge history and rotate\n# git rm --cached .env && git filter-repo --path .env --invert-paths",
        "learning": {
            "mistake": "Committing first, thinking about sensitivity later (or never).",
            "best_practice": "Secret files never enter git: strict .gitignore from commit #1 + pre-commit secret scanners.",
            "why": "One committed key can outlive the project; history keeps it forever and bots scrape public repos for secrets within minutes.",
        },
    },
    "ci_action_risk": {
        "explanation": "A GitHub Actions workflow uses pull_request_target (which carries repository secrets) while checking out code from the fork/PR — so untrusted fork code executes with access to your secrets.",
        "root_cause": "Copying a workflow pattern without understanding the trust model of pull_request_target.",
        "fix_conceptual": "Never combine pull_request_target with a checkout of PR head code. If needed, split into two jobs and pass only vetted artifacts.",
        "fix_code": "# Vulnerable pattern\non: pull_request_target\nsteps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.ref }}\n\n# Fixed\non: pull_request        # no repo secrets in the context\n# -or- keep pull_request_target but only build the BASE ref, never fork code",
        "learning": {
            "mistake": "Assuming 'the workflow runs on GitHub, it must be safe'.",
            "best_practice": "Treat PRs from forks as hostile; never give them secret-bearing contexts.",
            "why": "This exact mistake has leaked cloud credentials from major open-source projects repeatedly.",
        },
    },
    "docker_risk": {
        "explanation": "The Docker image runs as root, pipes downloads into a shell, or bakes secrets into layers. A container breakout or image leak then means full host access.",
        "root_cause": "Dockerfile written for convenience without hardening steps.",
        "fix_conceptual": "Create an unprivileged user, verify downloads by checksum, and pass secrets at runtime.",
        "fix_code": "# Dockerfile - fixed\nRUN adduser --disabled-password appuser\nUSER appuser\n# and: curl -sSL https://... -o pkg && sha256sum -c pkg.sha256 && npm i",
        "learning": {
            "mistake": "Treating the container as a mini-VM with root by default.",
            "best_practice": "Least privilege everywhere: non-root USER, checksummed installs, multi-stage builds, secrets via runtime injection.",
            "why": "Container escapes are rarely needed when the container already runs as root with baked-in secrets.",
        },
    },
    "unpinned_dependency": {
        "explanation": "A dependency is declared without an exact version, so builds silently drift and vulnerability audits become guesswork.",
        "root_cause": "Loose specifiers chosen for flexibility.",
        "fix_conceptual": "Pin exact versions in lockfiles, or pin with caret + committed lockfile.",
        "fix_code": "# requirements.txt\nflask==3.0.3        # not flask>=2\n# package.json + committed package-lock.json",
        "learning": {
            "mistake": "Leaving version specifiers loose 'to stay flexible'.",
            "best_practice": "Lockfiles committed; updates via automated, reviewable PRs.",
            "why": "Unpinned builds are non-reproducible and can't be proven safe — you no longer know what you ship.",
        },
    },
}


class SentinelMindBackend:
    """Offline rule-based analyst - instant, deterministic, zero-cost."""

    name = "sentinel-mind"

    @property
    def backend_name(self):
        return self.name

    @property
    def diag(self):
        """No provider calls happen here, so the ledger stays empty."""
        return {}

    def analyze_finding(self, finding, deadline=None):
        entry = KB.get(finding.get("category"), KB["error_handling"])
        return {
            "explanation": entry["explanation"],
            "root_cause": entry["root_cause"],
            "fix_conceptual": entry["fix_conceptual"],
            "fix_code": entry["fix_code"],
            "learning": dict(entry["learning"]),
        }

    def summarize_scan(self, target, findings, scores, deadline=None):
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

    def verify_batch(self, items, deadline=None):
        """Offline fallback: no code reasoning available, skip verification."""
        return None


class AILayer:
    """Facade selecting the best available backend; caches per finding."""

    def __init__(self):
        self.backend = LLMBackend() if Config.LLM_API_KEY else SentinelMindBackend()
        self._cache = {}

    @property
    def backend_name(self):
        return self.backend.name

    @property
    def diag(self):
        """Live call ledger for the active backend (empty for the offline one)."""
        snap = getattr(self.backend, "_diag_snapshot", None)
        return snap() if callable(snap) else {}

    def analyze_finding(self, finding, deadline=None):
        key = finding.get("fingerprint") or finding.get("id")
        if key in self._cache:
            return self._cache[key]
        try:
            result = self.backend.analyze_finding(finding, deadline=deadline)
        except Exception:
            result = SentinelMindBackend().analyze_finding(finding)
        self._cache[key] = result
        return result

    def summarize_scan(self, target, findings, scores, deadline=None):
        try:
            return self.backend.summarize_scan(target, findings, scores,
                                               deadline=deadline)
        except Exception:
            return SentinelMindBackend().summarize_scan(target, findings, scores)

    def assistant_chat(self, question, context):
        try:
            return self.backend.assistant_chat(question, context)
        except Exception:
            return SentinelMindBackend().assistant_chat(question, context)

    def verify_batch(self, items, deadline=None):
        """Verification agent passthrough. Returns a verdict list, or None
        when the provider call failed (timeout / rate limit) — an empty list
        means the model answered but produced no usable verdict."""
        try:
            return self.backend.verify_batch(items, deadline=deadline)
        except Exception:
            return None


_ai = AILayer()


def get_ai():
    return _ai
