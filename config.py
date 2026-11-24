"""Sentinel AI - global configuration."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")

os.makedirs(REPORT_DIR, exist_ok=True)


def _load_env_file(path):
    """Zero-dependency .env loader: KEY=VALUE lines, '#' comments, quotes
    stripped. Real environment variables always win over the file."""
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                # never let template placeholders activate features
                if not val or "PASTE" in val.upper() or val.endswith("..."):
                    continue
                if key and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


_load_env_file(os.path.join(BASE_DIR, ".env"))

class Config:
    HOST = os.environ.get("SENTINEL_HOST", "127.0.0.1")
    PORT = int(os.environ.get("SENTINEL_PORT", "5000"))

    # Demo vulnerable target (auto-launched with --with-demo)
    DEMO_TARGET_URL = os.environ.get("SENTINEL_DEMO_URL", "http://127.0.0.1:5099")

    # HTTP behavior of the scanner/attack engines
    REQUEST_TIMEOUT = float(os.environ.get("SENTINEL_TIMEOUT", "6"))
    MAX_RESPONSE_SNIPPET = 600          # chars of response body stored as evidence
    SLOW_REQUEST_MS = 1500              # latency threshold for performance warnings
    VERY_SLOW_REQUEST_MS = 4000

    # AI layer (OpenAI-compatible REST endpoint). Falls back to the built-in
    # rule-based analyst ("SentinelMind") when no key is configured.
    LLM_API_KEY = os.environ.get("OPENAI_API_KEY") or os.environ.get("SENTINEL_LLM_KEY")
    LLM_BASE_URL = os.environ.get("SENTINEL_LLM_BASE_URL", "https://api.openai.com/v1")
    LLM_MODEL = os.environ.get("SENTINEL_LLM_MODEL", "gpt-4o-mini")

    # Requests-per-minute budget enforced client-side (NVIDIA NIM free tier
    # allows 40 RPM; default leaves headroom). 429s are also retried with
    # backoff, but staying under the quota is the polite way. The key is
    # often shared with other tooling (an assistant, CI, a second service),
    # so the default is deliberately well under the provider ceiling.
    LLM_RPM_LIMIT = int(os.environ.get("SENTINEL_LLM_RPM", "28"))
    # Concurrent in-flight requests allowed per key. Measured on the NVIDIA
    # NIM free tier: four simultaneous calls answer once and 429 the other
    # three — the binding constraint is concurrency, not just RPM. Raise it
    # only if your provider plan allows parallel requests.
    LLM_MAX_CONCURRENCY = int(os.environ.get("SENTINEL_LLM_CONCURRENCY", "1"))
    # Per-request read timeout. Free-tier models can sit in long queues
    # (healthy calls answer in seconds, starved ones never do). Network
    # timeouts retry only once, then the circuit breaker opens after two
    # consecutive failed calls — scans degrade to SentinelMind, never hang.
    LLM_TIMEOUT = int(os.environ.get("SENTINEL_LLM_TIMEOUT", "60"))
    # Wall-clock budget for the provider work inside ONE scan. The key is
    # often shared with other tooling, so the quota can be saturated when a
    # scan starts. A scan must never hang on that: past the budget the
    # remaining AI work falls back to the offline analyst and the scan
    # completes with honest (partial) AI coverage.
    LLM_BUDGET_S = int(os.environ.get("SENTINEL_LLM_BUDGET_S", "300"))

    # Performance engine defaults
    PERF_DURATION_S = 8
    PERF_CONCURRENCY = 20

    # AI verification agents (repo scans). When an LLM key is configured,
    # every static-analysis finding is re-reviewed in real code context:
    # false positives are dismissed, real issues get severity + a fix.
    VERIFY_ENABLED = os.environ.get("SENTINEL_VERIFY", "1") not in ("0", "false", "no")
    VERIFY_MAX_FINDINGS = int(os.environ.get("SENTINEL_VERIFY_MAX", "16"))
    VERIFY_BATCH = int(os.environ.get("SENTINEL_VERIFY_BATCH", "4"))
    VERIFY_PARALLEL = int(os.environ.get("SENTINEL_VERIFY_PARALLEL", "3"))
    VERIFY_CONTEXT_LINES = int(os.environ.get("SENTINEL_VERIFY_CONTEXT", "8"))
    # Repo scans enrich only a few findings beyond what the verification
    # agents already covered — the quota is small and often shared.
    REPO_ENRICH_MAX = int(os.environ.get("SENTINEL_REPO_ENRICH_MAX", "1"))

    # Continuous monitoring
    MONITOR_INTERVAL_S = int(os.environ.get("SENTINEL_MONITOR_INTERVAL", "900"))

# Weighted scoring model -------------------------------------------------
SEVERITY_WEIGHTS = {
    "critical": 22.0,
    "high": 12.0,
    "medium": 6.0,
    "low": 2.5,
    "info": 0.5,
}

SECURITY_HEADERS_REQUIRED = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

MAX_SCORE = 100.0
