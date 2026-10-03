"""Sentinel AI - global configuration."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")

os.makedirs(REPORT_DIR, exist_ok=True)

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

    # Performance engine defaults
    PERF_DURATION_S = 8
    PERF_CONCURRENCY = 20

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
