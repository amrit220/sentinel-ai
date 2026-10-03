"""Performance Testing Module.

Simulates concurrent virtual users against a target endpoint, measures
latency distribution, throughput and error rate, and detects instability
(status flapping / timeouts).
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from config import Config


def _hammer(url, duration_s, results, lock, stop_flag):
    session = requests.Session()
    while not stop_flag.is_set() and time.time() - results["start"] < duration_s:
        t0 = time.time()
        try:
            r = session.get(url, timeout=Config.REQUEST_TIMEOUT)
            elapsed = (time.time() - t0) * 1000
            with lock:
                results["latencies"].append(elapsed)
                results["statuses"].append(r.status_code)
                if r.status_code >= 400:
                    results["errors"] += 1
        except requests.RequestException:
            with lock:
                results["latencies"].append((time.time() - t0) * 1000)
                results["statuses"].append(0)
                results["errors"] += 1
                results["connection_failures"] += 1
        results["requests"] += 1


def run_load_test(url, concurrency=None, duration_s=None):
    """Returns a perf report dict."""
    concurrency = concurrency or Config.PERF_CONCURRENCY
    duration_s = duration_s or Config.PERF_DURATION_S

    results = {
        "start": time.time(), "latencies": [], "statuses": [],
        "requests": 0, "errors": 0, "connection_failures": 0,
    }
    lock = threading.Lock()
    stop_flag = threading.Event()

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_hammer, url, duration_s, results, lock, stop_flag)
                  for _ in range(concurrency)]
        for f in futures:
            f.result(timeout=duration_s + 30)
    stop_flag.set()

    lats = sorted(results["latencies"])
    total = max(results["requests"], 1)
    wall = max(time.time() - results["start"], 0.001)

    def pct(p):
        if not lats:
            return 0
        return round(lats[min(int(len(lats) * p), len(lats) - 1)], 1)

    error_rate = results["errors"] / total
    p50, p95, p99 = pct(0.50), pct(0.95), pct(0.99)

    if results["connection_failures"] > total * 0.05:
        verdict, bottleneck = "unstable", "Server refused/dropped connections under load (saturation or crash)."
    elif p95 > 3000 or error_rate > 0.05:
        verdict, bottleneck = "degraded", "High tail latency (p95 > 3s) or error rate - likely unindexed queries, blocking I/O or thread starvation."
    elif p95 > 1000:
        verdict, bottleneck = "acceptable", "p95 above 1s - profile hot paths and add caching."
    else:
        verdict, bottleneck = "healthy", "No significant bottlenecks detected at tested concurrency."

    return {
        "url": url,
        "concurrency": concurrency,
        "duration_s": duration_s,
        "total_requests": results["requests"],
        "throughput_rps": round(results["requests"] / wall, 1),
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "latency_p99_ms": p99,
        "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else 0,
        "error_rate": round(error_rate, 4),
        "connection_failures": results["connection_failures"],
        "verdict": verdict,
        "bottleneck_analysis": bottleneck,
    }
