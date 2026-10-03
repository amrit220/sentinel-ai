"""Risk Scoring System.

Weighted scoring model producing three 0-100 scores plus a letter grade:
- Security Score   (driven by weighted vulnerability severities)
- Performance Score (driven by latency percentiles + error rate)
- Quality Score    (driven by test pass-rate + error-handling findings)
"""
import math

from config import SEVERITY_WEIGHTS

RISK_COLORS = {
    "critical": "#ff3b5c",
    "high":     "#ff8b3d",
    "medium":   "#ffd23d",
    "low":      "#4dd8ff",
    "info":     "#8b95a5",
}


def clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


def security_score(findings):
    """100 - saturating sum of weighted severities."""
    raw = 0.0
    for f in findings:
        raw += SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0.5)
    # saturating curve: the first few criticals hit hard, later ones less
    score = 100.0 - (100.0 * (1 - math.exp(-raw / 28.0)))
    # exploit-successful findings carry extra penalty
    exploited = sum(1 for f in findings if f.get("exploit_success"))
    score -= min(exploited * 1.5, 12.0)
    return round(clamp(score), 1)


def performance_score(latencies_ms, error_rate=0.0):
    """Score from p50/p95 latency and error rate."""
    if not latencies_ms:
        return 80.0
    s = sorted(latencies_ms)
    p50 = s[len(s) // 2]
    p95 = s[int(len(s) * 0.95)] if len(s) > 1 else s[-1]
    score = 100.0
    if p50 > 300:  score -= min((p50 - 300) / 25, 25)
    if p95 > 1000: score -= min((p95 - 1000) / 40, 30)
    score -= min(error_rate * 100 * 0.8, 35)
    return round(clamp(score), 1)


def quality_score(test_results):
    """Score from functional/edge/negative test pass rate."""
    if not test_results:
        return 70.0
    passed = sum(1 for t in test_results if t.get("status") == "pass")
    warned = sum(1 for t in test_results if t.get("status") == "warn")
    rate = (passed + warned * 0.5) / len(test_results)
    return round(clamp(rate * 100), 1)


def grade(score):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


def risk_level(score):
    if score >= 80: return "Low risk", RISK_COLORS["info"]
    if score >= 60: return "Moderate risk", RISK_COLORS["low"]
    if score >= 40: return "Elevated risk", RISK_COLORS["medium"]
    if score >= 20: return "High risk", RISK_COLORS["high"]
    return "Critical risk", RISK_COLORS["critical"]


def overall(security, performance, quality):
    """Weighted blend - security dominates."""
    return round(clamp(security * 0.6 + performance * 0.25 + quality * 0.15), 1)
