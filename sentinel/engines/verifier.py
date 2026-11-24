"""AI Verification Agents.

The static rule packs are intentionally cheap and pattern-based, which
means they over-report (docstring examples, internal identifiers, test
fixtures) and can't judge reachability. When an LLM is configured, this
engine acts as a verification layer between the sweep and scoring:

  1. Collect static findings, prioritize by severity, cap the budget
  2. Group by source file, read a real code window around each hit
  3. Send batches to the LLM verification agent (parallel, fault-tolerant)
  4. Apply verdicts:
       confirmed     -> severity adjusted, real fix code + lesson attached
       false_positive-> downgraded to info, exploit flag cleared, reasoning shown
       uncertain     -> kept with honest confidence + reasoning

Every verdict is transparent: the reasoning travels in the finding's AI
explanation (visible in the dashboard finding modal and dev report), so a
dismissed finding is never silently dropped. With no LLM configured the
engine is a no-op and behavior is identical to the plain regex pipeline.

Zero schema changes: verdicts reuse the existing severity/confidence/
exploit_success/ai_* fields, so scoring, reports, UI and monitoring work
unchanged.
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config

SKIP_CATEGORIES = {
    # fact-based findings — code context adds nothing
    "dependency_cve", "unpinned_dependency", "exposed_file", "engine_error",
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def verify_findings(findings, repo_path, ai, progress_cb=None, deadline=None):
    """Verify static findings in code context. Returns (findings, stats).

    stats is None when verification was skipped (no LLM / no repo path);
    otherwise {verified, confirmed, false_positive, uncertain, skipped,
    overflow}.

    `deadline` is an optional wall-clock cutoff (time.time()). When the
    provider budget for this scan is spent, the remaining batches are
    abandoned instead of queueing behind a saturated quota — the scan
    completes with the verdicts it did get, and `budget_skipped` says so.
    """
    if not getattr(Config, "VERIFY_ENABLED", True):
        return findings, None
    if ai.backend_name != "llm" or not repo_path or not os.path.isdir(repo_path):
        return findings, None

    def cb(stage, pct=None):
        if progress_cb:
            progress_cb(stage, pct)

    # 1. select + prioritize ------------------------------------------------
    static = [f for f in findings
              if (f.get("request") or {}).get("mode") == "static"
              and f.get("category") not in SKIP_CATEGORIES]
    if not static:
        return findings, None
    static.sort(key=lambda f: SEV_RANK.get(f.get("severity"), 4))
    to_verify = static[:Config.VERIFY_MAX_FINDINGS]
    overflow = len(static) - len(to_verify)

    # 2. build code-context items, batched across files -----------------------
    # Findings are grouped per file so each item gets a code window from its
    # own source, then packed into batches of VERIFY_BATCH. Batches may span
    # files (every item carries its own window) — packing them per file
    # would create many tiny groups and waste the provider's quota.
    by_file = {}
    for f in to_verify:
        rel = f["request"]["file"]
        by_file.setdefault(rel, []).append(f)

    items = []
    for rel, chunk in by_file.items():
        lines = _read_lines(repo_path, rel)
        if lines is None:
            continue
        items.extend(_item(f, lines) for f in chunk)

    batches = []
    for i in range(0, len(items), Config.VERIFY_BATCH):
        batches.append(items[i:i + Config.VERIFY_BATCH])

    if not batches:
        return findings, None

    # 3. run verification agents (parallel, per-batch isolation) -------------
    stats = {"verified": 0, "confirmed": 0, "false_positive": 0,
             "uncertain": 0, "skipped": 0, "overflow": overflow,
             "groups": len(batches), "groups_empty": 0, "groups_failed": 0,
             "groups_budget_skipped": 0}
    finding_by_fp = {str(f["fingerprint"]): f for f in to_verify}
    cb(f"AI verification agents: 0/{len(batches)} groups", 78)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, Config.VERIFY_PARALLEL)) as pool:
        futures = []
        for grp in batches:
            if deadline and time.time() > deadline:
                # provider budget spent — don't queue work we can't afford
                stats["groups_budget_skipped"] += 1
                continue
            futures.append(pool.submit(_verify_group, ai, grp, deadline))
        for fut in as_completed(futures):
            if deadline and time.time() > deadline:
                # stop waiting on the queued remainder; running batches
                # still finish (their request is already in flight)
                for pending in futures:
                    pending.cancel()
            try:
                verdicts, failed = fut.result()   # never raises
            except Exception:
                verdicts, failed = [], True
            if failed:
                stats["groups_failed"] += 1
            elif not verdicts:
                stats["groups_empty"] += 1
            for v in verdicts:
                f = finding_by_fp.get(str(v.get("id")))
                if f is not None:
                    _apply_verdict(f, v, stats)
            done += 1
            cb(f"AI verification agents: {done}/{len(batches)} groups", 78)

    stats["verified"] = (stats["confirmed"] + stats["false_positive"]
                         + stats["uncertain"])
    stats["skipped"] = len(to_verify) - stats["verified"]
    cb(f"AI verification complete — {stats['confirmed']} confirmed, "
       f"{stats['false_positive']} dismissed", 80)
    return findings, stats


# ------------------------------------------------------------------ helpers
def _read_lines(repo_path, rel):
    """Read a scanned source file from the repo/clone. Never raises."""
    path = os.path.join(repo_path, rel.replace("/", os.sep))
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def _item(f, lines):
    """One verification item: finding metadata + numbered code window."""
    line_no = int((f.get("request") or {}).get("line") or 0)
    lo = max(0, line_no - 1 - Config.VERIFY_CONTEXT_LINES)
    hi = min(len(lines), line_no + Config.VERIFY_CONTEXT_LINES)
    window = "\n".join(f"{n + 1}: {lines[n]}" for n in range(lo, hi)) or "(file unreadable)"
    return {
        "id": f["fingerprint"],
        "title": f.get("title"),
        "category": f.get("category"),
        "claimed_severity": f.get("severity"),
        "rule": (f.get("request") or {}).get("rule"),
        "line": line_no,
        "evidence": (f.get("evidence") or "")[:200],
        # the window is the expensive part of the prompt — keep it tight
        "code": window[:2000],
    }


def _verify_group(ai, items, deadline=None):
    """Verify one batch. Returns (verdicts, failed); errors degrade to an
    empty list so one bad batch never kills a scan. `failed` marks a batch
    whose call never completed (timeout / 429)."""
    try:
        verdicts = ai.verify_batch(items, deadline=deadline)
    except Exception:
        return [], True
    if verdicts is None:
        return [], True          # provider call failed (timeout / 429)
    if not verdicts:
        return [], False         # model replied, but with no usable verdict
    out = [v for v in verdicts if isinstance(v, dict) and v.get("id")]
    return out, False


def _apply_verdict(f, v, stats):
    """Merge one verdict into the finding dict (pre-persistence)."""
    verdict = str(v.get("verdict") or "").strip().lower()
    reasoning = str(v.get("reasoning") or "").strip()[:600]
    try:
        conf = float(v.get("confidence"))
        f["confidence"] = round(min(max(conf, 0.0), 1.0), 2)
    except (TypeError, ValueError):
        pass

    if verdict == "false_positive":
        f["severity"] = "info"
        f["exploit_success"] = False
        f["ai_analysis"] = {
            "explanation": f"[AI-verified · false positive] {reasoning}",
            "fix_conceptual": "",
            "fix_code": "",
            "learning": None,
        }
        stats["false_positive"] += 1
        return

    if verdict not in ("confirmed", "uncertain"):
        stats["skipped"] += 1
        return

    if v.get("severity") in SEV_RANK:
        f["severity"] = v["severity"]
    tag = "confirmed" if verdict == "confirmed" else "uncertain — needs human review"
    lesson = str(v.get("lesson") or "").strip()
    f["ai_analysis"] = {
        "explanation": f"[AI-verified · {tag}] {reasoning}",
        "fix_conceptual": str(v.get("fix_conceptual") or "").strip(),
        "fix_code": str(v.get("fix_code") or "").strip(),
        "learning": ({"mistake": f.get("title", ""),
                      "best_practice": lesson,
                      "why": reasoning} if lesson else None),
    }
    stats["confirmed" if verdict == "confirmed" else "uncertain"] += 1
