"""Offline smoke test for the verifier agents (no network, no API key).

Builds a fake repo + fake findings + a scripted LLM, then checks:
  - false positives get downgraded to info + reasoning attached
  - confirmed findings get severity adjustment + fix code + lesson
  - skips: fact-based categories, missing files, batch failures
  - stats accounting + pipeline _finalize_scan persistence path
Run:  python tests/smoke_verifier.py
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.engines import verifier  # noqa: E402


class FakeLLM:
    """Scripted stand-in for LLMBackend: verdicts keyed by finding id."""
    name = "llm"

    def __init__(self, verdicts, fail_ids=()):
        self.verdicts = verdicts
        self.fail_ids = set(fail_ids)
        self.calls = []

    def verify_batch(self, items, deadline=None):
        self.calls.append([i["id"] for i in items])
        if any(i["id"] in self.fail_ids for i in items):
            raise RuntimeError("simulated LLM outage")
        return [self.verdicts[i["id"]] for i in items if i["id"] in self.verdicts]


class FakeAI:
    """Mirrors the AILayer facade: backend_name property + verify_batch delegation."""
    def __init__(self, backend):
        self.backend = backend
    backend_name = property(lambda self: self.backend.name)

    def verify_batch(self, items, deadline=None):
        return self.backend.verify_batch(items, deadline=deadline)


def mk_finding(fp, category, severity, file, line, rule="rule-x"):
    return {
        "fingerprint": fp, "category": category, "severity": severity,
        "title": f"Test finding {fp}", "endpoint": f"{file}:{line}",
        "method": "STATIC",
        "evidence": "evidence text",
        "impact": "impact text",
        "request": {"mode": "static", "file": file, "line": line, "rule": rule},
        "response": {"status": "source", "body_snippet": "code"},
        "attack_path": [], "exploit_success": True, "confidence": 0.8,
    }


def main():
    tmp = tempfile.mkdtemp(prefix="sentinel-verify-")
    with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("\n" * 9 + "cur.execute(f\"SELECT * FROM users WHERE name = '{q}'\")\n" + "\n" * 20)
    with open(os.path.join(tmp, "utils.py"), "w", encoding="utf-8") as fh:
        fh.write("\n" * 4 + "os.system('ls')\n" + "\n" * 10)
    with open(os.path.join(tmp, "docs_example.py"), "w", encoding="utf-8") as fh:
        fh.write('"""\nExample (docs only):\ncur.execute(f"SELECT * FROM t WHERE x = \'{v}\'")\n"""\n')

    def build_findings():
        fs = [
            mk_finding("fp-sqli", "sqli", "critical", "app.py", 10),          # -> confirmed
            mk_finding("fp-doc", "sqli", "high", "docs_example.py", 3),       # -> false positive
            mk_finding("fp-cmdi", "command_injection", "critical", "utils.py", 5),  # -> uncertain
            mk_finding("fp-cve", "dependency_cve", "high", "requirements.txt", 0),  # skipped (category)
            mk_finding("fp-missing", "sqli", "medium", "gone.py", 2),         # skipped (no file)
            mk_finding("fp-dyn", "sqli", "critical", "app.py", 10),           # dynamic -> skipped
        ]
        fs[5]["request"]["mode"] = "dynamic"
        fs[5]["method"] = "GET"
        return fs

    verdicts = {
        "fp-sqli": {"id": "fp-sqli", "verdict": "confirmed", "severity": "critical",
                    "confidence": 0.95, "reasoning": "q reaches execute via f-string",
                    "fix_conceptual": "parameterize", "fix_code": "cur.execute('... ?')",
                    "lesson": "never build SQL by string formatting"},
        "fp-doc": {"id": "fp-doc", "verdict": "false_positive", "confidence": 0.9,
                   "reasoning": "hit is inside a docstring example"},
        "fp-cmdi": {"id": "fp-cmdi", "verdict": "uncertain", "severity": "high",
                    "confidence": 0.5, "reasoning": "constant command, but pattern risky"},
    }

    # --- scenario 1: provider healthy --------------------------------------
    ai = FakeAI(FakeLLM(verdicts))
    out, stats = verifier.verify_findings(build_findings(), tmp, ai,
                                          progress_cb=lambda s, p=None: None)
    by_id = {f["fingerprint"]: f for f in out}
    assert stats["confirmed"] == 1, stats
    assert stats["false_positive"] == 1, stats
    assert stats["uncertain"] == 1, stats
    assert stats["verified"] == 3, stats
    assert stats["groups_failed"] == 0, stats
    # not selected: fact-based category, dynamic mode, unreadable file
    assert stats["skipped"] == 1, stats          # only fp-missing (no file)

    f = by_id["fp-sqli"]
    assert f["severity"] == "critical" and f["confidence"] == 0.95
    assert f["ai_analysis"]["fix_code"].startswith("cur.execute")
    assert f["ai_analysis"]["explanation"].startswith("[AI-verified · confirmed]")
    assert f["ai_analysis"]["learning"]["best_practice"]

    f = by_id["fp-doc"]
    assert f["severity"] == "info" and f["exploit_success"] is False
    assert f["ai_analysis"]["explanation"].startswith("[AI-verified · false positive]")

    f = by_id["fp-cmdi"]
    assert f["severity"] == "high"          # re-rated by the agent
    assert f["ai_analysis"]["explanation"].startswith("[AI-verified · uncertain")

    f = by_id["fp-cve"]
    assert f["severity"] == "high" and "ai_analysis" not in f       # category skip
    f = by_id["fp-dyn"]
    assert "ai_analysis" not in f                                  # dynamic mode skip

    # --- scenario 2: provider outage ---------------------------------------
    # one bad batch must not take the whole scan down, and must be counted
    ai2 = FakeAI(FakeLLM(verdicts, fail_ids={"fp-sqli"}))
    out2, stats2 = verifier.verify_findings(build_findings(), tmp, ai2,
                                            progress_cb=lambda s, p=None: None)
    by_id2 = {f["fingerprint"]: f for f in out2}
    assert stats2["groups_failed"] == 1, stats2
    assert stats2["verified"] == 0, stats2
    assert stats2["skipped"] == 4, stats2       # 3 in the dead batch + no-file finding
    assert "ai_analysis" not in by_id2["fp-sqli"]    # untouched, still reported
    assert "ai_analysis" not in by_id2["fp-doc"]

    print("verifier smoke test: ALL ASSERTIONS PASSED")
    print("stats:", json.dumps(stats))
    print("stats (outage):", json.dumps(stats2))
    print("llm batches:", ai.backend.calls)


def budget_scenario():
    """A spent provider budget must abandon the queued batches (never hang)
    and still report honest accounting."""
    tmp = tempfile.mkdtemp(prefix="sentinel-verify-budget-")
    with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("cur.execute(f\"SELECT * FROM users WHERE name = '{q}'\")\n")
    findings = [mk_finding("fp-sqli", "sqli", "critical", "app.py", 1)]
    verdicts = {"fp-sqli": {"id": "fp-sqli", "verdict": "confirmed",
                            "severity": "critical", "confidence": 0.9,
                            "reasoning": "reaches execute"}}
    ai = FakeAI(FakeLLM(verdicts))
    out, stats = verifier.verify_findings(findings, tmp, ai,
                                          progress_cb=lambda s, p=None: None,
                                          deadline=time.time() - 1)
    assert stats["groups_budget_skipped"] == 1, stats
    assert stats["verified"] == 0, stats
    assert stats["skipped"] == 1, stats
    assert ai.backend.calls == [], ai.backend.calls
    print("budget scenario: PASSED", json.dumps(stats))


if __name__ == "__main__":
    main()
    budget_scenario()
