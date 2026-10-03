"""Reporting System.

Generates two HTML reports plus a JSON export:
- Developer report : technical - findings, attack replay, code fixes.
- Client report     : plain-language executive summary, scores, priorities.
Reports are written to data/reports/ and returned as file paths.
"""
import html
import json
import os
import time

from config import REPORT_DIR
from .. import scoring

_CSS = """
:root{--bg:#0a0e14;--card:#101623;--ink:#e6edf3;--dim:#8b95a5;--acc:#00e5a0;
--crit:#ff3b5c;--high:#ff8b3d;--med:#ffd23d;--low:#4dd8ff;--border:#1c2738}
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.6 'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--ink);padding:40px 20px}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:26px;letter-spacing:.5px}h2{font-size:18px;margin:34px 0 12px;color:var(--acc)}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin:14px 0}
.grid{display:flex;gap:14px;flex-wrap:wrap}
.score{flex:1;min-width:180px;text-align:center}
.score .n{font-size:34px;font-weight:700}
.muted{color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--dim);text-align:left;padding:8px;border-bottom:1px solid var(--border)}
td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}
.sev{font-weight:600;padding:2px 10px;border-radius:20px;font-size:12px}
.critical{background:#ff3b5c22;color:var(--crit)}.high{background:#ff8b3d22;color:var(--high)}
.medium{background:#ffd23d22;color:var(--med)}.low{background:#4dd8b322;color:var(--low)}
pre{background:#070a10;border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-size:12px;color:#9fe8c9}
.tag{display:inline-block;background:#1c2738;padding:2px 10px;border-radius:6px;font-size:12px;margin:2px 4px 2px 0}
code{background:#1c2738;padding:1px 5px;border-radius:4px;font-size:12px}
.pill{font-size:12px;padding:2px 10px;border-radius:20px;background:#1c2738}
"""

_SEV_LEGEND = [
    ("critical", "Critical - directly exploitable, fix immediately"),
    ("high", "High - realistic attack vector, fix this sprint"),
    ("medium", "Medium - weakens security posture, plan a fix"),
    ("low", "Low - hygiene and quality issue"),
]


def _e(s):
    return html.escape(str(s if s is not None else ""))


def _timestamp():
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


def _score_cards(summary):
    s = summary.get("scores", {})
    cells = []
    for key, label in (("overall", "Overall"), ("security", "Security"),
                       ("performance", "Performance"), ("quality", "Quality")):
        v = s.get(key, 0)
        cells.append(
            f'<div class="card score"><div class="muted">{label}</div>'
            f'<div class="n" style="color:{_score_color(v)}">{v}</div>'
            f'<div class="pill">{scoring.grade(v)}</div></div>'
        )
    return f'<div class="grid">{"".join(cells)}</div>'


def _score_color(v):
    if v >= 80: return "#00e5a0"
    if v >= 60: return "#4dd8ff"
    if v >= 40: return "#ffd23d"
    return "#ff3b5c"


def _sev_span(sev):
    return f'<span class="sev {sev}">{sev.upper()}</span>'


# ------------------------------------------------------- developer report --
def _finding_block_dev(f):
    ai = f.get("ai_learning") or {}
    replay = ""
    for step in f.get("attack_path") or []:
        replay += (f'<tr><td class="muted">Step {step.get("step")}</td>'
                   f'<td><b>{_e(step.get("title"))}</b><br>{_e(step.get("detail"))}</td></tr>')
    code = ""
    if f.get("ai_fix_code") or (f.get("ai_analysis") or {}).get("fix_code"):
        code = (f.get("ai_analysis") or {}).get("fix_code") or f.get("ai_fix_code")
        code = f'<h3 style="margin-top:10px">Suggested fix</h3><pre>{_e(code)}</pre>'
    return f"""
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3 style="margin:0">{_e(f.get('title'))} {_sev_span(f.get('severity'))}</h3>
        <span class="muted">{_e(f.get('method','GET'))} {_e(f.get('endpoint',''))}</span>
      </div>
      <p class="muted" style="margin-top:6px">Category: <span class="tag">{_e(f.get('category'))}</span>
         CVSS ≈ <span class="tag">{_e(f.get('cvss','n/a'))}</span>
         Confidence: <span class="tag">{f.get('confidence',0)*100:.0f}%</span></p>
      <p><b>Evidence:</b> {_e(f.get('evidence'))}</p>
      <p><b>Impact:</b> {_e(f.get('impact'))}</p>
      <h3 style="margin-top:12px">AI explanation</h3>
      <p>{_e((f.get('ai_analysis') or {}).get('explanation') or f.get('ai_explanation'))}</p>
      <p><b>Root cause:</b> {_e((f.get('ai_analysis') or {}).get('root_cause'))}</p>
      {code}
      <h3 style="margin-top:12px">Attack replay</h3>
      <table>{replay}</table>
    </div>"""


def generate_dev_report(scan, findings, path=None):
    summary = scan.get("summary") or {}
    counts = summary.get("counts", {})
    blocks = "".join(_finding_block_dev(f) for f in findings) or '<div class="card">No findings recorded.</div>'
    perf = summary.get("performance") or {}
    perf_html = ""
    if perf:
        perf_html = f"""
        <h2>Load test</h2>
        <div class="card"><div class="grid" style="font-size:13px">
          <div>Requests: <b>{perf.get('total_requests',0)}</b></div>
          <div>Throughput: <b>{perf.get('throughput_rps',0)} rps</b></div>
          <div>p50: <b>{perf.get('latency_p50_ms',0)}ms</b></div>
          <div>p95: <b>{perf.get('latency_p95_ms',0)}ms</b></div>
          <div>p99: <b>{perf.get('latency_p99_ms',0)}ms</b></div>
          <div>Error rate: <b>{perf.get('error_rate',0)*100:.1f}%</b></div>
        </div><p class="muted" style="margin-top:8px">{_e(perf.get('bottleneck_analysis',''))}</p></div>"""
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Sentinel AI - Developer Report</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>&#128737; Sentinel AI <span class="muted" style="font-size:14px">Developer Report</span></h1>
<p class="muted">Target: <b>{_e(scan.get('target'))}</b> &middot; Scan ID: <code>{scan.get('id')}</code> &middot; {_timestamp()}</p>
{_score_cards(summary)}
<div class="card"><b>Findings:</b>
 <span class="pill">{counts.get('critical',0)} critical</span>
 <span class="pill">{counts.get('high',0)} high</span>
 <span class="pill">{counts.get('medium',0)} medium</span>
 <span class="pill">{counts.get('low',0)} low</span></div>
<h2>AI executive summary</h2>
<div class="card"><p>{_e((summary.get('ai_summary') or {}).get('executive_summary',''))}</p>
<p style="margin-top:10px"><b>Top risks:</b></p><ul>{"".join(f'<li>{_e(r)}</li>' for r in (summary.get('ai_summary') or {}).get('top_risks',[]))}</ul></div>
<h2>Findings & attack replays ({len(findings)})</h2>
{blocks}
{perf_html}
<h2>Test case results</h2>
<div class="card muted">See the dashboard results page for the full {summary.get('test_total',0)} test cases
({summary.get('test_passed',0)} passed, {summary.get('test_warned',0)} warnings, {summary.get('test_failed',0)} failed).</div>
<p class="muted" style="margin-top:30px;font-size:12px">Generated by Sentinel AI - autonomous QA & security platform. Authorized testing only.</p>
</div></body></html>"""
    return _save(doc, scan.get("id"), "developer", path)


# ---------------------------------------------------------- client report --
def generate_client_report(scan, findings, path=None):
    summary = scan.get("summary") or {}
    counts = summary.get("counts", {})
    ai = summary.get("ai_summary") or {}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    plain = {
        "sqli": "Attackers can read or alter your entire database.",
        "xss": "Attackers can run malicious code in your users' browsers.",
        "broken_auth": "Attackers can log in without stealing anyone's password.",
        "open_endpoint": "Private admin features are visible to anyone on the internet.",
        "data_leakage": "Your API is sharing passwords/secrets with everyone who asks.",
        "path_traversal": "Attackers can read files they should never see.",
        "command_injection": "Attackers can control your server.",
        "missing_headers": "Your website lacks standard protective shields.",
        "verbose_error": "Your API tells attackers too much about how it works.",
        "improper_validation": "Your API accepts clearly invalid data.",
        "perf_latency": "Parts of your service are slow.",
        "error_handling": "Parts of your service behave inconsistently.",
    }
    rows = ""
    for f in sorted(findings, key=lambda x: sev_order.get(x.get("severity"), 5)):
        rows += (f'<tr><td>{_sev_span(f.get("severity"))}</td><td><b>{_e(f.get("title"))}</b><br>'
                 f'<span class="muted">{_e(plain.get(f.get("category"), f.get("evidence","")))}</span></td></tr>')
    legend = "".join(f'<li><span class="sev {s}">{s.upper()}</span> <span class="muted">{d}</span></li>' for s, d in _SEV_LEGEND)
    recs = "".join(f"<li>{_e(r)}</li>" for r in ai.get("recommendations", []))
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Sentinel AI - Client Report</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>&#128737; Sentinel AI <span class="muted" style="font-size:14px">Client Report</span></h1>
<p class="muted">Prepared for the stakeholders of <b>{_e(scan.get('target'))}</b> &middot; {_timestamp()}</p>
{_score_cards(summary)}
<h2>What we tested</h2>
<div class="card"><p>Sentinel AI automatically tested the application's interfaces: it checked that every
endpoint behaves correctly, attempted {len(findings) and 'the' or ''} simulated attacks a real hacker would try,
and reviewed how the system responds under pressure. Testing was performed in a safe, controlled environment.</p></div>
<h2>In plain language</h2>
<div class="card"><p>{_e(ai.get('executive_summary',''))}</p></div>
<h2>Issues found</h2>
<div class="card"><table>{rows or '<tr><td class="muted">No issues found.</td></tr>'}</table></div>
<h2>What the labels mean</h2>
<div class="card"><ul style="list-style:none">{legend}</ul></div>
<h2>Our recommendations</h2>
<div class="card"><ol>{recs}</ol></div>
<p class="muted" style="margin-top:30px;font-size:12px">This report was generated automatically by Sentinel AI.
It summarizes security testing authorized by the application owner.</p>
</div></body></html>"""
    return _save(doc, scan.get("id"), "client", path)


def generate_json_export(scan, findings, tests):
    payload = {
        "scan": {k: v for k, v in scan.items() if k != "_id"},
        "findings": findings,
        "tests": tests,
    }
    path = os.path.join(REPORT_DIR, f"sentinel-{scan.get('id')}-export.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def _save(doc, scan_id, kind, path=None):
    path = path or os.path.join(REPORT_DIR, f"sentinel-{scan_id}-{kind}-report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
