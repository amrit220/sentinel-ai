# 🛡️ Sentinel AI

**An AI-powered autonomous QA engineer + ethical hacking platform.**

Sentinel AI accepts API endpoints or OpenAPI specs, automatically generates and runs
functional / edge / negative tests, simulates controlled real-world attacks, classifies
vulnerabilities with severity and CVSS-style scoring, explains every finding in plain
language (with code fixes), computes weighted risk scores, and produces developer + client
reports — all behind a modern dark-theme dashboard.

> ⚠️ **Authorized testing only.** Sentinel AI is built for security teams testing systems
> they own or are explicitly authorized to assess.

---

## 🚀 Quick start

```bash
pip install -r requirements.txt

# Option A — dashboard + bundled vulnerable demo target (full demo in one command)
python app.py --with-demo
#   dashboard  →  http://127.0.0.1:5000
#   demo API   →  http://127.0.0.1:5099

# Option B — dashboard only (scan your own authorized target)
python app.py
```

Open **http://127.0.0.1:5000**, go to **New Scan**, click **"⚡ Use bundled demo target"**,
tick the modules you want, and press **Launch scan**. The pipeline completes in ~20–40s.

### Optional: connect a real LLM

The AI layer works fully offline via **SentinelMind** (built-in rule-based analyst).
To plug in any OpenAI-compatible LLM instead:

```powershell
$env:OPENAI_API_KEY = "sk-..."
# optional overrides:
# $env:SENTINEL_LLM_BASE_URL = "https://api.openai.com/v1"
# $env:SENTINEL_LLM_MODEL    = "gpt-4o-mini"
```

The active backend is shown in the dashboard sidebar (`AI: sentinel-mind` or `AI: llm`).

---

## 🧠 System architecture

```
                        ┌────────────────────────────────────────────────┐
                        │                FRONTEND SPA                     │
                        │  Dashboard · Scan · Results · Reports ·        │
                        │  Monitoring · Learning  (dark cyber theme)     │
                        └───────────────┬────────────────────────────────┘
                                        │ REST (JSON, hash-routed SPA)
                        ┌───────────────▼────────────────────────────────┐
                        │             FLASK API LAYER  (app.py)           │
                        │  /api/scans · /api/findings · /api/reports ·    │
                        │  /api/ai/assistant · /api/monitor · /api/alerts│
                        └───────────────┬────────────────────────────────┘
                                        │  background threads
        ┌───────────────┬───────────────┼───────────────┬─────────────────┐
        ▼               ▼               ▼               ▼                 ▼
┌──────────────┐ ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ SCANNER      │ │ ATTACK      │ │ VULN         │ │ AI LAYER     │ │ PERF ENGINE  │
│ discovery,   │ │ ENGINE      │ │ ENGINE       │ │ LLM or       │ │ concurrent    │
│ functional/  │ │ controlled  │ │ classification│ │ SentinelMind │ │ virtual users │
│ edge/negative│ │ payload     │ │ severity,    │ │ explanations │ │ p50/p95/p99   │
│ test suites  │ │ injection   │ │ CVSS, dedup  │ │ fixes, learn │ │ bottlenecks   │
└──────┬───────┘ └──────┬──────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │               │                │                │
       └────────────────┴───────┬───────┴────────────────┴────────────────┘
                                 ▼
                    ┌─────────────────────────┐      ┌──────────────────────┐
                    │ PIPELINE ORCHESTRATOR   │─────▶│ SCORING SYSTEM        │
                    │ (sentinel/engines/      │      │ security / perf /     │
                    │  pipeline.py, threads)  │      │ quality 0–100, grade  │
                    └────────────┬─────────────┘      └──────────────────────┘
                                 ▼
                    ┌─────────────────────────┐      ┌──────────────────────┐
                    │ SQLITE PERSISTENCE      │◀────▶│ MONITOR ENGINE       │
                    │ scans · findings ·      │      │ periodic re-scans,   │
                    │ tests · alerts          │      │ new-vuln alerting    │
                    └────────────┬─────────────┘      └──────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ REPORT GENERATOR        │
                    │ Developer (technical)   │
                    │ Client (plain language) │
                    │ JSON export              │
                    └─────────────────────────┘
```

### Data flow

```
User → Scan config → API layer → pipeline thread
     → discovery (OpenAPI input / target-hosted spec / path probing)
     → functional · edge · negative test suite (status/structure/latency/error handling)
     → attack simulation (SQLi · XSS · auth · open endpoints · traversal · cmd-injection ·
       header audit · data-leak audit · verbose-error audit · validation audit)
     → vulnerability classification (severity + CVSS + confidence + fingerprint dedup)
     → AI enrichment (explanation, root cause, conceptual fix, code fix, learning lesson)
     → weighted scoring (security 60% / performance 25% / quality 15%)
     → AI executive summary + recommendations
     → SQLite → dashboard / reports / alerts
```

---

## 📁 Folder structure

```
SentinelAI/
├── app.py                        # Flask app, REST routes, --with-demo launcher
├── config.py                     # global config, weights, thresholds
├── requirements.txt
├── sentinel/
│   ├── __init__.py
│   ├── database.py               # thread-safe SQLite layer (scans/tests/findings/alerts/monitors)
│   ├── ai_layer.py               # AI facade: LLMBackend + SentinelMind fallback + knowledge base
│   ├── scoring.py                # weighted scoring, grades, risk levels
│   └── engines/
│       ├── scanner.py            # discovery, OpenAPI parsing, test generation + execution
│       ├── attack_engine.py      # controlled attack suites + passive audits + attack paths
│       ├── vuln_engine.py        # classification, severity mapping, fingerprinting
│       ├── perf_engine.py        # load testing, latency percentiles, verdicts
│       ├── report_generator.py   # developer / client / JSON reports (self-contained HTML)
│       ├── pipeline.py            # orchestrator running the whole flow in a thread
│       └── monitor.py             # continuous monitoring scheduler + alerting
├── demo_target/
│   └── vulnerable_app.py         # deliberately vulnerable demo API (DO NOT EXPOSE)
├── frontend/
│   ├── index.html                # SPA shell (sidebar, topbar, modal, toasts)
│   ├── styles.css                # dark cybersecurity SaaS theme
│   └── js/
│       ├── api.js                # fetch client + esc/severity helpers
│       ├── charts.js             # hand-rolled SVG donut + bar charts (no CDN)
│       └── app.js                # hash router + all page views + AI modals
└── data/                         # runtime: sentinel.db + generated reports
```

---

## 🔌 Backend API design

| Method | Route | Purpose |
|---|---|---|
| `GET`  | `/api/health` | Service status, active AI backend, demo URL |
| `POST` | `/api/scans` | Start scan (target, OpenAPI spec, module flags) → `{scan_id}` |
| `GET`  | `/api/scans` | List scans with status/progress/scores |
| `GET`  | `/api/scans/<id>` | Scan status, progress, stage, summary, recent alerts |
| `GET`  | `/api/scans/<id>/findings` | All findings (severity, evidence, AI, attack path) |
| `GET`  | `/api/scans/<id>/findings/<fid>` | Single finding |
| `GET`  | `/api/scans/<id>/tests` | Functional/edge/negative/perf test case results |
| `POST` | `/api/scans/<id>/analyze` | On-demand AI deep-analysis of one finding |
| `POST` | `/api/scans/<id>/perf` | Run/re-run load test on demand |
| `GET`  | `/api/scans/<id>/report?format=developer\|client\|json` | Download report |
| `POST` | `/api/ai/assistant` | AI debug-assistant chat (finding context) |
| `GET`  | `/api/alerts` | Alert feed (`?unread=1` for unread only) |
| `POST` | `/api/alerts/read` | Mark alerts read |
| `POST` | `/api/monitor/<id>/start` | Enable continuous monitoring (interval) |
| `POST` | `/api/monitor/<id>/stop` | Disable monitoring |
| `GET`  | `/api/monitor/<id>` | Monitoring status |

---

## 🖥️ Frontend pages

| Page | Route | Contents |
|---|---|---|
| Dashboard | `#/dashboard` | Score donuts (overall/security/performance/quality), threat-distribution bars, alert feed, recent scans |
| New Scan | `#/scan` | Target input, OpenAPI textarea, module toggles, perf sliders, demo-target button, **live progress** |
| Scans & Results | `#/scans`, `#/results/:id` | Score cards, AI executive summary, expandable finding cards, **attack replay modal**, **AI deep-analyze**, **debug-assistant chat**, test table with kind filters, load-test panel |
| Reports | `#/reports` | Download developer / client / JSON reports per scan |
| Monitoring | `#/monitor` | Enable periodic re-scans, interval, alert feed with mark-read |
| Learning | `#/learn` | Lessons from real findings: mistake / best practice / why it matters |

UI system: cards, SVG donuts, severity pills (red/orange/yellow/blue), expandable sections,
modals, toasts, live progress bars, keyboard-friendly chat. Fully dark, zero-CDN, works offline.

---

## 🎯 What the engines detect (verified against the bundled demo target)

| Finding | Class | Detected on demo |
|---|---|---|
| SQL injection | critical | ✅ /api/users (differential tautology attack) |
| Broken authentication | critical | ✅ /api/login (weak creds + predictable token) |
| Open endpoint | critical | ✅ /api/admin/secret (no auth) |
| Sensitive data exposure | critical | ✅ /api/users, /api/profile (password_hash) |
| Reflected XSS | high | ✅ /api/search (unencoded reflection) |
| Verbose error disclosure | high | ✅ /api/error (stack trace) |
| Improper input validation | medium | ✅ multiple endpoints |
| Missing security headers | medium | ✅ CSP/nosniff/frame-deny/HSTS/referrer |
| Performance / error handling | medium/low | ✅ slow-response + contract findings |

**Scoring model** (`sentinel/scoring.py`): security = saturating exponential decay over
weighted severities (critical 22 · high 12 · medium 6 · low 2.5) with exploit-success
penalty; performance from p50/p95 + error rate; quality from test pass-rate; overall =
`0.6·security + 0.25·performance + 0.15·quality`, with A–F grade and risk-level text.

---

## 🔐 Safety & ethics model

- All attack payloads are **non-destructive** (no DROP/DELETE payloads; read-only probes).
- Attack engine is intended solely for targets supplied by the operator; the bundled demo
  app makes safe end-to-end demonstration possible without touching third parties.
- Reports and dashboards carry the "authorized testing only" notice.

## 🧩 Extending the system

- **New attack suite** → add payload list + detector function in `attack_engine.py`,
  register it in `run_all_attacks`, add severity/TITLE in `vuln_engine.py`, add a
  knowledge-base entry in `ai_layer.py::KB`. That's it — pipeline, scoring, replay,
  reports, learning and UI pick it up automatically.
- **Different DB** → swap functions in `sentinel/database.py` (single choke point).
- **Async scales** → pipeline threads map 1:1 onto Celery/RQ workers for production.
- **Auth for the dashboard itself** → add a Flask `before_request` guard; the API surface
  is already centralized in `app.py`.
