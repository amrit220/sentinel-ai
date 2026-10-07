# 🛡️ Sentinel AI

**An AI-powered autonomous QA engineer + ethical hacking platform.**

Sentinel AI scans **anything you own** — a live API, any public GitHub repo, or a
local project folder:

- **API scans** — auto-generated functional/edge/negative tests, controlled
  attack simulation (SQLi, XSS, auth, open endpoints…), risk scoring.
- **Repo scans (static)** — shallow-clones any GitHub repo (or reads a local
  folder) and analyzes the code *without ever executing it*: language rule
  packs, hardcoded secrets, committed sensitive files, CI/CD + Dockerfile
  audits, and dependency CVE checks via OSV.dev.
- **Runtime sandbox (experimental)** — with Docker installed, repo scans can
  optionally build & run the project in an isolated container and attack it
  dynamically.

Every finding is explained in plain language (with code fixes), scored with a
weighted model, and published to developer + client reports — all behind a
modern dark-theme dashboard.

> ⚠️ **Authorized testing only.** Sentinel AI is built for security teams testing
> systems they own or are explicitly authorized to assess.

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

Open **http://127.0.0.1:5000**, go to **New Scan**, and pick a scan type:

- **⚡ API Target** — live endpoint (click "Use bundled demo target" for the full demo)
- **🐙 GitHub Repo** — paste any public repo URL, e.g. `https://github.com/amrit220/sentinel-ai`
- **📁 Local Folder** — any project directory on this machine

The API-mode pipeline completes in ~20–40s; repo scans in ~10–60s
(large repos add clone time + OSV dependency checks).

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
                        │  Dashboard · Scan (api|github|local) ·          │
                        │  Results · Reports · Monitoring · Learning     │
                        └───────────────┬────────────────────────────────┘
                                        │ REST (JSON, hash-routed SPA)
                        ┌───────────────▼────────────────────────────────┐
                        │             FLASK API LAYER  (app.py)           │
                        │  POST /api/scans {mode: api|repo} dispatches to  │
                        │  the right pipeline; everything else is shared  │
                        └───────────────┬────────────────────────────────┘
                                        │  background threads
              ┌─────────────────────────┴─────────────────────────┐
              ▼  mode=api                                        ▼  mode=repo
┌───────────────────────────────┐             ┌───────────────────────────────┐
│ SCANNER (dynamic)             │             │ REPO ENGINE (static)          │
│ discovery · functional/edge/  │             │ git clone --depth 1 / local   │
│ negative tests                │             │ read · language detection     │
│ ATTACK ENGINE                 │             │ Python+JS rule packs · secret │
│ SQLi/XSS/auth/open-endpoints  │             │ scan · sensitive files · CI + │
│ payloads + attack replay      │             │ Dockerfile audit · OSV CVE   │
│ PERF ENGINE                   │             │ dependency audit              │
│ concurrent virtual users      │             │ (optional) DOCKER RUNTIME    │
│ p50/p95/p99 · bottleneck      │             │ sandbox → ATTACK ENGINE       │
└───────────────┬───────────────┘             └───────────────┬───────────────┘
                └──────────────────┬──────────────────────────┘
                                   ▼
                    ┌─────────────────────────┐
                    │ VULN ENGINE (classify)   │
                    │ severity · CVSS · dedup │
                    └────────────┬─────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ AI LAYER                 │
                    │ LLM or SentinelMind      │
                    │ explanations + fixes +   │
                    │ learning lessons          │
                    └────────────┬─────────────┘
                                 ▼
                    ┌─────────────────────────┐      ┌──────────────────────┐
                    │ SCORING + SUMMARY        │─────▶│ REPORT GENERATOR      │
                    │ security/perf/quality    │      │ dev · client · JSON  │
                    └────────────┬─────────────┘      └──────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ SQLITE + ALERTS +        │
                    │ MONITOR (periodic re-    │
                    │ scans, new-vuln alerts)  │
                    └─────────────────────────┘
```

### Data flow

```
User → Scan config → API layer → pipeline thread (mode dispatch)

api mode:
  → reachability check → discovery (OpenAPI input / hosted spec / path probing)
  → functional · edge · negative test suite (status/structure/latency/error handling)
  → attack simulation (SQLi · XSS · auth · open endpoints · traversal · cmd-injection ·
    header audit · data-leak audit · verbose-error audit · validation audit)

repo mode:
  → git clone --depth 1 (GitHub) or local folder read
  → inventory + language detection → Python/JS rule packs → secret scan
  → sensitive-file scan → CI workflow + Dockerfile audit → OSV.dev dependency CVEs
  → (optional, Docker) build & run in container → dynamic attack engines

both modes:
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
├── app.py                        # Flask app, REST routes, mode dispatch, --with-demo launcher
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
│       ├── repo_engine.py        # static analysis: clone/local, rule packs, secrets, CI/Docker, OSV
│       ├── vuln_engine.py        # classification, severity mapping, fingerprinting
│       ├── perf_engine.py        # load testing, latency percentiles, verdicts
│       ├── report_generator.py   # developer / client / JSON reports (self-contained HTML)
│       ├── pipeline.py            # orchestrator: mode dispatch + shared scoring/AI tail
│       └── monitor.py             # continuous monitoring scheduler + alerting
├── demo_target/
│   └── vulnerable_app.py         # deliberately vulnerable demo API (DO NOT EXPOSE)
├── frontend/
│   ├── index.html                # SPA shell (sidebar, drawer, topbar, modal, toasts)
│   ├── styles.css                # dark responsive cybersecurity SaaS theme
│   └── js/
│       ├── api.js                # fetch client + esc/severity helpers
│       ├── charts.js             # hand-rolled SVG donut + bar charts (no CDN)
│       └── app.js                # hash router + all page views + AI modals
├── tests/
│   ├── fixture_repo/             # planted-flaw project (36 known issues) for e2e tests
│   ├── e2e_dashboard.py          # Playwright: full API-mode UI flow
│   ├── e2e_repo_scan.py          # Playwright: repo-mode UI flow (local folder)
│   └── e2e_mobile.py             # Playwright: responsive suites at 3 viewports
├── tools/
│   └── refresh_demo_data.py      # regenerate the GitHub Pages static-demo dataset
├── docs/                         # GitHub Pages site (static demo of the dashboard)
└── data/                         # runtime: sentinel.db + reports + cloned repos (gitignored)
```

---

## 🔌 Backend API design

| Method | Route | Purpose |
|---|---|---|
| `GET`  | `/api/health` | Service status, active AI backend, demo URL |
| `POST` | `/api/scans` | Start scan — `{mode:"api", target, ...}` or `{mode:"repo", repoUrl/localPath, ...}` → `{scan_id}` |
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

## 🎯 What the engines detect

### Repo scans (static analysis — the project's code is never executed)

| Category | Examples |
|---|---|
| Injection flaws | SQL built via f-strings/concatenation, `eval`/`exec`, `pickle.loads`, `yaml.load` without SafeLoader, `shell=True`, `os.system`, JS `child_process` template strings |
| Web vulnerabilities | XSS sinks (`dangerouslySetInnerHTML`, `innerHTML`, `document.write`) |
| Crypto & config | MD5/SHA1 for passwords, `random` for tokens, `debug=True`, wildcard CORS, `verify=False` / `rejectUnauthorized:false` |
| Secrets | Hardcoded API keys / passwords / tokens, committed `.env`, private keys, `credentials.json`, database files |
| Supply chain | Dependency CVEs via the free OSV.dev API (exact-version matching), unpinned dependencies |
| CI/CD & containers | `pull_request_target` + fork checkout, secrets echoed to logs, Dockerfiles running as root, pipe-to-shell installs |

### API scans (dynamic testing — verified against the bundled demo target)

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
penalty; performance from p50/p95 + error rate (API scans; shown as N/A for repo scans);
quality from test pass-rate (API) or code-hygiene penalty (repo); overall =
`0.6·security + 0.25·performance + 0.15·quality`, with A–F grade and risk-level text.

**Known limitation (by design):** static rules are pattern-based without dataflow
analysis — they can flag safe code (e.g. f-string SQL over internal identifiers) and
vulnerable code inside documentation strings. Findings carry a confidence score;
treat static results as review targets, not proof.

## 🧪 Testing

```bash
pip install playwright
python -m playwright install chromium
python app.py --with-demo          # backend must be running first (separate terminal)
python tests/e2e_dashboard.py      # full desktop flow: dashboard -> scan -> live
                                  # pipeline -> results -> attack replay -> reports
python tests/e2e_repo_scan.py      # repo mode: local-folder scan of tests/fixture_repo
                                  # (36 planted flaws) -> static findings -> code trace
python tests/e2e_mobile.py         # responsive suite: desktop / tablet / phone
                                  # viewports, drawer navigation, overflow checks
                                  # screenshots land in tests/artifacts/ (gitignored)
```

The UI is fully responsive: persistent sidebar ≥900px, slide-in drawer + hamburger
below, single-column grids and horizontally scrollable tables on phones.

## 🛠️ Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `app.py` crashes with `WinError 10048` / "address already in use" | Another Sentinel instance is already listening on port 5000. Stop it — PowerShell: `Get-Process python \| Stop-Process` — then relaunch. |
| Scan fails: *"Target ... is unreachable"* | The target URL isn't listening. For the bundled demo you must start Sentinel with `python app.py --with-demo` (demo serves on `:5099`). |
| Dashboard shows *"backend unreachable"* | Flask isn't serving — check its console output (usually a port conflict). |
| Demo button warns *"Demo target NOT running"* | Same as above — the button live-pings `:5099` before filling the form. |

---

## 🔐 Safety & ethics model

- All attack payloads are **non-destructive** (no DROP/DELETE payloads; read-only probes).
- Attack engine is intended solely for targets supplied by the operator; the bundled demo
  app makes safe end-to-end demonstration possible without touching third parties.
- Reports and dashboards carry the "authorized testing only" notice.

## 🧩 Extending the system

- **New static rule** → add a `_R(...)` entry in `sentinel/engines/repo_engine.py`,
  plus a `TITLES`/`SEVERITY_MAP` entry in `vuln_engine.py` and a knowledge-base
  entry in `ai_layer.py::KB`. Pipeline, scoring, reports and UI pick it up automatically.
- **New attack suite** → add payload list + detector function in `attack_engine.py`,
  register it in `run_all_attacks`.
- **New language** → add a rule pack in `repo_engine.py` and detect it via a
  manifest in `Inventory._build` (Go/Ruby/Java are natural next steps).
- **Private repos** → thread a PAT through `git clone` in `prepare_repo_target`
  (in-memory only — never persist it to the database or logs).
- **Different DB** → swap functions in `sentinel/database.py` (single choke point).
- **Async scales** → pipeline threads map 1:1 onto Celery/RQ workers for production.
- **Auth for the dashboard itself** → add a Flask `before_request` guard; the API surface
  is already centralized in `app.py`.
