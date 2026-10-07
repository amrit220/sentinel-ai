"""Universal Repo Scanning Engine (static code analysis).

Scans ANY project — a public GitHub repo (shallow-cloned) or a local
folder — WITHOUT executing any of its code:

  1. Inventory + language detection (Python / JS / TS via manifests)
  2. Per-language security rule packs (SQLi, XSS, eval, deserialization,
     command injection, TLS-off, weak crypto, CORS, debug mode, ...)
  3. Secret scanning (hardcoded credentials / API keys)
  4. Sensitive-file detection (.env, keys, .pem, databases committed)
  5. CI/CD workflow audit (GitHub Actions) + Dockerfile audit
  6. Dependency CVE audit via the free OSV.dev API (offline-safe)

Optionally (experimental, requires Docker): builds and runs the project
inside an isolated container so the dynamic attack engines can hit it.

All output uses the same finding schema as the dynamic pipeline, so
scoring, AI analysis, reports, learning mode and monitoring work
unchanged.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

import requests

from config import Config

try:  # data/ is gitignored; clones land there
    from config import DATA_DIR
except ImportError:  # pragma: no cover
    DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data")

REPO_DIR = os.path.join(DATA_DIR, "repos")

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "dist", "build",
    "__pycache__", ".idea", ".vscode", "coverage", ".next", ".nuxt",
    "vendor", "target", "bin", "obj", "site-packages", ".tox", ".mypy_cache",
    ".pytest_cache", "migrations",
}
TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env",
    ".txt", ".md", ".html", ".htm", ".vue", ".svelte", ".cfg", ".ini",
    ".toml", ".sh", ".bash", ".ps1", ".rb", ".go", ".java", ".php",
}
NO_CONTENT_EXT = (".min.js", ".min.css", ".map", ".lock")
MAX_FILE_BYTES = 800_000       # skip huge files for content rules
MAX_FILES = 4000
MAX_MATCHES_PER_RULE = 6       # avoid finding floods from repetitive code
SECRET_VALUE_EXCLUDES = [
    "changeme", "change_me", "change-me", "example", "xxxxx", "your_",
    "yours", "placeholder", "dummy", "sample", "<", ">", "insert", "todo",
    "fixme", "none", "null", "default", "getenv", "environ", "process.env",
    "${", "os.environ", "secret_key", "...", "test123",
]

OSV_API = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 8
MAX_DEP_QUERIES = 30


# ============================================================ target prep ==
def prepare_repo_target(cfg, scan_id):
    """Returns (kind, path, display, note). kind in {github, local}."""
    os.makedirs(REPO_DIR, exist_ok=True)
    repo_url = (cfg.get("repo_url") or "").strip()
    local_path = (cfg.get("local_path") or "").strip()
    branch = (cfg.get("branch") or "").strip() or None

    if repo_url:
        m = re.match(
            r"^(?:https?://)?(?:www\.)?github\.com[:/]([\w.\-]+)/([\w.\-]+?)"
            r"(?:\.git)?(?:/tree/([\w.\-/]+))?/?$",
            repo_url, re.IGNORECASE)
        if not m:
            raise ValueError(
                f"Not a valid GitHub repository URL: {repo_url!r}. "
                "Expected https://github.com/owner/repo (optionally /tree/branch).")
        owner, repo, url_branch = m.groups()
        branch = branch or url_branch
        dest = os.path.join(REPO_DIR, f"{scan_id}_{repo}")
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        clone_url = f"https://github.com/{owner}/{repo}.git"
        cmd = ["git", "clone", "--depth", "1", "--quiet"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [clone_url, dest]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise ValueError(
                f"git clone failed: {(proc.stderr or 'unknown error').strip()[:300]}")
        display = f"github.com/{owner}/{repo}" + (f"@{branch}" if branch else "")
        return "github", dest, display, None

    if local_path:
        if not os.path.isdir(local_path):
            raise ValueError(f"Local path does not exist or is not a folder: {local_path}")
        display = os.path.basename(os.path.normpath(local_path)) or local_path
        return "local", local_path, display, None

    raise ValueError("No repository URL or local folder provided.")


# ============================================================== inventory ==
class Inventory:
    def __init__(self, root):
        self.root = root
        self.files = []          # (abs_path, rel_path, size)
        self.texts = {}           # rel_path -> list[str] (content lines)
        self.languages = set()
        self.loc = 0
        self._build()

    def _build(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if len(self.files) >= MAX_FILES:
                    return
                abs_p = os.path.join(dirpath, fn)
                rel_p = os.path.relpath(abs_p, self.root).replace("\\", "/")
                try:
                    size = os.path.getsize(abs_p)
                except OSError:
                    continue
                self.files.append((abs_p, rel_p, size))

        for abs_p, rel_p, size in self.files:
            ext = os.path.splitext(rel_p)[1].lower()
            base = os.path.basename(rel_p)
            if rel_p.endswith(NO_CONTENT_EXT):
                continue
            if size > MAX_FILE_BYTES:
                continue
            if ext in TEXT_EXTS or base == "Dockerfile" or base.startswith(".env") \
                    or base in ("LICENSE",) or rel_p.startswith(".github/"):
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as fh:
                        self.texts[rel_p] = fh.read().splitlines()
                        self.loc += len(self.texts[rel_p])
                except OSError:
                    continue

        names = {os.path.basename(f[1]).lower() for f in self.files}
        if any(n in ("requirements.txt", "pyproject.toml", "setup.py", "pipfile")
               for n in names) or any(r.endswith(".py") for r in self.texts):
            self.languages.add("python")
        if "package.json" in names or any(
                r.endswith((".js", ".jsx", ".ts", ".tsx")) for r in self.texts):
            self.languages.add("javascript")


# ================================================================== rules ==
IMPACTS = {
    "sqli": "Attacker-controlled input is concatenated into SQL — full database read/write is possible.",
    "xss": "Unescaped input rendered into HTML lets attackers run JavaScript in victims' browsers.",
    "command_injection": "Unsanitized input reaches a shell — remote code execution on the server.",
    "unsafe_eval": "Evaluating dynamic strings as code lets attackers inject arbitrary logic.",
    "unsafe_deserialize": "Deserializing untrusted data can achieve remote code execution.",
    "tls_verify_off": "TLS certificate validation disabled — man-in-the-middle attacks go undetected.",
    "weak_crypto": "Weak/broken primitives give attackers a trivial path to hashes and tokens.",
    "debug_prod": "Debug mode leaks stack traces and internal state to end users.",
    "cors_wildcard": "Any origin can read API responses with credentials — cross-site data theft.",
    "hardcoded_secret": "A credential in source control is effectively public once leaked or shared.",
    "exposed_file": "A sensitive file committed to the repository exposes keys/data to anyone with read access.",
    "dependency_cve": "A known vulnerability exists in this exact dependency version.",
    "ci_action_risk": "A misconfigured workflow can let fork/PR code access repository secrets.",
    "docker_risk": "Container hardening gap: root user, shell-piped installs, or baked-in secrets.",
    "path_traversal": "User-influenced paths can escape the intended directory and read system files.",
    "unpinned_dependency": "Loose dependency versions make builds non-reproducible and hide vulnerable versions.",
}


def _R(rid, category, severity, title, pattern, confidence=0.8,
        exclude=(), must=(), per_rule=MAX_MATCHES_PER_RULE, multiline=False):
    """Static analysis rule definition (regex; multiline joins 3 lines)."""
    return {
        "id": rid, "category": category, "severity": severity, "title": title,
        "pattern": re.compile(pattern, re.IGNORECASE), "confidence": confidence,
        "exclude": [e.lower() for e in exclude], "must": [m.lower() for m in must],
        "per_rule": per_rule, "multiline": multiline,
    }


PY_RULES = [
    _R("py-sql-fstring", "sqli", "critical", "SQL Injection (f-string query)",
       r"\.execute\w*\(\s*f[\"']", 0.9, must=("select", "insert", "update", "delete", "drop", "create"),
       multiline=True),
    _R("py-sql-concat", "sqli", "critical", "SQL Injection (concatenated query)",
       r"\.execute\w*\(\s*[\"'][^\"']*(select|insert|update|delete)[^\"']*[\"']\s*[\"']?\s*(\+|%)",
       0.85, multiline=True),
    _R("py-sql-var", "sqli", "high", "SQL query built via f-string",
       r"(query|sql|stmt)\s*=\s*f[\"'].*(select|insert|update|delete)", 0.7),
    _R("py-eval", "unsafe_eval", "high", "Use of eval()/exec()",
       r"\b(eval|exec)\s*\(", 0.85, exclude=("ast.literal_eval", "safe_eval")),
    _R("py-pickle", "unsafe_deserialize", "high", "Unsafe deserialization (pickle)",
       r"pickle\.loads?\s*\(", 0.9),
    _R("py-yaml-load", "unsafe_deserialize", "high", "Unsafe yaml.load without SafeLoader",
       r"yaml\.load\s*\(", 0.8, exclude=("safeloader", "safe_load")),
    _R("py-shell-true", "command_injection", "critical", "Subprocess with shell=True",
       r"shell\s*=\s*True", 0.9, must=()),
    _R("py-os-system", "command_injection", "critical", "os.system() call",
       r"os\.system\s*\(", 0.9),
    _R("py-tls-off", "tls_verify_off", "high", "TLS certificate verification disabled",
       r"(verify\s*=\s*False|check_hostname\s*=\s*False)", 0.95),
    _R("py-debug", "debug_prod", "medium", "Debug mode enabled",
       r"debug\s*=\s*True", 0.75, exclude=("#",)),
    _R("py-cors-star", "cors_wildcard", "medium", "Wildcard CORS policy",
       r"(origins?\s*[\"']?\s*[:=]\s*[\[\(]?[\"']\*|access-control-allow-origin[\"'\s,]*\*)", 0.8),
    _R("py-weak-hash", "weak_crypto", "medium", "Weak hash function (MD5/SHA1)",
       r"hashlib\.(md5|sha1)\s*\(", 0.7),
    _R("py-random-secret", "weak_crypto", "high", "Insecure randomness for secrets",
       r"(token|secret|password|otp|session)[_a-z]*\s*=\s*.*\brandom\.", 0.7),
    _R("py-traversal", "path_traversal", "critical", "User-controlled file path",
       r"(open|send_file|send_from_directory)\s*\(\s*(f?[\"'][^\"']*[\"']?\s*,?\s*)?(request\.|user_|input)", 0.6),
]

JS_RULES = [
    _R("js-dangerous-html", "xss", "high", "dangerouslySetInnerHTML (React XSS)",
       r"dangerouslysetinnerhtml", 0.9),
    _R("js-innerhtml", "xss", "medium", "innerHTML assigned dynamic content",
       r"\.innerHTML\s*=\s*(?![\"'])", 0.7),
    _R("js-document-write", "xss", "medium", "document.write with dynamic content",
       r"document\.write\s*\(\s*(?!([\"']\s*\)))", 0.6),
    _R("js-eval", "unsafe_eval", "high", "Use of eval()/new Function()",
       r"(\beval\s*\(|new\s+Function\s*\()", 0.85),
    _R("js-cmd-template", "command_injection", "critical", "Command built from template string",
       r"(exec|execsync|spawn|spawnsync)\s*\(\s*[\"'`][^\"'`]*\$\{", 0.85),
    _R("js-tls-off", "tls_verify_off", "high", "TLS rejection disabled (Node)",
       r"rejectunauthorized\s*:\s*false|node_tls_reject_unauthorized\s*=\s*['\"]?0", 0.95),
]

# filename / path rules — matched against the file list, not content
FILE_RULES = [
    dict(rid="file-env", category="exposed_file", severity="critical",
         title="Environment file committed to repository",
         match=lambda r, b: b == ".env" or b.startswith(".env."),
         impact="Committed .env files typically contain live database credentials and API keys."),
    dict(rid="file-pem", category="exposed_file", severity="critical",
         title="Private key / certificate committed to repository",
         match=lambda r, b: r.endswith((".pem", ".p12", ".pfx", ".key"))
                            or b in ("id_rsa", "id_ed25519", "id_ecdsa"),
         impact="A private key in git history gives anyone with read access server/network access."),
    dict(rid="file-creds", category="exposed_file", severity="critical",
         title="Credentials file committed to repository",
         match=lambda r, b: b in ("credentials.json", "secrets.json", "config.gypi")
                            or re.match(r"service[_-]?account.*\.json$", b, re.I),
         impact="Cloud service-account files grant full access to the associated cloud project."),
    dict(rid="file-db", category="exposed_file", severity="low",
         title="Database file committed to repository",
         match=lambda r, b: r.endswith((".sqlite", ".sqlite3", ".db")) and "readme" not in r.lower(),
         impact="Databases in the repo may contain real user data and password hashes."),
]

# CI workflow + Dockerfile content rules
CI_RULES = [
    _R("ci-prtarget", "ci_action_risk", "critical",
       "pull_request_target with untrusted checkout",
       r"pull_request_target", 0.9,
       must=("github.event.pull_request",)),
    _R("ci-echo-secret", "hardcoded_secret", "medium",
       "Workflow echoes a repository secret to logs",
       r"echo[^|]*\$\{\{\s*secrets\.", 0.85),
]

DOCKER_RULES = [
    _R("dk-pipe-shell", "docker_risk", "high", "Installer piped into shell",
       r"(curl|wget)[^|]*\|\s*(ba)?sh", 0.85),
]

SECRET_RE = re.compile(
    r"(?i)\b[a-z0-9_]*(password|passwd|pwd|secret|api[_-]?key|apikey|token|"
    r"access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|"
    r"admin[_-]?key)[a-z0-9_]*[\"']?"
    r"\s*[:=]\s*[\"'][^\"'\s${]{6,}[\"']")


# ============================================================== scanning ===
def _fingerprint(category, rel, line, rid):
    return hashlib.sha1(f"{category}|{rel}|{line}|{rid}".encode()).hexdigest()[:16]


def _finding(rule, rel, line_no, snippet, extra_evidence=""):
    cat = rule["category"]
    return {
        "fingerprint": _fingerprint(cat, rel, line_no, rule["id"]),
        "category": cat,
        "severity": rule["severity"],
        "title": rule["title"],
        "endpoint": f"{rel}:{line_no}",
        "method": "STATIC",
        "evidence": (f"{rel}:{line_no} — {snippet.strip()[:220]}"
                     + (f" | {extra_evidence}" if extra_evidence else "")),
        "impact": IMPACTS.get(cat, ""),
        "request": {"mode": "static", "file": rel, "line": line_no,
                    "rule": rule["id"]},
        "response": {"status": "source", "body_snippet": snippet[:400]},
        "attack_path": [
            {"step": 1, "title": "File located",
             "detail": f"Analyzed {rel} during repository scan."},
            {"step": 2, "title": "Pattern matched",
             "detail": f"Line {line_no} matched rule '{rule['id']}': {snippet.strip()[:180]}"},
            {"step": 3, "title": "Why it's dangerous",
             "detail": IMPACTS.get(cat, "")},
            {"step": 4, "title": "Next step",
             "detail": "See the AI analysis below for the concrete, code-level fix."},
        ],
        "exploit_success": True,
        "confidence": rule["confidence"],
    }


def _run_content_rules(inv, rules, languages, progress_cb=None, stage=""):
    findings = []
    hits = {}
    for rel, lines in inv.texts.items():
        ext = os.path.splitext(rel)[1].lower()
        for rule in rules:
            if rule["id"].startswith("py-") and "python" not in languages:
                continue
            if rule["id"].startswith("js-") and "javascript" not in languages:
                continue
            if hits.get(rule["id"], 0) >= rule["per_rule"]:
                continue
            last_end = -1   # avoids re-reporting the same multiline match
            for i, raw in enumerate(lines):
                stripped = raw.strip()
                if i <= last_end:
                    continue
                # skip commented-out code
                if stripped.startswith(("#", "//")):
                    continue
                if rule["exclude"] and any(e in stripped.lower() for e in rule["exclude"]):
                    continue
                # single line, or a 3-line window for multiline rules
                window = "\n".join(x.strip() for x in lines[i:i + 3]) \
                    if rule["multiline"] else stripped
                m = rule["pattern"].search(window)
                if not m:
                    continue
                if rule["must"] and not any(k in window.lower() for k in rule["must"]):
                    continue
                ctx = "\n".join(lines[i:i + 3 if rule["multiline"] else 2])
                findings.append(_finding(rule, rel, i + 1, ctx))
                if rule["multiline"]:
                    last_end = i + 2
                hits[rule["id"]] = hits.get(rule["id"], 0) + 1
                if hits.get(rule["id"], 0) >= rule["per_rule"]:
                    break
    return findings


def _scan_files_rules(inv):
    findings = []
    for abs_p, rel, size in inv.files:
        base = os.path.basename(rel)
        for fr in FILE_RULES:
            if fr["match"](rel.lower(), base.lower()):
                findings.append({
                    "fingerprint": _fingerprint(fr["category"], rel, 0, fr["rid"]),
                    "category": fr["category"],
                    "severity": fr["severity"],
                    "title": fr["title"],
                    "endpoint": rel,
                    "method": "STATIC",
                    "evidence": f"Committed file: {rel} ({size} bytes)",
                    "impact": fr["impact"],
                    "request": {"mode": "static", "file": rel, "rule": fr["rid"]},
                    "response": {"status": "source",
                                 "body_snippet": "\n".join(inv.texts.get(rel, ["(binary file)"])[:3])[:400]},
                    "attack_path": [
                        {"step": 1, "title": "Repository inventory",
                         "detail": f"File found in the tree: {rel}"},
                        {"step": 2, "title": "Why it's dangerous",
                         "detail": fr["impact"]},
                        {"step": 3, "title": "Next step",
                         "detail": "Remove from git history and rotate the exposed credential."},
                    ],
                    "exploit_success": True,
                    "confidence": 0.9,
                })
                break
    return findings


def _scan_secrets(inv):
    findings = []
    count = 0
    for rel, lines in inv.texts.items():
        if rel.startswith((".github/", "tests/", "test/", "docs/", "README")):
            continue
        for i, raw in enumerate(lines):
            if count >= 12:
                return findings
            stripped = raw.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            m = SECRET_RE.search(stripped)
            if not m:
                continue
            low = stripped.lower()
            if any(x in low for x in SECRET_VALUE_EXCLUDES):
                continue
            rule = _R("secret-assign", "hardcoded_secret", "critical",
                      "Hardcoded secret in source code", "x")
            ctx = "\n".join(lines[i:i + 1])
            findings.append(_finding(rule, rel, i + 1, ctx))
            count += 1
    return findings


def _scan_workflows_and_docker(inv):
    findings = []
    for rel, lines in inv.texts.items():
        base = os.path.basename(rel)
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            joined = "\n".join(lines).lower()
            for rule in CI_RULES:
                must_ok = all(k in joined for k in rule["must"]) if rule["must"] else True
                for i, raw in enumerate(lines):
                    if rule["pattern"].search(raw.strip()) and must_ok:
                        findings.append(_finding(rule, rel, i + 1, raw.strip()))
                        break
        elif base.lower() == "dockerfile":
            findings.extend(_run_content_rules(
                _SingleFile(rel, lines), DOCKER_RULES, {"javascript"}))
            joined = "\n".join(lines).lower()
            has_user = re.search(r"^\s*user\s+\S+", joined, re.M)
            if not has_user:
                rule = _R("dk-root", "docker_risk", "medium",
                          "Container runs as root", "x")
                findings.append(_finding(rule, rel, 1, "(no USER directive found)"))
    return findings


class _SingleFile:
    """Adapter so one file can run through _run_content_rules."""
    def __init__(self, rel, lines):
        self.texts = {rel: lines}


# ========================================================= dependencies ====
def _collect_dependencies(inv):
    deps = []          # (ecosystem, name, version, source)
    unpinned = []      # (name, source)
    for rel, lines in inv.texts.items():
        base = os.path.basename(rel)
        if base == "requirements.txt":
            for raw in lines:
                s = raw.strip()
                if not s or s.startswith(("#", "-")):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.]*)$", s)
                if m:
                    deps.append(("PyPI", m.group(1), m.group(2), rel))
                else:
                    name = re.match(r"^([A-Za-z0-9_.\-]+)", s)
                    if name:
                        unpinned.append((name.group(1), rel))
        elif base == "package-lock.json":
            try:
                data = json.loads("\n".join(lines))
            except ValueError:
                continue
            for name, info in (data.get("dependencies") or {}).items():
                v = info.get("version")
                if v:
                    deps.append(("npm", name, v, rel))
            for path, info in (data.get("packages") or {}).items():
                name = path.rsplit("node_modules/", 1)[-1]
                v = info.get("version")
                if v and name and name not in ("", "."):
                    if not any(d[1] == name for d in deps):
                        deps.append(("npm", name, v, rel))
    return deps, unpinned


def _osv_severity(vuln):
    ds = (vuln.get("database_specific") or {}).get("severity", "")
    ds = ds.upper()
    if "CRIT" in ds:
        return "critical"
    if "HIGH" in ds:
        return "high"
    if "MODERATE" in ds or "MEDIUM" in ds:
        return "medium"
    if "LOW" in ds:
        return "low"
    for sev in vuln.get("severity") or []:
        score = sev.get("score") or ""
        m = re.search(r":(\d+\.\d+)$", score)
        if m:
            try:
                v = float(m.group(1))
                if v >= 9: return "critical"
                if v >= 7: return "high"
                if v >= 4: return "medium"
                return "low"
            except ValueError:
                continue
    return "medium"


def _suggest_fix(vuln):
    versions = set()
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    versions.add(ev["fixed"])
    if versions:
        return "Upgrade to a fixed release: " + ", ".join(sorted(versions))
    return "Upgrade this package to the latest version."


def audit_dependencies(inv, progress_cb=None):
    """Query OSV.dev for known CVEs in pinned dependencies (offline-safe)."""
    deps, unpinned = _collect_dependencies(inv)
    findings = []
    for name, src in unpinned[:5]:
        rule = _R("dep-unpinned", "unpinned_dependency", "low",
                  f"Dependency not pinned: {name}", "x", 0.6)
        findings.append(_finding(rule, src, 0,
                                 f"{name} declared without an exact version"))
    queries = 0
    for eco, name, version, src in deps:
        if queries >= MAX_DEP_QUERIES:
            break
        queries += 1
        if progress_cb:
            progress_cb(f"dependency audit: {name}")
        try:
            r = requests.post(OSV_API, json={
                "package": {"ecosystem": eco, "name": name},
                "version": version,
            }, timeout=OSV_TIMEOUT)
            if r.status_code != 200:
                continue
            vulns = (r.json() or {}).get("vulns") or []
        except requests.RequestException:
            continue  # offline — skip silently
        for vuln in vulns[:3]:
            vid = vuln.get("id", "unknown")
            sev = _osv_severity(vuln)
            summary = (vuln.get("summary") or vuln.get("details") or "")[:200]
            rule = _R(f"dep-{vid}", "dependency_cve", sev,
                      f"Vulnerable dependency: {name}@{version}", "x", 0.95)
            f = _finding(rule, src, 0,
                         f"{name}=={version} → {vid}",
                         extra_evidence=f"{summary}. Fix: {_suggest_fix(vuln)}")
            f["attack_path"][2]["detail"] = f"{summary} — {IMPACTS['dependency_cve']}"
            f["attack_path"][3]["detail"] = _suggest_fix(vuln)
            findings.append(f)
    return findings


# ============================================================= runtime =====
def try_runtime(repo_path):
    """EXPERIMENTAL: build & run the project in Docker, return attack base URL.

    Returns (base_url, error). Requires the Docker CLI. Never raises.
    """
    if shutil.which("docker") is None:
        return None, ("Docker CLI not detected on this machine — the runtime "
                      "sandbox requires Docker Desktop. Static analysis results "
                      "above are unaffected.")
    has_compose = any(os.path.basename(f[1]) in ("docker-compose.yml", "compose.yml",
                                                 "docker-compose.yaml")
                      for f in [(None, p) for p in os.listdir(repo_path)])
    has_dockerfile = os.path.exists(os.path.join(repo_path, "Dockerfile"))
    if not (has_compose or has_dockerfile):
        return None, ("Runtime sandbox skipped: the project has no Dockerfile or "
                      "compose file to build from.")
    try:
        if has_dockerfile and not has_compose:
            tag = f"sentinel-sandbox-{int(time.time())}"
            subprocess.run(["docker", "build", "-t", tag, repo_path],
                           capture_output=True, timeout=600)
            proc = subprocess.run(["docker", "run", "-d", "-P", "--rm", tag],
                                  capture_output=True, text=True, timeout=60)
            cid = proc.stdout.strip()
            ports = subprocess.run(["docker", "port", cid],
                                   capture_output=True, text=True, timeout=30)
            m = re.search(r"0\.0\.0\.0:(\d+)", ports.stdout)
            if m:
                return f"http://127.0.0.1:{m.group(1)}", None
            return None, "Runtime sandbox started but no published port was detected."
        return None, ("Runtime sandbox with docker-compose requires the compose "
                      "file to expose a HTTP port; skipped in this prototype.")
    except Exception as exc:
        return None, f"Runtime sandbox failed: {str(exc)[:200]}"


# ============================================================== orchestrator
def run_repo_scan(cfg, scan_id, progress_cb=None):
    """Main entry: returns (findings, meta) — finding dicts ready for pipeline."""
    def cb(stage=None, pct=None):
        if progress_cb:
            progress_cb(stage, pct)

    cb("preparing repository", 5)
    kind, root, display, _note = prepare_repo_target(cfg, scan_id)

    cb("inventorying files", 15)
    inv = Inventory(root)
    if not inv.files:
        raise ValueError("Repository/folder contains no scannable files.")

    cb(f"analyzing {len(inv.texts)} files ({', '.join(sorted(inv.languages)) or 'generic'})", 25)
    findings = []

    cb("language rule packs", 30)
    findings += _run_content_rules(inv, PY_RULES, inv.languages)
    findings += _run_content_rules(inv, JS_RULES, inv.languages)

    cb("secret scan", 45)
    findings += _scan_secrets(inv)

    cb("sensitive file scan", 55)
    findings += _scan_files_rules(inv)

    cb("CI/Docker audit", 62)
    findings += _scan_workflows_and_docker(inv)

    if cfg.get("repo_modules", {}).get("deps", True):
        cb("dependency CVE audit (OSV.dev)", 70)
        findings += audit_dependencies(inv, lambda s: cb(s, 72))

    # dedupe by fingerprint
    seen, uniq = set(), []
    for f in findings:
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            uniq.append(f)
    findings = uniq

    meta = {
        "kind": kind, "display": display, "files": len(inv.files),
        "text_files": len(inv.texts), "loc": inv.loc,
        "languages": sorted(inv.languages),
        "repo_path": root,
    }
    return findings, meta
