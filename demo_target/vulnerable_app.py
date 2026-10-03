"""DELIBERATELY VULNERABLE demo target for Sentinel AI.

A standalone mini-API that intentionally contains real, classic
vulnerabilities so the Sentinel platform can demonstrate its full
detection pipeline against a live target. NEVER deploy this anywhere
internet-reachable.

Launch:  python demo_target/vulnerable_app.py   (port 5099)
or automatically via:  python app.py --with-demo
"""
import sqlite3

from flask import Flask, jsonify, request, Response

app = Flask(__name__)
DB = "sentinel_demo.db"

SEED = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT, password_hash TEXT
);
INSERT OR IGNORE INTO users VALUES (1,'alice','alice@demo.io','user','hash$alice123');
INSERT OR IGNORE INTO users VALUES (2,'bob','bob@demo.io','user','hash$bob123');
INSERT OR IGNORE INTO users VALUES (3,'carol','carol@demo.io','user','hash$carol123');
INSERT OR IGNORE INTO users VALUES (4,'dave','dave@demo.io','user','hash$dave123');
INSERT OR IGNORE INTO users VALUES (5,'erin','erin@demo.io','user','hash$erin123');
INSERT OR IGNORE INTO users VALUES (6,'admin','admin@demo.io','admin','hash$admin123');
"""


def db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


with db() as conn:
    conn.executescript(SEED)


@app.get("/api/users")
def users():
    q = request.args.get("q", "")
    conn = db()
    # VULN: SQL injection - string concatenation into SQL
    rows = conn.execute(
        f"SELECT id, name, email, role, password_hash FROM users WHERE name LIKE '%{q}%'"
    ).fetchall()
    return jsonify([dict(zip(("id", "name", "email", "role", "password_hash"), r))
                    for r in rows])


@app.get("/api/search")
def search():
    q = request.args.get("q", "")
    # VULN: reflected XSS - raw HTML interpolation
    return Response(
        f"<html><body><h2>Search results</h2><p>Showing results for: {q}</p>"
        f"<p>Nothing found.</p></body></html>",
        mimetype="text/html",
    )


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    # VULN: weak/default credentials + static predictable token
    if data.get("username") == "admin" and data.get("password") == "password123":
        return jsonify({"token": "demo-token-12345", "role": "admin"})
    return jsonify({"error": "invalid credentials"}), 401


@app.get("/api/admin/secret")
def admin_secret():
    # VULN: open endpoint - no authentication/authorization at all
    return jsonify({"secret": "internal-key-98765", "db_host": "10.0.0.5:5432",
                    "note": "admin configuration endpoint"})


@app.get("/api/profile")
def profile():
    conn = db()
    # VULN: data leakage - full row incl. password hash, no auth
    row = conn.execute("SELECT * FROM users WHERE id = 1").fetchone()
    return jsonify(dict(zip(("id", "name", "email", "role", "password_hash"), row)))


@app.get("/api/echo")
def echo():
    # VULN: improper validation - echoes any input of any type/size
    return jsonify({"you_sent": request.args.get("text", ""),
                    "raw_query": str(request.query_string)[:100]})


@app.get("/api/error")
def boom():
    # VULN: verbose errors - leaks stack trace to the client
    try:
        raise RuntimeError("intentional crash in order_processor.calculate_totals()")
    except Exception as e:
        import traceback
        return Response(traceback.format_exc(), mimetype="text/plain"), 500


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "demo-target", "version": "0.9.1"})


if __name__ == "__main__":
    print("Vulnerable demo target on http://127.0.0.1:5099 (DO NOT EXPOSE)")
    app.run(host="127.0.0.1", port=5099, threaded=True)
