"""Fixture app with INTENTIONAL security flaws (for testing Sentinel AI's
static repo scanner). Never run this code for real."""
import os
import pickle
import sqlite3

import yaml
from flask import Flask, request

app = Flask(__name__)


def get_user(username):
    conn = sqlite3.connect("users.db")
    # VULN: SQL injection - f-string query
    rows = conn.execute(
        f"SELECT * FROM users WHERE name = '{username}'"
    ).fetchall()
    return rows


def find_active(query):
    conn = sqlite3.connect("users.db")
    # VULN: SQL injection - concatenated query
    return conn.execute("SELECT * FROM users WHERE status = '" + query + "'").fetchall()


def run_custom(expr):
    # VULN: eval of user-controlled input
    return eval(expr)


def import_backup(blob):
    # VULN: unsafe deserialization
    return pickle.loads(blob)


def load_config(text):
    # VULN: yaml.load without SafeLoader
    return yaml.load(text)


@app.route("/exec", methods=["POST"])
def exec_cmd():
    cmd = request.json["cmd"]
    # VULN: command injection
    os.system("echo " + cmd)
    return {"ok": True}


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    # VULN: debug mode in production path
    app.run(host="0.0.0.0", port=8080, debug=True)
