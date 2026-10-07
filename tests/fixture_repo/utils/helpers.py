"""Fixture helpers with INTENTIONAL flaws for Sentinel AI testing."""
import hashlib
import random
import subprocess

import requests


def hash_password(password):
    # VULN: weak hash for passwords
    return hashlib.md5(password.encode()).hexdigest()


def make_token(user):
    # VULN: predictable token from non-crypto RNG
    return random.randint(100000, 999999)


def ping_service(url):
    # VULN: TLS verification disabled
    return requests.get(url, verify=False)


def tail_log(path):
    # VULN: subprocess with shell=True
    out = subprocess.run(f"tail -n 20 {path}", shell=True, capture_output=True)
    return out.stdout
