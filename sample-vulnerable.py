# sample-vulnerable.py
# Drop this file into the WebGuard scanner to verify everything works.
# It contains 5 intentional vulnerabilities — all 4 scanners should flag at least some.

import sqlite3
import hashlib
import pickle
import subprocess

# 1. Hardcoded API key (Gitleaks + detect-secrets)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_aBCdEFghIJKlmnOPQRstuvwxYZ0123456789"

# 2. SQL injection (Semgrep + Bandit)
def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()

# 3. Weak hash (Bandit)
def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()

# 4. Insecure deserialization (Bandit + Semgrep)
def load_session(blob):
    return pickle.loads(blob)

# 5. Command injection (Bandit + Semgrep)
def ping_host(host):
    subprocess.call(f"ping -c 1 {host}", shell=True)
