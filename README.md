# WebGuard

> Open-source security analysis tool. Runs locally on your machine. Nothing leaves your laptop.

WebGuard is a self-hosted SAST scanner that wraps four industry-standard tools — **Semgrep**, **Bandit**, **Gitleaks**, and **detect-secrets** — behind a clean web UI.

Right now, the **File Upload Scanner** is functional. URL Scanner and Code Review (paste) panels exist in the UI but still use placeholder logic; they'll be wired to real backends in upcoming releases.

## What it scans

The File Upload Scanner accepts source files in these languages:

| Extension | Language |
|-----------|----------|
| `.py`     | Python (Semgrep + Bandit + Gitleaks + detect-secrets) |
| `.js`, `.jsx`, `.ts`, `.tsx` | JavaScript / TypeScript (Semgrep + Gitleaks + detect-secrets) |
| `.java`   | Java (Semgrep + Gitleaks + detect-secrets) |
| `.php`    | PHP (Semgrep + Gitleaks + detect-secrets) |
| `.rb`     | Ruby (Semgrep + Gitleaks + detect-secrets) |
| `.go`     | Go (Semgrep + Gitleaks + detect-secrets) |

**File size cap:** 10 MB.
**What gets detected:** SQLi, XSS, RCE, hardcoded secrets, weak crypto, insecure deserialization, path traversal, unsafe `eval`, exposed API keys, JWTs, AWS keys, GitHub tokens, and ~1,000 more rule-based patterns.

---

## Quick start (Docker — recommended)

Requires [Docker](https://docs.docker.com/get-docker/) only.

```bash
git clone https://github.com/saconyfx/webguard.git
cd webguard
docker compose up
```

Then open <http://localhost:8000> in your browser.

The first build takes ~3-5 minutes (downloads Python deps + Gitleaks binary + Semgrep ruleset). Subsequent runs start in seconds.

To stop:
```bash
docker compose down
```

---

## Quick start (Linux / macOS shortcut)

```bash
chmod +x run.sh
./run.sh
```

## Quick start (Windows shortcut)

```cmd
run.bat
```

---

## Project structure

```
webguard/
├── frontend/                  Static UI (HTML/CSS/JS, no framework)
│   ├── index.html
│   ├── scan.html
│   ├── url-scan.html
│   ├── file-upload.html       ← wired to real backend
│   ├── code-review.html
│   ├── styles.css
│   └── wg-shared.js
│
├── function/                  Backend (FastAPI)
│   ├── main.py                API entry point
│   ├── orchestrator.py        Runs all 4 scanners in parallel
│   ├── models.py              Pydantic schemas
│   ├── scanners/
│   │   ├── semgrep_runner.py
│   │   ├── bandit_runner.py
│   │   ├── gitleaks_runner.py
│   │   └── secrets_runner.py
│   └── requirements.txt
│
├── Dockerfile                 All-in-one image (Python + 4 scanners)
├── docker-compose.yml         One-command runner
├── run.sh / run.bat           Convenience wrappers
└── README.md
```

---

## API contract

```
POST /scan/file          Multipart upload, single file
GET  /health             Health check
GET  /                   Frontend
```

Response shape:
```json
{
  "source": "File scan · app.py",
  "findings": [
    {
      "sev": "high",
      "cat": "Injection",
      "finding": "SQL injection via string interpolation",
      "code": "SG-PYTHON.LANG.SECURITY.SQLI",
      "status": "New",
      "line": 12,
      "tool": "semgrep"
    }
  ],
  "tools_run": ["semgrep", "bandit", "detect-secrets", "gitleaks"],
  "tools_failed": [],
  "scan_seconds": 7.4
}
```

Severity values: `critical | high | med | low | info | clean`.

---

## Native (non-Docker) install

If you'd rather run without Docker:

```bash
# 1. Python deps
cd function
pip install -r requirements.txt

# 2. Gitleaks (Go binary — install once)
# macOS:   brew install gitleaks
# Debian:  apt install gitleaks
# Other:   download from https://github.com/gitleaks/gitleaks/releases

# 3. Run
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open <http://localhost:8000>.

---

## Security notes

WebGuard runs **static analysis** only. None of the four scanners *execute* uploaded code — they read it as text and pattern-match against rules.

That said:
- Run it locally on your own machine. It's not designed to be exposed to the public internet.
- The Docker container runs as an unprivileged user, with a read-only root filesystem and a tmpfs-backed scratch dir.
- Uploaded files are deleted immediately after each scan.

---

