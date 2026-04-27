"""
Semgrep runner — multi-language SAST.
Tries `--config=auto` first; falls back to language-specific bundled rules
if registry download fails (offline, sandboxed, etc.).
"""

import json
import asyncio
import logging
from pathlib import Path
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.semgrep")

SEV_MAP = {"ERROR": "high", "WARNING": "med", "INFO": "low"}

# Per-language fallback ruleset (used if --config=auto fails)
LANG_CONFIG = {
    ".py":  "p/python",
    ".js":  "p/javascript",
    ".jsx": "p/javascript",
    ".ts":  "p/typescript",
    ".tsx": "p/typescript",
    ".java": "p/java",
    ".php": "p/php",
    ".rb":  "p/ruby",
    ".go":  "p/golang",
}


def _category_from_check_id(check_id: str) -> str:
    cid = check_id.lower()
    if "sql" in cid or "sqli" in cid: return "Injection"
    if "xss" in cid: return "XSS"
    if "ssrf" in cid: return "SSRF"
    if "rce" in cid or "command-injection" in cid or "exec" in cid: return "Code execution"
    if "path-traversal" in cid or "lfi" in cid: return "Path traversal"
    if "secret" in cid or "hardcoded" in cid or "api-key" in cid: return "Secrets"
    if "crypto" in cid or "weak-hash" in cid or "md5" in cid or "sha1" in cid: return "Cryptography"
    if "deserialization" in cid or "pickle" in cid: return "Deserialization"
    if "auth" in cid or "jwt" in cid: return "Authentication"
    if "xxe" in cid: return "XXE"
    if "csrf" in cid: return "CSRF"
    return "Code quality"


async def _run_semgrep_with_config(file_path: Path, config: str) -> Optional[dict]:
    """Run semgrep once with a given --config. Returns parsed JSON dict or None."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep",
            f"--config={config}",
            "--json",
            "--quiet",
            "--timeout", "60",
            "--metrics=off",
            "--no-git-ignore",
            str(file_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        log.warning("semgrep[%s]: timeout after 120s", config)
        return None
    except FileNotFoundError:
        log.error("semgrep: binary not found — install: pip install semgrep")
        return None
    except Exception as e:
        log.exception("semgrep[%s]: launch failed: %s", config, e)
        return None

    # 0 = no findings, 1 = findings present, others = error
    if proc.returncode not in (0, 1):
        log.warning("semgrep[%s]: exit %d, stderr: %s",
                    config, proc.returncode, stderr.decode()[:300])
        return None

    try:
        return json.loads(stdout.decode() or "{}")
    except json.JSONDecodeError as e:
        log.warning("semgrep[%s]: bad JSON: %s", config, e)
        return None


async def run_semgrep(file_path: Path) -> Optional[List[Finding]]:
    """
    Run Semgrep against a single file.

    Strategy: skip `--config=auto` (it requires metrics enabled, which we don't want
    for a privacy-respecting local tool) and go straight to language-specific
    bundled rulesets. These ship inside Semgrep — no network, no telemetry.
    """
    ext = file_path.suffix.lower()
    config = LANG_CONFIG.get(ext)

    if not config:
        log.info("semgrep: no bundled config for %s, skipping", ext)
        return []  # not a failure — just no rules for this language

    data = await _run_semgrep_with_config(file_path, config)
    if data is None:
        return None

    findings: List[Finding] = []
    for r in data.get("results", []):
        check_id = r.get("check_id", "semgrep-rule")
        # Friendly short code
        if "." in check_id:
            short_code = check_id.split(".")[-1][:30].upper()
        else:
            short_code = check_id[:30].upper()
        msg = r.get("extra", {}).get("message") or r.get("message") or "Semgrep rule matched"
        msg = msg.strip().split("\n")[0][:200]
        sev_raw = r.get("extra", {}).get("severity", r.get("severity", "INFO"))
        sev = SEV_MAP.get(sev_raw.upper(), "low")
        line = r.get("start", {}).get("line")

        findings.append(Finding(
            sev=sev,
            cat=_category_from_check_id(check_id),
            finding=msg,
            code=f"SG-{short_code}",
            status="New",
            line=line,
            tool="semgrep",
        ))

    log.info("semgrep: %d finding(s) in %s (config=%s)", len(findings), file_path.name, config)
    return findings
