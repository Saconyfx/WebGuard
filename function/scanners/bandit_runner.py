"""
Bandit runner — Python-only static analyzer.
Skips non-Python files. Returns Bandit's findings mapped to our format.
"""

import json
import asyncio
import logging
from pathlib import Path
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.bandit")

# Bandit severity → our scale
SEV_MAP = {
    "HIGH": "high",
    "MEDIUM": "med",
    "LOW": "low",
}

# Bandit confidence levels also feed into our judgment
# (We use severity directly; confidence is logged but not surfaced.)


def _category_from_test_id(test_id: str) -> str:
    """Bandit test IDs → readable category."""
    # B1xx = misc, B2xx = misc, B3xx = blacklists, B5xx = crypto, B6xx = injection
    if test_id.startswith("B5"): return "Cryptography"
    if test_id.startswith("B6"): return "Injection"
    if test_id.startswith("B3"): return "Blacklist call"
    if test_id.startswith("B7"): return "XSS / Templates"
    return "Python security"


async def run_bandit(file_path: Path) -> Optional[List[Finding]]:
    """Run bandit on Python files only."""
    if file_path.suffix.lower() != ".py":
        log.info("bandit: skipping non-Python file %s", file_path.name)
        return []  # not a failure — just doesn't apply

    try:
        proc = await asyncio.create_subprocess_exec(
            "bandit",
            "-f", "json",
            "-q",
            str(file_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        log.warning("bandit: timeout")
        return None
    except FileNotFoundError:
        log.error("bandit: binary not found — install: pip install bandit")
        return None
    except Exception as e:
        log.exception("bandit: launch failed: %s", e)
        return None

    # bandit exits 1 when issues found, 0 when clean
    if proc.returncode not in (0, 1):
        log.warning("bandit: exit %d, stderr: %s", proc.returncode, stderr.decode()[:200])

    try:
        data = json.loads(stdout.decode() or "{}")
    except json.JSONDecodeError as e:
        log.warning("bandit: bad JSON: %s", e)
        return None

    findings: List[Finding] = []
    for r in data.get("results", []):
        test_id = r.get("test_id", "B000")
        msg = r.get("issue_text", "Bandit issue").strip().split("\n")[0][:200]
        sev_raw = r.get("issue_severity", "LOW").upper()
        sev = SEV_MAP.get(sev_raw, "low")
        line = r.get("line_number")

        findings.append(Finding(
            sev=sev,
            cat=_category_from_test_id(test_id),
            finding=msg,
            code=test_id,
            status="New",
            line=line,
            tool="bandit",
        ))

    log.info("bandit: %d finding(s) in %s", len(findings), file_path.name)
    return findings
