"""
sqlmap_runner.py — wraps sqlmap.
Runs in --batch mode (no prompts), parses log/output for findings.
"""

import asyncio
import logging
import tempfile
import os
import re
from pathlib import Path
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.url.sqlmap")

# Profile timeouts (seconds)
TIMEOUTS = {"quick": 90, "standard": 240, "deep": 600}

# Profile → (level, risk, technique)
LEVEL_RISK = {
    "quick":    ("1", "1", "B"),         # Boolean only
    "standard": ("2", "2", "BEUSTQ"[:5]),  # B,E,U,S,T (no time-based)
    "deep":     ("3", "3", "BEUSTQ"),     # all techniques
}


async def run_sqlmap(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    timeout_s = TIMEOUTS.get(profile, 240)
    level, risk, technique = LEVEL_RISK.get(profile, ("2", "2", "BEUST"))

    # Skip sqlmap if URL has no query string — only useful on parameterized URLs.
    # sqlmap can crawl, but that's expensive; let users explicitly pass URLs with params.
    if "?" not in url and "=" not in url:
        log.info("sqlmap: skipping URL without parameters")
        return []

    with tempfile.TemporaryDirectory(prefix="wg-sqlmap-") as tmpdir:
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--disable-coloring",
            "--level", level,
            "--risk", risk,
            "--technique", technique,
            "--timeout", "10",
            "--retries", "1",
            "--threads", "4",
            "--output-dir", tmpdir,
            "--smart",
            "--random-agent",
            "--flush-session",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            log.warning("sqlmap: timeout after %ss", timeout_s)
            try: proc.kill()
            except Exception: pass
            return []
        except FileNotFoundError:
            log.error("sqlmap: binary not found")
            return None
        except Exception as e:
            log.exception("sqlmap: launch failed: %s", e)
            return None

        return _parse_sqlmap_output(stdout.decode(errors="replace"))


# Regex patterns for sqlmap log lines
_PARAM_INJECTABLE = re.compile(r"parameter\s+'([^']+)'\s+is\s+(?:.*?\s+)?vulnerable", re.IGNORECASE)
_TECHNIQUE_LINE = re.compile(r"Type:\s+(.+)")
_BACKEND = re.compile(r"back-end DBMS:\s+(.+)", re.IGNORECASE)


def _parse_sqlmap_output(text: str) -> List[Finding]:
    findings: List[Finding] = []
    seen_params = set()
    backend = None

    for line in text.splitlines():
        line = line.strip()
        m = _BACKEND.search(line)
        if m and not backend:
            backend = m.group(1).strip()[:50]

        m = _PARAM_INJECTABLE.search(line)
        if m:
            param = m.group(1)
            if param in seen_params:
                continue
            seen_params.add(param)
            extra = f" — backend: {backend}" if backend else ""
            findings.append(Finding(
                sev="critical",
                cat="Injection",
                finding=f"SQL injection in parameter '{param}'.{extra}",
                code=f"SQL-{param.upper()[:18]}",
                status="New",
                tool="sqlmap",
            ))

    return findings
