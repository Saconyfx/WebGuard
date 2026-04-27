"""
nikto_runner.py — wraps the Nikto perl scanner.
Outputs JSON, parses, normalizes severity.
"""

import json
import asyncio
import tempfile
import logging
import os
from typing import List, Optional
from pathlib import Path

from models import Finding

log = logging.getLogger("webguard.url.nikto")

# Profile timeouts (seconds)
TIMEOUTS = {"quick": 60, "standard": 180, "deep": 360}


async def run_nikto(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    timeout_s = TIMEOUTS.get(profile, 180)
    # Nikto -Format json -output <file>
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    cmd = [
        "nikto",
        "-h", url,
        "-Format", "json",
        "-output", report_path,
        "-ask", "no",
        "-nointeractive",
        "-maxtime", str(timeout_s - 10),
        "-Tuning", _tuning_for_profile(profile),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        log.warning("nikto: hard timeout (%ss)", timeout_s)
        try: proc.kill()
        except Exception: pass
        # Still try to read partial report below
    except FileNotFoundError:
        log.error("nikto: binary not found")
        Path(report_path).unlink(missing_ok=True)
        return None
    except Exception as e:
        log.exception("nikto: launch failed: %s", e)
        Path(report_path).unlink(missing_ok=True)
        return None

    findings: List[Finding] = []
    try:
        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            return []  # Nikto produced no findings

        text = Path(report_path).read_text(errors="replace") or ""
        # Nikto JSON is usually a single object with "vulnerabilities" array
        # Format varies between versions; handle both common shapes
        data = None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Some Nikto builds emit JSON-lines; try line-by-line
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try: data = json.loads(line); break
                    except: continue

        if not data:
            return []

        vulns = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities") or data.get("findings") or []
        elif isinstance(data, list):
            vulns = data

        for v in vulns:
            if not isinstance(v, dict):
                continue
            osvdb = v.get("OSVDB") or v.get("osvdb") or ""
            ref = v.get("id") or v.get("reference") or osvdb or "NIKTO"
            msg = (v.get("msg") or v.get("description") or "Nikto issue").strip()
            method = v.get("method", "GET")
            sev = _guess_severity(msg)
            findings.append(Finding(
                sev=sev, cat="Web server",
                finding=f"[{method}] {msg[:200]}",
                code=f"NIKTO-{str(ref)[:18]}",
                status="New",
                tool="nikto",
            ))
    finally:
        Path(report_path).unlink(missing_ok=True)

    log.info("nikto: %d finding(s) for %s", len(findings), url)
    return findings


def _tuning_for_profile(profile: str) -> str:
    """
    Nikto -Tuning controls which categories of checks to run.
    1 = Interesting File / Seen in logs
    2 = Misconfiguration / Default File
    3 = Information Disclosure
    4 = Injection (XSS/Script/HTML)
    5 = Remote File Retrieval - Inside Web Root
    6 = Denial of Service
    7 = Remote File Retrieval - Server Wide
    8 = Command Execution / Remote Shell
    9 = SQL Injection
    a = Authentication Bypass
    b = Software Identification
    c = Remote source inclusion
    """
    if profile == "quick":
        return "23b"      # misconfig + info disclosure + software ID
    if profile == "deep":
        return "123459abc"  # everything except DoS
    return "1234589ab"     # standard: skip DoS + remote file retrieval (safer)


def _guess_severity(msg: str) -> str:
    m = (msg or "").lower()
    if any(t in m for t in ("rce", "remote code", "command exec", "auth bypass", "default password", "default cred")):
        return "critical"
    if any(t in m for t in ("sql injection", "xss", "lfi", "rfi", "directory trav", "credential")):
        return "high"
    if any(t in m for t in ("disclos", "exposed", "outdated", "vulnerable")):
        return "med"
    if "missing" in m or "header" in m:
        return "low"
    return "info"
