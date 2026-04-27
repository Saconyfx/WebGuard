"""
xsstrike_runner.py — wraps XSStrike (XSS scanner).
Parses its colorized stdout for vulnerable parameter reports.
"""

import re
import asyncio
import logging
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.url.xsstrike")

TIMEOUTS = {"quick": 60, "standard": 180, "deep": 360}


async def run_xsstrike(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    timeout_s = TIMEOUTS.get(profile, 180)

    # Only useful when there are parameters to test
    if "?" not in url and "=" not in url:
        log.info("xsstrike: skipping URL without parameters")
        return []

    cmd = [
        "xsstrike",
        "-u", url,
        "--skip",            # don't ask interactive questions
        "--blind",           # only run blind detection (faster, lower noise)
        "--timeout", "10",
    ]
    if profile == "deep":
        # In deep mode, also run the full crawl
        cmd = ["xsstrike", "-u", url, "--crawl", "--skip", "--timeout", "15"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        log.warning("xsstrike: timeout after %ss", timeout_s)
        try: proc.kill()
        except Exception: pass
        return []
    except FileNotFoundError:
        log.error("xsstrike: binary not found")
        return None
    except Exception as e:
        log.exception("xsstrike: launch failed: %s", e)
        return None

    return _parse_xsstrike_output(
        stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
    )


# XSStrike emits things like:
#   [+] Vulnerable to XSS at parameter 'q'
#   [!] Reflected XSS Found
#   [*] Confidence: 9
#   [+] Payload: <svg onload=alert(1)>
_VULN_PATTERN = re.compile(r"vulnerable\s+(?:to\s+)?xss\s+(?:at\s+)?parameter[:\s]+['\"]?(\w+)", re.IGNORECASE)
_REFLECTED = re.compile(r"reflected\s+xss\s+found", re.IGNORECASE)
_PAYLOAD = re.compile(r"payload:\s*(.+)", re.IGNORECASE)


def _parse_xsstrike_output(text: str) -> List[Finding]:
    findings: List[Finding] = []
    seen_params = set()
    last_payload = None
    reflected_seen = False

    # Strip ANSI color codes
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    clean = ansi.sub("", text)

    for line in clean.splitlines():
        line = line.strip()

        m = _PAYLOAD.search(line)
        if m:
            last_payload = m.group(1).strip()[:80]

        m = _VULN_PATTERN.search(line)
        if m:
            param = m.group(1)
            if param in seen_params:
                continue
            seen_params.add(param)
            extra = f" Payload: {last_payload}" if last_payload else ""
            findings.append(Finding(
                sev="high",
                cat="XSS",
                finding=f"XSS vulnerability in parameter '{param}'.{extra}",
                code=f"XSS-{param.upper()[:18]}",
                status="New",
                tool="xsstrike",
            ))
            continue

        if _REFLECTED.search(line) and not reflected_seen:
            reflected_seen = True
            findings.append(Finding(
                sev="high", cat="XSS",
                finding="Reflected XSS detected by XSStrike crawler.",
                code="XSS-REFLECTED",
                status="New",
                tool="xsstrike",
            ))

    return findings
