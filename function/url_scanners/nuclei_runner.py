"""
nuclei_runner.py — wraps Nuclei scanner.
JSON-lines output → parsed and normalized.
"""

import json
import asyncio
import logging
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.url.nuclei")

# Profile timeouts (seconds)
TIMEOUTS = {"quick": 60, "standard": 240, "deep": 480}

# Nuclei severity → our scale
SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "med",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


async def run_nuclei(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    timeout_s = TIMEOUTS.get(profile, 240)
    severities, tags = _filters_for_profile(profile)

    cmd = [
        "nuclei",
        "-target", url,
        "-jsonl",                       # JSON-lines output to stdout
        "-silent",                      # only emit findings
        "-disable-update-check",
        "-no-color",
        "-rate-limit", "100",
        "-concurrency", "10",
        "-timeout", "10",
        "-severity", severities,
    ]
    if tags:
        cmd += ["-tags", tags]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        log.warning("nuclei: timeout after %ss", timeout_s)
        try: proc.kill()
        except Exception: pass
        return []
    except FileNotFoundError:
        log.error("nuclei: binary not found")
        return None
    except Exception as e:
        log.exception("nuclei: launch failed: %s", e)
        return None

    if proc.returncode not in (0, 1):
        log.warning("nuclei: exit %d, stderr: %s", proc.returncode, stderr.decode()[:300])

    findings: List[Finding] = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = ev.get("info", {})
        template_id = ev.get("template-id") or ev.get("templateID") or "nuclei"
        name = info.get("name", template_id)
        sev_raw = (info.get("severity") or "info").lower()
        sev = SEV_MAP.get(sev_raw, "info")
        matched = ev.get("matched-at") or ev.get("matched") or ""
        desc = info.get("description") or name
        msg = f"{name}: {desc[:160]}"
        if matched and matched != url:
            msg += f" (matched: {matched[:80]})"

        findings.append(Finding(
            sev=sev,
            cat=_category_for_template(template_id),
            finding=msg[:250],
            code=f"NU-{template_id[:24].upper()}",
            status="New",
            tool="nuclei",
        ))

    log.info("nuclei: %d finding(s) for %s", len(findings), url)
    return findings


def _filters_for_profile(profile: str):
    """Returns (severities, tags) for nuclei -severity / -tags."""
    if profile == "quick":
        return "critical,high", "cve,exposure,misconfig,default-login"
    if profile == "deep":
        return "critical,high,medium,low,info", ""
    # standard
    return "critical,high,medium", "cve,exposure,misconfig,default-login,vulnerability"


def _category_for_template(tid: str) -> str:
    t = (tid or "").lower()
    if "cve-" in t or t.startswith("cve") or "cves/" in t: return "Known CVE"
    if "exposure" in t or "exposed" in t: return "Exposure"
    if "misconfig" in t: return "Misconfiguration"
    if "default-login" in t or "default-cred" in t: return "Default credentials"
    if "tech" in t or "fingerprint" in t: return "Tech detection"
    return "Web vulnerability"
