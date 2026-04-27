"""
cors_check.py — active CORS misconfiguration probe.

Sends a request with `Origin: https://evil.example.com` and inspects the
Access-Control-Allow-Origin response header for unsafe configurations.
"""

import logging
from typing import List, Optional

import httpx

from models import Finding

log = logging.getLogger("webguard.url.cors")

PROBE_ORIGIN = "https://evil.example.com"


async def run_cors_check(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    findings: List[Finding] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            verify=False,
            headers={"User-Agent": "WebGuard-Scanner/0.1", "Origin": PROBE_ORIGIN},
        ) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        log.warning("cors: request failed: %s", e)
        return None
    except Exception:
        log.exception("cors: unexpected error")
        return None

    h = {k.lower(): v for k, v in resp.headers.items()}

    aco = h.get("access-control-allow-origin")
    acc = h.get("access-control-allow-credentials", "").lower()

    if aco == "*":
        # Wildcard — bad if also returns sensitive data
        if acc == "true":
            findings.append(Finding(
                sev="high", cat="CORS",
                finding="Access-Control-Allow-Origin: * combined with credentials=true (browsers reject this, but indicates misconfig).",
                code="COR-WILDCARD-CREDS", status="New", tool="cors",
            ))
        else:
            findings.append(Finding(
                sev="med", cat="CORS",
                finding="Access-Control-Allow-Origin: * — any origin can read responses.",
                code="COR-WILDCARD", status="New", tool="cors",
            ))
    elif aco and aco.lower() == PROBE_ORIGIN.lower():
        # Origin reflected — very dangerous if creds=true
        sev = "critical" if acc == "true" else "high"
        findings.append(Finding(
            sev=sev, cat="CORS",
            finding=f"Access-Control-Allow-Origin reflects arbitrary Origin header (probed with {PROBE_ORIGIN}). "
                    + ("Credentials allowed — full account takeover risk." if acc == "true"
                       else "Allows attacker-controlled origins to read public responses."),
            code="COR-REFLECT", status="New", tool="cors",
        ))
    elif aco and "null" == aco.lower():
        findings.append(Finding(
            sev="med", cat="CORS",
            finding="Access-Control-Allow-Origin: null — exploitable via sandboxed iframe.",
            code="COR-NULL", status="New", tool="cors",
        ))

    log.info("cors: %d finding(s) for %s", len(findings), url)
    return findings
