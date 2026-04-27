"""
url_orchestrator.py — coordinates the URL scanner runners.
Runs them all in parallel, merges findings, returns ScanResponse.
"""

import time
import asyncio
import logging
from typing import List
from urllib.parse import urlparse

from models import Finding, ScanResponse
from url_scanners.httpx_check import run_httpx_check
from url_scanners.tls_check import run_tls_check
from url_scanners.cors_check import run_cors_check
from url_scanners.nikto_runner import run_nikto
from url_scanners.nuclei_runner import run_nuclei
from url_scanners.sqlmap_runner import run_sqlmap
from url_scanners.xsstrike_runner import run_xsstrike

log = logging.getLogger("webguard.url_orchestrator")

SEV_RANK = {"critical": 6, "high": 5, "med": 4, "low": 3, "info": 2, "clean": 1}


async def run_url_scan(url: str, profile: str = "standard") -> ScanResponse:
    start = time.monotonic()

    # Profile picks which scanners participate
    if profile == "quick":
        # Fast: passive header/TLS only
        tasks = [
            ("httpx", run_httpx_check(url, profile)),
            ("tls",   run_tls_check(url, profile)),
            ("cors",  run_cors_check(url, profile)),
        ]
    elif profile == "deep":
        # Everything
        tasks = [
            ("httpx",    run_httpx_check(url, profile)),
            ("tls",      run_tls_check(url, profile)),
            ("cors",     run_cors_check(url, profile)),
            ("nikto",    run_nikto(url, profile)),
            ("nuclei",   run_nuclei(url, profile)),
            ("sqlmap",   run_sqlmap(url, profile)),
            ("xsstrike", run_xsstrike(url, profile)),
        ]
    else:
        # Standard: passive + Nikto + Nuclei (skip aggressive payloads by default)
        tasks = [
            ("httpx",  run_httpx_check(url, profile)),
            ("tls",    run_tls_check(url, profile)),
            ("cors",   run_cors_check(url, profile)),
            ("nikto",  run_nikto(url, profile)),
            ("nuclei", run_nuclei(url, profile)),
        ]

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    all_findings: List[Finding] = []
    tools_run: List[str] = []
    tools_failed: List[str] = []

    for (name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            log.warning("URL scanner %s errored: %s", name, result)
            tools_failed.append(name)
            continue
        if result is None:
            tools_failed.append(name)
            continue
        tools_run.append(name)
        all_findings.extend(result)

    # Dedupe — same code + same first 40 chars of finding
    deduped = _dedupe(all_findings)

    if not deduped:
        deduped = [Finding(
            sev="clean", cat="General",
            finding="No security issues detected by any URL scanner.",
            code="—", status="Clean", tool="all",
        )]

    deduped.sort(key=lambda f: -SEV_RANK.get(f.sev, 0))

    parsed = urlparse(url)
    src = parsed.netloc + parsed.path[:60] if parsed.netloc else url[:80]
    return ScanResponse(
        source=f"URL scan · {src}",
        findings=deduped,
        tools_run=tools_run,
        tools_failed=tools_failed,
        scan_seconds=round(time.monotonic() - start, 2),
    )


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = {}
    for f in findings:
        key = (f.code, f.finding[:40].lower())
        if key not in seen:
            seen[key] = f
        else:
            if SEV_RANK.get(f.sev, 0) > SEV_RANK.get(seen[key].sev, 0):
                seen[key] = f
    return list(seen.values())
