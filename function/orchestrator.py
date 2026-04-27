"""
Orchestrator — runs Semgrep + Bandit + Gitleaks + detect-secrets in parallel,
merges + dedupes their findings, attaches code snippets, returns a single ScanResponse.
"""

import asyncio
import time
import logging
from pathlib import Path
from typing import List

from models import Finding, ScanResponse, CodeSnippet
from snippet import extract_snippet
from scanners.semgrep_runner import run_semgrep
from scanners.bandit_runner import run_bandit
from scanners.gitleaks_runner import run_gitleaks
from scanners.secrets_runner import run_detect_secrets

log = logging.getLogger("webguard.orchestrator")

# Severity rank for sorting (higher = worse)
SEV_RANK = {"critical": 6, "high": 5, "med": 4, "low": 3, "info": 2, "clean": 1}


async def run_all_scanners(file_path: Path, original_name: str) -> ScanResponse:
    """
    Run all 4 scanners concurrently against the same file.
    Bandit is Python-only — it's still called but skips non-Python files.
    """
    start = time.monotonic()

    tasks = [
        ("semgrep", run_semgrep(file_path)),
        ("bandit", run_bandit(file_path)),
        ("gitleaks", run_gitleaks(file_path)),
        ("detect-secrets", run_detect_secrets(file_path)),
    ]

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    all_findings: List[Finding] = []
    tools_run: List[str] = []
    tools_failed: List[str] = []

    for (name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            log.warning("Scanner %s errored: %s", name, result)
            tools_failed.append(name)
            continue
        if result is None:
            tools_failed.append(name)
            continue
        tools_run.append(name)
        all_findings.extend(result)

    # Dedupe (same line + similar text)
    deduped = _dedupe(all_findings)

    # Attach code snippets — pulls the full enclosing function for each finding
    _attach_snippets(deduped, file_path)

    # If nothing found, return a clean finding
    if not deduped:
        deduped = [
            Finding(
                sev="clean",
                cat="General",
                finding="No security issues detected by any scanner",
                code="—",
                status="Clean",
                tool="all",
            )
        ]

    # Sort: severity desc, then line number asc
    deduped.sort(key=lambda f: (-SEV_RANK.get(f.sev, 0), f.line or 0))

    return ScanResponse(
        source=f"File scan · {original_name}",
        findings=deduped,
        tools_run=tools_run,
        tools_failed=tools_failed,
        scan_seconds=round(time.monotonic() - start, 2),
    )


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """
    Two findings on the same line with overlapping descriptions usually mean
    multiple tools caught the same thing — keep the highest severity one.
    """
    seen = {}
    for f in findings:
        key = (f.line, f.finding[:40].lower().strip())
        if key not in seen:
            seen[key] = f
        else:
            if SEV_RANK.get(f.sev, 0) > SEV_RANK.get(seen[key].sev, 0):
                seen[key] = f
    return list(seen.values())


def _attach_snippets(findings: List[Finding], file_path: Path) -> None:
    """
    Cache snippets per (line) so we don't re-parse the file for every finding.
    Mutates findings in place.
    """
    cache = {}
    for f in findings:
        if not f.line:
            continue
        if f.line not in cache:
            snip = extract_snippet(file_path, f.line)
            cache[f.line] = CodeSnippet(**snip) if snip else None
        if cache[f.line]:
            f.code_snippet = cache[f.line]
