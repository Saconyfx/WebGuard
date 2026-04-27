"""
Gitleaks runner — secret scanner (any language).
Runs gitleaks in 'no-git' mode against a single file.
"""

import json
import asyncio
import logging
import tempfile
from pathlib import Path
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.gitleaks")


async def run_gitleaks(file_path: Path) -> Optional[List[Finding]]:
    """
    Gitleaks v8+ with --no-git scans a directory or file directly.
    Output mode: JSON to a temp file we then read.
    """
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp_report:
        report_path = tmp_report.name

    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect",
            "--source", str(file_path.parent),
            "--no-git",
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            "--exit-code", "0",  # don't fail the process even if leaks found
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        log.warning("gitleaks: timeout")
        Path(report_path).unlink(missing_ok=True)
        return None
    except FileNotFoundError:
        log.error("gitleaks: binary not found — install via 'apt install gitleaks' or download from github.com/gitleaks/gitleaks")
        Path(report_path).unlink(missing_ok=True)
        return None
    except Exception as e:
        log.exception("gitleaks: launch failed: %s", e)
        Path(report_path).unlink(missing_ok=True)
        return None

    findings: List[Finding] = []
    try:
        report_text = Path(report_path).read_text() or "[]"
        data = json.loads(report_text)
        for r in data:
            rule = r.get("RuleID", "secret")
            desc = r.get("Description", "Secret detected")
            line = r.get("StartLine")
            findings.append(Finding(
                sev="high",
                cat="Secrets",
                finding=f"{desc} ({rule})"[:200],
                code=f"GL-{rule.upper()[:24]}",
                status="New",
                line=line,
                tool="gitleaks",
            ))
    except json.JSONDecodeError as e:
        log.warning("gitleaks: bad JSON: %s", e)
        return None
    finally:
        Path(report_path).unlink(missing_ok=True)

    log.info("gitleaks: %d secret(s) in %s", len(findings), file_path.name)
    return findings
