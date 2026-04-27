"""
detect-secrets runner — Yelp's entropy + plugin-based secret scanner.
Catches things Gitleaks may miss (high-entropy random strings, base64 blobs).
"""

import json
import asyncio
import logging
from pathlib import Path
from typing import List, Optional

from models import Finding

log = logging.getLogger("webguard.detect_secrets")

# detect-secrets plugin name → readable category & code
PLUGIN_LABELS = {
    "AWSKeyDetector": "AWS access key",
    "PrivateKeyDetector": "Private key",
    "JwtTokenDetector": "JWT token",
    "GitHubTokenDetector": "GitHub token",
    "SlackDetector": "Slack token",
    "StripeDetector": "Stripe key",
    "SquareOAuthDetector": "Square OAuth",
    "Base64HighEntropyString": "High-entropy base64 string",
    "HexHighEntropyString": "High-entropy hex string",
    "KeywordDetector": "Hardcoded credential",
    "BasicAuthDetector": "Basic auth credentials",
}


async def run_detect_secrets(file_path: Path) -> Optional[List[Finding]]:
    """Run detect-secrets scan against a single file."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "detect-secrets", "scan",
            "--all-files",
            str(file_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        log.warning("detect-secrets: timeout")
        return None
    except FileNotFoundError:
        log.error("detect-secrets: binary not found — install: pip install detect-secrets")
        return None
    except Exception as e:
        log.exception("detect-secrets: launch failed: %s", e)
        return None

    if proc.returncode != 0:
        log.warning("detect-secrets: exit %d, stderr: %s", proc.returncode, stderr.decode()[:200])

    try:
        data = json.loads(stdout.decode() or "{}")
    except json.JSONDecodeError as e:
        log.warning("detect-secrets: bad JSON: %s", e)
        return None

    findings: List[Finding] = []
    results = data.get("results", {})
    for filename, items in results.items():
        for item in items:
            plugin = item.get("type", "Unknown")
            label = PLUGIN_LABELS.get(plugin, plugin)
            line = item.get("line_number")
            findings.append(Finding(
                sev="high" if "Key" in plugin or "Token" in plugin or "Auth" in plugin else "med",
                cat="Secrets",
                finding=f"Possible {label} detected"[:200],
                code=f"DS-{plugin[:24]}",
                status="New",
                line=line,
                tool="detect-secrets",
            ))

    log.info("detect-secrets: %d secret(s) in %s", len(findings), file_path.name)
    return findings
