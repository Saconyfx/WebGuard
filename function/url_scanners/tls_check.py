"""
tls_check.py — TLS/SSL configuration inspection.

Establishes a TLS handshake against the target host and inspects the
negotiated protocol, cipher, certificate, expiry, hostname match.
"""

import ssl
import socket
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from models import Finding

log = logging.getLogger("webguard.url.tls")

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


async def run_tls_check(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []  # not applicable for plain HTTP

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return None

    findings: List[Finding] = []

    def _do_handshake():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "cert": ssock.getpeercert(binary_form=False) or {},
                    "cert_bin": ssock.getpeercert(binary_form=True),
                }

    try:
        info = await asyncio.get_event_loop().run_in_executor(None, _do_handshake)
    except (socket.gaierror, socket.timeout, ssl.SSLError, OSError) as e:
        log.warning("tls: handshake failed for %s:%d: %s", host, port, e)
        return [Finding(
            sev="info", cat="TLS",
            finding=f"TLS handshake failed: {type(e).__name__} — {str(e)[:140]}",
            code="TLS-HANDSHAKE", status="Error", tool="tls",
        )]
    except Exception as e:
        log.exception("tls: unexpected error: %s", e)
        return None

    # ── Protocol version ──────────────────────────
    proto = info.get("protocol") or ""
    if proto in WEAK_PROTOCOLS:
        findings.append(Finding(
            sev="high", cat="TLS",
            finding=f"Weak/deprecated TLS protocol negotiated: {proto}",
            code="TLS-WEAK-PROTO", status="New", tool="tls",
        ))

    # ── Cipher strength ───────────────────────────
    cipher = info.get("cipher")
    if cipher:
        name, _, bits = cipher
        if isinstance(bits, int) and bits < 128:
            findings.append(Finding(
                sev="high", cat="TLS",
                finding=f"Weak cipher in use: {name} ({bits} bits)",
                code="TLS-WEAK-CIPHER", status="New", tool="tls",
            ))
        for weak in ("RC4", "DES", "MD5", "EXPORT", "NULL"):
            if weak in (name or ""):
                findings.append(Finding(
                    sev="high", cat="TLS",
                    finding=f"Insecure cipher suite contains '{weak}': {name}",
                    code=f"TLS-CIPHER-{weak}", status="New", tool="tls",
                ))
                break

    # ── Certificate ───────────────────────────────
    cert = info.get("cert", {}) or {}
    if cert:
        # Expiry
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(Finding(
                        sev="critical", cat="TLS",
                        finding=f"Certificate expired {abs(days_left)} day(s) ago.",
                        code="TLS-CERT-EXPIRED", status="New", tool="tls",
                    ))
                elif days_left < 14:
                    findings.append(Finding(
                        sev="med", cat="TLS",
                        finding=f"Certificate expires in {days_left} day(s) — renew soon.",
                        code="TLS-CERT-EXPIRING", status="New", tool="tls",
                    ))
            except ValueError:
                pass

        # Hostname match (re-enable verification just for this check)
        try:
            ssl.match_hostname(cert, host)
        except (ssl.CertificateError, KeyError):
            findings.append(Finding(
                sev="high", cat="TLS",
                finding=f"Certificate not valid for hostname '{host}'.",
                code="TLS-CERT-NAME", status="New", tool="tls",
            ))

    log.info("tls: %d finding(s) for %s", len(findings), url)
    return findings
