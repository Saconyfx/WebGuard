"""
httpx_check.py — passive security header inspection.

Sends a single GET request to the URL, then reads the response headers
to flag missing security headers, exposed banners, info disclosures.
Also flags missing/weak cookie flags from Set-Cookie.
"""

import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse

import httpx

from models import Finding

log = logging.getLogger("webguard.url.httpx")

# Headers we expect on a hardened modern web app
EXPECTED_HEADERS = {
    "content-security-policy": ("HDR-CSP-MISSING", "high",
        "Missing Content-Security-Policy — exposes the page to XSS and content injection."),
    "strict-transport-security": ("HDR-HSTS-MISSING", "high",
        "Missing Strict-Transport-Security — TLS downgrade attacks possible."),
    "x-frame-options": ("HDR-XFO-MISSING", "med",
        "Missing X-Frame-Options — clickjacking risk (CSP frame-ancestors may also fix this)."),
    "x-content-type-options": ("HDR-XCT-MISSING", "low",
        "Missing X-Content-Type-Options — MIME sniffing not prevented."),
    "referrer-policy": ("HDR-REF-MISSING", "low",
        "Missing Referrer-Policy — referrer info may leak across origins."),
    "permissions-policy": ("HDR-PERM-MISSING", "low",
        "Missing Permissions-Policy — browser features not restricted."),
}

# Headers that leak information when present
LEAKY_HEADERS = {
    "server": "Server banner discloses server software/version",
    "x-powered-by": "X-Powered-By header reveals tech stack",
    "x-aspnet-version": "X-AspNet-Version exposes ASP.NET version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version exposes ASP.NET MVC version",
    "x-generator": "X-Generator reveals CMS/framework",
    "x-drupal-cache": "X-Drupal-Cache exposes Drupal usage",
}


async def run_httpx_check(url: str, profile: str = "standard") -> Optional[List[Finding]]:
    """Fetch URL once, inspect headers + cookies."""
    findings: List[Finding] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=20.0,
            verify=False,  # don't choke on self-signed certs (TLS check has its own)
            headers={"User-Agent": "WebGuard-Scanner/0.1"},
        ) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        log.warning("httpx: request failed for %s: %s", url, e)
        return [Finding(
            sev="info", cat="Connectivity",
            finding=f"Could not reach the target: {type(e).__name__} — {str(e)[:140]}",
            code="NET-001", status="Error", tool="httpx",
        )]
    except Exception as e:
        log.exception("httpx: unexpected error: %s", e)
        return None

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}

    # ── Missing security headers ─────────────────────
    if url.lower().startswith("https://"):
        # HSTS only relevant on https
        for h, (code, sev, msg) in EXPECTED_HEADERS.items():
            if h not in headers_lc:
                findings.append(Finding(
                    sev=sev, cat="Headers",
                    finding=msg, code=code, status="New", tool="httpx",
                ))
    else:
        # Non-HTTPS site → headers matter less, but flag the bigger issue
        findings.append(Finding(
            sev="high", cat="Transport",
            finding="Site served over plain HTTP — credentials and cookies travel unencrypted.",
            code="NET-HTTP-PLAIN", status="New", tool="httpx",
        ))

    # ── Information disclosure ───────────────────────
    for h, msg in LEAKY_HEADERS.items():
        if h in headers_lc:
            value = str(headers_lc[h])[:80]
            findings.append(Finding(
                sev="info", cat="Info leak",
                finding=f"{msg}: {value}",
                code=f"INF-{h.upper().replace('-', '_')[:18]}",
                status="New", tool="httpx",
            ))

    # ── Cookie inspection ────────────────────────────
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        # Fallback for httpx versions without get_list
        sc = resp.headers.get("set-cookie")
        if sc: set_cookies = [sc]

    for raw in set_cookies:
        cookie_findings = _check_cookie(raw, is_https=url.lower().startswith("https://"))
        findings.extend(cookie_findings)

    # ── Redirect chain to HTTP ───────────────────────
    if resp.history:
        for r in resp.history:
            if r.url.scheme == "http" and url.lower().startswith("https"):
                findings.append(Finding(
                    sev="med", cat="Transport",
                    finding=f"HTTPS request redirected through HTTP step: {str(r.url)[:120]}",
                    code="NET-REDIR-DOWNGRADE", status="New", tool="httpx",
                ))
                break

    log.info("httpx: %d finding(s) for %s", len(findings), url)
    return findings


def _check_cookie(raw_cookie: str, is_https: bool) -> List[Finding]:
    """Parse a single Set-Cookie header and flag weak attributes."""
    out: List[Finding] = []
    parts = [p.strip() for p in raw_cookie.split(";")]
    if not parts:
        return out
    name_val = parts[0].split("=", 1)
    name = name_val[0] if name_val else "cookie"
    attrs = {p.lower().split("=", 1)[0]: p for p in parts[1:]}

    # Likely session cookies = lowercase contains 'session', 'sid', 'auth', 'token'
    name_lc = name.lower()
    looks_like_session = any(k in name_lc for k in ("session", "sid", "auth", "token", "jwt"))

    if "secure" not in attrs and is_https:
        out.append(Finding(
            sev="med" if looks_like_session else "low",
            cat="Cookies",
            finding=f"Cookie '{name}' missing Secure flag.",
            code="CKE-NO-SECURE", status="New", tool="httpx",
        ))
    if "httponly" not in attrs:
        out.append(Finding(
            sev="med" if looks_like_session else "low",
            cat="Cookies",
            finding=f"Cookie '{name}' missing HttpOnly — readable by JavaScript.",
            code="CKE-NO-HTTPONLY", status="New", tool="httpx",
        ))
    if "samesite" not in attrs:
        out.append(Finding(
            sev="low", cat="Cookies",
            finding=f"Cookie '{name}' missing SameSite — CSRF risk.",
            code="CKE-NO-SAMESITE", status="New", tool="httpx",
        ))
    return out
