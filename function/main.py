"""
WebGuard — Scanner Backend
FastAPI app that runs Semgrep + Bandit + Gitleaks + detect-secrets (file/code scans)
and httpx + TLS + CORS + Nikto + Nuclei + sqlmap + XSStrike (URL scans).

Endpoints:
  GET  /              → serves the frontend
  GET  /health        → health check
  POST /scan/file     → upload a file, get findings back
  POST /scan/code     → paste a code snippet, get findings back
  POST /scan/url      → scan a live URL, get findings back
  POST /report/pdf    → convert a ScanResponse into a PDF download
"""

import io
import os
import uuid
import shutil
import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from orchestrator import run_all_scanners
from url_orchestrator import run_url_scan
from models import ScanResponse
from pdf_builder import build_pdf

# ────────────────────────────────────────────────────────────────
# CONFIG
# ────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_CODE_CHARS = 50_000           # ~1000 lines
TEMP_BASE = Path("/tmp/webguard")
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

# Map UI language label → file extension
LANGUAGE_MAP = {
    "auto": ".txt",   # placeholder; real ext picked by detection
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
}

# Patterns for auto-detection (when user picks "Auto")
import re
AUTO_DETECT_PATTERNS = [
    (".py", re.compile(r"^\s*(import |from |def |class |#!.*python)", re.MULTILINE)),
    (".php", re.compile(r"<\?php|<\?=")),
    (".rb", re.compile(r"^\s*(def\s+\w|require\s|class\s+\w.*\bend\b)", re.MULTILINE)),
    (".go", re.compile(r"^\s*(package\s+\w+|func\s+\w|import\s*\(|^var\s)", re.MULTILINE)),
    (".java", re.compile(r"^\s*(public\s+class|package\s+[\w.]+;|import\s+java\.)", re.MULTILINE)),
    (".ts", re.compile(r"\binterface\s+\w+|:\s*(string|number|boolean)\s*[=,)]|<\w+>")),
    (".js", re.compile(r"^\s*(const |let |var |function |import .* from)", re.MULTILINE)),
]


def detect_language(code: str) -> str:
    """Return a file extension. Defaults to .py if nothing matches."""
    for ext, pat in AUTO_DETECT_PATTERNS:
        if pat.search(code):
            return ext
    return ".py"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("webguard")


# ────────────────────────────────────────────────────────────────
# LIFESPAN — clean temp dir on startup
# ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    TEMP_BASE.mkdir(parents=True, exist_ok=True)
    log.info("WebGuard backend ready. Temp: %s, Frontend: %s", TEMP_BASE, FRONTEND_DIR)
    yield
    # Cleanup any leftover scan dirs on shutdown
    if TEMP_BASE.exists():
        for d in TEMP_BASE.iterdir():
            shutil.rmtree(d, ignore_errors=True)


# ────────────────────────────────────────────────────────────────
# APP
# ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WebGuard Scanner API",
    description="Local-first SAST scanner powered by Semgrep, Bandit, Gitleaks, detect-secrets",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Quick health check — used by Docker healthcheck."""
    return {"status": "ok", "version": "0.1.0"}


# ────────────────────────────────────────────────────────────────
# /scan/file — main scan endpoint
# ────────────────────────────────────────────────────────────────
@app.post("/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """
    Upload a source file, run all 4 scanners in parallel, return merged findings.
    """
    # ── Validate filename ───────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # ── Read file (with size cap) ───────────────────────
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(contents)/1024/1024:.2f} MB). Max is {MAX_FILE_SIZE//1024//1024} MB.",
        )
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    # ── Save to isolated temp dir ───────────────────────
    scan_id = uuid.uuid4().hex
    scan_dir = TEMP_BASE / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename).name  # strip any path traversal
    file_path = scan_dir / safe_name

    try:
        file_path.write_bytes(contents)
        log.info("Scan %s: saved %s (%d bytes)", scan_id, safe_name, len(contents))

        # ── Run all 4 scanners in parallel ──────────────
        result = await run_all_scanners(file_path, original_name=safe_name)

        log.info(
            "Scan %s: complete. Findings=%d (tools=%s)",
            scan_id, len(result.findings), ",".join(result.tools_run),
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Scan %s failed", scan_id)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        # ── Always clean up temp files ──────────────────
        shutil.rmtree(scan_dir, ignore_errors=True)


# ────────────────────────────────────────────────────────────────
# /scan/code — paste-in-text scanner
# ────────────────────────────────────────────────────────────────
class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze")
    language: str = Field(default="auto", description="UI language label")


@app.post("/scan/code", response_model=ScanResponse)
async def scan_code(req: CodeScanRequest):
    """
    Accept pasted source code, write it to a temp file with the right extension,
    run all 4 scanners, return findings.
    """
    code = (req.code or "").strip()

    # ── Validate ────────────────────────────────────────
    if not code:
        raise HTTPException(status_code=400, detail="Code snippet is empty.")
    if len(code) < 10:
        raise HTTPException(status_code=400, detail="Snippet is too short — provide at least a few meaningful lines.")
    if len(code) > MAX_CODE_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"Snippet too long ({len(code):,} chars). Max is {MAX_CODE_CHARS:,}.",
        )

    # ── Resolve language → file extension ───────────────
    lang_key = (req.language or "auto").strip().lower()
    if lang_key == "auto" or lang_key == "auto-detect":
        ext = detect_language(code)
        log.info("Code scan: auto-detected language as %s", ext)
    else:
        ext = LANGUAGE_MAP.get(lang_key, ".py")

    # ── Save to isolated temp dir ───────────────────────
    scan_id = uuid.uuid4().hex
    scan_dir = TEMP_BASE / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"snippet{ext}"
    file_path = scan_dir / file_name

    try:
        file_path.write_text(code, encoding="utf-8")
        log.info("Code scan %s: wrote snippet (%d chars, %s)", scan_id, len(code), ext)

        result = await run_all_scanners(file_path, original_name=file_name)

        # Override source label to make it clear this was a paste, not an upload
        result.source = f"Code review · pasted {ext.lstrip('.')} snippet"

        log.info(
            "Code scan %s: complete. Findings=%d (tools=%s)",
            scan_id, len(result.findings), ",".join(result.tools_run),
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Code scan %s failed", scan_id)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# ────────────────────────────────────────────────────────────────
# /scan/url — live URL vulnerability scanner
# ────────────────────────────────────────────────────────────────
class UrlScanRequest(BaseModel):
    url: str = Field(..., description="Target URL (http:// or https://)")
    profile: str = Field(default="standard", description="quick | standard | deep")
    authorized: bool = Field(default=False, description="User confirmed they have authorization to scan")


@app.post("/scan/url", response_model=ScanResponse)
async def scan_url(req: UrlScanRequest):
    """
    Active scan of a URL. Runs httpx/TLS/CORS + Nikto + Nuclei + (optional sqlmap, xsstrike).
    Requires the user to have explicitly confirmed they're authorized to scan the target.
    """
    url = (req.url or "").strip()
    profile = (req.profile or "standard").strip().lower()

    # ── Validate URL ─────────────────────────────────
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL too long.")

    # ── Validate profile ─────────────────────────────
    if profile not in ("quick", "standard", "deep"):
        profile = "standard"

    # ── Authorization check ──────────────────────────
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm authorization to scan the target before running URL scans.",
        )

    log.info("URL scan: target=%s profile=%s", url, profile)

    try:
        result = await run_url_scan(url, profile)
        log.info(
            "URL scan complete: %d findings (tools=%s, failed=%s, %.1fs)",
            len(result.findings), ",".join(result.tools_run),
            ",".join(result.tools_failed), result.scan_seconds,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.exception("URL scan failed")
        raise HTTPException(status_code=500, detail=f"URL scan failed: {str(e)}")



@app.post("/report/pdf")
async def report_pdf(scan: ScanResponse):
    """
    Accepts a ScanResponse JSON (the same one /scan/file or /scan/code returned)
    and streams back a PDF report.
    """
    try:
        pdf_bytes = build_pdf(scan)
    except Exception as e:
        log.exception("PDF build failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    # Build a filename from the source line
    src = (scan.source or "scan").split("·")[-1].strip()
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in src)[:60] or "scan"
    filename = f"webguard-{safe}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ────────────────────────────────────────────────────────────────
# STATIC FRONTEND (mounted last so /scan/* routes win)
# ────────────────────────────────────────────────────────────────
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    log.warning("Frontend dir not found: %s", FRONTEND_DIR)


# ────────────────────────────────────────────────────────────────
# Local dev entry point
# ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
