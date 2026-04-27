"""
Pydantic schemas — defines what comes back from the scan API.
Matches the {sev, cat, finding, code, status} contract the frontend already expects.
"""

from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "med", "low", "info", "clean"]


class CodeSnippet(BaseModel):
    """Snippet of source code surrounding the vulnerable line."""
    language: str = Field(..., description="Highlighter language id (python, javascript, etc.)")
    start_line: int = Field(..., description="First line of the snippet (1-indexed)")
    end_line: int = Field(..., description="Last line of the snippet (1-indexed, inclusive)")
    vulnerable_line: int = Field(..., description="The line number that triggered the finding")
    lines: List[str] = Field(default_factory=list, description="Raw source lines, no numbering")


class Finding(BaseModel):
    """One vulnerability finding from any of the 4 scanners."""
    sev: Severity = Field(..., description="Normalized severity")
    cat: str = Field(..., description="Category, e.g. 'Injection', 'Secrets'")
    finding: str = Field(..., description="Human-readable description")
    code: str = Field(..., description="Rule/check ID, e.g. 'B301', 'sqli-injection'")
    status: str = Field(default="New", description="Status — usually 'New'")
    line: Optional[int] = Field(default=None, description="Line number in the file")
    tool: Optional[str] = Field(default=None, description="Which scanner found it")
    code_snippet: Optional[CodeSnippet] = Field(default=None, description="Full function (or context) containing the line")


class ScanResponse(BaseModel):
    """Response from POST /scan/file"""
    source: str = Field(..., description="e.g. 'File scan · app.py'")
    findings: List[Finding] = Field(default_factory=list)
    tools_run: List[str] = Field(default_factory=list, description="Tools that ran successfully")
    tools_failed: List[str] = Field(default_factory=list, description="Tools that errored out")
    scan_seconds: float = Field(default=0.0)
