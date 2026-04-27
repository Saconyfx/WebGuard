"""
Snippet extractor — given a source file and a line number,
return the full function containing that line.

Strategy per language:
  - Python: AST-based (most accurate)
  - JS / TS / Java / PHP / Ruby / Go: brace/keyword-based heuristic
  - Fallback: ±10 lines around the target line
"""

import ast
import logging
from pathlib import Path
from typing import Dict, Optional, List

log = logging.getLogger("webguard.snippet")

# Map extension → highlight.js / PrismJS language id
LANG_MAP = {
    ".py":  "python",
    ".js":  "javascript",
    ".jsx": "jsx",
    ".ts":  "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".php": "php",
    ".rb":  "ruby",
    ".go":  "go",
}

# Fallback context size (lines before + after)
FALLBACK_CONTEXT = 10


def language_for(file_path: Path) -> str:
    return LANG_MAP.get(file_path.suffix.lower(), "plaintext")


# ────────────────────────────────────────────────────────────────
# PUBLIC API
# ────────────────────────────────────────────────────────────────
def extract_snippet(file_path: Path, line_number: Optional[int]) -> Optional[Dict]:
    """
    Return a dict shaped like:
        {
          "language": "python",
          "start_line": 12,
          "end_line": 28,
          "vulnerable_line": 17,
          "lines": [...]   # raw source lines, no numbering
        }
    Or None if line_number is missing / file unreadable.
    """
    if not line_number:
        return None
    try:
        text = file_path.read_text(errors="replace")
    except Exception as e:
        log.warning("snippet: cannot read %s: %s", file_path, e)
        return None

    lines = text.splitlines()
    if not lines:
        return None
    if line_number < 1 or line_number > len(lines):
        return None

    ext = file_path.suffix.lower()
    span = None

    if ext == ".py":
        span = _python_function_span(text, line_number)
    elif ext in (".js", ".jsx", ".ts", ".tsx"):
        span = _brace_span(lines, line_number, opening_keywords=("function ", "=> {", " function(", "function*"))
    elif ext == ".java":
        span = _brace_span(lines, line_number, opening_keywords=("public ", "private ", "protected ", "static "))
    elif ext == ".php":
        span = _brace_span(lines, line_number, opening_keywords=("function ",))
    elif ext == ".go":
        span = _brace_span(lines, line_number, opening_keywords=("func ",))
    elif ext == ".rb":
        span = _ruby_span(lines, line_number)

    if span is None:
        # Fallback: ±N lines
        start = max(1, line_number - FALLBACK_CONTEXT)
        end = min(len(lines), line_number + FALLBACK_CONTEXT)
        span = (start, end)

    start, end = span
    snippet_lines = lines[start - 1 : end]

    return {
        "language": language_for(file_path),
        "start_line": start,
        "end_line": end,
        "vulnerable_line": line_number,
        "lines": snippet_lines,
    }


# ────────────────────────────────────────────────────────────────
# PYTHON — proper AST walk
# ────────────────────────────────────────────────────────────────
def _python_function_span(source: str, line: int) -> Optional[tuple]:
    """Find the smallest Python function/class/method enclosing `line`."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    best = None  # (start, end, span_size)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start and end and start <= line <= end:
                size = end - start
                if best is None or size < best[2]:
                    best = (start, end, size)

    if best is None:
        return None
    return (best[0], best[1])


# ────────────────────────────────────────────────────────────────
# Brace languages — JS/TS/Java/PHP/Go
# ────────────────────────────────────────────────────────────────
def _brace_span(lines: List[str], line: int, opening_keywords: tuple) -> Optional[tuple]:
    """
    Walk backwards from `line` to find the line that opens the enclosing
    function (matched by keyword + `{`), then walk forward counting braces
    until we close it.
    """
    # Step 1: find a line at or before `line` that contains a function-opening keyword
    func_start = None
    for i in range(line - 1, -1, -1):
        ln = lines[i]
        if any(kw in ln for kw in opening_keywords) and "{" in _strip_strings_and_comments(ln):
            func_start = i + 1  # 1-indexed
            break

    if func_start is None:
        return None

    # Step 2: count braces forward from func_start until balanced
    depth = 0
    started = False
    end_line = None
    for i in range(func_start - 1, len(lines)):
        cleaned = _strip_strings_and_comments(lines[i])
        for ch in cleaned:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    end_line = i + 1
                    break
        if end_line is not None:
            break

    if end_line is None:
        return None
    return (func_start, end_line)


def _strip_strings_and_comments(s: str) -> str:
    """Crude strip of string literals and // comments so braces inside don't fool us."""
    out = []
    i = 0
    in_string = None  # ', ", or `
    while i < len(s):
        ch = s[i]
        if in_string:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_string = ch
            i += 1
            continue
        # Single-line comments
        if ch == "/" and i + 1 < len(s) and s[i + 1] == "/":
            break
        if ch == "#":  # PHP / shell-style
            break
        out.append(ch)
        i += 1
    return "".join(out)


# ────────────────────────────────────────────────────────────────
# Ruby — uses `def ... end`
# ────────────────────────────────────────────────────────────────
def _ruby_span(lines: List[str], line: int) -> Optional[tuple]:
    """Find enclosing Ruby def...end block."""
    func_start = None
    for i in range(line - 1, -1, -1):
        stripped = lines[i].lstrip()
        if stripped.startswith("def ") or stripped.startswith("def\t"):
            func_start = i + 1
            break
    if func_start is None:
        return None

    # Count def vs end keywords
    depth = 0
    end_line = None
    block_keywords = ("def ", "class ", "module ", "if ", "unless ", "while ", "until ", "begin ", "case ", "do")
    for i in range(func_start - 1, len(lines)):
        s = lines[i].strip()
        for kw in block_keywords:
            if s.startswith(kw):
                depth += 1
                break
        if s == "end" or s.startswith("end "):
            depth -= 1
            if depth == 0:
                end_line = i + 1
                break

    if end_line is None:
        return None
    return (func_start, end_line)
