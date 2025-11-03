from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(
    title="Rule 111 — OPEN DATASET without MODE/ENCODING",
    version="1.0"
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    # results field will be added dynamically
    rule111_findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def line_of_offset(text: str, off: int) -> int:
    """Return 1-based line number for a 0-based offset."""
    return text.count("\n", 0, off) + 1


def snippet_at(text: str, start: int, end: int) -> str:
    """Return a short snippet around the match (escaped newlines)."""
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")


# ---------------------------------------------------------------------------
# Rule detection logic
# ---------------------------------------------------------------------------
STMT_RE      = re.compile(r"(?is)\bOPEN\s+DATASET\b[^.]*\.", re.DOTALL)
MODE_RE      = re.compile(r"(?i)\bIN\s+(TEXT|BINARY)\s+MODE\b")
TEXT_MODE_RE = re.compile(r"(?i)\bIN\s+TEXT\s+MODE\b")
ENCODING_RE  = re.compile(r"(?i)\bENCODING\b\s+\S+")


def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in STMT_RE.finditer(src):
        stmt = m.group(0)
        start = m.start()
        end = m.end()

        has_mode     = MODE_RE.search(stmt) is not None
        is_text_mode = TEXT_MODE_RE.search(stmt) is not None
        has_encoding = ENCODING_RE.search(stmt) is not None

        # 1️⃣ Missing MODE addition
        if not has_mode:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "OpenDatasetNoMode",
                "severity": "warning",
                "line": line_of_offset(src, start),
                "message": "OPEN DATASET without MODE or ENCODING.",
                "suggestion": "Specify IN TEXT MODE ENCODING UTF-8 or IN BINARY MODE. OPEN DATASET without MODE or ENCODING.",
                "snippet": snippet_at(src, start, end),
            })
            continue

        # 2️⃣ Text mode without encoding (always enforce)
        if is_text_mode and not has_encoding:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "OpenDatasetTextNoEncoding",
                "severity": "info",
                "line": line_of_offset(src, start),
                "message": "OPEN DATASET in TEXT MODE without explicit ENCODING.",
                "suggestion": "Add ENCODING UTF-8 (or the required codepage). OPEN DATASET without MODE or ENCODING.",
                "snippet": snippet_at(src, start, end),
            })

    obj = unit.model_dump()
    obj["rule111_findings"] = findings
    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array")
async def scan_rule111(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.get("rule111_findings"):
            results.append(res)
    return results


@app.get("/health")
async def health():
    return {"ok": True, "rule": 111}
