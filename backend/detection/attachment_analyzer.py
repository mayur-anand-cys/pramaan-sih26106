"""
Static analysis of email attachments for malware indicators.

Never executes macros or opens files — all analysis is byte-level parsing.

Detection rules:
  1. Macro-enabled file extensions (.docm, .xlsm, .pptm, .dotm, .xltm)
     containing OLE VBA storage streams
     -> HIGH (25 points)
  2. Double extension in filename (e.g. invoice.pdf.exe)
     -> HIGH (20 points)
  3. PDF containing JavaScript, /OpenAction, /AA, or /Launch actions
     -> HIGH (20 points)
  4. Attachment with embedded OLE streams beyond the required minimum
     -> MEDIUM (10 points)
"""
import hashlib
import os
import re
from typing import Dict, Any, List, Optional

try:
    import olefile  # type: ignore
    _HAS_OLEFILE = True
except ImportError:
    olefile = None  # type: ignore
    _HAS_OLEFILE = False

try:
    import pypdf  # type: ignore
    _HAS_PYPDF = True
except ImportError:
    pypdf = None  # type: ignore
    _HAS_PYPDF = False


# ── Scoring ──────────────────────────────────────────────────

SCORE_MACRO_ENABLED = 25        # HIGH
SCORE_DOUBLE_EXTENSION = 20     # HIGH
SCORE_PDF_JAVASCRIPT = 20       # HIGH
SCORE_EMBEDDED_FILES = 10       # MEDIUM

MAX_RISK_MODIFIER = 40          # Cap total contribution (matches other detectors)


# ── Constants ────────────────────────────────────────────────

MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam",
    ".pptm", ".potm", ".ppam", ".sldm",
}

# Extension that masquerades as a benign document but is an executable
DANGEROUS_EXECUTABLE_EXTS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "ps1", "jar", "msi", "hta", "cpl",
}

BENIGN_DOCUMENT_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "jpg", "jpeg", "png", "gif", "zip", "rar", "7z",
}

DOUBLE_EXT_RE = re.compile(
    r"\.(" + "|".join(sorted(BENIGN_DOCUMENT_EXTS)) + r")"
    r"\.(" + "|".join(sorted(DANGEROUS_EXECUTABLE_EXTS)) + r")$",
    re.IGNORECASE,
)

# OLE streams that indicate VBA macros
VBA_STREAM_MARKERS = ("VBA", "_VBA_PROJECT", "Macros", "PROJECT", "PROJECTwm")

# PDF dictionary keys/operators that indicate active content
PDF_ACTIVE_MARKERS = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile")


# ── Helpers ──────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def _guess_mime(filename: str, data: bytes = b"") -> str:
    """Best-effort MIME type without external deps."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext == ".docm":
        return "application/vnd.ms-word.document.macroEnabled.12"
    if ext == ".dotm":
        return "application/vnd.ms-word.template.macroEnabled.12"
    if ext == ".xlsm":
        return "application/vnd.ms-excel.sheet.macroEnabled.12"
    if ext == ".xltm":
        return "application/vnd.ms-excel.template.macroEnabled.12"
    if ext == ".pptm":
        return "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
    if ext == ".pdf":
        return "application/pdf"
    if ext in (".doc", ".xls", ".ppt"):
        return "application/vnd.ms-office"
    if ext in (".docx", ".xlsx", ".pptx"):
        return "application/vnd.openxmlformats-officedocument"
    if ext in (".zip", ".rar", ".7z"):
        return "application/zip"
    if ext in (".txt",):
        return "text/plain"
    # Fallback: detect by magic bytes
    if data[:4] == b"%PDF":
        return "application/pdf"
    if data[:4] == b"PK\x03\x04":
        return "application/zip"  # OOXML files are ZIPs
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/vnd.ms-office"  # OLE compound file
    return "application/octet-stream"


def _has_double_extension(filename: str) -> Optional[str]:
    """Return the matched double extension, or None."""
    m = DOUBLE_EXT_RE.search(filename or "")
    return m.group(0) if m else None


def _ole_streams(data: bytes) -> List[str]:
    """Return the list of stream names in an OLE compound file."""
    if not _HAS_OLEFILE or not data:
        return []
    try:
        with olefile.OleFileIO(data) as ole:
            return ["/".join(s) for s in ole.listdir()]
    except Exception:
        return []


def _has_vba_macros_ole(data: bytes) -> bool:
    """Detect VBA macro storage in an OLE file (static, no execution)."""
    streams = _ole_streams(data)
    if not streams:
        return False
    joined = "|".join(streams).lower()
    return any(marker.lower() in joined for marker in VBA_STREAM_MARKERS)


def _has_vba_macros_zip(data: bytes) -> bool:
    """Detect VBA in OOXML (.docm is a ZIP containing vbaProject.bin)."""
    if not data:
        return False
    return b"vbaProject.bin" in data


def _has_vba_macros(data: bytes) -> bool:
    """Try both OLE and OOXML detection paths."""
    return _has_vba_macros_ole(data) or _has_vba_macros_zip(data)


def _count_embedded_files(data: bytes) -> int:
    """
    Count embedded objects/streams beyond the bare minimum.
    For an OLE file, count objects in the 'ObjectPool' or 'Root Entry' subtree.
    For a PDF, count /EmbeddedFile objects.
    """
    if not data:
        return 0
    # PDF path
    if data[:4] == b"%PDF":
        return data.count(b"/EmbeddedFile")
    # OLE path — count "ObjectPool" streams
    if _HAS_OLEFILE and data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        streams = _ole_streams(data)
        return sum(1 for s in streams if s.lower().startswith("objectpool"))
    return 0


def _pdf_has_javascript(data: bytes) -> bool:
    """Static check for active content markers in a PDF."""
    if not data or data[:4] != b"%PDF":
        return False
    lower = data.lower()
    return any(marker.lower() in lower for marker in PDF_ACTIVE_MARKERS)


# ── Public API ───────────────────────────────────────────────

def analyze_attachment(filename: str, data: bytes) -> Dict[str, Any]:
    """
    Statically analyze one attachment. Never executes or opens the file
    via the OS — all inspection is done on the in-memory bytes.

    Returns a dict with: filename, sha256, size_bytes, mime_type,
    has_macros, embedded_file_count, double_extension, pdf_javascript,
    risk_factors, risk_modifier.
    """
    filename = filename or "unnamed"
    data = data or b""
    ext = os.path.splitext(filename)[1].lower()

    mime = _guess_mime(filename, data)

    has_macros = False
    if ext in MACRO_EXTENSIONS or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        has_macros = _has_vba_macros(data)

    embedded = _count_embedded_files(data)
    double_ext = _has_double_extension(filename)
    pdf_js = _pdf_has_javascript(data)

    factors: List[Dict[str, Any]] = []
    risk = 0

    if has_macros:
        factors.append({
            "type": "Macro-Enabled Attachment",
            "severity": "HIGH",
            "points": SCORE_MACRO_ENABLED,
            "explanation": f"Attachment '{filename}' contains VBA macros.",
        })
        risk += SCORE_MACRO_ENABLED

    if double_ext:
        factors.append({
            "type": "Double Extension",
            "severity": "HIGH",
            "points": SCORE_DOUBLE_EXTENSION,
            "explanation": f"Filename '{filename}' uses double extension '{double_ext}'.",
        })
        risk += SCORE_DOUBLE_EXTENSION

    if pdf_js:
        factors.append({
            "type": "PDF Active Content",
            "severity": "HIGH",
            "points": SCORE_PDF_JAVASCRIPT,
            "explanation": f"PDF '{filename}' contains JavaScript or auto-action operators.",
        })
        risk += SCORE_PDF_JAVASCRIPT

    if embedded > 0:
        factors.append({
            "type": "Embedded Files",
            "severity": "MEDIUM",
            "points": SCORE_EMBEDDED_FILES,
            "explanation": f"Attachment '{filename}' embeds {embedded} additional object(s).",
        })
        risk += SCORE_EMBEDDED_FILES

    return {
        "filename": filename,
        "sha256": _sha256(data),
        "size_bytes": len(data),
        "mime_type": mime,
        "has_macros": has_macros,
        "embedded_file_count": embedded,
        "double_extension": double_ext,
        "pdf_javascript": pdf_js,
        "risk_factors": factors,
        "risk_modifier": min(risk, MAX_RISK_MODIFIER),
    }


def analyze_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze a list of attachments (each: {"filename": str, "data": bytes}).

    Returns:
        {
            "attachments": [ ...per-attachment reports... ],
            "attachment_count": int,
            "total_risk_modifier": int (capped at MAX_RISK_MODIFIER),
            "flagged_count": int,
        }
    """
    reports: List[Dict[str, Any]] = []
    total_risk = 0

    for att in attachments or []:
        name = att.get("filename") or att.get("name") or "unnamed"
        data = att.get("data") or att.get("content") or b""
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        report = analyze_attachment(name, data)
        reports.append(report)
        total_risk += report["risk_modifier"]

    return {
        "attachments": reports,
        "attachment_count": len(reports),
        "total_risk_modifier": min(total_risk, MAX_RISK_MODIFIER),
        "flagged_count": sum(1 for r in reports if r["risk_modifier"] > 0),
    }


__all__ = ["analyze_attachment", "analyze_attachments"]
