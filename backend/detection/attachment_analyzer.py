"""
Attachment Analyzer for PRAMAAN (#48).

Static analysis of email attachments — never executes code, only inspects
structure and metadata to detect malicious patterns.

Detections:
  1. Per-attachment SHA-256 hash
  2. MIME type detection (via python-magic if available, else mimetypes)
  3. VBA macro presence in .docm/.xlsm/.doc/.xls via olefile
  4. JavaScript/embedded files in PDFs via pypdf
  5. Double extension detection (invoice.pdf.exe)
  6. Embedded OLE file count (unusual = suspicious)
"""
import hashlib
import io
import mimetypes
import re
import zipfile
from typing import Any, Dict, List, Optional

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False


# ── Risk scoring weights ─────────────────────────────────────

RISK_POINTS = {
    "macro_enabled": 25,
    "pdf_javascript": 20,
    "double_extension": 30,
    "embedded_ole": 15,
    "executable_extension": 40,
    "suspicious_mime": 10,
}

EXECUTABLE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".jar", ".msi", ".hta", ".cpl",
}

# OLE-based (old binary format) — analyzed via olefile
MACRO_EXTS_OLE = {".doc", ".xls", ".ppt", ".dot"}

# ZIP-based (OOXML with macro support) — analyzed via zipfile
MACRO_EXTS_ZIP = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam"}

# Combined (for legacy callers)
MACRO_EXTS = MACRO_EXTS_OLE | MACRO_EXTS_ZIP

SUSPICIOUS_MIMES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msdos-program",
    "application/vnd.ms-office",
    "application/octet-stream",  # generic binary
}


# ── Per-attachment analysis ──────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_mime(filename: str, data: bytes) -> str:
    """Best-effort MIME detection."""
    try:
        import magic  # python-magic, optional
        return magic.from_buffer(data, mime=True)
    except Exception:
        pass
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def _has_double_extension(filename: str) -> bool:
    """
    Detect suspicious double extensions:
      invoice.pdf.exe  -> True
      report.xlsm      -> False
      archive.tar.gz   -> False (common legit combo)
    """
    if not filename:
        return False
    lower = filename.lower()
    parts = lower.split(".")

    # Need at least 3 parts: name.ext1.ext2
    if len(parts) < 3:
        return False

    # Common legit multi-dot patterns to whitelist
    legit_tails = {("tar", "gz"), ("tar", "bz2"), ("tar", "xz")}
    if (parts[-2], parts[-1]) in legit_tails:
        return False

    # First extension should be a "harmless-looking" one
    deceptive = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "csv", "zip"}
    dangerous = {"exe", "scr", "bat", "cmd", "vbs", "js", "jar", "ps1", "hta", "msi", "com", "pif"}

    if parts[-2] in deceptive and parts[-1] in dangerous:
        return True
    return False


def _detect_macros_ole(data: bytes) -> Dict[str, Any]:
    """
    Detect VBA macros in an OLE / Office file.
    Returns {"has_macros": bool, "streams": [...], "error": str|None}.
    """
    result = {"has_macros": False, "streams": [], "error": None}
    if not HAS_OLEFILE:
        result["error"] = "olefile not installed"
        return result

    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as e:
        result["error"] = f"not an OLE file: {type(e).__name__}"
        return result

    try:
        streams = ["/".join(s) for s in ole.listdir()]
        result["streams"] = streams

        # Standard VBA storage indicators
        vba_indicators = [
            "VBA",
            "Macros",
            "_VBA_PROJECT",
            "PROJECT",
            "dir",
        ]
        has_vba = any(
            any(ind in stream for ind in vba_indicators)
            for stream in streams
        )
        result["has_macros"] = has_vba

        # Look for auto-exec macro entry points in the VBA stream
        autoexec_names = (
            "AutoOpen", "AutoExec", "AutoClose", "Auto_Open",
            "Document_Open", "Workbook_Open", "DocumentBeforeClose",
        )
        try:
            vba_stream = ole.openstream("VBA/ThisDocument").read()
            vba_text = vba_stream.decode("latin-1", errors="ignore")
            found = [n for n in autoexec_names if n in vba_text]
            if found:
                result["has_macros"] = True
                result["autoexec_macros"] = found
        except Exception:
            pass
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return result


def _analyze_pdf(data: bytes) -> Dict[str, Any]:
    """
    Analyze a PDF for JavaScript, embedded files, and auto-actions.
    """
    result = {
        "has_javascript": False,
        "javascript_snippets": [],
        "embedded_files": 0,
        "embedded_file_names": [],
        "page_count": 0,
        "error": None,
    }
    if not HAS_PYPDF:
        result["error"] = "pypdf not installed"
        return result

    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        result["page_count"] = len(reader.pages)

        # Traverse objects looking for JavaScript and embedded files
        seen_js = set()
        for page in reader.pages:
            try:
                if "/Annots" in page:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        if "/A" in obj and "/JS" in obj["/A"]:
                            js = obj["/A"]["/JS"]
                            if isinstance(js, pypdf.generic.TextStringObject):
                                snippet = str(js)[:200]
                                if snippet not in seen_js:
                                    seen_js.add(snippet)
                                    result["javascript_snippets"].append(snippet)
                                    result["has_javascript"] = True
            except Exception:
                pass

        # Root-level JavaScript (OpenAction / Names / JavaScript)
        try:
            root = reader.trailer.get("/Root", {})
            if "/OpenAction" in root:
                oa = root["/OpenAction"]
                if hasattr(oa, "get") and "/JS" in oa:
                    snippet = str(oa["/JS"])[:200]
                    result["javascript_snippets"].append(snippet)
                    result["has_javascript"] = True
        except Exception:
            pass

        # Embedded files
        try:
            root = reader.trailer.get("/Root", {})
            names = root.get("/Names", {})
            embedded = names.get("/EmbeddedFiles", {})
            if embedded:
                result["embedded_files"] = 1  # at least one present
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def _count_embedded_ole(data: bytes) -> int:
    """Count embedded OLE files inside a ZIP (Office 2007+ files are ZIPs)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return sum(1 for n in z.namelist() if "oleObject" in n.lower())
    except Exception:
        return 0


# ── Main API ─────────────────────────────────────────────────

def _detect_macros_zip(data: bytes) -> Dict[str, Any]:
    """
    Detect VBA macros in OOXML files (.docm, .xlsm, .pptm).
    These are ZIP archives containing a 'vbaProject.bin' entry.
    """
    result = {
        "has_macros": False,
        "vba_parts": [],
        "embedded_ole_count": 0,
        "error": None,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            vba_parts = [n for n in names if "vbaProject.bin" in n or "vbaProject" in n]
            result["vba_parts"] = vba_parts
            result["has_macros"] = len(vba_parts) > 0
            result["embedded_ole_count"] = sum(
                1 for n in names if "oleObject" in n.lower() or "embeddings" in n.lower()
            )
    except zipfile.BadZipFile as e:
        result["error"] = f"not a ZIP: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def analyze_attachment(filename: str, data: bytes) -> Dict[str, Any]:
    """
    Analyze a single attachment. Returns a dict with detections and risk score.
    Never executes the attachment.
    """
    sha256 = _sha256(data)
    mime = _detect_mime(filename, data)
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    size = len(data)

    result: Dict[str, Any] = {
        "filename": filename,
        "sha256": sha256,
        "mime_type": mime,
        "extension": ext,
        "size_bytes": size,
        "is_macro_enabled": False,
        "has_javascript": False,
        "has_double_extension": False,
        "embedded_file_count": 0,
        "risk_score": 0,
        "risk_factors": [],
        "details": {},
    }

    # ── Double extension check (fast, filename-only) ──
    if _has_double_extension(filename):
        result["has_double_extension"] = True
        result["risk_score"] += RISK_POINTS["double_extension"]
        result["risk_factors"].append({
            "factor": "Double Extension",
            "points": RISK_POINTS["double_extension"],
            "detail": f"Suspicious double extension in '{filename}'",
        })

    # ── Executable extension ──
    if ext in EXECUTABLE_EXTS:
        result["risk_score"] += RISK_POINTS["executable_extension"]
        result["risk_factors"].append({
            "factor": "Executable Attachment",
            "points": RISK_POINTS["executable_extension"],
            "detail": f"Attachment has executable extension: {ext}",
        })

    # ── Suspicious MIME ──
    if mime in SUSPICIOUS_MIMES and ext not in {".txt", ".csv"}:
        result["risk_score"] += RISK_POINTS["suspicious_mime"]
        result["risk_factors"].append({
            "factor": "Suspicious MIME",
            "points": RISK_POINTS["suspicious_mime"],
            "detail": f"MIME type '{mime}' is often malicious",
        })

    # ── Macro analysis ──
    # Legacy binary formats (.doc, .xls, .ppt) -> OLE detection
    # OOXML macro formats (.docm, .xlsm, .pptm) -> ZIP detection
    macro_info: Dict[str, Any] = {}
    if ext in MACRO_EXTS_OLE:
        macro_info = _detect_macros_ole(data)
    elif ext in MACRO_EXTS_ZIP:
        macro_info = _detect_macros_zip(data)
    elif ext in {".docx", ".xlsx", ".pptx"}:
        # Non-macro OOXML — check for disguised macros
        macro_info = _detect_macros_zip(data)

    if macro_info:
        result["details"]["macro_analysis"] = macro_info
        if macro_info.get("has_macros"):
            result["is_macro_enabled"] = True
            result["risk_score"] += RISK_POINTS["macro_enabled"]
            result["risk_factors"].append({
                "factor": "Macro-Enabled Attachment",
                "points": RISK_POINTS["macro_enabled"],
                "detail": f"VBA macros detected in {filename}",
            })

        # Embedded OLE objects
        ole_count = macro_info.get("embedded_ole_count") or _count_embedded_ole(data)
        if ole_count > 0:
            result["embedded_file_count"] = ole_count
            result["risk_score"] += RISK_POINTS["embedded_ole"]
            result["risk_factors"].append({
                "factor": "Embedded OLE Objects",
                "points": RISK_POINTS["embedded_ole"],
                "detail": f"{ole_count} embedded OLE object(s) found",
            })

    # ── PDF analysis ──
    if mime == "application/pdf" or ext == ".pdf":
        pdf_info = _analyze_pdf(data)
        result["details"]["pdf_analysis"] = pdf_info
        if pdf_info.get("has_javascript"):
            result["has_javascript"] = True
            result["risk_score"] += RISK_POINTS["pdf_javascript"]
            result["risk_factors"].append({
                "factor": "PDF JavaScript",
                "points": RISK_POINTS["pdf_javascript"],
                "detail": "PDF contains JavaScript (potential exploit vector)",
            })
        result["embedded_file_count"] += pdf_info.get("embedded_files", 0)

    result["risk_score"] = min(100, result["risk_score"])
    return result


def analyze_attachments(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze a batch of attachments.
    Each item: {"filename": str, "data": bytes}
    Returns aggregated summary + per-file results.
    """
    results = [analyze_attachment(f["filename"], f["data"]) for f in files]
    total_risk = sum(r["risk_score"] for r in results)
    macro_count = sum(1 for r in results if r["is_macro_enabled"])
    js_count = sum(1 for r in results if r["has_javascript"])
    double_ext_count = sum(1 for r in results if r["has_double_extension"])

    return {
        "count": len(results),
        "total_risk": min(100, total_risk),
        "macro_enabled_count": macro_count,
        "javascript_count": js_count,
        "double_extension_count": double_ext_count,
        "attachments": results,
    }


__all__ = ["analyze_attachment", "analyze_attachments", "RISK_POINTS"]
