from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .security_scanner import extract_urls


@dataclass
class ExtractedUrlText:
    """
    Represents text extracted from a file (best-effort), plus notes about
    what was/wasn't supported for the given file type.
    """

    text: str
    notes: list[str]


def _decode_bytes_best_effort(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def extract_text_from_upload(filename: str, content_type: str, raw: bytes) -> ExtractedUrlText:
    """
    Best-effort text extraction from common file types so we can pull out URLs.

    Supported:
    - plain text (anything decodable)
    - html/htm (BeautifulSoup if available; falls back to raw text)
    - pdf (pdfminer.six if available)
    - docx (python-docx if available)
    - png/jpg/jpeg (pytesseract + Pillow if available)

    Not supported by default:
    - legacy .doc (binary Word format)
    """
    name = (filename or "").lower()
    ct = (content_type or "").lower()
    notes: list[str] = []

    # --- HTML ---
    if name.endswith((".html", ".htm")) or ct in ("text/html", "application/xhtml+xml"):
        txt = _decode_bytes_best_effort(raw)
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(txt, "lxml")
            # Include link href/src attributes explicitly; they often contain URLs.
            attrs = []
            for tag in soup.find_all(True):
                for k in ("href", "src", "action"):
                    v = tag.get(k)
                    if isinstance(v, str) and v:
                        attrs.append(v)
            combined = "\n".join([soup.get_text("\n"), "\n".join(attrs)])
            return ExtractedUrlText(text=combined, notes=notes)
        except Exception:
            notes.append("HTML parser not available; scanned raw HTML text.")
            return ExtractedUrlText(text=txt, notes=notes)

    # --- PDF ---
    if name.endswith(".pdf") or ct == "application/pdf":
        try:
            from io import BytesIO

            from pdfminer.high_level import extract_text  # type: ignore

            text = extract_text(BytesIO(raw)) or ""
            return ExtractedUrlText(text=text, notes=notes)
        except Exception:
            notes.append("PDF text extraction not available (install pdfminer.six).")
            return ExtractedUrlText(text="", notes=notes)

    # --- DOCX ---
    if name.endswith(".docx") or ct in (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ):
        try:
            from io import BytesIO

            import docx  # type: ignore

            doc = docx.Document(BytesIO(raw))
            parts = []
            for p in doc.paragraphs:
                if p.text:
                    parts.append(p.text)
            return ExtractedUrlText(text="\n".join(parts), notes=notes)
        except Exception:
            notes.append("DOCX text extraction not available (install python-docx).")
            return ExtractedUrlText(text="", notes=notes)

    # --- Legacy DOC (not supported safely by default) ---
    if name.endswith(".doc") or ct in ("application/msword",):
        notes.append("Legacy .doc is not supported by default. Save as .docx or .pdf.")
        return ExtractedUrlText(text="", notes=notes)

    # --- Images via OCR ---
    if name.endswith((".png", ".jpg", ".jpeg", ".webp")) or ct in (
        "image/png",
        "image/jpeg",
        "image/webp",
    ):
        try:
            from io import BytesIO

            from PIL import Image  # type: ignore
            import pytesseract  # type: ignore

            img = Image.open(BytesIO(raw))
            text = pytesseract.image_to_string(img) or ""
            return ExtractedUrlText(text=text, notes=notes)
        except Exception:
            notes.append("Image OCR not available (install Pillow + pytesseract and Tesseract OCR).")
            return ExtractedUrlText(text="", notes=notes)

    # --- Default: treat as text if possible ---
    # This covers .txt, .csv, logs, and many other formats where URLs appear as ASCII.
    txt = _decode_bytes_best_effort(raw)
    if not txt.strip():
        notes.append("No readable text extracted from this file type.")
    return ExtractedUrlText(text=txt, notes=notes)


def extract_urls_from_upload(
    *,
    filename: str,
    content_type: str,
    raw: bytes,
    url_limit: int,
) -> dict[str, Any]:
    extracted = extract_text_from_upload(filename, content_type, raw)
    urls = extract_urls(extracted.text, limit=url_limit)
    return {"urls": urls, "notes": extracted.notes, "extracted_text_len": len(extracted.text or "")}

