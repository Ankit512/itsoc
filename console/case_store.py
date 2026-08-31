#!/usr/bin/env python3
"""Case attachment blobs.

Seam for a later database (Postgres BYTEA / object storage). Today the bytes
live under console/.soc/case-blobs/<caseId>/<attachmentId> — verbatim, never
executed, never rewritten. Metadata stays on the case record.

anomaly_detector.py is never imported.
"""

import hashlib
import re
from pathlib import Path

import soc  # SOC_DIR is monkeypatched in tests

MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff"
_GIF = b"GIF8"
_WEBP = b"WEBP"


def blobs_root():
    return Path(soc.SOC_DIR) / "case-blobs"


def safe_id(value):
    text = str(value or "")
    if not _ID_RE.match(text):
        raise ValueError("invalid attachment path")
    return text


def sniff(name, data):
    """Kind + download content-type from bytes and filename. Never trusts the client."""
    name = str(name or "").lower()
    head = data[:32] if data else b""
    if head.startswith(_PNG):
        return "image", "image/png"
    if head.startswith(_JPEG):
        return "image", "image/jpeg"
    if head.startswith(_GIF):
        return "image", "image/gif"
    if head[8:12] == _WEBP:
        return "image", "image/webp"
    if head[:1] in (b"{", b"[") or name.endswith(".json"):
        return "json", "application/json"
    if name.endswith((".html", ".htm")) or b"<html" in head.lower() or b"<!doctype html" in head.lower():
        return "html", "text/plain; charset=utf-8"   # never text/html — XSS
    if name.endswith((".txt", ".md", ".csv")) or (data or b"").isascii():
        return "note", "text/plain; charset=utf-8"
    return "other", "application/octet-stream"


def put(case_id, att_id, data):
    cid, aid = safe_id(case_id), safe_id(att_id)
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("attachment bytes are required")
    raw = bytes(data)
    if not raw:
        raise ValueError("an attachment file is empty")
    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise ValueError(f"file is larger than {MAX_ATTACHMENT_BYTES // (1024 * 1024)}MB")
    folder = blobs_root() / cid
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / aid
    path.write_bytes(raw)
    return {
        "stored": True,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def get(case_id, att_id):
    cid, aid = safe_id(case_id), safe_id(att_id)
    path = blobs_root() / cid / aid
    if not path.is_file():
        return None
    return path.read_bytes()
