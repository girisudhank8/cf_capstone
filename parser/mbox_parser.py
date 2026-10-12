"""
BEC-FORGE MBOX Forensic Parser

Handles industry-standard MBOX mailbox format files (Google Workspace, Thunderbird,
EnCase/FTK exports). Iterates through messages and provides raw RFC-822 bytes for acquisition.
"""

import io
import mailbox
import re
import tempfile
from pathlib import Path
from typing import Generator, Tuple


def _sanitize_slug(text: str, max_len: int = 30) -> str:
    """Create a safe filename slug from email subject or identifier."""
    if not text:
        return "unnamed_email"
    s = re.sub(r"[^\w\-_]", "_", text).strip("_")
    return s[:max_len] if s else "email"


def parse_mbox_bytes(mbox_bytes: bytes) -> Generator[Tuple[str, bytes], None, None]:
    """
    Yields (synthetic_filename, raw_email_bytes) for every email inside an MBOX byte stream.
    Never alters original bytes.
    """
    with tempfile.NamedTemporaryFile(suffix=".mbox", delete=False) as tmp:
        tmp.write(mbox_bytes)
        tmp_path = Path(tmp.name)

    try:
        box = mailbox.mbox(str(tmp_path))
        for idx, msg in enumerate(box, start=1):
            raw = msg.as_bytes()
            subj = msg.get("subject", "no_subject")
            slug = _sanitize_slug(subj)
            msg_id = msg.get("message-id", "")
            id_slug = _sanitize_slug(msg_id, 12) if msg_id else f"{idx:04d}"
            filename = f"mbox_{idx:03d}_{slug}_{id_slug}.eml"
            yield filename, raw
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass


def parse_mbox_file(mbox_path: Path) -> Generator[Tuple[str, bytes], None, None]:
    """Yields (filename, raw_bytes) directly from an on-disk MBOX file."""
    box = mailbox.mbox(str(mbox_path))
    for idx, msg in enumerate(box, start=1):
        raw = msg.as_bytes()
        subj = msg.get("subject", "no_subject")
        slug = _sanitize_slug(subj)
        filename = f"mbox_{idx:03d}_{slug}.eml"
        yield filename, raw
