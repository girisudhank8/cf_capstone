"""
BEC-FORGE Email Parser

Parses .eml files using Python's built-in email library.
Returns a structured ParsedEmail dataclass.
Never modifies original evidence.
"""

import email
import email.policy
import logging
import re
import quopri
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import utils as email_utils
from email.message import Message
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────

@dataclass
class AttachmentInfo:
    filename: str
    extension: str
    mime_type: str
    file_size: int
    sha256: str
    content: bytes = field(repr=False, default=b"")


@dataclass
class ParsedEmail:
    # Raw
    raw_bytes: bytes = field(repr=False)

    # Identifiers
    message_id: Optional[str] = None

    # From / sender
    from_raw: Optional[str] = None
    from_name: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None

    # Recipients
    to_raw: Optional[str] = None
    to_addresses: list[str] = field(default_factory=list)
    cc_raw: Optional[str] = None
    cc_addresses: list[str] = field(default_factory=list)

    # Core headers
    subject: Optional[str] = None
    date_raw: Optional[str] = None
    date_parsed: Optional[datetime] = None

    # Threading / Conversation Tracking
    in_reply_to: Optional[str] = None
    references: list[str] = field(default_factory=list)

    # Routing
    reply_to: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_address: Optional[str] = None
    return_path_domain: Optional[str] = None

    # Client / routing
    user_agent: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None

    # Auth headers (raw strings — analysed separately)
    received_spf: Optional[str] = None
    authentication_results: Optional[str] = None
    dkim_signature: Optional[str] = None
    arc_authentication_results: Optional[str] = None

    # Received chain
    received_headers: list[str] = field(default_factory=list)

    # Body
    body_plain: Optional[str] = None
    body_html: Optional[str] = None

    # Attachments
    attachments: list[AttachmentInfo] = field(default_factory=list)

    # All headers (name, value, position)
    all_headers: list[tuple[str, str]] = field(default_factory=list)

    # Parse metadata
    parse_errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _decode_header_value(value: Optional[str]) -> str:
    """Decode RFC-2047 encoded header values."""
    if not value:
        return ""
    try:
        parts = email.header.decode_header(value)
        decoded = []
        for part, enc in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded).strip()
    except Exception:
        return str(value).strip()


def _extract_address(raw: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a raw From/Reply-To etc.

    Handles edge cases like 'Name, Title <email@domain.com>' where parseaddr
    fails because of the comma in the display name.
    """
    if not raw:
        return "", ""

    # Primary attempt
    name, addr = email_utils.parseaddr(raw)
    name = _decode_header_value(name)

    # Fallback: if addr has no @, try getaddresses which handles comma-in-name
    if "@" not in addr:
        pairs = email_utils.getaddresses([raw])
        if pairs:
            # Take the pair with a valid email address
            for n, a in pairs:
                if "@" in a:
                    name = _decode_header_value(n) or name
                    addr = a
                    break
        # Last resort: extract via regex
        if "@" not in addr:
            import re
            m = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", raw)
            if m:
                addr = m.group(0)
                # Try to extract display name as everything before <
                angle_m = re.match(r"^(.*?)\s*<", raw)
                if angle_m:
                    name = angle_m.group(1).strip().strip('"')

    return name.strip(), addr.strip().lower()


def _domain_from_address(addr: str) -> str:
    """Extract domain from an email address."""
    if addr and "@" in addr:
        return addr.split("@", 1)[1].lower()
    return ""


def _extract_all_addresses(raw: str) -> list[str]:
    """Parse comma-separated list of addresses."""
    if not raw:
        return []
    pairs = email_utils.getaddresses([raw])
    return [addr.lower() for _, addr in pairs if addr]


def _decode_payload(part: Message) -> bytes:
    """Safely decode a message part payload."""
    try:
        payload = part.get_payload(decode=True)
        return payload if isinstance(payload, bytes) else b""
    except Exception:
        return b""


# ─────────────────────────────────────────────────────────────
# Main parser
# ─────────────────────────────────────────────────────────────

def parse_eml(raw_bytes: bytes) -> ParsedEmail:
    """
    Parse raw .eml bytes into a ParsedEmail object.
    The raw_bytes are stored but NEVER modified.
    """
    result = ParsedEmail(raw_bytes=raw_bytes)

    try:
        msg: Message = email.message_from_bytes(
            raw_bytes,
            policy=email.policy.compat32,
        )
    except Exception as exc:
        result.parse_errors.append(f"Failed to parse email: {exc}")
        return result

    # ── Collect all headers ──────────────────────────────────
    for idx, (name, value) in enumerate(msg.items()):
        result.all_headers.append((name, _decode_header_value(value)))

    def _hdr(name: str) -> Optional[str]:
        raw_val = msg.get(name)
        return _decode_header_value(raw_val) if raw_val else None

    # ── Core identifiers ──────────────────────────────────────
    result.message_id = _hdr("Message-ID")

    # ── From ─────────────────────────────────────────────────
    result.from_raw = _hdr("From")
    result.from_name, result.from_address = _extract_address(result.from_raw or "")
    result.from_domain = _domain_from_address(result.from_address or "")

    # ── Recipients ───────────────────────────────────────────
    result.to_raw = _hdr("To")
    result.to_addresses = _extract_all_addresses(result.to_raw or "")
    result.cc_raw = _hdr("Cc")
    result.cc_addresses = _extract_all_addresses(result.cc_raw or "")

    # ── Subject ──────────────────────────────────────────────
    result.subject = _hdr("Subject")

    # ── Threading headers ────────────────────────────────────
    result.in_reply_to = _hdr("In-Reply-To")
    refs_raw = _hdr("References")
    if refs_raw:
        # References header contains whitespace/bracket-separated Message-IDs
        result.references = re.findall(r"<[^>]+>", refs_raw) or [refs_raw.strip()]

    # ── Date ─────────────────────────────────────────────────
    result.date_raw = _hdr("Date")
    if result.date_raw:
        try:
            parsed_tuple = email_utils.parsedate_tz(result.date_raw)
            if parsed_tuple:
                ts = email_utils.mktime_tz(parsed_tuple)
                result.date_parsed = datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception as e:
            result.parse_errors.append(f"Date parse error: {e}")

    # ── Reply-To ──────────────────────────────────────────────
    result.reply_to = _hdr("Reply-To")
    _, result.reply_to_address = _extract_address(result.reply_to or "")
    result.reply_to_domain = _domain_from_address(result.reply_to_address or "")

    # ── Return-Path ───────────────────────────────────────────
    result.return_path = _hdr("Return-Path")
    # Return-Path is often wrapped in <>
    rp_raw = result.return_path or ""
    rp_clean = re.sub(r"[<>]", "", rp_raw).strip()
    _, result.return_path_address = _extract_address(rp_clean)
    result.return_path_domain = _domain_from_address(result.return_path_address or "")

    # ── Client headers ────────────────────────────────────────
    result.user_agent = _hdr("User-Agent")
    result.x_mailer = _hdr("X-Mailer")
    result.x_originating_ip = _hdr("X-Originating-IP")

    # ── Auth headers ──────────────────────────────────────────
    result.received_spf = _hdr("Received-SPF")
    result.authentication_results = _hdr("Authentication-Results")
    result.dkim_signature = _hdr("DKIM-Signature")
    result.arc_authentication_results = _hdr("ARC-Authentication-Results")

    # ── Received chain ────────────────────────────────────────
    result.received_headers = [
        _decode_header_value(v) for v in msg.get_all("Received") or []
    ]

    # ── Body + attachments ────────────────────────────────────
    _extract_body_and_attachments(msg, result)

    return result


def _extract_body_and_attachments(msg: Message, result: ParsedEmail) -> None:
    """Walk the MIME tree to extract body parts and attachments."""
    import hashlib

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = part.get("Content-Disposition", "")
        filename = part.get_filename()

        # Attachments
        if "attachment" in disposition or (filename and content_type not in ("text/plain", "text/html")):
            payload = _decode_payload(part)
            if not payload:
                continue
            fname = filename or "unknown"
            ext = Path(fname).suffix.lower()
            info = AttachmentInfo(
                filename=fname,
                extension=ext,
                mime_type=content_type,
                file_size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                content=payload,
            )
            result.attachments.append(info)
            continue

        # Text body
        if content_type == "text/plain" and result.body_plain is None:
            payload = _decode_payload(part)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    result.body_plain = payload.decode(charset, errors="replace")
                except Exception:
                    result.body_plain = payload.decode("utf-8", errors="replace")

        elif content_type == "text/html" and result.body_html is None:
            payload = _decode_payload(part)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    result.body_html = payload.decode(charset, errors="replace")
                except Exception:
                    result.body_html = payload.decode("utf-8", errors="replace")
