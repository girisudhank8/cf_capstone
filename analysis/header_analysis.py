"""
BEC-FORGE Header Analysis Module

Analyses parsed email headers for forensic indicators:
- Reply-To / Return-Path mismatch
- Display name spoofing
- Received chain anomalies
- IP/hostname extraction
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parser.eml_parser import ParsedEmail

logger = logging.getLogger(__name__)

# IP regex
_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
# Hostname + by patterns in Received headers
_RECEIVED_FROM_RE = re.compile(r"from\s+([\w.\-\[\]]+)", re.IGNORECASE)
_RECEIVED_BY_RE   = re.compile(r"by\s+([\w.\-\[\]]+)", re.IGNORECASE)


@dataclass
class HeaderFinding:
    category: str
    severity: str           # INFO | LOW | MEDIUM | HIGH | CRITICAL
    title: str
    description: str
    evidence_field: str
    evidence_value: str


@dataclass
class HeaderAnalysisResult:
    reply_to_mismatch: bool = False
    reply_to_domain_differs: bool = False
    return_path_mismatch: bool = False
    display_name_spoofing: bool = False
    display_name_org_mismatch: bool = False

    reply_to_score: float = 0.0     # 0–100
    return_path_score: float = 0.0  # 0–100
    display_name_score: float = 0.0 # 0–100

    received_ips: list[str] = field(default_factory=list)
    received_hops: list[dict] = field(default_factory=list)

    findings: list[HeaderFinding] = field(default_factory=list)


def _finding(category, severity, title, description, field_, value) -> HeaderFinding:
    return HeaderFinding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence_field=field_,
        evidence_value=str(value)[:500],
    )


# ─────────────────────────────────────────────────────────────
# Main analyser
# ─────────────────────────────────────────────────────────────

def analyse_headers(email: ParsedEmail) -> HeaderAnalysisResult:
    result = HeaderAnalysisResult()

    _check_reply_to(email, result)
    _check_return_path(email, result)
    _check_display_name(email, result)
    _parse_received_chain(email, result)

    return result


# ─────────────────────────────────────────────────────────────
# Reply-To analysis
# ─────────────────────────────────────────────────────────────

def _check_reply_to(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    from_addr   = email.from_address or ""
    from_domain = email.from_domain  or ""
    rt_addr     = email.reply_to_address or ""
    rt_domain   = email.reply_to_domain  or ""

    if not rt_addr:
        return   # No Reply-To header — normal

    # Full address mismatch
    if rt_addr and from_addr and rt_addr != from_addr:
        result.reply_to_mismatch = True
        result.reply_to_score = 80.0

        result.findings.append(_finding(
            "REPLY-TO ANOMALY", "HIGH",
            "Reply-To address differs from sender address",
            (f"The Reply-To header points to '{rt_addr}' which differs from the "
             f"From address '{from_addr}'. Replies will be sent to a different address "
             f"than the apparent sender — a classic BEC indicator."),
            "Reply-To",
            email.reply_to or "",
        ))

        # Domain mismatch is even more suspicious
        if rt_domain and from_domain and rt_domain != from_domain:
            result.reply_to_domain_differs = True
            result.reply_to_score = 100.0
            result.findings.append(_finding(
                "REPLY-TO ANOMALY", "CRITICAL",
                "Reply-To domain differs from sender domain",
                (f"Reply-To domain '{rt_domain}' is completely different from "
                 f"sender domain '{from_domain}'. This strongly indicates "
                 f"possible spoofing or a compromised account redirecting replies."),
                "Reply-To",
                email.reply_to or "",
            ))
        # Same domain different address — still suspicious
        elif rt_domain == from_domain and rt_addr != from_addr:
            result.reply_to_score = 60.0


# ─────────────────────────────────────────────────────────────
# Return-Path analysis
# ─────────────────────────────────────────────────────────────

def _check_return_path(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    from_domain = email.from_domain      or ""
    rp_addr     = email.return_path_address or ""
    rp_domain   = email.return_path_domain  or ""

    if not rp_addr:
        return  # Missing Return-Path — note but don't penalise heavily

    if rp_domain and from_domain and rp_domain != from_domain:
        result.return_path_mismatch = True
        result.return_path_score = 75.0
        result.findings.append(_finding(
            "RETURN-PATH ANOMALY", "HIGH",
            "Return-Path domain differs from sender domain",
            (f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}'. "
             f"While some legitimate mail services use separate bounce domains, "
             f"combined with other indicators this may indicate spoofing."),
            "Return-Path",
            email.return_path or "",
        ))


# ─────────────────────────────────────────────────────────────
# Display name analysis
# ─────────────────────────────────────────────────────────────

_FREE_EMAIL_DOMAINS = frozenset([
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com",
])

_EXEC_TITLE_RE = re.compile(
    r"\b(ceo|cfo|coo|president|director|vp|vice president|manager|"
    r"chief executive|chief financial|head of|partner)\b",
    re.IGNORECASE,
)


def _check_display_name(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    name    = (email.from_name    or "").strip()
    addr    = (email.from_address or "").strip().lower()
    domain  = (email.from_domain  or "").strip().lower()

    if not name or not addr:
        return

    # Case 1 — Free email domain with corporate-sounding display name
    if domain in _FREE_EMAIL_DOMAINS:
        result.display_name_spoofing = True
        result.display_name_score = 70.0
        result.findings.append(_finding(
            "DISPLAY NAME SPOOFING", "HIGH",
            "Corporate display name with free email domain",
            (f"Display name '{name}' appears corporate but the sending address "
             f"uses the free email domain '{domain}'. This is a common BEC "
             f"impersonation technique."),
            "From",
            email.from_raw or "",
        ))

    # Case 2 — Executive title in display name + free domain
    if _EXEC_TITLE_RE.search(name) and domain in _FREE_EMAIL_DOMAINS:
        result.display_name_score = 90.0
        result.findings.append(_finding(
            "DISPLAY NAME SPOOFING", "CRITICAL",
            "Executive title in display name with free email domain",
            (f"Display name '{name}' contains an executive title but the email "
             f"originates from a free email service '{domain}'. "
             f"This is strongly indicative of executive impersonation (BEC)."),
            "From",
            email.from_raw or "",
        ))

    # Case 3 — Name contains @ symbol (name collision trick)
    if "@" in name:
        result.display_name_spoofing = True
        result.display_name_score = max(result.display_name_score, 85.0)
        result.findings.append(_finding(
            "DISPLAY NAME SPOOFING", "CRITICAL",
            "Display name contains an email address (name trick)",
            (f"The display name '{name}' contains an email address. "
             f"This can trick email clients into showing a different email than the real sender."),
            "From",
            email.from_raw or "",
        ))


# ─────────────────────────────────────────────────────────────
# Received chain parsing
# ─────────────────────────────────────────────────────────────

def _parse_received_chain(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    """Extract IPs and hops from Received headers (last = origin)."""
    ips: list[str] = []
    hops: list[dict] = []

    for hdr in reversed(email.received_headers):  # reverse: oldest first
        hop: dict = {"raw": hdr}

        from_m = _RECEIVED_FROM_RE.search(hdr)
        by_m   = _RECEIVED_BY_RE.search(hdr)
        if from_m:
            hop["from"] = from_m.group(1)
        if by_m:
            hop["by"] = by_m.group(1)

        ip_matches = _IP_RE.findall(hdr)
        if ip_matches:
            # ip_matches returns strings of the last octet group; reconstruct
            # Actually findall with groups returns tuples, use finditer
            for m in _IP_RE.finditer(hdr):
                ip = m.group(0)
                ips.append(ip)
                hop.setdefault("ips", []).append(ip)

        hops.append(hop)

    result.received_ips = list(dict.fromkeys(ips))  # deduplicated, order preserved
    result.received_hops = hops

    # X-Originating-IP
    if email.x_originating_ip:
        ip = email.x_originating_ip.strip().strip("[]")
        if ip not in result.received_ips:
            result.received_ips.insert(0, ip)
