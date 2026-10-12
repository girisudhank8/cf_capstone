"""
BEC-FORGE Domain Analysis Module

Detects:
- Sender / Reply-To / Return-Path domain mismatches
- Lookalike / typosquatting-like domains (difflib + Levenshtein)
- Suspicious TLDs
- Character substitution (e.g. rn → m, 0 → o)
- IP-based senders
"""

import logging
import re
import difflib
from dataclasses import dataclass, field
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parser.eml_parser import ParsedEmail
from config.settings import LOOKALIKE_SIMILARITY_THRESHOLD, SUSPICIOUS_TLDS

logger = logging.getLogger(__name__)

# Common confusable character pairs used in lookalike attacks
_CONFUSABLES: list[tuple[str, str]] = [
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"),
    ("i", "l"), ("cl", "d"), ("nn", "m"), ("li", "h"),
]


@dataclass
class DomainFinding:
    severity: str
    title: str
    description: str
    evidence_field: str
    evidence_value: str


@dataclass
class DomainAnalysisResult:
    from_domain: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""

    domains_match: bool = True
    lookalike_detected: bool = False
    suspicious_tld: bool = False
    ip_based_sender: bool = False

    similarity_score: float = 0.0  # 0-1 (1 = identical)
    domain_score: float = 0.0      # 0-100 risk

    findings: list[DomainFinding] = field(default_factory=list)


def _similarity(a: str, b: str) -> float:
    """SequenceMatcher ratio — 1.0 means identical."""
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _is_lookalike(domain_a: str, domain_b: str) -> tuple[bool, float]:
    """
    Returns (is_lookalike, ratio).
    Checks string similarity after applying common confusable substitutions.
    """
    if not domain_a or not domain_b:
        return False, 0.0
    if domain_a == domain_b:
        return False, 1.0

    # Strip TLD for comparison
    a_base = domain_a.rsplit(".", 1)[0] if "." in domain_a else domain_a
    b_base = domain_b.rsplit(".", 1)[0] if "." in domain_b else domain_b

    ratio = _similarity(a_base, b_base)

    # Check with confusable substitutions
    for orig, replacement in _CONFUSABLES:
        a_sub = a_base.replace(orig, replacement)
        b_sub = b_base.replace(orig, replacement)
        sub_ratio = _similarity(a_sub, b_sub)
        ratio = max(ratio, sub_ratio)

    is_lookalike = (
        LOOKALIKE_SIMILARITY_THRESHOLD <= ratio < 1.0
        and domain_a != domain_b
    )
    return is_lookalike, ratio


_IP_DOMAIN_RE = re.compile(r"^\[?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?$")


def analyse_domains(email: ParsedEmail) -> DomainAnalysisResult:
    result = DomainAnalysisResult(
        from_domain=email.from_domain or "",
        reply_to_domain=email.reply_to_domain or "",
        return_path_domain=email.return_path_domain or "",
    )

    from_d = result.from_domain
    rt_d   = result.reply_to_domain
    rp_d   = result.return_path_domain

    _check_ip_based(from_d, result)
    _check_suspicious_tld(from_d, result)
    _check_domain_mismatches(from_d, rt_d, rp_d, result, email)
    _check_lookalike(from_d, rt_d, rp_d, result)

    # ── Compute overall domain risk score ─────────────────────
    score = 0.0
    if result.ip_based_sender:
        score += 60.0
    if result.suspicious_tld:
        score += 30.0
    if not result.domains_match:
        score += 40.0
    if result.lookalike_detected:
        score += 70.0
    result.domain_score = min(score, 100.0)

    return result


def _check_ip_based(domain: str, result: DomainAnalysisResult) -> None:
    if _IP_DOMAIN_RE.match(domain):
        result.ip_based_sender = True
        result.findings.append(DomainFinding(
            severity="HIGH",
            title="IP-based sender domain",
            description=(f"The sender domain appears to be an IP address '{domain}'. "
                         f"Legitimate corporate email is rarely sent directly from an IP address."),
            evidence_field="From",
            evidence_value=domain,
        ))


def _check_suspicious_tld(domain: str, result: DomainAnalysisResult) -> None:
    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            result.suspicious_tld = True
            result.findings.append(DomainFinding(
                severity="MEDIUM",
                title=f"Sender domain uses suspicious TLD '{tld}'",
                description=(f"The sender domain '{domain}' uses a TLD commonly associated "
                             f"with low-cost/disposable domains ('{tld}'). "
                             f"While not conclusive, this is a potential indicator."),
                evidence_field="From (domain)",
                evidence_value=domain,
            ))
            break


def _check_domain_mismatches(
    from_d: str, rt_d: str, rp_d: str,
    result: DomainAnalysisResult,
    email: ParsedEmail,
) -> None:
    mismatches: list[str] = []

    if rt_d and from_d and rt_d != from_d:
        mismatches.append(f"Reply-To domain '{rt_d}' ≠ From domain '{from_d}'")
        result.domains_match = False

    if rp_d and from_d and rp_d != from_d:
        mismatches.append(f"Return-Path domain '{rp_d}' ≠ From domain '{from_d}'")
        result.domains_match = False

    if mismatches:
        result.findings.append(DomainFinding(
            severity="HIGH",
            title="Domain mismatch detected",
            description=(
                "Multiple domain inconsistencies detected:\n" +
                "\n".join(f"• {m}" for m in mismatches) +
                "\nThis pattern is commonly observed in BEC and spoofing attacks."
            ),
            evidence_field="From / Reply-To / Return-Path",
            evidence_value=f"From={from_d} | ReplyTo={rt_d} | ReturnPath={rp_d}",
        ))


def _check_lookalike(
    from_d: str, rt_d: str, rp_d: str,
    result: DomainAnalysisResult,
) -> None:
    """Check if Reply-To or Return-Path look like a lookalike of the From domain."""
    for other_d, field_name in [(rt_d, "Reply-To"), (rp_d, "Return-Path")]:
        if not other_d or other_d == from_d:
            continue
        is_la, ratio = _is_lookalike(from_d, other_d)
        if is_la:
            result.lookalike_detected = True
            result.similarity_score = max(result.similarity_score, ratio)
            result.findings.append(DomainFinding(
                severity="CRITICAL",
                title=f"Lookalike domain detected in {field_name}",
                description=(
                    f"The {field_name} domain '{other_d}' is visually similar to "
                    f"the From domain '{from_d}' (similarity: {ratio:.0%}). "
                    f"This pattern is characteristic of typosquatting/lookalike "
                    f"domain attacks used in BEC campaigns."
                ),
                evidence_field=field_name,
                evidence_value=f"From={from_d} vs {field_name}={other_d} (ratio={ratio:.2f})",
            ))
