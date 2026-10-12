"""
BEC-FORGE Authentication Analysis Module — Phase 2 Enhanced

Features:
- SPF, DKIM, DMARC parsing
- DMARC Alignment Verification (SPF alignment and DKIM alignment against From header domain)
- Authenticated Received Chain (ARC) analysis
- Multi-layer Consistency calculation
- Distinguish between "Potential Spoofing" vs "Possible Compromised Account"

Status values:
  PASS | FAIL | SOFTFAIL | NEUTRAL | NONE | UNKNOWN
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


@dataclass
class AuthResult:
    spf_status:   str = "NONE"   # PASS | FAIL | SOFTFAIL | NEUTRAL | NONE | UNKNOWN
    dkim_status:  str = "NONE"
    dmarc_status: str = "NONE"
    arc_status:   str = "NONE"   # PASS | FAIL | NONE | UNKNOWN

    spf_domain:   Optional[str] = None
    dkim_domain:  Optional[str] = None
    dmarc_domain: Optional[str] = None
    arc_domain:   Optional[str] = None

    # DMARC Alignment checks (RFC 7489)
    spf_aligned:  bool = False
    dkim_aligned: bool = False
    dmarc_aligned: bool = False

    # Multi-layer identity consistency classification
    # 0 = Completely Inconsistent / Spoofed, 100 = Fully Consistent & Authenticated
    identity_consistency_score: float = 100.0
    threat_hypothesis: str = "BENIGN / NORMAL"  # "POTENTIAL_SPOOFING", "POSSIBLE_COMPROMISE", "BENIGN / NORMAL", "UNVERIFIED"

    raw_auth_results: Optional[str] = None
    raw_received_spf: Optional[str] = None
    raw_arc_results:  Optional[str] = None

    auth_score: float = 0.0  # Risk score contribution (0-100)
    findings: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────

_SPF_STATUS_RE   = re.compile(r"spf=(pass|fail|softfail|neutral|none|permerror|temperror)", re.IGNORECASE)
_DKIM_STATUS_RE  = re.compile(r"dkim=(pass|fail|none|permerror|temperror)", re.IGNORECASE)
_DMARC_STATUS_RE = re.compile(r"dmarc=(pass|fail|none|bestguesspass)", re.IGNORECASE)
_ARC_STATUS_RE   = re.compile(r"arc=(pass|fail|none)", re.IGNORECASE)

_SPF_DOMAIN_RE   = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_DKIM_DOMAIN_RE  = re.compile(r"header\.[di]=([^\s;@]+@[^\s;]+|[^\s;]+)", re.IGNORECASE)
_DMARC_DOMAIN_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)
_ARC_DOMAIN_RE   = re.compile(r"arc\.chain=([^\s;]+)", re.IGNORECASE)

# Received-SPF
_RCVD_SPF_RE = re.compile(r"^(pass|fail|softfail|neutral|none|permerror|temperror)", re.IGNORECASE)


def _normalise(status: str) -> str:
    s = status.upper()
    if s in ("PASS", "BESTGUESSPASS"):
        return "PASS"
    if s in ("FAIL", "PERMERROR"):
        return "FAIL"
    if s == "SOFTFAIL":
        return "SOFTFAIL"
    if s == "NEUTRAL":
        return "NEUTRAL"
    if s in ("NONE",):
        return "NONE"
    return "UNKNOWN"


def _extract_domain(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    val = val.strip().lower()
    if "@" in val:
        return val.split("@")[-1].strip()
    return val.strip()


def _is_domain_aligned(domain_a: Optional[str], domain_b: Optional[str], relaxed: bool = True) -> bool:
    """Check DMARC alignment between two domains (relaxed matching allows subdomains)."""
    if not domain_a or not domain_b:
        return False
    da = domain_a.lower().strip(".")
    db = domain_b.lower().strip(".")
    if da == db:
        return True
    if relaxed:
        # Check parent domain alignment
        return da.endswith("." + db) or db.endswith("." + da)
    return False


def analyse_authentication(email: ParsedEmail) -> AuthResult:
    result = AuthResult(
        raw_auth_results=email.authentication_results,
        raw_received_spf=email.received_spf,
        raw_arc_results=email.arc_authentication_results,
    )

    auth_text = email.authentication_results or ""
    spf_text  = email.received_spf or ""
    arc_text  = email.arc_authentication_results or ""
    from_dom  = email.from_domain or ""

    # ── SPF ──────────────────────────────────────────────────
    spf_m = _SPF_STATUS_RE.search(auth_text)
    if spf_m:
        result.spf_status = _normalise(spf_m.group(1))
        d_m = _SPF_DOMAIN_RE.search(auth_text)
        result.spf_domain = _extract_domain(d_m.group(1)) if d_m else None
    elif spf_text:
        rcvd_m = _RCVD_SPF_RE.match(spf_text.strip())
        if rcvd_m:
            result.spf_status = _normalise(rcvd_m.group(1))

    # Fallback to Return-Path domain for SPF if not in header
    if not result.spf_domain and email.return_path_domain:
        result.spf_domain = email.return_path_domain

    # ── DKIM ─────────────────────────────────────────────────
    dkim_m = _DKIM_STATUS_RE.search(auth_text)
    if dkim_m:
        result.dkim_status = _normalise(dkim_m.group(1))
        d_m = _DKIM_DOMAIN_RE.search(auth_text)
        result.dkim_domain = _extract_domain(d_m.group(1)) if d_m else None
    elif email.dkim_signature:
        # Check d= tag in DKIM-Signature
        sig_m = re.search(r"\bd=([^\s;]+)", email.dkim_signature, re.IGNORECASE)
        if sig_m:
            result.dkim_domain = _extract_domain(sig_m.group(1))
        result.dkim_status = "UNKNOWN"

    # ── DMARC ────────────────────────────────────────────────
    dmarc_m = _DMARC_STATUS_RE.search(auth_text)
    if dmarc_m:
        result.dmarc_status = _normalise(dmarc_m.group(1))
        d_m = _DMARC_DOMAIN_RE.search(auth_text)
        result.dmarc_domain = _extract_domain(d_m.group(1)) if d_m else None

    # ── ARC (Authenticated Received Chain) ───────────────────
    arc_m = _ARC_STATUS_RE.search(arc_text) or _ARC_STATUS_RE.search(auth_text)
    if arc_m:
        result.arc_status = _normalise(arc_m.group(1))
        a_d_m = _ARC_DOMAIN_RE.search(arc_text)
        result.arc_domain = _extract_domain(a_d_m.group(1)) if a_d_m else None

    # ── Alignment Verification ───────────────────────────────
    if from_dom:
        result.spf_aligned = (result.spf_status == "PASS") and _is_domain_aligned(result.spf_domain, from_dom)
        result.dkim_aligned = (result.dkim_status == "PASS") and _is_domain_aligned(result.dkim_domain, from_dom)
        result.dmarc_aligned = (result.dmarc_status == "PASS") or (result.spf_aligned or result.dkim_aligned)
    else:
        result.spf_aligned = (result.spf_status == "PASS")
        result.dkim_aligned = (result.dkim_status == "PASS")
        result.dmarc_aligned = (result.dmarc_status == "PASS")

    # ── Multi-Layer Identity Consistency Scoring ─────────────
    consistency = 100.0

    if result.spf_status == "FAIL":
        consistency -= 35.0
    elif result.spf_status == "SOFTFAIL":
        consistency -= 20.0
    elif result.spf_status in ("NONE", "UNKNOWN"):
        consistency -= 10.0

    if result.dkim_status == "FAIL":
        consistency -= 35.0
    elif result.dkim_status in ("NONE", "UNKNOWN"):
        consistency -= 10.0

    if result.dmarc_status == "FAIL" or (from_dom and not result.dmarc_aligned and result.spf_status == "FAIL"):
        consistency -= 30.0

    if from_dom and result.spf_domain and not result.spf_aligned and result.spf_status == "PASS":
        # SPF passed but for a different domain (relay / forward without alignment)
        consistency -= 15.0

    result.identity_consistency_score = max(0.0, round(consistency, 1))

    # ── Risk Scoring & Findings Generation ───────────────────
    score = 0.0

    # SPF Findings
    if result.spf_status == "FAIL":
        score += 40.0
        result.findings.append({
            "severity": "HIGH", "title": "SPF Failure",
            "description": f"SPF check FAILED for sender domain. Sending IP is not authorised to send on behalf of '{result.spf_domain or from_dom}'.",
            "field": "Received-SPF / Authentication-Results",
        })
    elif result.spf_status == "SOFTFAIL":
        score += 25.0
        result.findings.append({
            "severity": "MEDIUM", "title": "SPF Softfail",
            "description": f"SPF returned SOFTFAIL for '{result.spf_domain or from_dom}'. The sending host is not strictly authorised.",
            "field": "Received-SPF / Authentication-Results",
        })

    # DKIM Findings
    if result.dkim_status == "FAIL":
        score += 35.0
        result.findings.append({
            "severity": "HIGH", "title": "DKIM Verification Failure",
            "description": f"DKIM cryptographic signature verification FAILED. Possible header/body tampering or unauthorized re-signing.",
            "field": "Authentication-Results / DKIM-Signature",
        })

    # DMARC Findings
    if result.dmarc_status == "FAIL":
        score += 25.0
        result.findings.append({
            "severity": "HIGH", "title": "DMARC Policy Failure",
            "description": "DMARC alignment check FAILED. The message violates published DMARC policy for the From header domain.",
            "field": "Authentication-Results",
        })

    # Combined failure (Severe Spoofing)
    if result.spf_status == "FAIL" and result.dkim_status == "FAIL":
        score = min(score + 15.0, 100.0)
        result.findings.append({
            "severity": "CRITICAL",
            "title": "Severe Authentication Failure (SPF + DKIM)",
            "description": "Both SPF and DKIM verification failed simultaneously. This strongly indicates email spoofing.",
            "field": "Authentication-Results",
        })

    # ARC Finding
    if result.arc_status == "FAIL":
        score += 20.0
        result.findings.append({
            "severity": "HIGH",
            "title": "ARC (Authenticated Received Chain) Validation Failed",
            "description": "The ARC seal/chain failed validation, indicating broken chain-of-custody during message forwarding.",
            "field": "ARC-Authentication-Results",
        })
    elif result.arc_status == "PASS":
        result.findings.append({
            "severity": "INFO",
            "title": "ARC Chain Preserved",
            "description": "ARC validation passed across forwarding intermediaries.",
            "field": "ARC-Authentication-Results",
        })

    # Alignment findings
    if from_dom and result.spf_domain and not result.spf_aligned and result.spf_status == "PASS":
        result.findings.append({
            "severity": "MEDIUM",
            "title": "DMARC SPF Alignment Mismatch",
            "description": f"SPF passed for '{result.spf_domain}', but does not align with From domain '{from_dom}'.",
            "field": "Authentication-Results (SPF Alignment)",
        })

    # ── Threat Hypothesis Classification ─────────────────────
    # Distinguish between Potential Spoofing vs Compromised Account
    auth_passed = (result.spf_status == "PASS" and result.dkim_status == "PASS" and result.dmarc_status != "FAIL")
    auth_failed = (result.spf_status == "FAIL" or result.dkim_status == "FAIL" or result.dmarc_status == "FAIL")

    if auth_failed or result.identity_consistency_score < 50.0:
        result.threat_hypothesis = "POTENTIAL_SPOOFING"
        result.findings.append({
            "severity": "HIGH",
            "title": "Threat Hypothesis: Potential Spoofing",
            "description": "Authentication failures and identity inconsistency suggest external display-name or domain spoofing.",
            "field": "Multi-Layer Identity Consistency Engine",
        })
    elif auth_passed:
        result.threat_hypothesis = "POSSIBLE_COMPROMISE"
        result.findings.append({
            "severity": "INFO",
            "title": "Threat Hypothesis: Legitimate Channel / Possible Compromise",
            "description": "Cryptographic authentication passed. Any suspicious behavioral or urgency patterns indicate potential legitimate account compromise.",
            "field": "Multi-Layer Identity Consistency Engine",
        })
    else:
        result.threat_hypothesis = "UNVERIFIED"

    result.auth_score = min(score, 100.0)
    return result
