"""
BEC-FORGE NLP / Social Engineering Analysis Module

Detects and scores:
- Urgency language
- Financial language
- Authority language
- Secrecy / discretion language
- Credential request language

Uses rule-based keyword matching with normalisation.
Does NOT rely on large ML models.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (
    URGENCY_KEYWORDS, FINANCIAL_KEYWORDS, AUTHORITY_KEYWORDS,
    SECRECY_KEYWORDS, CREDENTIAL_KEYWORDS,
)
from parser.eml_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class NLPScores:
    urgency_score:     float = 0.0   # 0–100
    financial_score:   float = 0.0
    authority_score:   float = 0.0
    secrecy_score:     float = 0.0
    credential_score:  float = 0.0
    combined_score:    float = 0.0   # weighted combination

    urgency_hits:     list[str] = field(default_factory=list)
    financial_hits:   list[str] = field(default_factory=list)
    authority_hits:   list[str] = field(default_factory=list)
    secrecy_hits:     list[str] = field(default_factory=list)
    credential_hits:  list[str] = field(default_factory=list)

    findings: list[dict] = field(default_factory=list)


def _normalise(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation for matching."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _keyword_score(
    text_norm: str,
    keywords: list[str],
    cap_hits: int = 5,
) -> tuple[float, list[str]]:
    """
    Returns (score 0-100, list_of_matched_keywords).
    Score increases with each unique keyword hit, capped to avoid inflation.
    """
    hits: list[str] = []
    for kw in keywords:
        kw_norm = _normalise(kw)
        if kw_norm in text_norm:
            hits.append(kw)
    # Score: each unique hit adds progressively less weight (diminishing returns)
    unique_hits = list(dict.fromkeys(hits))  # preserve order, deduplicate
    score = 0.0
    for i, _ in enumerate(unique_hits[:cap_hits]):
        score += max(10.0, 25.0 - i * 5)
    return min(score, 100.0), unique_hits


def analyse_nlp(email: ParsedEmail) -> NLPScores:
    result = NLPScores()

    # Combine subject + body for analysis
    subject   = email.subject or ""
    body      = email.body_plain or ""
    if not body and email.body_html:
        # Strip HTML tags for plain text analysis
        body = re.sub(r"<[^>]+>", " ", email.body_html)

    combined  = f"{subject} {body}"
    norm      = _normalise(combined)

    # ── Keyword scoring ───────────────────────────────────────
    result.urgency_score,    result.urgency_hits    = _keyword_score(norm, URGENCY_KEYWORDS)
    result.financial_score,  result.financial_hits  = _keyword_score(norm, FINANCIAL_KEYWORDS)
    result.authority_score,  result.authority_hits  = _keyword_score(norm, AUTHORITY_KEYWORDS)
    result.secrecy_score,    result.secrecy_hits    = _keyword_score(norm, SECRECY_KEYWORDS)
    result.credential_score, result.credential_hits = _keyword_score(norm, CREDENTIAL_KEYWORDS)

    # ── Findings ─────────────────────────────────────────────
    if result.urgency_score >= 20:
        result.findings.append({
            "severity": "HIGH" if result.urgency_score >= 50 else "MEDIUM",
            "title": "Urgency language detected",
            "description": (
                f"The email contains urgency language commonly used in social engineering. "
                f"Matched terms: {', '.join(result.urgency_hits[:5])}."
            ),
        })

    if result.financial_score >= 20:
        result.findings.append({
            "severity": "HIGH" if result.financial_score >= 50 else "MEDIUM",
            "title": "Financial language detected",
            "description": (
                f"The email contains financial terminology commonly associated with "
                f"BEC fraud. Matched terms: {', '.join(result.financial_hits[:5])}."
            ),
        })

    if result.authority_score >= 20:
        result.findings.append({
            "severity": "MEDIUM",
            "title": "Authority language detected",
            "description": (
                f"The email invokes authority or executive titles. "
                f"Matched terms: {', '.join(result.authority_hits[:5])}."
            ),
        })

    if result.secrecy_score >= 20:
        result.findings.append({
            "severity": "HIGH",
            "title": "Secrecy/discretion language detected",
            "description": (
                f"The email attempts to prevent disclosure or verification — "
                f"a strong BEC social engineering indicator. "
                f"Matched terms: {', '.join(result.secrecy_hits[:5])}."
            ),
        })

    if result.credential_score >= 20:
        result.findings.append({
            "severity": "CRITICAL",
            "title": "Credential request detected",
            "description": (
                f"The email requests credentials or authentication information. "
                f"Matched terms: {', '.join(result.credential_hits[:5])}."
            ),
        })

    # High urgency + financial together is especially suspicious
    if result.urgency_score >= 30 and result.financial_score >= 30:
        result.findings.append({
            "severity": "CRITICAL",
            "title": "Urgency + Financial language combination",
            "description": (
                "The email combines urgency pressure with financial content. "
                "This combination is a primary indicator of BEC wire fraud tactics."
            ),
        })

    # ── Combined NLP score ────────────────────────────────────
    result.combined_score = min(
        result.urgency_score    * 0.30 +
        result.financial_score  * 0.30 +
        result.authority_score  * 0.15 +
        result.secrecy_score    * 0.15 +
        result.credential_score * 0.10,
        100.0,
    )

    return result
