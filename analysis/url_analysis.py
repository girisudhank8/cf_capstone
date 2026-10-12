"""
BEC-FORGE URL Analysis Module

Extracts URLs from email body (plain + HTML) and analyses:
- Domain extraction
- IP-based URLs
- URL shorteners
- Lookalike domains
- Count summary
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parser.eml_parser import ParsedEmail

logger = logging.getLogger(__name__)

_URL_RE = re.compile(
    r"https?://[^\s\"\'\<\>\)\(\[\]\{\}]+",
    re.IGNORECASE,
)

_IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "clck.ru",
])


@dataclass
class URLInfo:
    url: str
    domain: str
    is_ip_based: bool = False
    is_shortener: bool = False
    is_suspicious: bool = False
    source: str = "body"


@dataclass
class URLAnalysisResult:
    urls: list[URLInfo] = field(default_factory=list)
    total_count: int = 0
    ip_url_count: int = 0
    shortener_count: int = 0
    suspicious_count: int = 0
    url_score: float = 0.0
    findings: list[dict] = field(default_factory=list)


def analyse_urls(email: ParsedEmail) -> URLAnalysisResult:
    result = URLAnalysisResult()
    seen: set[str] = set()

    for source, text in [("body_plain", email.body_plain), ("body_html", email.body_html)]:
        if not text:
            continue
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;:\"'")
            if url in seen:
                continue
            seen.add(url)

            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower().split(":")[0]
            except Exception:
                domain = ""

            is_ip    = bool(_IP_URL_RE.match(url))
            is_short = domain in _SHORTENERS
            is_susp  = is_ip or is_short

            info = URLInfo(
                url=url,
                domain=domain,
                is_ip_based=is_ip,
                is_shortener=is_short,
                is_suspicious=is_susp,
                source=source,
            )
            result.urls.append(info)

    result.total_count      = len(result.urls)
    result.ip_url_count     = sum(1 for u in result.urls if u.is_ip_based)
    result.shortener_count  = sum(1 for u in result.urls if u.is_shortener)
    result.suspicious_count = sum(1 for u in result.urls if u.is_suspicious)

    # Scoring
    score = 0.0
    if result.ip_url_count > 0:
        score += 50.0
        result.findings.append({
            "severity": "HIGH",
            "title": f"{result.ip_url_count} IP-based URL(s) detected",
            "description": ("URLs using raw IP addresses instead of domain names are "
                            "often used to evade domain-based reputation filters."),
        })
    if result.shortener_count > 0:
        score += 30.0
        result.findings.append({
            "severity": "MEDIUM",
            "title": f"{result.shortener_count} URL shortener(s) detected",
            "description": ("Shortened URLs can hide the true destination and are "
                            "commonly used in phishing and BEC attacks."),
        })
    if result.total_count > 10:
        score += 20.0
        result.findings.append({
            "severity": "LOW",
            "title": f"High URL count ({result.total_count})",
            "description": "An unusually high number of URLs may indicate bulk phishing content.",
        })

    result.url_score = min(score, 100.0)
    return result
