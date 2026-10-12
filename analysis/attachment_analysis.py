"""
BEC-FORGE Attachment Analysis Module

Extracts attachment metadata from parsed email and flags
suspicious file types based on extension and MIME type.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parser.eml_parser import ParsedEmail, AttachmentInfo
from config.settings import SUSPICIOUS_EXTENSIONS

logger = logging.getLogger(__name__)


@dataclass
class AttachmentFinding:
    severity: str
    title: str
    description: str
    filename: str


@dataclass
class AttachmentAnalysisResult:
    attachments: list[AttachmentInfo] = field(default_factory=list)
    suspicious_count: int = 0
    attachment_score: float = 0.0
    findings: list[AttachmentFinding] = field(default_factory=list)


_SUSPICIOUS_MIME: frozenset[str] = frozenset([
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/javascript",
    "application/x-sh",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
])


def analyse_attachments(email: ParsedEmail) -> AttachmentAnalysisResult:
    result = AttachmentAnalysisResult(attachments=email.attachments)
    score = 0.0

    for att in email.attachments:
        ext_suspicious  = att.extension.lower() in SUSPICIOUS_EXTENSIONS
        mime_suspicious = att.mime_type.lower() in _SUSPICIOUS_MIME

        if ext_suspicious or mime_suspicious:
            result.suspicious_count += 1
            severity = "CRITICAL" if ext_suspicious else "HIGH"
            reason = []
            if ext_suspicious:
                reason.append(f"extension '{att.extension}' is in the suspicious list")
            if mime_suspicious:
                reason.append(f"MIME type '{att.mime_type}' is flagged")

            result.findings.append(AttachmentFinding(
                severity=severity,
                title=f"Suspicious attachment: {att.filename}",
                description=(
                    f"The attachment '{att.filename}' may be malicious. "
                    f"Reason(s): {'; '.join(reason)}. "
                    f"This is an indicator, not proof of maliciousness. "
                    f"SHA-256: {att.sha256}"
                ),
                filename=att.filename,
            ))
            score += 60.0

    # Double-extension trick
    for att in email.attachments:
        parts = att.filename.split(".")
        if len(parts) >= 3:
            penultimate = "." + parts[-2].lower()
            if penultimate in SUSPICIOUS_EXTENSIONS:
                result.findings.append(AttachmentFinding(
                    severity="CRITICAL",
                    title=f"Double-extension trick: {att.filename}",
                    description=(
                        f"The attachment '{att.filename}' uses a double-extension, "
                        f"which is a common technique to disguise executable files "
                        f"as benign documents."
                    ),
                    filename=att.filename,
                ))
                score += 40.0

    result.attachment_score = min(score, 100.0)
    return result
