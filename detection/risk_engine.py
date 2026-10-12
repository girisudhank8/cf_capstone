"""
BEC-FORGE Risk Engine

Transparent weighted scoring engine.
Produces:
- Total risk score (0-100)
- Risk level label
- Component scores breakdown
- Explainable findings (ordered by severity)
- Lightweight counterfactual analysis
"""

import logging
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import RISK_WEIGHTS, get_risk_level
from analysis.header_analysis import HeaderAnalysisResult
from analysis.auth_analysis import AuthResult
from analysis.domain_analysis import DomainAnalysisResult
from analysis.url_analysis import URLAnalysisResult
from analysis.attachment_analysis import AttachmentAnalysisResult
from nlp.language_analysis import NLPScores

logger = logging.getLogger(__name__)


@dataclass
class RiskComponent:
    name: str
    weight: float
    raw_score: float       # 0-100 before weighting
    weighted_score: float  # raw_score * weight


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    description: str
    evidence_field: Optional[str] = None
    evidence_value: Optional[str] = None


@dataclass
class Counterfactual:
    condition: str           # "If Reply-To matched historical sender"
    impact_description: str  # "Risk would reduce to approximately 76"
    estimated_new_score: float


@dataclass
class RiskAssessment:
    total_score: float
    risk_level: str
    risk_colour: str
    identity_consistency_score: float = 100.0
    threat_hypothesis: str = "BENIGN / NORMAL"
    identity_drift_score: float = 0.0
    identity_drift_level: str = "NONE"
    components: list[RiskComponent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    counterfactuals: list[Counterfactual] = field(default_factory=list)
    assessed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "identity_consistency_score": self.identity_consistency_score,
            "threat_hypothesis": self.threat_hypothesis,
            "identity_drift_score": self.identity_drift_score,
            "identity_drift_level": self.identity_drift_level,
            "components": [
                {
                    "name": c.name,
                    "weight": c.weight,
                    "raw_score": c.raw_score,
                    "weighted_score": c.weighted_score,
                }
                for c in self.components
            ],
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence_field": f.evidence_field,
                    "evidence_value": f.evidence_value,
                }
                for f in self.findings
            ],
            "counterfactuals": [
                {
                    "condition": c.condition,
                    "impact_description": c.impact_description,
                    "estimated_new_score": c.estimated_new_score,
                }
                for c in self.counterfactuals
            ],
            "assessed_at": self.assessed_at,
        }


# ─────────────────────────────────────────────────────────────
# Main scoring function
# ─────────────────────────────────────────────────────────────

def compute_risk(
    header: HeaderAnalysisResult,
    auth: AuthResult,
    domain: DomainAnalysisResult,
    url: URLAnalysisResult,
    attachment: AttachmentAnalysisResult,
    nlp: NLPScores,
    drift: Optional[object] = None,
    graph_anomalies: Optional[list] = None,
    hijack: Optional[object] = None,
    weights: dict[str, float] | None = None,
) -> RiskAssessment:
    """
    Compute the overall BEC risk score.

    Parameters can be overridden with custom weights dict.
    Returns a fully explainable RiskAssessment.
    """
    w = weights or RISK_WEIGHTS
    components: list[RiskComponent] = []

    def _component(name: str, raw: float) -> RiskComponent:
        weight = w.get(name, 0.0)
        return RiskComponent(
            name=name,
            weight=weight,
            raw_score=round(raw, 1),
            weighted_score=round(raw * weight, 2),
        )

    # ── Component raw scores ──────────────────────────────────

    # Display name spoofing
    dn_score = header.display_name_score
    components.append(_component("display_name_spoofing", dn_score))

    # Domain anomaly
    domain_score = domain.domain_score
    components.append(_component("domain_anomaly", domain_score))

    # Reply-To mismatch
    rt_score = header.reply_to_score
    components.append(_component("reply_to_mismatch", rt_score))

    # Return-Path anomaly
    rp_score = header.return_path_score
    components.append(_component("return_path_anomaly", rp_score))

    # Authentication anomalies
    auth_score = auth.auth_score
    components.append(_component("auth_anomalies", auth_score))

    # Behavioral anomaly — Phase 3 Sender Identity Drift
    drift_score = getattr(drift, "identity_drift_score", 0.0) if drift else 0.0
    components.append(_component("behavioral_anomaly", drift_score))

    # Communication anomaly — Phase 5 Communication Graph
    comm_score = 0.0
    if graph_anomalies:
        comm_score = min(100.0, len(graph_anomalies) * 45.0)
    components.append(_component("communication_anomaly", comm_score))

    # Urgency language
    urgency_score = nlp.urgency_score
    components.append(_component("urgency_language", urgency_score))

    # Financial language
    financial_score = nlp.financial_score
    components.append(_component("financial_language", financial_score))

    # Authority + secrecy combined
    auth_sec_score = (nlp.authority_score + nlp.secrecy_score) / 2
    components.append(_component("authority_secrecy", auth_sec_score))

    # Conversation hijacking — Phase 6
    hijack_score = getattr(hijack, "hijack_score", 0.0) if hijack else 0.0
    components.append(_component("conversation_hijacking", hijack_score))

    # ── Total score ───────────────────────────────────────────
    total = sum(c.weighted_score for c in components)
    total = round(min(total, 100.0), 1)
    risk_level, risk_colour = get_risk_level(total)

    # ── Aggregate findings ────────────────────────────────────
    all_findings: list[Finding] = []

    # Header findings
    for f in header.findings:
        all_findings.append(Finding(
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            evidence_field=f.evidence_field,
            evidence_value=f.evidence_value,
        ))

    # Auth findings
    for f in auth.findings:
        all_findings.append(Finding(
            category="AUTHENTICATION",
            severity=f["severity"],
            title=f["title"],
            description=f["description"],
            evidence_field=f.get("field"),
        ))

    # Domain findings
    for f in domain.findings:
        all_findings.append(Finding(
            category="DOMAIN ANALYSIS",
            severity=f.severity,
            title=f.title,
            description=f.description,
            evidence_field=f.evidence_field,
            evidence_value=f.evidence_value,
        ))

    # NLP findings
    for f in nlp.findings:
        all_findings.append(Finding(
            category="SOCIAL ENGINEERING",
            severity=f["severity"],
            title=f["title"],
            description=f["description"],
        ))

    # URL findings
    for f in url.findings:
        all_findings.append(Finding(
            category="URL ANALYSIS",
            severity=f["severity"],
            title=f["title"],
            description=f["description"],
        ))

    # Attachment findings
    for f in attachment.findings:
        all_findings.append(Finding(
            category="ATTACHMENT ANALYSIS",
            severity=f.severity,
            title=f.title,
            description=f.description,
        ))

    # Behavioral Drift findings (Phase 3)
    if drift and hasattr(drift, "findings"):
        for f in drift.findings:
            all_findings.append(Finding(
                category="SENDER BEHAVIORAL DRIFT",
                severity=f.get("severity", "MEDIUM"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                evidence_field=f.get("evidence_field"),
                evidence_value=f.get("evidence_value"),
            ))

    # Communication Graph findings (Phase 5)
    if graph_anomalies:
        for a in graph_anomalies:
            all_findings.append(Finding(
                category="COMMUNICATION GRAPH",
                severity=getattr(a, "severity", "MEDIUM"),
                title=f"GRAPH: {getattr(a, 'anomaly_type', 'NEW_RELATIONSHIP')}",
                description=getattr(a, "description", ""),
                evidence_field="Communication Graph Edge",
                evidence_value=f"{getattr(a, 'sender', '')} → {getattr(a, 'recipient', '')}",
            ))

    # Conversation Hijacking findings (Phase 6)
    if hijack and hasattr(hijack, "findings"):
        for f in hijack.findings:
            all_findings.append(Finding(
                category="CONVERSATION HIJACKING",
                severity=f.get("severity", "CRITICAL"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                evidence_field=f.get("evidence_field"),
                evidence_value=f.get("evidence_value"),
            ))

    # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: _sev_order.get(f.severity, 5))

    # ── Counterfactuals ───────────────────────────────────────
    counterfactuals = _build_counterfactuals(total, components, header, auth, nlp, w)

    assessment = RiskAssessment(
        total_score=total,
        risk_level=risk_level,
        risk_colour=risk_colour,
        identity_consistency_score=auth.identity_consistency_score,
        threat_hypothesis=auth.threat_hypothesis,
        identity_drift_score=getattr(drift, "identity_drift_score", 0.0) if drift else 0.0,
        identity_drift_level=getattr(drift, "drift_level", "NONE") if drift else "NONE",
        components=components,
        findings=all_findings,
        counterfactuals=counterfactuals,
        assessed_at=datetime.now(timezone.utc).isoformat(),
    )
    return assessment


def _build_counterfactuals(
    total: float,
    components: list[RiskComponent],
    header: HeaderAnalysisResult,
    auth: AuthResult,
    nlp: NLPScores,
    w: dict[str, float],
) -> list[Counterfactual]:
    """
    Generate lightweight analytical counterfactuals.

    IMPORTANT: These are analytical estimates presented as such,
    not factual predictions.
    """
    cf: list[Counterfactual] = []

    # Reply-To counterfactual
    rt_comp = next((c for c in components if c.name == "reply_to_mismatch"), None)
    if rt_comp and rt_comp.weighted_score > 0:
        new_score = round(total - rt_comp.weighted_score, 1)
        cf.append(Counterfactual(
            condition="If Reply-To matched the sender address",
            impact_description=(
                f"Estimated risk would reduce from {total:.0f} to approximately {new_score:.0f}. "
                f"(This is an analytical estimate based on removing the Reply-To mismatch indicator.)"
            ),
            estimated_new_score=new_score,
        ))

    # Auth counterfactual
    auth_comp = next((c for c in components if c.name == "auth_anomalies"), None)
    if auth_comp and auth_comp.weighted_score > 0:
        new_score = round(total - auth_comp.weighted_score, 1)
        cf.append(Counterfactual(
            condition="If SPF/DKIM/DMARC all passed",
            impact_description=(
                f"Estimated risk would reduce from {total:.0f} to approximately {new_score:.0f}. "
                f"Note: passing authentication alone does not rule out account compromise."
            ),
            estimated_new_score=new_score,
        ))

    # Urgency counterfactual
    urg_comp = next((c for c in components if c.name == "urgency_language"), None)
    if urg_comp and urg_comp.weighted_score > 0:
        new_score = round(total - urg_comp.weighted_score, 1)
        cf.append(Counterfactual(
            condition="If urgency language indicators were absent",
            impact_description=(
                f"Estimated risk would reduce from {total:.0f} to approximately {new_score:.0f}. "
                f"Urgency language is a significant social engineering indicator in BEC attacks."
            ),
            estimated_new_score=new_score,
        ))

    # Display name counterfactual
    dn_comp = next((c for c in components if c.name == "display_name_spoofing"), None)
    if dn_comp and dn_comp.weighted_score > 0:
        new_score = round(total - dn_comp.weighted_score, 1)
        cf.append(Counterfactual(
            condition="If display name matched a verified sender identity",
            impact_description=(
                f"Estimated risk would reduce from {total:.0f} to approximately {new_score:.0f}. "
                f"Display name spoofing is a primary BEC vector."
            ),
            estimated_new_score=new_score,
        ))

    return cf
