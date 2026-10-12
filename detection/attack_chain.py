"""
BEC-FORGE Attack-Chain Reconstruction Module (Phase 7)

Core Innovation #4: BEC ATTACK-CHAIN RECONSTRUCTION

Reconstructs the progressive attack progression across multi-stage BEC operations:
1. Normal Communication (Baseline trust established)
2. Behavioral Deviation (Shift in hours / stylistic variance)
3. New Recipient / Entity Introduced
4. Executive Impersonation / Identity Drift
5. Urgency / Secrecy Pressure Injected
6. Financial Wire / Account Change Request
7. Payment Instruction / Fraud Execution

Constructs an interactive chronological attack progression timeline.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor

logger = logging.getLogger(__name__)


@dataclass
class AttackChainStage:
    stage_id: int          # 1 to 7
    stage_name: str
    status: str            # "CONFIRMED", "DETECTED", "ABSENT"
    timestamp: Optional[str]
    evidence_id: Optional[str]
    description: str
    indicators: list[str] = field(default_factory=list)


@dataclass
class AttackChainProgression:
    attack_detected: bool
    confidence_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    total_stages_observed: int
    stages: list[AttackChainStage] = field(default_factory=list)
    narrative: str = ""


# Canonical BEC Kill-Chain Stages
STAGE_DEFINITIONS = [
    (1, "Normal Trust Baseline", "Historical communications establishing business legitimacy"),
    (2, "Behavioral Deviation", "Initial temporal anomaly or stylistic divergence"),
    (3, "New Entity / Recipient Injection", "Introduction of new participants, external vendors, or new communication channels"),
    (4, "Executive Impersonation / Drift", "Authority leverage, display name spoofing, or significant identity drift"),
    (5, "Urgency & Secrecy Pressure", "Social engineering pressure, time-sensitive demands, confidentiality mandates"),
    (6, "Financial Diversion Request", "Request for invoice modification, wire transfer, or updated banking coordinates"),
    (7, "Payment Execution Mandate", "Explicit urgency to complete payment outside standard procurement verification"),
]


def reconstruct_attack_chain(evidence_id: Optional[str] = None) -> AttackChainProgression:
    """
    Reconstruct BEC attack progression for a specific evidence item or overall case history.
    """
    stages: list[AttackChainStage] = []
    
    # Query findings and risk components from database
    with db_cursor() as (conn, cur):
        if evidence_id:
            cur.execute("""
                SELECT f.category, f.severity, f.title, f.description, e.date_parsed, f.evidence_id
                FROM findings f
                JOIN emails e ON f.evidence_id = e.evidence_id
                WHERE f.evidence_id = ?
            """, (evidence_id,))
            findings = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT r.*, e.date_parsed 
                FROM risk_assessments r
                JOIN emails e ON r.evidence_id = e.evidence_id
                WHERE r.evidence_id = ?
            """, (evidence_id,))
            risk_row = cur.fetchone()
            risk_data = dict(risk_row) if risk_row else {}
        else:
            cur.execute("""
                SELECT f.category, f.severity, f.title, f.description, e.date_parsed, f.evidence_id
                FROM findings f
                JOIN emails e ON f.evidence_id = e.evidence_id
                ORDER BY e.date_parsed ASC
            """)
            findings = [dict(r) for r in cur.fetchall()]
            risk_data = {}

    # Stage 1: Normal Baseline
    has_baseline = any(f.get("identity_drift_score", 0) > 0 for f in [risk_data]) or any("Baseline" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=1,
        stage_name="Normal Trust Baseline",
        status="CONFIRMED" if has_baseline else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Legitimate business communication history established prior to divergence.",
        indicators=["Verified historical communication records in database"] if has_baseline else [],
    ))

    # Stage 2: Behavioral Deviation
    drift_score = float(risk_data.get("identity_drift_score") or 0.0)
    has_dev = drift_score >= 25.0 or any("Deviation" in f["title"] or "Sending Hour" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=2,
        stage_name="Behavioral Deviation",
        status="CONFIRMED" if has_dev else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Temporal sending anomaly or sudden linguistic shift detected against baseline.",
        indicators=[f"Drift score: {drift_score}/100"] if has_dev else [],
    ))

    # Stage 3: New Entity / Recipient Injection
    has_new_recip = any("NEW COMMUNICATION RELATIONSHIP" in f["title"] or "NEW_RELATIONSHIP" in f["title"] or "Recipient" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=3,
        stage_name="New Entity / Recipient Injection",
        status="CONFIRMED" if has_new_recip else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Targeting new individuals or injecting unauthorized recipients into communications.",
        indicators=["First-time communication relationship established"] if has_new_recip else [],
    ))

    # Stage 4: Executive Impersonation / Drift
    has_impersonation = (risk_data.get("threat_hypothesis") == "POTENTIAL_SPOOFING") or any("Spoofing" in f["title"] or "Authority" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=4,
        stage_name="Executive Impersonation / Authority Leverage",
        status="CONFIRMED" if has_impersonation else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Leveraging corporate hierarchy or spoofed executive identity to command compliance.",
        indicators=["Display name spoofing / Free webmail executive impersonation"] if has_impersonation else [],
    ))

    # Stage 5: Urgency & Secrecy Pressure
    has_urgency = any("Urgency" in f["title"] or "Secrecy" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=5,
        stage_name="Urgency & Confidentiality Mandate",
        status="CONFIRMED" if has_urgency else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Imposing strict time constraints and demanding secrecy to bypass out-of-band verification.",
        indicators=[f["title"] for f in findings if "Urgency" in f["title"] or "Secrecy" in f["title"]],
    ))

    # Stage 6: Financial Diversion Request
    has_financial = any("Financial" in f["title"] or "Invoice" in f["title"] or "Wire" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=6,
        stage_name="Financial Diversion Request",
        status="CONFIRMED" if has_financial else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Requesting wire transfers, banking detail adjustments, or urgent invoice processing.",
        indicators=[f["title"] for f in findings if "Financial" in f["title"]],
    ))

    # Stage 7: Payment Execution Mandate
    has_hijack = any("HIJACKING" in f["title"] or "REPLY_TO_ALTERATION" in f["title"] for f in findings)
    stages.append(AttackChainStage(
        stage_id=7,
        stage_name="Payment Execution Mandate",
        status="CONFIRMED" if has_hijack else "ABSENT",
        timestamp=risk_data.get("date_parsed"),
        evidence_id=evidence_id,
        description="Redirecting transaction routing or hijacking ongoing invoice threads to finalize payment fraud.",
        indicators=["Reply-To diversion / Thread hijacking detected"] if has_hijack else [],
    ))

    confirmed_count = sum(1 for s in stages if s.status == "CONFIRMED")
    
    if confirmed_count >= 5:
        confidence = "CRITICAL"
        narrative = "Complete multi-stage BEC attack chain reconstructed with high forensic confidence."
    elif confirmed_count >= 3:
        confidence = "HIGH"
        narrative = "Multiple sequential stages of a Business Email Compromise operation identified."
    elif confirmed_count >= 2:
        confidence = "MEDIUM"
        narrative = "Partial BEC kill-chain indicators observed."
    else:
        confidence = "LOW"
        narrative = "Isolated or benign communication telemetry."

    return AttackChainProgression(
        attack_detected=(confirmed_count >= 3),
        confidence_level=confidence,
        total_stages_observed=confirmed_count,
        stages=stages,
        narrative=narrative,
    )
