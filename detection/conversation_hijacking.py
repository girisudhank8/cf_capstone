"""
BEC-FORGE Conversation Hijacking Detection Module (Phase 6)

Detects sudden deviations inside an otherwise normal ongoing email conversation/thread:
- Thread participants deviation (sudden insertion of new recipients or drop of legitimate parties)
- Thread Reply-To deviation (sudden Reply-To modification mid-thread)
- In-Reply-To and References header tracking
- Financial instruction alteration inside an established thread (e.g. "update vendor bank routing")
- Sudden domain substitution in long-running email chains
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor
from parser.eml_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class ConversationHijackAnomaly:
    dimension: str        # "REPLY_TO_ALTERATION", "RECIPIENT_DRIFT", "FINANCIAL_INJECTION", "DOMAIN_MUTATION"
    severity: str         # HIGH, CRITICAL
    description: str
    evidence_field: str
    evidence_value: str


@dataclass
class ConversationHijackResult:
    is_part_of_thread: bool
    thread_parent_message_id: Optional[str]
    hijack_detected: bool
    hijack_score: float   # 0 to 100 contribution to conversation_hijacking risk component
    anomalies: list[ConversationHijackAnomaly] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


def analyse_conversation_hijacking(
    parsed_email: ParsedEmail,
    financial_score: float = 0.0,
    urgency_score: float = 0.0,
) -> ConversationHijackResult:
    """
    Detect if an email is an attempt to hijack an existing thread.
    Compares the current email with parent/preceding emails matching In-Reply-To or References.
    """
    parent_id = parsed_email.in_reply_to or (parsed_email.references[-1] if parsed_email.references else None)
    
    # Also attempt matching Re: <Subject> if in_reply_to header is missing
    parent_email_record = None
    if parent_id:
        parent_email_record = _get_email_by_message_id(parent_id)
    
    if not parent_email_record and parsed_email.subject:
        # Check normalized Re: subject match
        subj = parsed_email.subject.strip()
        if subj.lower().startswith("re:"):
            base_subj = subj[3:].strip()
            parent_email_record = _get_email_by_subject(base_subj)

    if not parent_email_record:
        # Not part of any known tracked thread in the database
        return ConversationHijackResult(
            is_part_of_thread=False,
            thread_parent_message_id=None,
            hijack_detected=False,
            hijack_score=0.0,
            anomalies=[],
            findings=[],
        )

    # We found a parent thread message!
    anomalies = []
    hijack_points = 0.0

    # 1. Reply-To Deviation mid-thread
    parent_from = (parent_email_record.get("from_address") or "").lower()
    parent_rt = (parent_email_record.get("reply_to") or parent_from).lower()
    current_rt = (parsed_email.reply_to_address or parsed_email.from_address or "").lower()

    if current_rt and parent_rt and current_rt != parent_rt and current_rt != parent_from:
        hijack_points += 45.0
        anomalies.append(ConversationHijackAnomaly(
            dimension="REPLY_TO_ALTERATION",
            severity="CRITICAL",
            description=f"Reply-To altered mid-conversation! Parent thread directed replies to '{parent_rt}', but new reply directs to '{current_rt}'. Classic vendor thread hijacking indicator.",
            evidence_field="In-Reply-To / Reply-To",
            evidence_value=f"Thread: {parent_rt} → Hijacked: {current_rt}",
        ))

    # 2. Financial instruction alteration in thread
    if financial_score >= 50.0:
        hijack_points += 35.0
        anomalies.append(ConversationHijackAnomaly(
            dimension="FINANCIAL_INJECTION",
            severity="CRITICAL",
            description="High financial language / wire instruction injected into existing conversation thread. Attackers frequently hijack vendor threads to request sudden routing number alterations.",
            evidence_field="Body / Financial Instructions",
            evidence_value=f"Financial language score: {financial_score:.1f}",
        ))

    # 3. New participants / Drops
    parent_to = (parent_email_record.get("to_raw") or "").lower()
    curr_recips = [r.lower() for r in (parsed_email.to_addresses + parsed_email.cc_addresses)]
    unseen_recips = [r for r in curr_recips if r not in parent_to and r != parent_from]
    if unseen_recips:
        hijack_points += 20.0
        anomalies.append(ConversationHijackAnomaly(
            dimension="RECIPIENT_DRIFT",
            severity="HIGH",
            description=f"Thread participants altered. Unseen recipient(s) introduced to thread: {', '.join(unseen_recips[:3])}.",
            evidence_field="To / CC",
            evidence_value=", ".join(unseen_recips),
        ))

    total_hijack_score = min(100.0, round(hijack_points, 1))
    hijack_detected = total_hijack_score >= 50.0

    findings = []
    if hijack_detected:
        findings.append({
            "severity": "CRITICAL",
            "title": "🚨 POSSIBLE CONVERSATION HIJACKING DETECTED",
            "description": f"Email appears to hijack established thread '{parent_email_record.get('subject')}'. "
                           f"Deviations detected: {', '.join(a.dimension for a in anomalies)}.",
            "evidence_field": "Thread Context / In-Reply-To",
            "evidence_value": parent_email_record.get("message_id") or "Subject Match",
        })

    for a in anomalies:
        findings.append({
            "severity": a.severity,
            "title": f"Thread Anomaly: {a.dimension}",
            "description": a.description,
            "evidence_field": a.evidence_field,
            "evidence_value": a.evidence_value,
        })

    return ConversationHijackResult(
        is_part_of_thread=True,
        thread_parent_message_id=parent_email_record.get("message_id"),
        hijack_detected=hijack_detected,
        hijack_score=total_hijack_score,
        anomalies=anomalies,
        findings=findings,
    )


def _get_email_by_message_id(msg_id: str) -> Optional[dict]:
    clean_id = msg_id.strip("<> \n\r\t")
    with db_cursor() as (conn, cur):
        cur.execute(
            """SELECT * FROM emails 
               WHERE message_id = ? OR message_id LIKE ? LIMIT 1""",
            (msg_id, f"%{clean_id}%"),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def _get_email_by_subject(base_subject: str) -> Optional[dict]:
    if not base_subject or len(base_subject) < 5:
        return None
    with db_cursor() as (conn, cur):
        cur.execute(
            """SELECT * FROM emails 
               WHERE subject LIKE ? OR subject LIKE ? 
               ORDER BY id DESC LIMIT 1""",
            (f"%{base_subject}%", base_subject),
        )
        row = cur.fetchone()
    return dict(row) if row else None
