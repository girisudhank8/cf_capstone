"""
BEC-FORGE Analysis Orchestrator

Ties all analysis modules together into a single pipeline call.
Returns a complete ForensicAnalysis result.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from acquisition.evidence import acquire_evidence
from parser.eml_parser import parse_eml, ParsedEmail
from analysis.header_analysis import analyse_headers, HeaderAnalysisResult
from analysis.auth_analysis import analyse_authentication, AuthResult
from analysis.domain_analysis import analyse_domains, DomainAnalysisResult
from analysis.url_analysis import analyse_urls, URLAnalysisResult
from analysis.attachment_analysis import analyse_attachments, AttachmentAnalysisResult
from nlp.language_analysis import analyse_nlp, NLPScores
from behavioral.fingerprint import compare_sender_identity, build_or_update_fingerprint, IdentityDriftResult
from graph.communication_graph import analyze_email_relationships, EdgeAnomaly
from detection.conversation_hijacking import analyse_conversation_hijacking, ConversationHijackResult
from detection.attack_chain import reconstruct_attack_chain, AttackChainProgression
from detection.risk_engine import compute_risk, RiskAssessment
from database.db import db_cursor

logger = logging.getLogger(__name__)


@dataclass
class ForensicAnalysis:
    """Complete forensic analysis result for a single email evidence item."""
    evidence: dict                          # from acquire_evidence
    parsed: ParsedEmail
    header: HeaderAnalysisResult
    auth: AuthResult
    domain: DomainAnalysisResult
    url: URLAnalysisResult
    attachment: AttachmentAnalysisResult
    nlp: NLPScores
    drift: IdentityDriftResult
    graph_anomalies: list[EdgeAnomaly]
    hijack: ConversationHijackResult
    attack_chain: AttackChainProgression
    risk: RiskAssessment
    analysis_id: Optional[int] = None


def run_analysis(
    raw_bytes: bytes,
    filename: str,
    case_id: Optional[str] = None,
    learn_baseline_if_clean: bool = True,
) -> ForensicAnalysis:
    """
    Full analysis pipeline for a single .eml file.

    Steps:
    1. Acquire evidence (hash, store, integrity)
    2. Parse email
    3. Header analysis
    4. Authentication analysis
    5. Domain analysis
    6. URL analysis
    7. Attachment analysis
    8. NLP analysis
    9. Sender Identity Drift / Behavioral Fingerprinting (Phase 3)
    10. Risk scoring
    11. Persist to database
    """
    logger.info("Starting forensic analysis for '%s'", filename)

    # Step 1 — Evidence acquisition
    evidence = acquire_evidence(raw_bytes, filename, case_id)
    evidence_id = evidence["evidence_id"]
    logger.info("Evidence ID: %s", evidence_id)

    # Step 2 — Parse
    parsed = parse_eml(raw_bytes)

    # Step 3-8 — Analysis modules
    header     = analyse_headers(parsed)
    auth       = analyse_authentication(parsed)
    domain     = analyse_domains(parsed)
    url        = analyse_urls(parsed)
    attachment = analyse_attachments(parsed)
    nlp        = analyse_nlp(parsed)

    # Step 9 — Sender Identity Drift
    drift = compare_sender_identity(
        parsed_email=parsed,
        urgency_score=nlp.urgency_score,
        financial_score=nlp.financial_score,
    )

    # Step 10 — Communication Graph Relationships (Phase 5)
    recipients = parsed.to_addresses + parsed.cc_addresses
    graph_anomalies = analyze_email_relationships(
        sender=parsed.from_address or "",
        recipients=recipients,
        evidence_id=evidence_id,
        subject=parsed.subject,
    )

    # Step 11 — Conversation Hijacking Analysis (Phase 6)
    hijack = analyse_conversation_hijacking(
        parsed_email=parsed,
        financial_score=nlp.financial_score,
        urgency_score=nlp.urgency_score,
    )

    # Step 12 — Risk Scoring
    risk = compute_risk(
        header, auth, domain, url, attachment, nlp,
        drift=drift,
        graph_anomalies=graph_anomalies,
        hijack=hijack,
    )

    # Step 13 — Persist
    _persist_analysis(evidence_id, parsed, risk)

    # If benign and clean, ingest into historical baseline fingerprint
    if learn_baseline_if_clean and risk.total_score < 30.0 and parsed.from_address:
        build_or_update_fingerprint(
            sender_address=parsed.from_address,
            parsed_email=parsed,
            urgency_score=nlp.urgency_score,
            financial_score=nlp.financial_score,
            auth_passed=(auth.spf_status == "PASS" and auth.dkim_status == "PASS"),
        )

    # Step 14 — Attack-Chain Reconstruction (Phase 7)
    attack_chain = reconstruct_attack_chain(evidence_id=evidence_id)

    return ForensicAnalysis(
        evidence=evidence,
        parsed=parsed,
        header=header,
        auth=auth,
        domain=domain,
        url=url,
        attachment=attachment,
        nlp=nlp,
        drift=drift,
        graph_anomalies=graph_anomalies,
        hijack=hijack,
        attack_chain=attack_chain,
        risk=risk,
    )


def _persist_analysis(
    evidence_id: str,
    parsed: ParsedEmail,
    risk: RiskAssessment,
) -> None:
    """Write parsed email and risk assessment to the database."""
    now = datetime.now(timezone.utc).isoformat()

    with db_cursor() as (conn, cur):
        # Email record
        cur.execute(
            """INSERT OR REPLACE INTO emails (
               evidence_id, message_id, from_raw, from_name, from_address,
               to_raw, cc_raw, subject, date_raw, date_parsed,
               reply_to, return_path, in_reply_to, user_agent, x_mailer,
               x_originating_ip, body_plain, body_html, parsed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                parsed.message_id,
                parsed.from_raw,
                parsed.from_name,
                parsed.from_address,
                parsed.to_raw,
                parsed.cc_raw,
                parsed.subject,
                parsed.date_raw,
                parsed.date_parsed.isoformat() if parsed.date_parsed else None,
                parsed.reply_to,
                parsed.return_path,
                parsed.in_reply_to,
                parsed.user_agent,
                parsed.x_mailer,
                parsed.x_originating_ip,
                (parsed.body_plain or "")[:5000],    # truncate for DB
                (parsed.body_html  or "")[:5000],
                now,
            ),
        )

        # All headers
        cur.execute("DELETE FROM email_headers WHERE evidence_id = ?", (evidence_id,))
        for pos, (name, value) in enumerate(parsed.all_headers):
            cur.execute(
                "INSERT INTO email_headers (evidence_id, header_name, header_value, position) VALUES (?,?,?,?)",
                (evidence_id, name, value[:1000], pos),
            )

        # Risk assessment
        cur.execute(
            """INSERT OR REPLACE INTO risk_assessments (
               evidence_id, total_score, risk_level, identity_consistency_score,
               threat_hypothesis, identity_drift_score, identity_drift_level,
               component_scores, explanation, counterfactuals, assessed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                risk.total_score,
                risk.risk_level,
                risk.identity_consistency_score,
                risk.threat_hypothesis,
                risk.identity_drift_score,
                risk.identity_drift_level,
                json.dumps([
                    {"name": c.name, "raw": c.raw_score, "weighted": c.weighted_score}
                    for c in risk.components
                ]),
                json.dumps([
                    {"severity": f.severity, "title": f.title, "description": f.description}
                    for f in risk.findings
                ]),
                json.dumps([
                    {"condition": c.condition, "score": c.estimated_new_score}
                    for c in risk.counterfactuals
                ]),
                risk.assessed_at,
            ),
        )

        # Findings
        cur.execute("DELETE FROM findings WHERE evidence_id = ?", (evidence_id,))
        for f in risk.findings:
            cur.execute(
                """INSERT INTO findings
                   (evidence_id, category, severity, title, description,
                    evidence_field, evidence_value, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    evidence_id, f.category, f.severity, f.title,
                    f.description, f.evidence_field, f.evidence_value, now,
                ),
            )

        # Senders
        if parsed.from_address:
            cur.execute(
                """INSERT INTO senders (email_address, display_name, domain, first_seen, last_seen, email_count)
                   VALUES (?,?,?,?,?,1)
                   ON CONFLICT(email_address) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       email_count=email_count+1""",
                (
                    parsed.from_address,
                    parsed.from_name,
                    parsed.from_domain,
                    now, now,
                ),
            )

        # Recipients
        cur.execute("DELETE FROM recipients WHERE evidence_id = ?", (evidence_id,))
        for addr in parsed.to_addresses:
            cur.execute(
                "INSERT INTO recipients (evidence_id, email_address, recipient_type) VALUES (?,?,?)",
                (evidence_id, addr, "TO"),
            )
        for addr in parsed.cc_addresses:
            cur.execute(
                "INSERT INTO recipients (evidence_id, email_address, recipient_type) VALUES (?,?,?)",
                (evidence_id, addr, "CC"),
            )

        # Attachments
        cur.execute("DELETE FROM attachments WHERE evidence_id = ?", (evidence_id,))
        for att in parsed.attachments:
            cur.execute(
                """INSERT INTO attachments
                   (evidence_id, filename, extension, mime_type, file_size, sha256, is_suspicious)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    evidence_id, att.filename, att.extension,
                    att.mime_type, att.file_size, att.sha256,
                    1 if any(f.filename == att.filename for f in []) else 0,
                ),
            )

    logger.info("Persisted analysis for evidence %s | Risk: %s (%.1f)",
                evidence_id, risk.risk_level, risk.total_score)



def get_all_analyses() -> list[dict]:
    """Retrieve all evidence + risk assessment summaries from DB."""
    with db_cursor() as (conn, cur):
        cur.execute("""
            SELECT e.evidence_id, e.filename, e.sha256, e.acquired_at,
                   em.from_address, em.from_name, em.subject, em.date_raw,
                   r.total_score, r.risk_level, r.identity_consistency_score, r.threat_hypothesis,
                   r.identity_drift_score, r.identity_drift_level
            FROM evidence e
            LEFT JOIN emails em ON e.evidence_id = em.evidence_id
            LEFT JOIN risk_assessments r ON e.evidence_id = r.evidence_id
            ORDER BY e.id DESC
        """)
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_analysis_by_id(evidence_id: str) -> Optional[dict]:
    """Retrieve full analysis data for a given evidence ID."""
    with db_cursor() as (conn, cur):
        cur.execute("""
            SELECT e.*, em.*, r.total_score, r.risk_level,
                   r.identity_consistency_score, r.threat_hypothesis,
                   r.identity_drift_score, r.identity_drift_level,
                   r.component_scores, r.explanation, r.counterfactuals
            FROM evidence e
            LEFT JOIN emails em ON e.evidence_id = em.evidence_id
            LEFT JOIN risk_assessments r ON e.evidence_id = r.evidence_id
            WHERE e.evidence_id = ?
        """, (evidence_id,))
        row = cur.fetchone()
    return dict(row) if row else None
