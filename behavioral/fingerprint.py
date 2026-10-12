"""
BEC-FORGE Behavioral & Sender Identity Fingerprinting Module (Phase 3)

Core Innovation #1: SENDER IDENTITY FINGERPRINTING & IDENTITY DRIFT DETECTION

Builds baseline behavioral identity profiles for senders based on historical emails:
- Display name variants
- Sending domain history
- Typical sending hours (0-23)
- Typical recipients & recipient frequency
- Typical Reply-To and Return-Path patterns
- Common subject line keywords
- Historical authentication pass rate

Compares newly analyzed emails against the historical fingerprint to compute:
- Identity Drift Score (0 - 100)
- Drift Severity (NONE, LOW, MODERATE, HIGH, CRITICAL)
- Multi-dimensional deviation breakdown
"""

import logging
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor
from parser.eml_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class SenderFingerprint:
    sender_address: str
    display_names: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    typical_sending_hours: list[int] = field(default_factory=list)  # e.g., [9, 10, 11, 14, 15, 16, 17]
    typical_recipients: dict[str, int] = field(default_factory=dict) # recipient -> count
    reply_to_addresses: list[str] = field(default_factory=list)
    return_path_addresses: list[str] = field(default_factory=list)
    common_subjects: list[str] = field(default_factory=list)
    auth_pass_rate: float = 1.0
    avg_urgency_score: float = 0.0
    avg_financial_score: float = 0.0
    sample_size: int = 0
    updated_at: str = ""


@dataclass
class DriftComponent:
    dimension: str        # Sending Time, Recipient, Reply-To, Domain, Subject, Language
    severity: str         # NORMAL, LOW, MODERATE, HIGH, CRITICAL
    baseline_value: str
    observed_value: str
    drift_points: float   # Points contributed to overall drift score


@dataclass
class IdentityDriftResult:
    sender_address: str
    has_baseline: bool
    sample_size: int
    identity_drift_score: float  # 0.0 to 100.0
    drift_level: str             # NONE, LOW, MODERATE, HIGH, CRITICAL
    deviations: list[DriftComponent] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Baseline Profile Storage & Retrieval
# ─────────────────────────────────────────────────────────────

def get_sender_fingerprint(sender_address: str) -> Optional[SenderFingerprint]:
    """Retrieve historical sender identity fingerprint from SQLite."""
    if not sender_address:
        return None
    addr = sender_address.strip().lower()
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT * FROM sender_fingerprints WHERE sender_address = ?",
            (addr,),
        )
        row = cur.fetchone()

    if not row:
        return None

    try:
        return SenderFingerprint(
            sender_address=row["sender_address"],
            display_names=json.loads(row["display_names"] or "[]"),
            domains=json.loads(row["domains"] or "[]"),
            typical_sending_hours=json.loads(row["typical_sending_hours"] or "[]"),
            typical_recipients=json.loads(row["typical_recipients"] or "{}"),
            reply_to_addresses=json.loads(row["reply_to_addresses"] or "[]"),
            return_path_addresses=json.loads(row["return_path_addresses"] or "[]"),
            common_subjects=json.loads(row["common_subjects"] or "[]"),
            auth_pass_rate=float(row["auth_pass_rate"] or 1.0),
            avg_urgency_score=float(row["avg_urgency_score"] or 0.0),
            avg_financial_score=float(row["avg_financial_score"] or 0.0),
            sample_size=int(row["sample_size"] or 0),
            updated_at=row["updated_at"] or "",
        )
    except Exception as e:
        logger.error("Error parsing sender fingerprint for %s: %s", addr, e)
        return None


def save_sender_fingerprint(fp: SenderFingerprint) -> None:
    """Save or update sender identity fingerprint in SQLite."""
    now = datetime.now(timezone.utc).isoformat()
    with db_cursor() as (conn, cur):
        cur.execute(
            """INSERT INTO sender_fingerprints (
                sender_address, display_names, domains, typical_sending_hours,
                typical_recipients, reply_to_addresses, return_path_addresses,
                common_subjects, auth_pass_rate, avg_urgency_score, avg_financial_score,
                sample_size, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sender_address) DO UPDATE SET
                display_names = excluded.display_names,
                domains = excluded.domains,
                typical_sending_hours = excluded.typical_sending_hours,
                typical_recipients = excluded.typical_recipients,
                reply_to_addresses = excluded.reply_to_addresses,
                return_path_addresses = excluded.return_path_addresses,
                common_subjects = excluded.common_subjects,
                auth_pass_rate = excluded.auth_pass_rate,
                avg_urgency_score = excluded.avg_urgency_score,
                avg_financial_score = excluded.avg_financial_score,
                sample_size = excluded.sample_size,
                updated_at = excluded.updated_at
            """,
            (
                fp.sender_address.strip().lower(),
                json.dumps(fp.display_names),
                json.dumps(fp.domains),
                json.dumps(fp.typical_sending_hours),
                json.dumps(fp.typical_recipients),
                json.dumps(fp.reply_to_addresses),
                json.dumps(fp.return_path_addresses),
                json.dumps(fp.common_subjects),
                fp.auth_pass_rate,
                fp.avg_urgency_score,
                fp.avg_financial_score,
                fp.sample_size,
                now,
            ),
        )


def build_or_update_fingerprint(
    sender_address: str,
    parsed_email: ParsedEmail,
    urgency_score: float = 0.0,
    financial_score: float = 0.0,
    auth_passed: bool = True,
) -> SenderFingerprint:
    """Ingest a verified benign email into the historical sender identity profile."""
    addr = sender_address.strip().lower()
    fp = get_sender_fingerprint(addr)
    if not fp:
        fp = SenderFingerprint(
            sender_address=addr,
            display_names=[],
            domains=[],
            typical_sending_hours=[],
            typical_recipients={},
            reply_to_addresses=[],
            return_path_addresses=[],
            common_subjects=[],
            auth_pass_rate=1.0,
            avg_urgency_score=0.0,
            avg_financial_score=0.0,
            sample_size=0,
        )

    # Update counts
    fp.sample_size += 1

    if parsed_email.from_name and parsed_email.from_name not in fp.display_names:
        fp.display_names.append(parsed_email.from_name)

    if parsed_email.from_domain and parsed_email.from_domain not in fp.domains:
        fp.domains.append(parsed_email.from_domain)

    # Sending hour (0-23)
    if parsed_email.date_parsed:
        hour = parsed_email.date_parsed.hour
        if hour not in fp.typical_sending_hours:
            fp.typical_sending_hours.append(hour)
            fp.typical_sending_hours.sort()

    # Recipients
    for r in (parsed_email.to_addresses + parsed_email.cc_addresses):
        fp.typical_recipients[r] = fp.typical_recipients.get(r, 0) + 1

    # Routing
    if parsed_email.reply_to_address and parsed_email.reply_to_address not in fp.reply_to_addresses:
        fp.reply_to_addresses.append(parsed_email.reply_to_address)
    if parsed_email.return_path_address and parsed_email.return_path_address not in fp.return_path_addresses:
        fp.return_path_addresses.append(parsed_email.return_path_address)

    # Subject keywords
    if parsed_email.subject:
        subj_words = [w.lower() for w in parsed_email.subject.split() if len(w) > 3]
        for w in subj_words[:5]:
            if w not in fp.common_subjects:
                fp.common_subjects.append(w)

    # Averages
    n = fp.sample_size
    fp.avg_urgency_score = ((fp.avg_urgency_score * (n - 1)) + urgency_score) / n
    fp.avg_financial_score = ((fp.avg_financial_score * (n - 1)) + financial_score) / n
    pass_val = 1.0 if auth_passed else 0.0
    fp.auth_pass_rate = ((fp.auth_pass_rate * (n - 1)) + pass_val) / n

    save_sender_fingerprint(fp)
    return fp


# ─────────────────────────────────────────────────────────────
# Identity Drift Analysis Engine
# ─────────────────────────────────────────────────────────────

def compare_sender_identity(
    parsed_email: ParsedEmail,
    urgency_score: float = 0.0,
    financial_score: float = 0.0,
) -> IdentityDriftResult:
    """
    Compare email under investigation against sender's historical baseline profile.
    Detects Identity Drift across multiple dimensions:
    1. Sending Time (e.g. 2:40 AM vs 9 AM - 6 PM baseline)
    2. Recipient Relationship (First-time / unknown recipient)
    3. Reply-To Deviation (Sudden alternative Reply-To mailbox)
    4. Domain Consistency
    5. Linguistic / Urgency Shifts
    """
    sender = (parsed_email.from_address or "").strip().lower()
    fp = get_sender_fingerprint(sender)

    if not fp or fp.sample_size < 1:
        # First time seen sender or no baseline established yet
        return IdentityDriftResult(
            sender_address=sender,
            has_baseline=False,
            sample_size=0,
            identity_drift_score=0.0,
            drift_level="NONE",
            deviations=[],
            findings=[{
                "severity": "INFO",
                "title": "No Historical Baseline for Sender",
                "description": f"Sender '{sender}' has no historical fingerprint in the database. Behavioral baseline established from current evidence.",
                "evidence_field": "From",
                "evidence_value": sender,
            }],
        )

    deviations: list[DriftComponent] = []
    drift_score = 0.0

    # 1. Sending Hours Anomaly
    if parsed_email.date_parsed:
        hour = parsed_email.date_parsed.hour
        if fp.typical_sending_hours:
            if hour not in fp.typical_sending_hours:
                # Check distance from typical hours
                min_dist = min(abs(hour - h) for h in fp.typical_sending_hours)
                sev = "CRITICAL" if min_dist >= 4 else "HIGH" if min_dist >= 2 else "MODERATE"
                pts = 30.0 if sev == "CRITICAL" else 20.0 if sev == "HIGH" else 10.0
                drift_score += pts
                h_range = f"{min(fp.typical_sending_hours):02d}:00–{max(fp.typical_sending_hours):02d}:00"
                deviations.append(DriftComponent(
                    dimension="Sending Time",
                    severity=sev,
                    baseline_value=f"Typical hours: {h_range}",
                    observed_value=f"{hour:02d}:{parsed_email.date_parsed.minute:02d} UTC (Anomaly distance: {min_dist}h)",
                    drift_points=pts,
                ))

    # 2. Recipient Relationship Anomaly
    new_recipients = []
    current_recips = parsed_email.to_addresses + parsed_email.cc_addresses
    for r in current_recips:
        if r and r not in fp.typical_recipients:
            new_recipients.append(r)

    if new_recipients:
        pts = 25.0
        drift_score += pts
        known_top = list(fp.typical_recipients.keys())[:3]
        deviations.append(DriftComponent(
            dimension="Recipient Relationship",
            severity="HIGH",
            baseline_value=f"Known recipients: {', '.join(known_top) if known_top else 'None'}",
            observed_value=f"NEW RECIPIENT(S): {', '.join(new_recipients[:3])}",
            drift_points=pts,
        ))

    # 3. Reply-To Redirection Anomaly
    observed_rt = (parsed_email.reply_to_address or "").strip().lower()
    if observed_rt:
        if fp.reply_to_addresses and observed_rt not in fp.reply_to_addresses:
            pts = 35.0
            drift_score += pts
            deviations.append(DriftComponent(
                dimension="Reply-To Routing",
                severity="CRITICAL",
                baseline_value=f"Historical Reply-To: {', '.join(fp.reply_to_addresses[:2])}",
                observed_value=f"NEW UNSEEN REPLY-TO: {observed_rt}",
                drift_points=pts,
            ))
        elif not fp.reply_to_addresses and observed_rt != sender:
            pts = 20.0
            drift_score += pts
            deviations.append(DriftComponent(
                dimension="Reply-To Routing",
                severity="HIGH",
                baseline_value=f"Default (Matches From: {sender})",
                observed_value=f"Alternative Reply-To: {observed_rt}",
                drift_points=pts,
            ))

    # 4. Domain Anomaly
    observed_dom = (parsed_email.from_domain or "").strip().lower()
    if fp.domains and observed_dom not in fp.domains:
        pts = 30.0
        drift_score += pts
        deviations.append(DriftComponent(
            dimension="Domain Identity",
            severity="CRITICAL",
            baseline_value=f"Historical domain(s): {', '.join(fp.domains)}",
            observed_value=f"NEW DOMAIN: {observed_dom}",
            drift_points=pts,
        ))

    # 5. Language / Urgency Deviation
    urgency_delta = urgency_score - fp.avg_urgency_score
    if urgency_delta >= 40.0:
        pts = 15.0
        drift_score += pts
        deviations.append(DriftComponent(
            dimension="Urgency Language",
            severity="HIGH",
            baseline_value=f"Avg urgency score: {fp.avg_urgency_score:.1f}",
            observed_value=f"Sudden spike: {urgency_score:.1f} (+{urgency_delta:.1f})",
            drift_points=pts,
        ))

    # Final Normalized Drift Score (0 - 100)
    final_drift = min(100.0, round(drift_score, 1))

    # Drift Level Categorization
    if final_drift >= 75.0:
        drift_level = "CRITICAL"
    elif final_drift >= 50.0:
        drift_level = "HIGH"
    elif final_drift >= 25.0:
        drift_level = "MODERATE"
    elif final_drift > 0.0:
        drift_level = "LOW"
    else:
        drift_level = "NONE"

    # Forensic Findings Generation
    findings = []
    if drift_level in ("HIGH", "CRITICAL"):
        findings.append({
            "severity": "CRITICAL" if drift_level == "CRITICAL" else "HIGH",
            "title": f"IDENTITY DRIFT: {drift_level} ({final_drift:.0f}/100)",
            "description": (
                f"Significant behavioral deviation detected against sender '{sender}' baseline profile. "
                f"Observed anomalies: {', '.join(d.dimension for d in deviations)}. "
                f"Indicators are consistent with account compromise or impersonation."
            ),
            "evidence_field": "Sender Behavioral Fingerprint",
            "evidence_value": f"Drift Score: {final_drift}/100 based on {fp.sample_size} historical emails",
        })

    for d in deviations:
        findings.append({
            "severity": d.severity,
            "title": f"Behavioral Deviation: {d.dimension}",
            "description": f"Observed '{d.observed_value}' deviates from baseline '{d.baseline_value}'.",
            "evidence_field": f"Fingerprint.{d.dimension}",
            "evidence_value": d.observed_value,
        })

    return IdentityDriftResult(
        sender_address=sender,
        has_baseline=True,
        sample_size=fp.sample_size,
        identity_drift_score=final_drift,
        drift_level=drift_level,
        deviations=deviations,
        findings=findings,
    )
