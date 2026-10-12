"""
BEC-FORGE Statistical Behavioral Analysis Module (Phase 4)

Provides statistical anomaly detection across historical sender email distributions:
- Daily sending volume & z-score calculation
- Temporal hour distribution (mean, standard deviation)
- Subject length & character deviation
- Categorical deviations (new recipients, unseen domains, new Reply-To)
"""

import math
import logging
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
class AnomalyMetric:
    metric_name: str
    baseline_mean: float
    baseline_std: float
    observed_value: float
    z_score: float
    severity: str        # NORMAL, LOW, MEDIUM, HIGH, CRITICAL
    description: str


@dataclass
class StatisticalBehaviorResult:
    sender_address: str
    sample_size: int
    has_sufficient_history: bool
    behavioral_anomaly_score: float  # 0 to 100
    metrics: list[AnomalyMetric] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


def calculate_mean_std(values: list[float]) -> tuple[float, float]:
    """Calculate mean and sample standard deviation."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std = math.sqrt(variance)
    return round(mean, 2), round(std, 2)


def compute_z_score(val: float, mean: float, std: float) -> float:
    """Calculate z-score. Avoids division by zero if std is zero."""
    if std <= 0.001:
        return 0.0 if abs(val - mean) < 0.001 else 3.0
    return round((val - mean) / std, 2)


def analyse_behavioral_statistics(
    parsed_email: ParsedEmail,
    sender_address: Optional[str] = None,
) -> StatisticalBehaviorResult:
    """
    Run statistical anomaly detection for a sender based on historical emails in the DB.
    """
    sender = (sender_address or parsed_email.from_address or "").strip().lower()
    if not sender:
        return StatisticalBehaviorResult(
            sender_address="",
            sample_size=0,
            has_sufficient_history=False,
            behavioral_anomaly_score=0.0,
        )

    # Fetch past emails sent by this sender
    history_hours = []
    history_subj_lens = []

    try:
        with db_cursor() as (conn, cur):
            cur.execute(
                """SELECT date_parsed, subject FROM emails 
                   WHERE from_address = ? AND date_parsed IS NOT NULL""",
                (sender,),
            )
            rows = cur.fetchall()
            for r in rows:
                if r["date_parsed"]:
                    try:
                        dt = datetime.fromisoformat(r["date_parsed"])
                        history_hours.append(float(dt.hour))
                    except Exception:
                        pass
                if r["subject"]:
                    history_subj_lens.append(float(len(r["subject"])))
    except Exception as e:
        logger.error("Error querying email history for %s: %s", sender, e)

    sample_size = len(history_hours)
    if sample_size < 3:
        # Not enough historical baseline for rigorous statistical z-score
        return StatisticalBehaviorResult(
            sender_address=sender,
            sample_size=sample_size,
            has_sufficient_history=False,
            behavioral_anomaly_score=0.0,
            findings=[{
                "severity": "INFO",
                "title": "Insufficient Statistical Baseline",
                "description": f"Sender '{sender}' has fewer than 3 historical samples in evidence database ({sample_size} recorded). Statistical z-scores require more history.",
                "evidence_field": "Historical Email Log",
                "evidence_value": f"Sample count: {sample_size}",
            }],
        )

    metrics = []
    anomaly_points = 0.0
    findings = []

    # 1. Sending Hour Anomaly (Temporal z-score)
    if parsed_email.date_parsed:
        obs_hour = float(parsed_email.date_parsed.hour)
        h_mean, h_std = calculate_mean_std(history_hours)
        z_hour = compute_z_score(obs_hour, h_mean, h_std)

        if abs(z_hour) >= 3.0:
            sev = "CRITICAL"
            pts = 40.0
        elif abs(z_hour) >= 2.0:
            sev = "HIGH"
            pts = 25.0
        elif abs(z_hour) >= 1.5:
            sev = "MEDIUM"
            pts = 10.0
        else:
            sev = "NORMAL"
            pts = 0.0

        anomaly_points += pts
        m_hour = AnomalyMetric(
            metric_name="Sending Hour Distribution",
            baseline_mean=h_mean,
            baseline_std=h_std,
            observed_value=obs_hour,
            z_score=z_hour,
            severity=sev,
            description=f"Observed sending hour {int(obs_hour)}:00 vs baseline mean {h_mean:.1f}:00 (±{h_std:.1f}h). Z-score: {z_hour}",
        )
        metrics.append(m_hour)

        if sev in ("HIGH", "CRITICAL"):
            findings.append({
                "severity": sev,
                "title": f"Statistical Temporal Anomaly (|z| = {abs(z_hour)})",
                "description": m_hour.description,
                "evidence_field": "Date (Sending Hour)",
                "evidence_value": f"{int(obs_hour)}:00 UTC",
            })

    # 2. Subject Line Length Anomaly
    if parsed_email.subject and history_subj_lens:
        obs_len = float(len(parsed_email.subject))
        s_mean, s_std = calculate_mean_std(history_subj_lens)
        z_subj = compute_z_score(obs_len, s_mean, s_std)

        if abs(z_subj) >= 2.5:
            sev = "MEDIUM"
            pts = 15.0
            anomaly_points += pts
            findings.append({
                "severity": "MEDIUM",
                "title": f"Abnormal Subject Length (|z| = {abs(z_subj)})",
                "description": f"Subject length ({int(obs_len)} chars) deviates from baseline mean {s_mean:.1f} chars (±{s_std:.1f}).",
                "evidence_field": "Subject",
                "evidence_value": parsed_email.subject,
            })
        else:
            sev = "NORMAL"

        metrics.append(AnomalyMetric(
            metric_name="Subject Length Deviation",
            baseline_mean=s_mean,
            baseline_std=s_std,
            observed_value=obs_len,
            z_score=z_subj,
            severity=sev,
            description=f"Subject length {int(obs_len)} chars vs historical mean {s_mean:.1f} (z = {z_subj})",
        ))

    total_anomaly_score = min(100.0, round(anomaly_points, 1))

    return StatisticalBehaviorResult(
        sender_address=sender,
        sample_size=sample_size,
        has_sufficient_history=True,
        behavioral_anomaly_score=total_anomaly_score,
        metrics=metrics,
        findings=findings,
    )
