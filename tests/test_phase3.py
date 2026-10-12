"""
BEC-FORGE Phase 3 Tests — Sender Identity Fingerprinting & Identity Drift Engine
"""

import sys
import os
import pytest
import tempfile
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import config.settings as cfg
from parser.eml_parser import parse_eml
from behavioral.fingerprint import (
    SenderFingerprint,
    save_sender_fingerprint,
    get_sender_fingerprint,
    build_or_update_fingerprint,
    compare_sender_identity,
)
from analysis.orchestrator import run_analysis
from server.app import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    tmp_dir = tempfile.mkdtemp()
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False, dir=tmp_dir)
    tmp_db.close()
    old_db = cfg.DB_PATH
    old_ev = cfg.EVIDENCE_DIR
    cfg.DB_PATH = tmp_db.name
    cfg.EVIDENCE_DIR = tmp_dir

    from database.db import initialize_database
    initialize_database()

    yield

    cfg.DB_PATH = old_db
    cfg.EVIDENCE_DIR = old_ev
    for root, dirs, files in os.walk(tmp_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                os.chmod(fp, 0o644)
            except Exception:
                pass
    shutil.rmtree(tmp_dir, ignore_errors=True)


def make_ceo_baseline_eml() -> bytes:
    return b"""From: Jane Doe <ceo@megacorp.com>
To: management@megacorp.com
Subject: Weekly Leadership Status Update
Date: Tue, 06 Oct 2026 14:30:00 +0000
Message-ID: <ceo001@megacorp.com>
Reply-To: ceo@megacorp.com
Return-Path: <ceo@megacorp.com>
Authentication-Results: mx.megacorp.com;
   dkim=pass header.d=megacorp.com;
   spf=pass smtp.mailfrom=ceo@megacorp.com;
   dmarc=pass header.from=megacorp.com
Received-SPF: pass

Team, here is the weekly recap for executive leadership.
"""


def make_ceo_drifted_compromised_eml() -> bytes:
    # Sent at 02:40 AM (night), to accounts@megacorp.com (new recipient), Reply-To changed to external mailbox
    return b"""From: Jane Doe <ceo@megacorp.com>
To: accounts@megacorp.com
Subject: URGENT: Wire Transfer Authorization Required Immediately
Date: Tue, 06 Oct 2026 02:40:00 +0000
Message-ID: <ceo002@megacorp.com>
Reply-To: jane.private.exec@gmail.com
Return-Path: <ceo@megacorp.com>
Authentication-Results: mx.megacorp.com;
   dkim=pass header.d=megacorp.com;
   spf=pass smtp.mailfrom=ceo@megacorp.com;
   dmarc=pass header.from=megacorp.com
Received-SPF: pass

Urgent. Please transfer funds immediately to the vendor account. Do not delay.
"""


class TestSenderIdentityFingerprinting:

    def test_fingerprint_creation_and_retrieval(self):
        fp = SenderFingerprint(
            sender_address="ceo@megacorp.com",
            display_names=["Jane Doe", "CEO"],
            domains=["megacorp.com"],
            typical_sending_hours=[9, 10, 11, 14, 15, 16],
            typical_recipients={"management@megacorp.com": 12},
            reply_to_addresses=["ceo@megacorp.com"],
            return_path_addresses=["ceo@megacorp.com"],
            common_subjects=["status", "update", "q4"],
            auth_pass_rate=1.0,
            avg_urgency_score=5.0,
            avg_financial_score=0.0,
            sample_size=12,
        )
        save_sender_fingerprint(fp)

        loaded = get_sender_fingerprint("ceo@megacorp.com")
        assert loaded is not None
        assert loaded.sender_address == "ceo@megacorp.com"
        assert loaded.sample_size == 12
        assert "management@megacorp.com" in loaded.typical_recipients
        assert 14 in loaded.typical_sending_hours

    def test_identity_drift_detection_high_or_critical(self):
        # 1. Establish historical baseline for CEO
        fp = SenderFingerprint(
            sender_address="ceo@megacorp.com",
            display_names=["Jane Doe"],
            domains=["megacorp.com"],
            typical_sending_hours=[9, 10, 11, 14, 15, 16],
            typical_recipients={"management@megacorp.com": 20},
            reply_to_addresses=["ceo@megacorp.com"],
            return_path_addresses=["ceo@megacorp.com"],
            common_subjects=["weekly", "update"],
            auth_pass_rate=1.0,
            avg_urgency_score=2.0,
            avg_financial_score=0.0,
            sample_size=20,
        )
        save_sender_fingerprint(fp)

        # 2. Analyze new anomalous email (2:40 AM, new recipient, different Reply-To, urgent)
        parsed_drift = parse_eml(make_ceo_drifted_compromised_eml())
        drift_res = compare_sender_identity(
            parsed_email=parsed_drift,
            urgency_score=80.0,
            financial_score=60.0,
        )

        assert drift_res.has_baseline is True
        assert drift_res.drift_level in ("HIGH", "CRITICAL")
        assert drift_res.identity_drift_score >= 70.0
        dims = [d.dimension for d in drift_res.deviations]
        assert "Sending Time" in dims
        assert "Recipient Relationship" in dims
        assert "Reply-To Routing" in dims

    def test_baseline_learning_from_clean_email(self):
        # Run clean benign email
        analysis = run_analysis(
            raw_bytes=make_ceo_baseline_eml(),
            filename="ceo_clean.eml",
            learn_baseline_if_clean=True,
        )
        assert analysis.risk.total_score < 30.0

        # Check that fingerprint was established
        fp = get_sender_fingerprint("ceo@megacorp.com")
        assert fp is not None
        assert fp.sample_size >= 1
        assert "management@megacorp.com" in fp.typical_recipients

    def test_orchestrator_drift_integration_and_elevation(self):
        # 1. Ingest baseline email
        run_analysis(raw_bytes=make_ceo_baseline_eml(), filename="base1.eml", learn_baseline_if_clean=True)
        run_analysis(raw_bytes=make_ceo_baseline_eml(), filename="base2.eml", learn_baseline_if_clean=True)

        # 2. Ingest drifted email
        drift_analysis = run_analysis(
            raw_bytes=make_ceo_drifted_compromised_eml(),
            filename="drifted.eml",
            learn_baseline_if_clean=False,
        )

        # Behavioral anomaly component should be non-zero
        beh_comp = next((c for c in drift_analysis.risk.components if c.name == "behavioral_anomaly"), None)
        assert beh_comp is not None
        assert beh_comp.raw_score > 50.0
        assert drift_analysis.risk.identity_drift_score > 50.0
        assert drift_analysis.risk.identity_drift_level in ("HIGH", "CRITICAL")

    def test_api_fingerprints_endpoints(self):
        fp = SenderFingerprint(
            sender_address="test@example.com",
            display_names=["Tester"],
            domains=["example.com"],
            typical_sending_hours=[10, 11],
            typical_recipients={"user@corp.com": 5},
            reply_to_addresses=["test@example.com"],
            return_path_addresses=["test@example.com"],
            sample_size=5,
        )
        save_sender_fingerprint(fp)

        resp_list = client.get("/api/fingerprints")
        assert resp_list.status_code == 200
        assert any(f["sender_address"] == "test@example.com" for f in resp_list.json()["fingerprints"])

        resp_get = client.get("/api/fingerprints/test@example.com")
        assert resp_get.status_code == 200
        assert resp_get.json()["sample_size"] == 5

        resp_html = client.get("/senders")
        assert resp_html.status_code == 200
        assert "Sender Identity Fingerprints" in resp_html.text
        assert "test@example.com" in resp_html.text
