"""
BEC-FORGE Phase 6 & Phase 7 Tests — Conversation Hijacking & Attack-Chain Reconstruction
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
from detection.conversation_hijacking import analyse_conversation_hijacking
from detection.attack_chain import reconstruct_attack_chain
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


def make_thread_original_eml() -> bytes:
    return b"""From: Alice Vendor <alice@vendorcorp.com>
To: bob@buyerfirm.com
Subject: Project Alpha Invoice Discussion
Date: Mon, 05 Oct 2026 14:00:00 +0000
Message-ID: <msg_orig_100@vendorcorp.com>
Reply-To: alice@vendorcorp.com
Return-Path: <alice@vendorcorp.com>
Authentication-Results: mx.buyerfirm.com; dkim=pass; spf=pass; dmarc=pass

Hi Bob, please find the discussion points for Project Alpha.
"""


def make_thread_hijacked_reply_eml() -> bytes:
    # In-Reply-To original message, but suddenly redirects Reply-To to attacker webmail + urgent payment update
    return b"""From: Alice Vendor <alice@vendorcorp.com>
To: bob@buyerfirm.com
Subject: Re: Project Alpha Invoice Discussion
Date: Tue, 06 Oct 2026 09:30:00 +0000
Message-ID: <msg_reply_200@vendorcorp.com>
In-Reply-To: <msg_orig_100@vendorcorp.com>
References: <msg_orig_100@vendorcorp.com>
Reply-To: alice.vendor.payments@gmail.com
Return-Path: <alice@vendorcorp.com>
Authentication-Results: mx.buyerfirm.com; dkim=pass; spf=pass; dmarc=pass

Bob, our banking coordinates have changed. Wire transfer payment immediately to our new routing account.
"""


class TestPhase6ConversationHijacking:

    def test_thread_header_extraction(self):
        parsed = parse_eml(make_thread_hijacked_reply_eml())
        assert parsed.in_reply_to == "<msg_orig_100@vendorcorp.com>"
        assert len(parsed.references) >= 1

    def test_hijack_detected_on_reply_to_and_financial_shift(self):
        # 1. Ingest original parent thread email
        orig_analysis = run_analysis(
            raw_bytes=make_thread_original_eml(),
            filename="orig_thread.eml",
        )
        assert orig_analysis.risk.total_score < 30.0

        # 2. Ingest hijacked reply
        hijack_analysis = run_analysis(
            raw_bytes=make_thread_hijacked_reply_eml(),
            filename="hijacked_reply.eml",
        )

        assert hijack_analysis.hijack.is_part_of_thread is True
        assert hijack_analysis.hijack.hijack_detected is True
        assert hijack_analysis.hijack.hijack_score >= 70.0
        dims = [a.dimension for a in hijack_analysis.hijack.anomalies]
        assert "REPLY_TO_ALTERATION" in dims
        assert "FINANCIAL_INJECTION" in dims


class TestPhase7AttackChainReconstruction:

    def test_multi_stage_attack_chain_reconstructed(self):
        # Ingest original thread email
        run_analysis(raw_bytes=make_thread_original_eml(), filename="email1.eml")
        # Ingest hijacked thread reply
        analysis = run_analysis(raw_bytes=make_thread_hijacked_reply_eml(), filename="email2.eml")
        
        chain = reconstruct_attack_chain(analysis.evidence["evidence_id"])
        assert chain.attack_detected is True
        assert chain.total_stages_observed >= 3
        assert chain.confidence_level in ("HIGH", "CRITICAL")
        
        stage_names = [s.stage_name for s in chain.stages if s.status == "CONFIRMED"]
        assert "Financial Diversion Request" in stage_names
        assert "Payment Execution Mandate" in stage_names

    def test_api_attack_chain_endpoint(self):
        analysis = run_analysis(raw_bytes=make_thread_hijacked_reply_eml(), filename="api_chain.eml")
        ev_id = analysis.evidence["evidence_id"]

        resp = client.get(f"/api/attack-chain/{ev_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"] == ev_id
        assert "stages" in data
        assert len(data["stages"]) == 7
        assert data["attack_detected"] is True
