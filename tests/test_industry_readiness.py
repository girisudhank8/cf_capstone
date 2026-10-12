"""
BEC-FORGE Test Suite — Industry Readiness & Real-World DFIR Operations

Tests verify:
1. Hop-by-hop RFC-822 mail routing telemetry and MTA delay tracking
2. Batch evidence ingestion from ZIP containers and MBOX mailbox exports
3. Forensic chain-of-custody cryptographic integrity audit (ISO/IEC 27037)
4. Court-admissible forensic PDF dossier generation with ReportLab
5. Real-world incident case benchmark ingestion and analysis
6. REST API and Web Console endpoints for PDF download, audit, and batch intake
"""

import io
import os
import sys
import tempfile
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test environment settings
os.environ["BEC_FORGE_TEST"] = "1"
import config.settings as app_settings
app_settings.DB_PATH = ":memory:"

from database.db import initialize_database
from acquisition.evidence import acquire_evidence, audit_all_evidence, verify_evidence_integrity
from acquisition.batch_ingest import ingest_zip_archive, ingest_mbox_stream, ingest_directory
from analysis.routing_analysis import trace_mail_routing
from parser.mbox_parser import parse_mbox_bytes
from reporting.pdf_report import generate_forensic_pdf_report
from datasets.forensic_cases import (
    build_operation_wireshifter_case,
    build_enterprise_baseline_case,
    build_executive_payroll_case,
)
from server.app import app


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Set up clean database and temporary evidence directory for each test."""
    test_db = tmp_path / "test_readiness.db"
    test_ev = tmp_path / "evidence_vault"
    test_ev.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(app_settings, "DB_PATH", str(test_db))
    monkeypatch.setattr(app_settings, "EVIDENCE_DIR", str(test_ev))
    initialize_database()


# ─────────────────────────────────────────────────────────────
# 1. Hop-by-Hop Mail Routing Tracer Tests
# ─────────────────────────────────────────────────────────────

class TestMailRoutingTracer:
    def test_trace_mail_routing_chronology_and_ips(self):
        received_hdrs = [
            # Topmost header (destination gateway)
            "from mail-relay02.destcorp.com (mail-relay02.destcorp.com [198.51.100.50]) by mx01.destcorp.com with ESMTPS id DEST-992 for <cfo@destcorp.com>; Tue, 06 Oct 2026 10:15:30 +0000",
            # Intermediate relay
            "from edge.relay-provider.net (edge.relay-provider.net [203.0.113.88]) by mail-relay02.destcorp.com with ESMTPS id RELAY-112; Tue, 06 Oct 2026 10:15:20 +0000",
            # Originating MTA (bottom header)
            "from internal-workstation.origincorp.com ([10.0.5.12]) by edge.relay-provider.net with ESMTPSA id ORIGIN-01; Tue, 06 Oct 2026 10:15:00 +0000",
        ]

        result = trace_mail_routing(received_hdrs, x_originating_ip="198.51.100.99")
        assert result.total_hops == 3
        # Chronological order: hop 1 should be the originating MTA ([10.0.5.12])
        assert result.hops[0].hop_number == 1
        assert result.hops[0].from_ip == "10.0.5.12"
        assert result.hops[0].from_ip_type == "PRIVATE_RFC1918"

        # Hop 2 should be the intermediate relay
        assert result.hops[1].hop_number == 2
        assert result.hops[1].from_ip == "203.0.113.88"
        assert result.hops[1].from_ip_type == "PUBLIC"
        assert result.hops[1].delay_seconds == pytest.approx(20.0, 1.0)

        # Hop 3 should be destination gateway
        assert result.hops[2].hop_number == 3
        assert result.hops[2].from_ip == "198.51.100.50"
        assert result.hops[2].delay_seconds == pytest.approx(10.0, 1.0)

        # Originating IP from X-Originating-IP
        assert result.originating_ip == "198.51.100.99"
        assert result.originating_ip_type == "PUBLIC"

    def test_trace_mail_routing_anomaly_detection(self):
        # Header with excessive queue delay (> 3600 seconds)
        received_hdrs = [
            "from relay2.corp.com ([203.0.113.10]) by mx.corp.com with ESMTP; Tue, 06 Oct 2026 15:00:00 +0000",
            "from relay1.corp.com ([203.0.113.20]) by relay2.corp.com with ESMTP; Tue, 06 Oct 2026 10:00:00 +0000",
        ]
        result = trace_mail_routing(received_hdrs)
        assert result.total_hops == 2
        assert len(result.anomalies_detected) > 0
        assert any("Unusual relay delay" in a for a in result.anomalies_detected)
        assert result.routing_score > 0.0


# ─────────────────────────────────────────────────────────────
# 2. Batch Evidence Ingestion & MBOX Tests
# ─────────────────────────────────────────────────────────────

class TestBatchIngestionEngine:
    def test_ingest_zip_archive(self):
        # Create a test ZIP archive containing 2 emails
        wire_emails = build_operation_wireshifter_case()[:2]
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
            for fname, content in wire_emails:
                z.writestr(fname, content)
        zip_bytes = zip_buf.getvalue()

        result = ingest_zip_archive(zip_bytes, case_id="CASE-TEST-ZIP")
        assert result.total_processed == 2
        assert result.total_successful == 2
        assert result.total_failed == 0
        assert len(result.items) == 2
        assert result.items[0].evidence_id.startswith("EVD-")
        assert len(result.items[0].sha256) == 64

    def test_ingest_mbox_stream(self):
        import mailbox
        mbox_buf = io.BytesIO()
        # Build mbox bytes with 2 messages
        with tempfile.NamedTemporaryFile(suffix=".mbox", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            box = mailbox.mbox(str(tmp_path))
            for fname, content in build_operation_wireshifter_case()[:2]:
                box.add(mailbox.mboxMessage(content.encode("utf-8")))
            box.flush()
            box.close()
            mbox_bytes = tmp_path.read_bytes()
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        result = ingest_mbox_stream(mbox_bytes, case_id="CASE-TEST-MBOX")
        assert result.total_processed == 2
        assert result.total_successful == 2
        assert result.total_failed == 0
        assert len(result.items) == 2


# ─────────────────────────────────────────────────────────────
# 3. Cryptographic Chain of Custody Audit Tests
# ─────────────────────────────────────────────────────────────

class TestForensicCryptographicAudit:
    def test_audit_all_evidence_integrity_verified(self):
        eml_bytes = b"From: alice@corp.com\nTo: bob@corp.com\nSubject: Test\n\nHello"
        ev = acquire_evidence(eml_bytes, "test_evidence.eml", case_id="CASE-AUDIT-01")

        audit = audit_all_evidence()
        assert audit["total"] == 1
        assert audit["verified"] == 1
        assert audit["tampered"] == 0
        assert audit["missing"] == 0
        assert audit["chain_intact"] is True

    def test_audit_detects_tampering(self):
        eml_bytes = b"From: alice@corp.com\nTo: bob@corp.com\nSubject: Test\n\nHello"
        ev = acquire_evidence(eml_bytes, "tamper_test.eml", case_id="CASE-AUDIT-02")
        stored_path = Path(ev["stored_path"])

        # Intentionally alter the file on disk to simulate evidence tampering
        stored_path.chmod(0o666)
        stored_path.write_bytes(b"TAMPERED EVIDENCE BY THREAT ACTOR")
        stored_path.chmod(0o444)

        audit = audit_all_evidence()
        assert audit["total"] == 1
        assert audit["tampered"] == 1
        assert audit["verified"] == 0
        assert audit["chain_intact"] is False


# ─────────────────────────────────────────────────────────────
# 4. Court-Admissible Forensic PDF Dossier Generation Tests
# ─────────────────────────────────────────────────────────────

class TestForensicPDFReport:
    def test_generate_pdf_report_bytes(self):
        analysis_data = {
            "evidence": {
                "evidence_id": "EVD-2026-9999",
                "case_id": "CASE-2026-COURT",
                "filename": "wire_transfer_intercept.eml",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size": 1845,
                "acquired_at": "2026-10-07T12:00:00+00:00",
            },
            "email": {
                "subject": "URGENT: Redirection of Q4 Wire Remittance",
                "from_name": "Titan Billing Desk",
                "from_address": "accounts@titan-industria1.com",
                "reply_to": "wire-settlements@titan-financial-routing.net",
                "return_path": "bounce@untrusted-relay.xyz",
                "body_plain": "Please wire funds immediately to Offshore Mercantile Bank.",
            },
            "risk": {
                "total_score": 88.5,
                "risk_level": "CRITICAL",
                "threat_hypothesis": "POTENTIAL_SPOOFING",
                "identity_consistency_score": 12.0,
                "component_scores": '{"urgency_language": 85.0, "financial_language": 90.0, "authority_secrecy": 45.0, "behavioral_anomaly": 75.0}',
                "counterfactuals": '[{"description": "If Reply-To domain aligned with sender domain", "counterfactual_score": 72.5, "delta": 16.0}]',
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "category": "DOMAIN ANOMALY",
                    "title": "Lookalike typosquatted domain detected",
                    "description": "Sender domain titan-industria1.com uses character replacement '1' for 'l'.",
                    "evidence_field": "From",
                },
                {
                    "severity": "HIGH",
                    "category": "REPLY-TO MISMATCH",
                    "title": "Reply-To diverges to untrusted infrastructure",
                    "description": "Replies directed to titan-financial-routing.net.",
                    "evidence_field": "Reply-To",
                },
            ],
            "headers": [
                ("From", "accounts@titan-industria1.com"),
                ("Reply-To", "wire-settlements@titan-financial-routing.net"),
                ("Authentication-Results", "mx.corp.com; dkim=fail; spf=fail"),
            ],
        }

        pdf = generate_forensic_pdf_report(
            analysis_data=analysis_data,
            examiner_name="Special Agent J. Vance, DFIR",
            agency_name="National Cyber Forensics Laboratory",
        )
        assert isinstance(pdf, bytes)
        assert len(pdf) > 2000
        # Check standard PDF header magic bytes %PDF-
        assert pdf.startswith(b"%PDF-")


# ─────────────────────────────────────────────────────────────
# 5. FastAPI Endpoints & UI Route Tests
# ─────────────────────────────────────────────────────────────

class TestServerIndustryEndpoints:
    def test_api_download_pdf_report_endpoint(self):
        client = TestClient(app)
        wire_cases = build_operation_wireshifter_case()
        eml_bytes = wire_cases[3][1].encode("utf-8")  # wire attack email

        # Ingest email via API
        r_upload = client.post(
            "/api/analyze",
            files={"file": ("wire_attack.eml", eml_bytes, "message/rfc822")},
            data={"case_id": "CASE-TEST-PDF"},
        )
        assert r_upload.status_code == 200
        ev_id = r_upload.json()["evidence_id"]

        # Request PDF download
        r_pdf = client.get(f"/api/reports/{ev_id}/pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert f"Forensic_Report_{ev_id}.pdf" in r_pdf.headers["content-disposition"]
        assert r_pdf.content.startswith(b"%PDF-")

    def test_api_audit_endpoint(self):
        client = TestClient(app)
        r = client.get("/api/audit")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "verified" in data
        assert "chain_intact" in data

    def test_batch_acquire_api_endpoint(self):
        client = TestClient(app)
        wire_cases = build_operation_wireshifter_case()[:2]
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            for fname, content in wire_cases:
                z.writestr(fname, content)

        r = client.post(
            "/api/acquire/batch",
            files={"file": ("batch_seizure.zip", zip_buf.getvalue(), "application/zip")},
            data={"case_id": "CASE-BATCH-API"},
        )
        assert r.status_code == 200
        res = r.json()
        assert res["format"] == "zip"
        assert res["total_processed"] == 2
        assert res["total_successful"] == 2

    def test_load_case_benchmark_endpoint(self):
        client = TestClient(app)
        # Load payroll benchmark
        r = client.post("/acquisition/load-case", data={"target": "payroll"}, follow_redirects=False)
        assert r.status_code == 303
        assert "/analysis?id=" in r.headers["location"]

    def test_reset_workspace_endpoint(self):
        client = TestClient(app)
        r = client.post("/evidence/reset", follow_redirects=False)
        assert r.status_code == 303
        assert "/?success=" in r.headers["location"]

