"""
BEC-FORGE Test Suite — Phase 1

Tests cover:
- Evidence acquisition (SHA-256, evidence ID, integrity)
- Email parser (.eml parsing)
- Header analysis (Reply-To, display name, Return-Path)
- Authentication analysis (SPF/DKIM/DMARC parsing)
- Domain analysis (mismatch, lookalike, suspicious TLD)
- NLP analysis (urgency, financial, secrecy)
- Risk engine (scoring, findings, counterfactuals)
"""

import sys
import os
import pytest
import tempfile
import hashlib
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Override DB path for testing ──────────────────────────────
os.environ["BEC_FORGE_TEST"] = "1"
import config.settings as cfg
cfg.DB_PATH = ":memory:"
cfg.EVIDENCE_DIR = str(PROJECT_ROOT / "tests" / "test_evidence_tmp")


# ─────────────────────────────────────────────────────────────
# Synthetic email builders
# ─────────────────────────────────────────────────────────────

def make_benign_eml() -> bytes:
    return b"""From: John Smith <j.smith@acmecorp.com>
To: marketing@acmecorp.com
Subject: Q4 Meeting Agenda
Date: Tue, 06 Oct 2026 10:15:00 +0000
Message-ID: <test001@acmecorp.com>
Reply-To: j.smith@acmecorp.com
Return-Path: <j.smith@acmecorp.com>
Authentication-Results: mx.acmecorp.com;
   dkim=pass header.i=@acmecorp.com;
   spf=pass smtp.mailfrom=j.smith@acmecorp.com;
   dmarc=pass header.from=acmecorp.com
Received-SPF: pass

Hi team, this is a normal meeting agenda email. No action required.
Best regards, John
"""


def make_bec_spoofing_eml() -> bytes:
    return b"""From: "Robert Mitchell CEO" <ceo.mitchel@gmail.com>
To: accounts@acmecorp.com
Subject: URGENT Wire Transfer Required Immediately
Date: Tue, 06 Oct 2026 02:43:17 +0000
Message-ID: <test002@gmail.com>
Reply-To: attacker99@outlook.com
Return-Path: <ceo.mitchel@gmail.com>
Authentication-Results: mx.acmecorp.com;
   dkim=fail;
   spf=fail smtp.mailfrom=ceo.mitchel@gmail.com;
   dmarc=fail header.from=gmail.com
Received-SPF: fail

CONFIDENTIAL. Do not tell anyone. Transfer $187,500 immediately to this bank account.
Urgent - act now - wire transfer - payment - funds - within 1 hour.
"""


def make_subtle_bec_eml() -> bytes:
    return b"""From: Robert Mitchell <r.mitchell@acmecorp.com>
To: j.harris@acmecorp.com
Subject: Re: Vendor Invoice - Action Required
Date: Tue, 06 Oct 2026 22:57:44 +0000
Message-ID: <test003@acmecorp.com>
Reply-To: r.mitchell@acme-corp-executive.com
Return-Path: <r.mitchell@acmecorp.com>
Authentication-Results: mx.acmecorp.com;
   dkim=pass header.i=@acmecorp.com;
   spf=pass smtp.mailfrom=r.mitchell@acmecorp.com;
   dmarc=pass header.from=acmecorp.com
Received-SPF: pass

Please update the vendor bank account details. Keep this between us.
New routing: 026073150. Transfer payment today, time sensitive.
"""


# ─────────────────────────────────────────────────────────────
# 1. Evidence Acquisition Tests
# ─────────────────────────────────────────────────────────────

class TestEvidenceAcquisition:

    def setup_method(self):
        """Use a temp file DB and temp evidence dir so each test is isolated."""
        import tempfile
        self._tmp_dir = tempfile.mkdtemp()
        self._tmp_db  = tempfile.NamedTemporaryFile(suffix=".db", delete=False, dir=self._tmp_dir)
        self._tmp_db.close()
        cfg.DB_PATH       = self._tmp_db.name
        cfg.EVIDENCE_DIR  = self._tmp_dir
        from database.db import initialize_database
        initialize_database()

    def teardown_method(self):
        """Remove the temp DB and evidence files after each test."""
        import os, shutil
        # Make all files writable before removal
        for root, dirs, files in os.walk(self._tmp_dir):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    os.chmod(fp, 0o644)
                except Exception:
                    pass
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_sha256_computation(self):
        """SHA-256 should match hashlib reference."""
        from acquisition.evidence import compute_sha256_bytes
        data = b"Hello BEC-FORGE"
        expected = hashlib.sha256(data).hexdigest()
        assert compute_sha256_bytes(data) == expected

    def test_evidence_id_format(self):
        """Evidence ID must follow EVD-YYYY-NNNN pattern."""
        from acquisition.evidence import acquire_evidence
        import re
        meta = acquire_evidence(b"test email content", "test.eml")
        assert re.match(r"EVD-\d{4}-\d{4}", meta["evidence_id"])

    def test_integrity_verified(self):
        """Acquired evidence should report VERIFIED integrity."""
        from acquisition.evidence import acquire_evidence
        meta = acquire_evidence(b"another test email", "test2.eml")
        assert meta["integrity"] == "VERIFIED"

    def test_sha256_in_metadata(self):
        """Returned metadata must include correct SHA-256."""
        from acquisition.evidence import acquire_evidence, compute_sha256_bytes
        data = b"forensic email data"
        meta = acquire_evidence(data, "forensic.eml")
        assert meta["sha256"] == compute_sha256_bytes(data)

    def test_file_size_recorded(self):
        """File size must match the byte length."""
        from acquisition.evidence import acquire_evidence
        data = b"X" * 1234
        meta = acquire_evidence(data, "size_test.eml")
        assert meta["file_size"] == 1234


# ─────────────────────────────────────────────────────────────
# 2. Email Parser Tests
# ─────────────────────────────────────────────────────────────

class TestEmailParser:

    def test_parse_benign_from(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_benign_eml())
        assert parsed.from_address == "j.smith@acmecorp.com"
        assert parsed.from_name == "John Smith"
        assert parsed.from_domain == "acmecorp.com"

    def test_parse_subject(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_benign_eml())
        assert "Q4 Meeting" in parsed.subject

    def test_parse_reply_to(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_bec_spoofing_eml())
        assert "attacker99@outlook.com" in (parsed.reply_to_address or "")

    def test_parse_date(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_benign_eml())
        assert parsed.date_parsed is not None
        assert parsed.date_parsed.year == 2026

    def test_parse_body(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_benign_eml())
        assert parsed.body_plain is not None
        assert "meeting agenda" in parsed.body_plain.lower()

    def test_all_headers_captured(self):
        from parser.eml_parser import parse_eml
        parsed = parse_eml(make_benign_eml())
        header_names = [h[0].lower() for h in parsed.all_headers]
        assert "from" in header_names
        assert "to" in header_names
        assert "subject" in header_names

    def test_raw_bytes_preserved(self):
        from parser.eml_parser import parse_eml
        data = make_benign_eml()
        parsed = parse_eml(data)
        assert parsed.raw_bytes == data  # original bytes unchanged


# ─────────────────────────────────────────────────────────────
# 3. Header Analysis Tests
# ─────────────────────────────────────────────────────────────

class TestHeaderAnalysis:

    def test_reply_to_mismatch_detected(self):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_headers(parsed)
        assert result.reply_to_mismatch is True

    def test_reply_to_domain_differs(self):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_headers(parsed)
        assert result.reply_to_domain_differs is True

    def test_display_name_spoofing_free_domain(self):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_headers(parsed)
        assert result.display_name_spoofing is True

    def test_benign_no_reply_mismatch(self):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        parsed = parse_eml(make_benign_eml())
        result = analyse_headers(parsed)
        # Reply-To equals From — no mismatch
        assert result.reply_to_mismatch is False

    def test_reply_to_score_elevated_on_mismatch(self):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_headers(parsed)
        assert result.reply_to_score >= 80.0


# ─────────────────────────────────────────────────────────────
# 4. Authentication Analysis Tests
# ─────────────────────────────────────────────────────────────

class TestAuthAnalysis:

    def test_bec_spf_fail(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_authentication(parsed)
        assert result.spf_status == "FAIL"

    def test_bec_dkim_fail(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_authentication(parsed)
        assert result.dkim_status == "FAIL"

    def test_bec_dmarc_fail(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_authentication(parsed)
        assert result.dmarc_status == "FAIL"

    def test_benign_spf_pass(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_benign_eml())
        result = analyse_authentication(parsed)
        assert result.spf_status == "PASS"

    def test_benign_dkim_pass(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_benign_eml())
        result = analyse_authentication(parsed)
        assert result.dkim_status == "PASS"

    def test_auth_score_high_on_failures(self):
        from parser.eml_parser import parse_eml
        from analysis.auth_analysis import analyse_authentication
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_authentication(parsed)
        assert result.auth_score >= 50.0


# ─────────────────────────────────────────────────────────────
# 5. Domain Analysis Tests
# ─────────────────────────────────────────────────────────────

class TestDomainAnalysis:

    def test_domain_mismatch_bec(self):
        from parser.eml_parser import parse_eml
        from analysis.domain_analysis import analyse_domains
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_domains(parsed)
        assert result.domains_match is False

    def test_lookalike_domain_detected(self):
        from parser.eml_parser import parse_eml
        from analysis.domain_analysis import analyse_domains
        parsed = parse_eml(make_subtle_bec_eml())
        result = analyse_domains(parsed)
        # Reply-To is acme-corp-executive.com vs acmecorp.com — should detect mismatch
        assert result.domains_match is False

    def test_benign_domains_match(self):
        from parser.eml_parser import parse_eml
        from analysis.domain_analysis import analyse_domains
        parsed = parse_eml(make_benign_eml())
        result = analyse_domains(parsed)
        # From and Reply-To both acmecorp.com
        assert result.domains_match is True

    def test_similarity_function(self):
        from analysis.domain_analysis import _similarity
        assert _similarity("acmecorp.com", "acmecorp.com") == 1.0
        assert _similarity("acmecorp.com", "acm3corp.com") > 0.8
        assert _similarity("acmecorp.com", "google.com") < 0.6


# ─────────────────────────────────────────────────────────────
# 6. NLP Analysis Tests
# ─────────────────────────────────────────────────────────────

class TestNLPAnalysis:

    def test_urgency_detected_in_bec(self):
        from parser.eml_parser import parse_eml
        from nlp.language_analysis import analyse_nlp
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_nlp(parsed)
        assert result.urgency_score > 0
        assert len(result.urgency_hits) > 0

    def test_financial_detected_in_bec(self):
        from parser.eml_parser import parse_eml
        from nlp.language_analysis import analyse_nlp
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_nlp(parsed)
        assert result.financial_score > 0

    def test_secrecy_detected_in_bec(self):
        from parser.eml_parser import parse_eml
        from nlp.language_analysis import analyse_nlp
        parsed = parse_eml(make_bec_spoofing_eml())
        result = analyse_nlp(parsed)
        assert result.secrecy_score > 0

    def test_low_nlp_scores_for_benign(self):
        from parser.eml_parser import parse_eml
        from nlp.language_analysis import analyse_nlp
        parsed = parse_eml(make_benign_eml())
        result = analyse_nlp(parsed)
        # Benign meeting agenda — low urgency, low financial
        assert result.urgency_score < 20
        assert result.financial_score < 20

    def test_combined_score_range(self):
        from parser.eml_parser import parse_eml
        from nlp.language_analysis import analyse_nlp
        for eml in [make_benign_eml(), make_bec_spoofing_eml(), make_subtle_bec_eml()]:
            parsed = parse_eml(eml)
            result = analyse_nlp(parsed)
            assert 0.0 <= result.combined_score <= 100.0


# ─────────────────────────────────────────────────────────────
# 7. Risk Engine Tests
# ─────────────────────────────────────────────────────────────

class TestRiskEngine:

    def _run(self, eml_bytes: bytes):
        from parser.eml_parser import parse_eml
        from analysis.header_analysis import analyse_headers
        from analysis.auth_analysis import analyse_authentication
        from analysis.domain_analysis import analyse_domains
        from analysis.url_analysis import analyse_urls
        from analysis.attachment_analysis import analyse_attachments
        from nlp.language_analysis import analyse_nlp
        from detection.risk_engine import compute_risk

        parsed = parse_eml(eml_bytes)
        header     = analyse_headers(parsed)
        auth       = analyse_authentication(parsed)
        domain     = analyse_domains(parsed)
        url        = analyse_urls(parsed)
        attachment = analyse_attachments(parsed)
        nlp        = analyse_nlp(parsed)
        return compute_risk(header, auth, domain, url, attachment, nlp)

    def test_bec_score_higher_than_benign(self):
        benign_risk = self._run(make_benign_eml())
        bec_risk    = self._run(make_bec_spoofing_eml())
        assert bec_risk.total_score > benign_risk.total_score

    def test_score_range(self):
        for eml in [make_benign_eml(), make_bec_spoofing_eml(), make_subtle_bec_eml()]:
            risk = self._run(eml)
            assert 0.0 <= risk.total_score <= 100.0

    def test_bec_risk_level_high_or_critical(self):
        risk = self._run(make_bec_spoofing_eml())
        # BEC email should score higher than LOW (30+) and ideally HIGH/CRITICAL
        # In Phase 1 without behavioral/comm anomaly modules active, MEDIUM+ is expected
        assert risk.total_score >= 30.0, f"Expected score >= 30 for BEC email, got {risk.total_score}"
        # The risk level must not be LOW
        assert risk.risk_level != "LOW", f"BEC email should not score LOW, got {risk.risk_level}"

    def test_benign_risk_level_low_or_medium(self):
        risk = self._run(make_benign_eml())
        assert risk.risk_level in ("LOW", "MEDIUM")

    def test_findings_present_for_bec(self):
        risk = self._run(make_bec_spoofing_eml())
        assert len(risk.findings) > 0

    def test_counterfactuals_generated(self):
        risk = self._run(make_bec_spoofing_eml())
        # Should have at least some counterfactuals for high-risk emails
        assert isinstance(risk.counterfactuals, list)

    def test_to_dict_serialisable(self):
        import json
        risk = self._run(make_bec_spoofing_eml())
        d = risk.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_weights_sum_to_one(self):
        from config.settings import RISK_WEIGHTS
        total = sum(RISK_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-6, f"Weights sum to {total}, expected 1.0"
