"""
BEC-FORGE Phase 2 Tests — Authentication, ARC, DMARC Alignment, & FastAPI Endpoints
"""

import sys
import os
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from parser.eml_parser import parse_eml
from analysis.auth_analysis import analyse_authentication
from fastapi.testclient import TestClient
from server.app import app
import config.settings as cfg
import tempfile
import shutil

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

client = TestClient(app)


def make_arc_eml() -> bytes:
    return b"""From: Legitimate Partner <partner@trustedcorp.com>
To: finance@acmecorp.com
Subject: Forwarded Invoice Details
Date: Tue, 06 Oct 2026 11:20:00 +0000
Message-ID: <arc001@trustedcorp.com>
Received-SPF: pass client-ip=198.51.100.1;
Authentication-Results: mx.acmecorp.com;
   dkim=pass header.d=trustedcorp.com;
   spf=pass smtp.mailfrom=partner@trustedcorp.com;
   dmarc=pass header.from=trustedcorp.com;
   arc=pass
ARC-Authentication-Results: i=1; mx.intermediary.com;
   dkim=pass header.d=trustedcorp.com;
   spf=pass smtp.mailfrom=partner@trustedcorp.com;
   arc=pass arc.chain=trustedcorp.com

Hello team, please find attached the reviewed invoice from our accounting partner.
Best regards.
"""


def make_spoofed_dmarc_fail_eml() -> bytes:
    return b"""From: Executive Officer <ceo@targetcorp.com>
To: employee@targetcorp.com
Subject: Urgent Action Needed
Date: Tue, 06 Oct 2026 03:15:00 +0000
Message-ID: <spoof001@targetcorp.com>
Received-SPF: fail (targetcorp.com: IP 203.0.113.100 not permitted) client-ip=203.0.113.100;
Authentication-Results: mx.targetcorp.com;
   dkim=fail;
   spf=fail smtp.mailfrom=attacker@fakehost.net;
   dmarc=fail (p=REJECT) header.from=targetcorp.com

Please transfer funds right away.
"""


class TestPhase2AuthEnhancements:

    def test_arc_validation_passed(self):
        parsed = parse_eml(make_arc_eml())
        res = analyse_authentication(parsed)
        assert res.arc_status == "PASS"
        assert res.threat_hypothesis in ("BENIGN / NORMAL", "POSSIBLE_COMPROMISE")
        assert res.identity_consistency_score >= 80.0

    def test_dmarc_alignment_verified(self):
        parsed = parse_eml(make_arc_eml())
        res = analyse_authentication(parsed)
        assert res.spf_aligned is True
        assert res.dkim_aligned is True
        assert res.dmarc_aligned is True

    def test_spoofing_threat_hypothesis_classification(self):
        parsed = parse_eml(make_spoofed_dmarc_fail_eml())
        res = analyse_authentication(parsed)
        assert res.threat_hypothesis == "POTENTIAL_SPOOFING"
        assert res.identity_consistency_score < 50.0
        assert any(f["title"] == "Threat Hypothesis: Potential Spoofing" for f in res.findings)

    def test_compromise_threat_hypothesis_on_auth_pass(self):
        parsed = parse_eml(make_arc_eml())
        res = analyse_authentication(parsed)
        # When auth passes, threat hypothesis categorizes it as benign baseline or possible compromise (if deviations occur)
        assert res.threat_hypothesis in ("BENIGN / NORMAL", "POSSIBLE_COMPROMISE")


class TestFastAPIServerEndpoints:

    def test_dashboard_endpoint_html(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "Digital Forensics Overview" in response.text
        assert "BEC-FORGE" in response.text

    def test_acquisition_endpoint_html(self):
        response = client.get("/acquisition")
        assert response.status_code == 200
        assert "Evidence Ingestion" in response.text

    def test_api_evidence_list_json(self):
        response = client.get("/api/evidence")
        assert response.status_code == 200
        data = response.json()
        assert "evidence" in data
        assert isinstance(data["evidence"], list)

    def test_api_analyses_list_json(self):
        response = client.get("/api/analyses")
        assert response.status_code == 200
        data = response.json()
        assert "analyses" in data
        assert isinstance(data["analyses"], list)

    def test_api_analyze_upload(self):
        files = {
            "file": ("test_benign.eml", make_arc_eml(), "message/rfc822")
        }
        data = {"case_id": "TEST-API-CASE"}
        response = client.post("/api/analyze", files=files, data=data)
        assert response.status_code == 200
        res = response.json()
        assert "evidence_id" in res
        assert "sha256" in res
        assert "risk_score" in res
        assert "identity_consistency_score" in res
        assert "threat_hypothesis" in res

    def test_openapi_docs_endpoint(self):
        response = client.get("/docs")
        assert response.status_code == 200
        assert "Swagger UI" in response.text or "swagger" in response.text.lower()
