"""
BEC-FORGE Phase 4 & Phase 5 Tests — Statistical Behavioral Analysis & Communication Graph
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
from behavioral.statistics import (
    calculate_mean_std,
    compute_z_score,
    analyse_behavioral_statistics,
)
from graph.communication_graph import (
    record_communication_edge,
    build_networkx_graph,
    get_graph_visualization_data,
    analyze_email_relationships,
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


class TestPhase4BehavioralStatistics:

    def test_mean_and_std_calculation(self):
        vals = [10.0, 11.0, 12.0, 13.0, 14.0]
        mean, std = calculate_mean_std(vals)
        assert mean == 12.0
        assert std > 1.5

    def test_z_score_computation(self):
        # 3 standard deviations away
        z = compute_z_score(val=20.0, mean=10.0, std=3.33)
        assert z >= 2.9

    def test_temporal_z_score_on_night_email(self):
        # Ingest baseline history for sender at 10 AM, 11 AM, 12 PM, 2 PM
        for i, hour in enumerate([10, 11, 10, 11, 12, 14]):
            eml_bytes = f"""From: employee@firm.com
To: boss@firm.com
Subject: Task Update {i}
Date: Tue, 06 Oct 2026 {hour:02d}:15:00 +0000
Message-ID: <test_stat_{i}@firm.com>
Authentication-Results: mx.firm.com; dkim=pass; spf=pass; dmarc=pass

Update details.
""".encode("utf-8")
            run_analysis(raw_bytes=eml_bytes, filename=f"stat_{i}.eml")

        # Now test an anomalous email sent at 03:00 AM
        night_eml = b"""From: employee@firm.com
To: boss@firm.com
Subject: Urgent Action Needed
Date: Tue, 06 Oct 2026 03:00:00 +0000
Message-ID: <test_stat_night@firm.com>
Authentication-Results: mx.firm.com; dkim=pass; spf=pass; dmarc=pass

Urgent task.
"""
        parsed_night = parse_eml(night_eml)
        stat_res = analyse_behavioral_statistics(parsed_night)
        assert stat_res.has_sufficient_history is True
        assert stat_res.behavioral_anomaly_score > 0
        assert any("Sending Hour" in m.metric_name for m in stat_res.metrics)


class TestPhase5CommunicationGraph:

    def test_record_edge_detects_new_relationship(self):
        # First time seen
        is_new = record_communication_edge(
            sender="alice@company.com",
            recipient="bob@company.com",
            subject="First meeting",
        )
        assert is_new is True

        # Second time seen
        is_new_again = record_communication_edge(
            sender="alice@company.com",
            recipient="bob@company.com",
            subject="Second meeting",
        )
        assert is_new_again is False

    def test_networkx_graph_construction(self):
        record_communication_edge("ceo@firm.com", "cfo@firm.com", subject="Budget")
        record_communication_edge("ceo@firm.com", "vendor@external.com", subject="Invoice")
        
        G = build_networkx_graph()
        assert G.has_node("ceo@firm.com")
        assert G.has_node("cfo@firm.com")
        assert G.has_edge("ceo@firm.com", "cfo@firm.com")
        assert G.has_edge("ceo@firm.com", "vendor@external.com")

    def test_graph_visualization_payload(self):
        record_communication_edge("sender1@corp.com", "target@corp.com", subject="Test")
        data = get_graph_visualization_data()
        assert "nodes" in data
        assert "edges" in data
        assert "summary" in data
        assert data["summary"]["total_nodes"] >= 2
        assert data["summary"]["total_edges"] >= 1

    def test_email_relationship_anomaly_flagging(self):
        anomalies = analyze_email_relationships(
            sender="ceo@firm.com",
            recipients=["unknown_vendor@fake.com"],
            subject="Urgent Payment",
        )
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "NEW_RELATIONSHIP"
        assert anomalies[0].severity in ("HIGH", "MEDIUM")

    def test_api_graph_endpoints(self):
        record_communication_edge("admin@corp.com", "staff@corp.com")
        
        resp_json = client.get("/api/graph")
        assert resp_json.status_code == 200
        assert "nodes" in resp_json.json()
        assert "edges" in resp_json.json()

        resp_html = client.get("/graph")
        assert resp_html.status_code == 200
        assert "Interactive Communication Graph" in resp_html.text
        assert "admin@corp.com" in resp_html.text
