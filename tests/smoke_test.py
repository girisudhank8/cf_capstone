import sys
import os
from pathlib import Path
sys.path.insert(0, '.')
import config.settings as app_settings
app_settings.DB_PATH = ":memory:"
from database.db import initialize_database
initialize_database()
from analysis.orchestrator import run_analysis
from datasets.forensic_cases import build_operation_wireshifter_case

for fname, content in build_operation_wireshifter_case()[:3]:
    raw = content.encode("utf-8")
    result = run_analysis(raw, fname, case_id="SMOKE-TEST")
    ev_id   = result.evidence["evidence_id"]
    sha     = result.evidence["sha256"][:32]
    integ   = result.evidence["integrity"]
    from_a  = result.parsed.from_address
    score   = result.risk.total_score
    level   = result.risk.risk_level
    nf      = len(result.risk.findings)
    print(f"\n{fname}")
    print(f"  Evidence ID : {ev_id}")
    print(f"  SHA-256     : {sha}...")
    print(f"  Integrity   : {integ}")
    print(f"  From        : {from_a}")
    print(f"  Risk Score  : {score:.1f} / 100")
    print(f"  Risk Level  : {level}")
    print(f"  Findings    : {nf}")

print("\n\nAll emails processed successfully!")
