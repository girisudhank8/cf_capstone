"""
BEC-FORGE Evidence Acquisition Page
"""

import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.orchestrator import run_analysis
from ui.common import section_header, evidence_info_block, risk_score_badge


def render_evidence_acquisition():
    st.title("📥 Evidence Acquisition")
    st.markdown(
        '<div style="color:#8B949E; margin-bottom:24px">'
        'Upload email evidence (.eml format). Each file will be hashed, '
        'timestamped, and stored with full integrity verification before analysis.'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Upload form ───────────────────────────────────────────
    with st.form("upload_form", clear_on_submit=True):
        uploaded = st.file_uploader(
            "Upload .eml file(s)",
            type=["eml"],
            accept_multiple_files=True,
            help="Select one or more .eml email files to analyse",
        )
        case_id = st.text_input(
            "Case ID (optional)",
            placeholder="e.g. CASE-2026-001",
            help="Associate this evidence with a named case",
        )
        submitted = st.form_submit_button("🔬 Acquire & Analyse", use_container_width=True)

    if submitted and uploaded:
        results = []
        prog = st.progress(0, text="Acquiring evidence…")

        for i, f in enumerate(uploaded):
            prog.progress((i) / len(uploaded), text=f"Analysing {f.name}…")
            try:
                raw_bytes = f.read()
                analysis = run_analysis(
                    raw_bytes=raw_bytes,
                    filename=f.name,
                    case_id=case_id or None,
                )
                results.append(("success", f.name, analysis))
            except Exception as exc:
                results.append(("error", f.name, str(exc)))

        prog.progress(1.0, text="Complete")

        st.markdown("---")
        section_header("Acquisition Results", "✓")

        for status, fname, data in results:
            if status == "error":
                st.error(f"❌ Failed to analyse **{fname}**: {data}")
                continue

            analysis = data
            st.success(f"✓ Evidence acquired: **{fname}**")

            col1, col2 = st.columns([3, 1])
            with col1:
                evidence_info_block(analysis.evidence)
            with col2:
                risk_score_badge(analysis.risk.total_score, analysis.risk.risk_level)

            # Quick finding count
            n_crit = sum(1 for f in analysis.risk.findings if f.severity == "CRITICAL")
            n_high = sum(1 for f in analysis.risk.findings if f.severity == "HIGH")
            if n_crit + n_high > 0:
                st.warning(f"⚠ {n_crit} CRITICAL + {n_high} HIGH severity findings detected. "
                           f"Go to **Email Analysis** for full details.")
            st.markdown("---")

    elif submitted and not uploaded:
        st.warning("Please upload at least one .eml file.")
