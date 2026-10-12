"""
BEC-FORGE Findings Page
"""

import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor
from ui.common import section_header, finding_card, RISK_LEVEL_COLOURS, SEVERITY_COLOURS


def render_findings_page():
    st.title("📊 Forensic Findings")
    st.markdown(
        '<div style="color:#8B949E; margin-bottom:24px">'
        'Aggregated forensic findings across all analysed evidence items.'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Filters ───────────────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        sev_filter = st.multiselect(
            "Filter by Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=["CRITICAL", "HIGH"],
        )
    with col2:
        category_filter = st.text_input("Filter by Category (optional)", placeholder="e.g. AUTHENTICATION")

    findings = _load_findings(sev_filter, category_filter)

    if not findings:
        st.info("No findings match the current filter. Try adjusting severity filters.")
        return

    section_header(f"{len(findings)} Finding(s) Found", "⚠")

    for f in findings:
        with st.container():
            col_ev, col_main = st.columns([1, 4])
            with col_ev:
                st.markdown(
                    f'<code style="color:#79C0FF; font-size:0.75rem">{f.get("evidence_id","")}</code>',
                    unsafe_allow_html=True,
                )
            with col_main:
                finding_card(
                    severity=f["severity"],
                    title=f["title"],
                    description=f["description"],
                    evidence_field=f.get("evidence_field"),
                    evidence_value=f.get("evidence_value"),
                )

    # ── Summary stats ─────────────────────────────────────────
    st.markdown("---")
    section_header("Findings Summary", "📈")
    all_findings = _load_findings([], "")
    if all_findings:
        from collections import Counter
        sev_counts = Counter(f["severity"] for f in all_findings)
        cat_counts = Counter(f.get("category","UNKNOWN") for f in all_findings)

        col1, col2, col3, col4, col5 = st.columns(5)
        for col, sev in zip([col1, col2, col3, col4, col5],
                             ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
            with col:
                colour = SEVERITY_COLOURS.get(sev, "#8B949E")
                st.markdown(
                    f'<div style="text-align:center; background:#161B22; border:1px solid {colour}44; '
                    f'border-radius:8px; padding:12px">'
                    f'<div style="color:{colour}; font-size:1.8rem; font-weight:700">{sev_counts.get(sev,0)}</div>'
                    f'<div style="color:#8B949E; font-size:0.7rem; text-transform:uppercase">{sev}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


def _load_findings(sev_filter: list[str], category_filter: str) -> list[dict]:
    try:
        with db_cursor() as (conn, cur):
            query = "SELECT * FROM findings"
            params: list = []
            conditions: list[str] = []

            if sev_filter:
                placeholders = ",".join("?" * len(sev_filter))
                conditions.append(f"severity IN ({placeholders})")
                params.extend(sev_filter)

            if category_filter:
                conditions.append("category LIKE ?")
                params.append(f"%{category_filter.upper()}%")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"

            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []
