"""
BEC-FORGE Dashboard Page
"""

import streamlit as st
from database.db import db_cursor
from ui.common import section_header, RISK_LEVEL_COLOURS, RISK_LEVEL_ICONS
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def render_dashboard():
    st.title("🔍 BEC-FORGE — Forensic Investigation Dashboard")
    st.markdown(
        '<div style="color:#8B949E; margin-bottom:24px">Business Email Compromise Forensic Investigation & Risk Assessment Engine</div>',
        unsafe_allow_html=True,
    )

    # ── KPI metrics ───────────────────────────────────────────
    stats = _load_stats()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Evidence Items", stats["total_evidence"])
    with col2:
        st.metric("Emails Analysed", stats["emails_analysed"])
    with col3:
        st.metric("🟠 High / 🔴 Critical Risk", stats["high_critical"])
    with col4:
        st.metric("Suspicious Senders", stats["suspicious_senders"])

    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("New Communication Relationships", stats["new_comms"])
    with col6:
        st.metric("Possible Account Compromise", stats["possible_compromise"])
    with col7:
        st.metric("Possible Spoofing", stats["possible_spoofing"])
    with col8:
        st.metric("Critical BEC Risk Emails", stats["critical_count"])

    st.markdown("---")

    # ── Recent evidence table ─────────────────────────────────
    section_header("Recent Evidence", "📋")
    recent = _load_recent()
    if not recent:
        st.info("No evidence items analysed yet. Go to **Evidence Acquisition** to upload your first email.")
        return

    for item in recent[:10]:
        level = item.get("risk_level") or "N/A"
        score = item.get("total_score")
        colour = RISK_LEVEL_COLOURS.get(level, "#8B949E")
        icon   = RISK_LEVEL_ICONS.get(level, "⚪")

        col_a, col_b, col_c, col_d = st.columns([2, 3, 2, 1])
        with col_a:
            st.markdown(f'<code style="color:#79C0FF">{item.get("evidence_id","")}</code>', unsafe_allow_html=True)
        with col_b:
            subject = (item.get("subject") or "—")[:60]
            sender  = item.get("from_address") or "unknown"
            st.markdown(f'**{subject}**<br><span style="color:#8B949E;font-size:0.8rem">{sender}</span>', unsafe_allow_html=True)
        with col_c:
            st.markdown(f'<span style="color:#8B949E; font-size:0.8rem">{item.get("acquired_at","")[:19]}</span>', unsafe_allow_html=True)
        with col_d:
            if score is not None:
                st.markdown(
                    f'<span style="color:{colour}; font-weight:700">{icon} {score:.0f} — {level}</span>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown('<span style="color:#8B949E">—</span>', unsafe_allow_html=True)


def _load_stats() -> dict:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("SELECT COUNT(*) as c FROM evidence")
            total = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM emails")
            analysed = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE risk_level IN ('HIGH','CRITICAL')")
            high_crit = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE total_score >= 50")
            susp = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE risk_level = 'CRITICAL'")
            crit_count = cur.fetchone()["c"]

        return {
            "total_evidence":    total,
            "emails_analysed":   analysed,
            "high_critical":     high_crit,
            "suspicious_senders": susp,
            "new_comms":         0,   # Phase 5
            "possible_compromise": 0,  # Phase 3
            "possible_spoofing": 0,    # Phase 2
            "critical_count":    crit_count,
        }
    except Exception:
        return {k: 0 for k in [
            "total_evidence","emails_analysed","high_critical","suspicious_senders",
            "new_comms","possible_compromise","possible_spoofing","critical_count",
        ]}


def _load_recent() -> list[dict]:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("""
                SELECT e.evidence_id, e.filename, e.acquired_at,
                       em.from_address, em.subject,
                       r.total_score, r.risk_level
                FROM evidence e
                LEFT JOIN emails em ON e.evidence_id = em.evidence_id
                LEFT JOIN risk_assessments r ON e.evidence_id = r.evidence_id
                ORDER BY e.id DESC LIMIT 20
            """)
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []
