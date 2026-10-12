"""
BEC-FORGE Email Analysis Page

Full forensic analysis view for a selected evidence item.
"""

import json
import streamlit as st
import plotly.graph_objects as go
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor
from ui.common import (
    section_header, evidence_info_block, finding_card,
    risk_score_badge, auth_status_html, severity_badge,
    RISK_LEVEL_COLOURS, SEVERITY_COLOURS,
)


def render_analysis_page():
    st.title("🔬 Email Forensic Analysis")

    # ── Evidence selector ─────────────────────────────────────
    evidence_list = _load_evidence_list()
    if not evidence_list:
        st.info("No evidence items found. Upload emails via **Evidence Acquisition** first.")
        return

    options = {
        f"{e['evidence_id']} — {e.get('subject','—')[:50]} [{e.get('risk_level','?')}]": e["evidence_id"]
        for e in evidence_list
    }
    selected_label = st.selectbox("Select Evidence Item", list(options.keys()))
    evidence_id = options[selected_label]

    data = _load_full_analysis(evidence_id)
    if not data:
        st.error("Could not load analysis data for this evidence ID.")
        return

    _render_full_analysis(data)


def _render_full_analysis(data: dict) -> None:
    ev   = data["evidence"]
    em   = data["email"]
    risk = data["risk"]
    findings = data["findings"]
    headers  = data["headers"]

    # ── Top bar ───────────────────────────────────────────────
    col1, col2 = st.columns([3, 1])
    with col1:
        evidence_info_block(ev)
    with col2:
        if risk:
            risk_score_badge(risk["total_score"], risk["risk_level"])
        else:
            st.info("No risk assessment available")

    st.markdown("---")

    # ── Email metadata ────────────────────────────────────────
    section_header("Email Metadata", "📧")
    c1, c2 = st.columns(2)
    with c1:
        _field_row("From",    f'{em.get("from_name","")} <{em.get("from_address","")}>'.strip())
        _field_row("To",      em.get("to_raw","—"))
        _field_row("CC",      em.get("cc_raw","—") or "—")
        _field_row("Subject", em.get("subject","—"))
    with c2:
        _field_row("Date",        em.get("date_raw","—"))
        _field_row("Reply-To",    em.get("reply_to","—") or "—")
        _field_row("Return-Path", em.get("return_path","—") or "—")
        _field_row("Message-ID",  em.get("message_id","—") or "—")

    st.markdown("---")

    # ── Authentication analysis ───────────────────────────────
    section_header("Authentication Analysis", "🔐")
    auth_raw = _find_header(headers, "Authentication-Results")
    spf_raw  = _find_header(headers, "Received-SPF")

    auth_results = _parse_auth_from_headers(headers, auth_raw, spf_raw)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"**SPF**<br>{auth_status_html(auth_results['spf'])}", unsafe_allow_html=True)
    with c2:
        st.markdown(f"**DKIM**<br>{auth_status_html(auth_results['dkim'])}", unsafe_allow_html=True)
    with c3:
        st.markdown(f"**DMARC**<br>{auth_status_html(auth_results['dmarc'])}", unsafe_allow_html=True)

    if auth_raw:
        with st.expander("Raw Authentication-Results header"):
            st.code(auth_raw, language="text")

    st.markdown("---")

    # ── Domain analysis ───────────────────────────────────────
    section_header("Domain Analysis", "🌐")
    from_domain = em.get("from_address","").split("@")[-1] if em.get("from_address") else "—"
    rt_raw  = em.get("reply_to","") or ""
    rp_raw  = em.get("return_path","") or ""
    rt_domain = rt_raw.split("@")[-1].strip(">").strip() if "@" in rt_raw else "—"
    rp_domain = rp_raw.split("@")[-1].strip(">").strip() if "@" in rp_raw else "—"

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"**From Domain**<br>`{from_domain}`", unsafe_allow_html=True)
    with c2:
        colour = "#F85149" if (rt_domain != "—" and rt_domain != from_domain) else "#3FB950"
        st.markdown(f"**Reply-To Domain**<br><code style='color:{colour}'>{rt_domain}</code>",
                    unsafe_allow_html=True)
    with c3:
        colour2 = "#F85149" if (rp_domain != "—" and rp_domain != from_domain) else "#3FB950"
        st.markdown(f"**Return-Path Domain**<br><code style='color:{colour2}'>{rp_domain}</code>",
                    unsafe_allow_html=True)

    st.markdown("---")

    # ── Risk score breakdown ──────────────────────────────────
    if risk:
        section_header("BEC Risk Score Breakdown", "📊")
        _render_risk_breakdown(risk)
        st.markdown("---")

    # ── Findings ──────────────────────────────────────────────
    section_header("Forensic Findings", "⚠")
    if findings:
        for f in findings:
            finding_card(
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                evidence_field=f.get("evidence_field"),
                evidence_value=f.get("evidence_value"),
            )
    else:
        st.success("✓ No forensic findings flagged for this email.")

    # ── Counterfactuals ───────────────────────────────────────
    if risk and risk.get("counterfactuals"):
        section_header("Counterfactual Risk Analysis", "🔄")
        st.markdown(
            '<div style="color:#8B949E; font-size:0.85rem; margin-bottom:12px">'
            'The following are analytical estimates, not factual predictions. '
            'They illustrate which indicators contribute most to the risk score.'
            '</div>',
            unsafe_allow_html=True,
        )
        try:
            cfs = json.loads(risk["counterfactuals"]) if isinstance(risk["counterfactuals"], str) else risk["counterfactuals"]
            for cf in cfs:
                current = risk["total_score"]
                est = cf.get("score", cf.get("estimated_new_score", 0))
                reduction = current - est
                st.markdown(f"""
                <div style="background:#161B22; border:1px solid #30363D; border-radius:6px;
                            padding:12px 16px; margin-bottom:8px;">
                    <div style="color:#58A6FF; font-weight:600; margin-bottom:4px">
                    ↩ {cf.get('condition','—')}
                    </div>
                    <div style="color:#8B949E; font-size:0.85rem">
                    Current Risk: <strong style="color:#E6EDF3">{current:.0f}</strong>
                    → Estimated Risk: <strong style="color:#3FB950">{est:.0f}</strong>
                    (−{reduction:.0f} points)
                    </div>
                </div>
                """, unsafe_allow_html=True)
        except Exception:
            pass
        st.markdown("---")

    # ── All headers ───────────────────────────────────────────
    with st.expander("📋 All Email Headers"):
        for name, value in headers:
            st.markdown(
                f'<div class="header-row"><div class="header-name">{name}</div>'
                f'<div class="header-value">{value[:300]}</div></div>',
                unsafe_allow_html=True,
            )

    # ── Body ──────────────────────────────────────────────────
    plain = em.get("body_plain","")
    if plain:
        with st.expander("📄 Email Body (Plain Text)"):
            st.text(plain[:3000])


def _field_row(label: str, value: str) -> None:
    st.markdown(
        f'<div style="margin-bottom:6px">'
        f'<span style="color:#58A6FF; font-size:0.8rem; font-weight:600">{label}:</span> '
        f'<span style="color:#E6EDF3; font-size:0.85rem">{value or "—"}</span></div>',
        unsafe_allow_html=True,
    )


def _find_header(headers: list[tuple], name: str) -> str:
    for h_name, h_val in headers:
        if h_name.lower() == name.lower():
            return h_val
    return ""


def _parse_auth_from_headers(headers, auth_raw: str, spf_raw: str) -> dict:
    import re
    result = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE"}
    if auth_raw:
        for key in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{key}=(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)",
                          auth_raw, re.IGNORECASE)
            if m:
                result[key] = m.group(1).upper()
    if spf_raw and result["spf"] == "NONE":
        m = re.match(r"(pass|fail|softfail|neutral|none)", spf_raw.strip(), re.IGNORECASE)
        if m:
            result["spf"] = m.group(1).upper()
    return result


def _render_risk_breakdown(risk: dict) -> None:
    """Render a horizontal bar chart of risk components."""
    try:
        components = json.loads(risk["component_scores"]) if isinstance(risk["component_scores"], str) else []
    except Exception:
        components = []

    if not components:
        return

    # Sort by weighted score descending
    components_sorted = sorted(components, key=lambda c: c.get("weighted", 0), reverse=True)
    labels  = [c["name"].replace("_", " ").title() for c in components_sorted]
    weights = [c.get("weighted", 0) for c in components_sorted]
    raws    = [c.get("raw", 0) for c in components_sorted]

    # Colour by raw score
    bar_colours = []
    for r in raws:
        if r >= 80:
            bar_colours.append("#FF0000")
        elif r >= 60:
            bar_colours.append("#FF4500")
        elif r >= 40:
            bar_colours.append("#FFA500")
        elif r > 0:
            bar_colours.append("#FFD700")
        else:
            bar_colours.append("#3FB950")

    fig = go.Figure(go.Bar(
        x=weights,
        y=labels,
        orientation="h",
        marker_color=bar_colours,
        text=[f"{w:.2f}" for w in weights],
        textposition="outside",
        hovertemplate="<b>%{y}</b><br>Weighted contribution: %{x:.2f}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#0D1117",
        plot_bgcolor="#0D1117",
        font=dict(color="#E6EDF3", size=11),
        xaxis=dict(
            gridcolor="#21262D",
            title="Weighted Score Contribution",
            range=[0, max(weights) * 1.3 if weights else 1],
        ),
        yaxis=dict(gridcolor="#21262D"),
        height=350,
        margin=dict(l=20, r=80, t=20, b=20),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Total score callout
    total = risk.get("total_score", 0)
    level = risk.get("risk_level", "N/A")
    colour = RISK_LEVEL_COLOURS.get(level, "#8B949E")
    st.markdown(
        f'<div style="text-align:right; color:{colour}; font-size:1.1rem; font-weight:700">'
        f'Total BEC Risk Score: {total:.1f} / 100 — {level}'
        f'</div>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────
# DB loaders
# ─────────────────────────────────────────────────────────────

def _load_evidence_list() -> list[dict]:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("""
                SELECT e.evidence_id, e.filename, e.acquired_at,
                       em.subject, r.risk_level, r.total_score
                FROM evidence e
                LEFT JOIN emails em ON e.evidence_id = em.evidence_id
                LEFT JOIN risk_assessments r ON e.evidence_id = r.evidence_id
                ORDER BY e.id DESC
            """)
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _load_full_analysis(evidence_id: str) -> dict | None:
    try:
        with db_cursor() as (conn, cur):
            # Evidence
            cur.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
            ev = dict(cur.fetchone() or {})

            # Email
            cur.execute("SELECT * FROM emails WHERE evidence_id = ?", (evidence_id,))
            em_row = cur.fetchone()
            em = dict(em_row) if em_row else {}

            # Risk
            cur.execute("SELECT * FROM risk_assessments WHERE evidence_id = ?", (evidence_id,))
            risk_row = cur.fetchone()
            risk = dict(risk_row) if risk_row else None

            # Findings
            cur.execute(
                "SELECT * FROM findings WHERE evidence_id = ? ORDER BY CASE severity "
                "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
                "WHEN 'LOW' THEN 3 ELSE 4 END",
                (evidence_id,),
            )
            findings = [dict(r) for r in cur.fetchall()]

            # Headers
            cur.execute(
                "SELECT header_name, header_value FROM email_headers WHERE evidence_id = ? ORDER BY position",
                (evidence_id,),
            )
            headers = [(r["header_name"], r["header_value"]) for r in cur.fetchall()]

        return {
            "evidence": ev,
            "email": em,
            "risk": risk,
            "findings": findings,
            "headers": headers,
        }
    except Exception as e:
        st.error(f"Database error: {e}")
        return None
