"""
BEC-FORGE Common UI Components & Styling
"""

import streamlit as st
from typing import Optional

# ─────────────────────────────────────────────────────────────
# Colour palette & severity map
# ─────────────────────────────────────────────────────────────

SEVERITY_COLOURS = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF4500",
    "MEDIUM":   "#FFA500",
    "LOW":      "#FFD700",
    "INFO":     "#4A90D9",
}

RISK_LEVEL_COLOURS = {
    "CRITICAL":   "#FF0000",
    "HIGH":       "#FF4500",
    "SUSPICIOUS": "#FFA500",
    "MEDIUM":     "#FFD700",
    "LOW":        "#00CC44",
}

RISK_LEVEL_ICONS = {
    "CRITICAL":   "🔴",
    "HIGH":       "🟠",
    "SUSPICIOUS": "🟡",
    "MEDIUM":     "🔵",
    "LOW":        "🟢",
}


def apply_global_css():
    """Inject custom CSS for the forensic dashboard look."""
    st.markdown("""
    <style>
    /* ── Root ─────────────────────────────────────────── */
    .stApp {
        background-color: #0D1117;
        color: #E6EDF3;
    }
    
    /* ── Sidebar ──────────────────────────────────────── */
    [data-testid="stSidebar"] {
        background-color: #161B22;
        border-right: 1px solid #30363D;
    }
    [data-testid="stSidebar"] .stMarkdown {
        color: #E6EDF3;
    }
    
    /* ── Headers ──────────────────────────────────────── */
    h1, h2, h3, h4 {
        color: #58A6FF !important;
    }
    
    /* ── Metric cards ─────────────────────────────────── */
    [data-testid="stMetric"] {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 12px !important;
    }
    [data-testid="stMetricValue"] {
        color: #58A6FF !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }
    [data-testid="stMetricLabel"] {
        color: #8B949E !important;
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* ── Expanders ────────────────────────────────────── */
    [data-testid="stExpander"] {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
    }
    
    /* ── DataFrames ───────────────────────────────────── */
    [data-testid="stDataFrame"] {
        background-color: #161B22;
    }
    
    /* ── Divider ──────────────────────────────────────── */
    hr {
        border-color: #30363D;
    }
    
    /* ── Code blocks ──────────────────────────────────── */
    code {
        background-color: #1F2937;
        color: #79C0FF;
        padding: 2px 6px;
        border-radius: 3px;
    }

    /* ── Severity badge ───────────────────────────────── */
    .sev-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        margin-right: 6px;
    }
    
    /* ── Finding card ─────────────────────────────────── */
    .finding-card {
        background: #161B22;
        border-left: 4px solid #FF4500;
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    
    /* ── Evidence block ───────────────────────────────── */
    .evidence-block {
        background: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 16px;
        font-family: monospace;
        font-size: 0.85rem;
    }
    
    /* ── Score gauge container ────────────────────────── */
    .score-container {
        text-align: center;
        padding: 20px;
        background: #161B22;
        border-radius: 10px;
        border: 1px solid #30363D;
    }
    .score-value {
        font-size: 4rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-label {
        font-size: 1rem;
        font-weight: 600;
        letter-spacing: 0.1em;
        margin-top: 4px;
    }
    
    /* ── Status chip ──────────────────────────────────── */
    .status-pass   { color: #3FB950; font-weight: 700; }
    .status-fail   { color: #F85149; font-weight: 700; }
    .status-none   { color: #8B949E; font-weight: 700; }
    .status-unknown{ color: #D29922; font-weight: 700; }
    
    /* ── Header table ─────────────────────────────────── */
    .header-row {
        display: flex;
        border-bottom: 1px solid #21262D;
        padding: 6px 0;
        font-size: 0.85rem;
    }
    .header-name {
        color: #58A6FF;
        width: 200px;
        flex-shrink: 0;
        font-family: monospace;
    }
    .header-value {
        color: #E6EDF3;
        word-break: break-all;
    }
    
    /* ── Nav logo ─────────────────────────────────────── */
    .nav-logo {
        font-size: 1.5rem;
        font-weight: 900;
        color: #58A6FF;
        letter-spacing: 0.05em;
    }
    .nav-sub {
        font-size: 0.65rem;
        color: #8B949E;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    </style>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Reusable components
# ─────────────────────────────────────────────────────────────

def risk_score_badge(score: float, level: str) -> None:
    colour = RISK_LEVEL_COLOURS.get(level, "#8B949E")
    icon   = RISK_LEVEL_ICONS.get(level, "⚪")
    st.markdown(f"""
    <div class="score-container">
        <div class="score-value" style="color:{colour}">{score:.0f}</div>
        <div style="color:#8B949E; font-size:0.85rem; margin:4px 0">/ 100</div>
        <div class="score-label" style="color:{colour}">{icon} {level} BEC RISK</div>
    </div>
    """, unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    colour = SEVERITY_COLOURS.get(severity, "#8B949E")
    return (f'<span class="sev-badge" '
            f'style="background:{colour}22; color:{colour}; '
            f'border:1px solid {colour}44">{severity}</span>')


def auth_status_html(status: str) -> str:
    css_class = {
        "PASS":    "status-pass",
        "FAIL":    "status-fail",
        "SOFTFAIL":"status-fail",
        "NONE":    "status-none",
        "UNKNOWN": "status-unknown",
    }.get(status, "status-none")
    icons = {
        "PASS": "✓", "FAIL": "✗", "SOFTFAIL": "~",
        "NONE": "—", "UNKNOWN": "?",
    }
    return f'<span class="{css_class}">{icons.get(status,"?")} {status}</span>'


def finding_card(severity: str, title: str, description: str,
                  evidence_field: Optional[str] = None,
                  evidence_value: Optional[str] = None) -> None:
    colour = SEVERITY_COLOURS.get(severity, "#8B949E")
    ev_html = ""
    if evidence_field:
        ev_html = f'<div style="margin-top:8px; font-size:0.75rem; color:#8B949E;">Evidence: <code>{evidence_field}</code>'
        if evidence_value:
            safe_val = str(evidence_value)[:200].replace("<","&lt;").replace(">","&gt;")
            ev_html += f' → <code style="color:#79C0FF">{safe_val}</code>'
        ev_html += "</div>"

    st.markdown(f"""
    <div class="finding-card" style="border-left-color:{colour}">
        {severity_badge(severity)}
        <strong style="color:#E6EDF3">{title}</strong>
        <div style="color:#8B949E; font-size:0.85rem; margin-top:4px">{description}</div>
        {ev_html}
    </div>
    """, unsafe_allow_html=True)


def evidence_info_block(evidence: dict) -> None:
    st.markdown(f"""
    <div class="evidence-block">
        <div style="color:#8B949E; font-size:0.7rem; text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px">
        ■ FORENSIC EVIDENCE RECORD
        </div>
        <div><span style="color:#58A6FF">Evidence ID   :</span> {evidence.get('evidence_id','N/A')}</div>
        <div><span style="color:#58A6FF">Filename      :</span> {evidence.get('filename','N/A')}</div>
        <div><span style="color:#58A6FF">SHA-256       :</span> <span style="color:#79C0FF">{evidence.get('sha256','N/A')}</span></div>
        <div><span style="color:#58A6FF">File Size     :</span> {evidence.get('file_size',0):,} bytes</div>
        <div><span style="color:#58A6FF">Acquired At   :</span> {evidence.get('acquired_at','N/A')}</div>
        <div style="margin-top:4px"><span style="color:#58A6FF">Integrity     :</span>
            <span style="color:{'#3FB950' if evidence.get('integrity')=='VERIFIED' else '#F85149'}; font-weight:700">
            {'✓ VERIFIED' if evidence.get('integrity')=='VERIFIED' else '✗ FAILED'}
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, icon: str = "◆") -> None:
    st.markdown(f"""
    <div style="
        border-bottom: 1px solid #30363D;
        padding-bottom: 6px;
        margin: 20px 0 12px 0;
        color: #58A6FF;
        font-weight: 700;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.08em
    ">{icon} {title}</div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        st.markdown("""
        <div class="nav-logo">BEC-FORGE</div>
        <div class="nav-sub">Forensic Investigation Engine</div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        page = st.radio(
            "Navigation",
            [
                "🏠  Dashboard",
                "📥  Evidence Acquisition",
                "🔬  Email Analysis",
                "📊  Findings",
            ],
            label_visibility="collapsed",
        )

        st.markdown("---")
        st.markdown(
            '<div style="color:#8B949E; font-size:0.7rem">BEC-FORGE v1.0.0 Phase 1<br>'
            'Cyber Forensics Capstone</div>',
            unsafe_allow_html=True,
        )

    return page
