"""
BEC-FORGE — FastAPI Server & Web Console (Phase 2)

Business Email Compromise Forensic Investigation & Risk Assessment Engine

Replaces Streamlit with high-performance FastAPI backend + Jinja2 forensic console.
Includes REST API endpoints (/api/...) and Interactive OpenAPI Swagger docs at /docs.
"""

import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from database.db import initialize_database, db_cursor
from acquisition.evidence import list_evidence, verify_evidence_integrity, audit_all_evidence
from acquisition.batch_ingest import ingest_zip_archive, ingest_mbox_stream, ingest_directory
from analysis.orchestrator import run_analysis, get_all_analyses, get_analysis_by_id
from analysis.routing_analysis import trace_mail_routing
from reporting.pdf_report import generate_forensic_pdf_report
from config.settings import APP_TITLE, APP_SUBTITLE, APP_VERSION

# Initialize SQLite database schema
initialize_database()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bec_forge.server")

# FastAPI App
app = FastAPI(
    title=APP_TITLE,
    description=APP_SUBTITLE,
    version=APP_VERSION,
)

# Static and Templates
SERVER_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(SERVER_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(SERVER_DIR / "templates"))


# ─────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────

def _get_dashboard_stats() -> dict:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("SELECT COUNT(*) as c FROM evidence")
            total_ev = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM emails")
            total_emails = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE risk_level IN ('HIGH', 'CRITICAL')")
            high_crit = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE threat_hypothesis = 'POTENTIAL_SPOOFING'")
            spoofing_count = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM risk_assessments WHERE threat_hypothesis = 'POSSIBLE_COMPROMISE'")
            compromise_count = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM findings WHERE title LIKE '%DMARC%' OR title LIKE '%SPF%'")
            dmarc_fails = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM findings")
            total_findings = cur.fetchone()["c"]

        return {
            "total_evidence": total_ev,
            "emails_analysed": total_emails,
            "high_critical": high_crit,
            "potential_spoofing": spoofing_count,
            "possible_compromise": compromise_count,
            "dmarc_failures": dmarc_fails,
            "total_findings": total_findings,
        }
    except Exception as e:
        logger.error("Error computing dashboard stats: %s", e)
        return {
            "total_evidence": 0, "emails_analysed": 0, "high_critical": 0,
            "potential_spoofing": 0, "possible_compromise": 0, "dmarc_failures": 0,
            "total_findings": 0,
        }


def _extract_auth_from_headers(headers: list) -> dict:
    import re
    res = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "arc": "NONE"}
    auth_raw = ""
    spf_raw = ""
    arc_raw = ""

    for h_name, h_val in headers:
        if h_name.lower() == "authentication-results":
            auth_raw = h_val
        elif h_name.lower() == "received-spf":
            spf_raw = h_val
        elif h_name.lower() in ("arc-authentication-results", "arc-seal"):
            arc_raw = h_val

    if auth_raw:
        for k in ("spf", "dkim", "dmarc", "arc"):
            m = re.search(rf"{k}=(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)", auth_raw, re.IGNORECASE)
            if m:
                res[k] = m.group(1).upper()

    if spf_raw and res["spf"] == "NONE":
        m = re.match(r"(pass|fail|softfail|neutral|none)", spf_raw.strip(), re.IGNORECASE)
        if m:
            res["spf"] = m.group(1).upper()

    if arc_raw and res["arc"] == "NONE":
        m = re.search(r"arc=(pass|fail)", arc_raw, re.IGNORECASE)
        if m:
            res["arc"] = m.group(1).upper()

    return res


# ─────────────────────────────────────────────────────────────
# Web Console HTML Routes (Jinja2)
# ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request, audit_msg: Optional[str] = None):
    """Forensic Dashboard View."""
    stats = _get_dashboard_stats()
    analyses = get_all_analyses()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "dashboard",
            "stats": stats,
            "analyses": analyses,
            "audit_msg": audit_msg,
        },
    )


@app.get("/acquisition", response_class=HTMLResponse)
async def acquisition_view(
    request: Request,
    success: Optional[str] = None,
    error: Optional[str] = None,
):
    """Evidence Acquisition View."""
    return templates.TemplateResponse(
        request=request,
        name="acquisition.html",
        context={
            "active_page": "acquisition",
            "success_msg": success,
            "error_msg": error,
        },
    )


@app.post("/acquisition/upload")
async def handle_evidence_upload(
    files: List[UploadFile] = File(...),
    case_id: Optional[str] = Form(None),
):
    """Handle multipart file upload for email evidence (.eml, .zip, .mbox)."""
    count = 0
    errors = []
    last_evidence_id = None
    c_id = case_id.strip() if case_id and case_id.strip() else None

    for file in files:
        fname = file.filename or ""
        lower = fname.lower()
        try:
            content = await file.read()
            if lower.endswith(".eml"):
                analysis = run_analysis(raw_bytes=content, filename=fname, case_id=c_id)
                count += 1
                last_evidence_id = analysis.evidence["evidence_id"]
            elif lower.endswith(".zip"):
                res = ingest_zip_archive(content, case_id=c_id)
                count += res.total_successful
                if res.items:
                    last_evidence_id = res.items[-1].evidence_id
                if res.errors:
                    errors.extend(res.errors)
            elif lower.endswith(".mbox"):
                res = ingest_mbox_stream(content, case_id=c_id)
                count += res.total_successful
                if res.items:
                    last_evidence_id = res.items[-1].evidence_id
                if res.errors:
                    errors.extend(res.errors)
            else:
                errors.append(f"{fname}: Unsupported file type (allowed: .eml, .zip, .mbox)")
        except Exception as e:
            logger.error("Error processing uploaded file %s: %s", fname, e)
            errors.append(f"{fname}: {str(e)}")

    if count > 0:
        msg = f"Successfully acquired, hashed, and analyzed {count} evidence item(s)."
        if count == 1 and last_evidence_id:
            return RedirectResponse(url=f"/analysis?id={last_evidence_id}", status_code=303)
        return RedirectResponse(url=f"/acquisition?success={msg}", status_code=303)
    else:
        err = f"Failed to acquire evidence: {', '.join(errors)}" if errors else "No valid evidence files provided."
        return RedirectResponse(url=f"/acquisition?error={err}", status_code=303)


@app.post("/acquisition/load-case")
async def handle_case_load(target: str = Form(...)):
    """Load authentic investigation benchmarks from datasets/cases/."""
    cases_dir = PROJECT_ROOT / "datasets" / "cases"
    count = 0
    last_id = None

    if target in ("wireshifter", "all"):
        wire_path = cases_dir / "operation_wireshifter"
        if wire_path.exists():
            r = ingest_directory(wire_path, case_id="CASE-2026-WIRE")
            count += r.total_successful
            if r.items:
                last_id = r.items[-1].evidence_id

    if target in ("baseline", "all"):
        base_path = cases_dir / "enterprise_baseline"
        if base_path.exists():
            r = ingest_directory(base_path, case_id="CASE-2026-BASE")
            count += r.total_successful
            if r.items and not last_id:
                last_id = r.items[-1].evidence_id

    if target in ("payroll", "all"):
        pay_path = cases_dir / "executive_payroll"
        if pay_path.exists():
            r = ingest_directory(pay_path, case_id="CASE-2026-PAYROLL")
            count += r.total_successful
            if r.items:
                last_id = r.items[-1].evidence_id

    if target == "mbox":
        mbox_path = cases_dir / "forensic_seizure.mbox"
        if mbox_path.exists():
            r = ingest_mbox_stream(mbox_path.read_bytes(), case_id="CASE-2026-MBOX")
            count += r.total_successful
            if r.items:
                last_id = r.items[-1].evidence_id

    msg = f"Successfully loaded forensic case benchmark ({count} evidence items ingested into chain-of-custody)."
    if count == 1 and last_id:
        return RedirectResponse(url=f"/analysis?id={last_id}", status_code=303)
    return RedirectResponse(url=f"/analysis?id={last_id}" if last_id else f"/?success={msg}", status_code=303)


@app.post("/evidence/audit")
async def handle_audit_action():
    """Trigger a complete cryptographic chain-of-custody audit."""
    res = audit_all_evidence()
    msg = f"Forensic Integrity Audit: {res['verified']}/{res['total']} files verified bitwise. Chain of custody: {'INTACT' if res['chain_intact'] else 'TAMPERING DETECTED'}."
    return RedirectResponse(url=f"/?audit_msg={msg}", status_code=303)


@app.post("/acquisition/ingest-synthetic")
@app.post("/evidence/reset")
async def handle_reset_workspace():
    """Wipe all active evidence and reset the forensic database to a completely clean slate."""
    from database.db import reset_database
    from acquisition.evidence import purge_all_evidence_vault
    reset_database()
    purged_count = purge_all_evidence_vault()
    msg = f"Forensic workspace reset. Evidence vault cleared ({purged_count} files purged). Active case ledger is completely clean."
    return RedirectResponse(url=f"/?success={msg}", status_code=303)


@app.get("/analysis", response_class=HTMLResponse)
async def analysis_view(request: Request, id: Optional[str] = None):
    """Forensic Analysis Dossier View."""
    analyses = get_all_analyses()
    if not analyses:
        return templates.TemplateResponse(
            "analysis.html",
            {
                "request": request,
                "active_page": "analysis",
                "options": [],
                "selected_id": None,
                "data": None,
            },
        )

    selected_id = id if id else analyses[0]["evidence_id"]
    data = _load_full_analysis_data(selected_id)

    auth_parsed = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "arc": "NONE"}
    domains = {"from_dom": "—", "rt_dom": "—", "rp_dom": "—"}
    counterfactuals = []

    if data:
        auth_parsed = _extract_auth_from_headers(data["headers"])
        from_a = data["email"].get("from_address") or ""
        rt_a = data["email"].get("reply_to") or ""
        rp_a = data["email"].get("return_path") or ""

        domains["from_dom"] = from_a.split("@")[-1].strip(">") if "@" in from_a else "—"
        domains["rt_dom"] = rt_a.split("@")[-1].strip(">") if "@" in rt_a else "—"
        domains["rp_dom"] = rp_a.split("@")[-1].strip(">") if "@" in rp_a else "—"

        if data["risk"] and data["risk"].get("counterfactuals"):
            try:
                cf_raw = data["risk"]["counterfactuals"]
                counterfactuals = json.loads(cf_raw) if isinstance(cf_raw, str) else cf_raw
            except Exception:
                counterfactuals = []

    attack_chain = None
    if selected_id:
        from detection.attack_chain import reconstruct_attack_chain
        attack_chain = reconstruct_attack_chain(evidence_id=selected_id)

    return templates.TemplateResponse(
        request=request,
        name="analysis.html",
        context={
            "active_page": "analysis",
            "options": analyses,
            "selected_id": selected_id,
            "data": data,
            "auth_parsed": auth_parsed,
            "domains": domains,
            "counterfactuals": counterfactuals,
            "attack_chain": attack_chain,
            "routing": data.get("routing") if data else None,
        },
    )


@app.get("/senders", response_class=HTMLResponse)
async def senders_view(request: Request):
    """Sender Intelligence & Identity Fingerprints View."""
    fingerprints = _load_all_fingerprints()
    severe_drift_count = sum(1 for fp in fingerprints if fp.get("sample_size", 0) > 0 and fp.get("auth_pass_rate", 1.0) < 0.6)
    return templates.TemplateResponse(
        request=request,
        name="senders.html",
        context={
            "active_page": "senders",
            "fingerprints": fingerprints,
            "severe_drift_count": severe_drift_count,
        },
    )


@app.get("/graph", response_class=HTMLResponse)
async def graph_view(request: Request):
    """Interactive Communication Graph Analysis View (Core Innovation #2)."""
    from graph.communication_graph import get_graph_visualization_data
    graph_data = get_graph_visualization_data()
    return templates.TemplateResponse(
        request=request,
        name="graph.html",
        context={
            "active_page": "graph",
            "graph_data": graph_data,
        },
    )


@app.get("/api/graph")
async def api_get_graph():
    """Retrieve full network graph nodes, edges, and relationship metrics."""
    from graph.communication_graph import get_graph_visualization_data
    return get_graph_visualization_data()


@app.get("/findings", response_class=HTMLResponse)
async def findings_view(
    request: Request,
    severity: Optional[str] = None,
    category: Optional[str] = None,
):
    """Forensic Findings and Anomalies Log."""
    findings = _load_findings_list(severity, category)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "active_page": "findings",
            "findings": findings,
            "selected_sev": severity,
            "category_query": category,
        },
    )


# ─────────────────────────────────────────────────────────────
# REST API Endpoints (For headless / forensic tooling)
# ─────────────────────────────────────────────────────────────

@app.get("/api/evidence")
async def api_list_evidence():
    """List all ingested evidence items."""
    return {"evidence": list_evidence()}


@app.get("/api/fingerprints")
async def api_list_fingerprints():
    """List all compiled sender identity fingerprints."""
    return {"fingerprints": _load_all_fingerprints()}


@app.get("/api/fingerprints/{sender_address}")
async def api_get_fingerprint(sender_address: str):
    """Get sender identity fingerprint and historical profile."""
    from behavioral.fingerprint import get_sender_fingerprint
    fp = get_sender_fingerprint(sender_address)
    if not fp:
        raise HTTPException(status_code=404, detail="Fingerprint not found for sender")
    return {
        "sender_address": fp.sender_address,
        "display_names": fp.display_names,
        "domains": fp.domains,
        "typical_sending_hours": fp.typical_sending_hours,
        "typical_recipients": fp.typical_recipients,
        "reply_to_addresses": fp.reply_to_addresses,
        "return_path_addresses": fp.return_path_addresses,
        "auth_pass_rate": fp.auth_pass_rate,
        "avg_urgency_score": fp.avg_urgency_score,
        "avg_financial_score": fp.avg_financial_score,
        "sample_size": fp.sample_size,
        "updated_at": fp.updated_at,
    }


@app.get("/api/analyses")
async def api_list_analyses():
    """List summary risk assessments for all analyzed emails."""
    return {"analyses": get_all_analyses()}


@app.get("/api/analyses/{evidence_id}")
async def api_get_analysis(evidence_id: str):
    """Get complete forensic dossier and risk breakdown for an evidence item."""
    data = _load_full_analysis_data(evidence_id)
    if not data:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return data


@app.get("/api/attack-chain/{evidence_id}")
async def api_get_attack_chain(evidence_id: str):
    """Retrieve reconstructed BEC Attack Progression Timeline (Core Innovation #4)."""
    from detection.attack_chain import reconstruct_attack_chain
    chain = reconstruct_attack_chain(evidence_id)
    return {
        "evidence_id": evidence_id,
        "attack_detected": chain.attack_detected,
        "confidence_level": chain.confidence_level,
        "total_stages_observed": chain.total_stages_observed,
        "narrative": chain.narrative,
        "stages": [
            {
                "stage_id": s.stage_id,
                "stage_name": s.stage_name,
                "status": s.status,
                "description": s.description,
                "indicators": s.indicators,
            }
            for s in chain.stages
        ],
    }


@app.post("/api/analyze")
async def api_analyze_email(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
):
    """Programmatically upload and analyze an .eml evidence file."""
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")
    
    content = await file.read()
    analysis = run_analysis(raw_bytes=content, filename=file.filename, case_id=case_id)
    return {
        "evidence_id": analysis.evidence["evidence_id"],
        "filename": analysis.evidence["filename"],
        "sha256": analysis.evidence["sha256"],
        "risk_score": analysis.risk.total_score,
        "risk_level": analysis.risk.risk_level,
        "identity_consistency_score": analysis.risk.identity_consistency_score,
        "threat_hypothesis": analysis.risk.threat_hypothesis,
        "findings_count": len(analysis.risk.findings),
    }


@app.get("/api/reports/{evidence_id}/pdf")
async def api_download_pdf_report(evidence_id: str):
    """Download official court-admissible forensic PDF dossier conforming to ISO/IEC 27037."""
    data = _load_full_analysis_data(evidence_id)
    if not data:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    
    pdf_bytes = generate_forensic_pdf_report(data)
    filename = f"Forensic_Report_{evidence_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/audit")
async def api_audit_evidence():
    """Verify cryptographic integrity of all stored evidence items on disk against the database ledger."""
    return audit_all_evidence()


@app.post("/api/acquire/batch")
async def api_acquire_batch(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
):
    """Ingest a batch evidence archive (.zip or .mbox) programmatically."""
    fname = file.filename or ""
    content = await file.read()
    if fname.lower().endswith(".zip"):
        res = ingest_zip_archive(content, case_id=case_id)
        return {
            "format": "zip",
            "total_processed": res.total_processed,
            "total_successful": res.total_successful,
            "total_failed": res.total_failed,
            "items": [i.__dict__ for i in res.items],
            "errors": res.errors,
        }
    elif fname.lower().endswith(".mbox"):
        res = ingest_mbox_stream(content, case_id=case_id)
        return {
            "format": "mbox",
            "total_processed": res.total_processed,
            "total_successful": res.total_successful,
            "total_failed": res.total_failed,
            "items": [i.__dict__ for i in res.items],
            "errors": res.errors,
        }
    else:
        raise HTTPException(status_code=400, detail="Only .zip and .mbox archives are accepted for batch acquisition.")


# ─────────────────────────────────────────────────────────────
# DB Loaders
# ─────────────────────────────────────────────────────────────

def _load_full_analysis_data(evidence_id: str) -> Optional[dict]:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
            ev_row = cur.fetchone()
            if not ev_row:
                return None
            ev = dict(ev_row)

            cur.execute("SELECT * FROM emails WHERE evidence_id = ?", (evidence_id,))
            em_row = cur.fetchone()
            em = dict(em_row) if em_row else {}

            cur.execute("SELECT * FROM risk_assessments WHERE evidence_id = ?", (evidence_id,))
            risk_row = cur.fetchone()
            risk = dict(risk_row) if risk_row else None

            cur.execute(
                """SELECT * FROM findings WHERE evidence_id = ? 
                   ORDER BY CASE severity 
                   WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END""",
                (evidence_id,),
            )
            findings = [dict(r) for r in cur.fetchall()]

            cur.execute(
                "SELECT header_name, header_value FROM email_headers WHERE evidence_id = ? ORDER BY position",
                (evidence_id,),
            )
            headers = [(r["header_name"], r["header_value"]) for r in cur.fetchall()]

        # Compute Hop-by-Hop mail routing trace
        recv_hdrs = [hv for hn, hv in headers if hn.lower() == "received"]
        x_orig = em.get("x_originating_ip")
        routing_trace = trace_mail_routing(recv_hdrs, x_orig)

        return {
            "evidence": ev,
            "email": em,
            "risk": risk,
            "findings": findings,
            "headers": headers,
            "routing": routing_trace,
        }
    except Exception as e:
        logger.error("DB load error for %s: %s", evidence_id, e)
        return None


def _load_findings_list(sev_filter: Optional[str] = None, cat_filter: Optional[str] = None) -> list:
    try:
        with db_cursor() as (conn, cur):
            q = "SELECT * FROM findings"
            params = []
            clauses = []

            if sev_filter:
                clauses.append("severity = ?")
                params.append(sev_filter.upper())
            if cat_filter:
                clauses.append("category LIKE ?")
                params.append(f"%{cat_filter.upper()}%")

            if clauses:
                q += " WHERE " + " AND ".join(clauses)

            q += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
            cur.execute(q, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _load_all_fingerprints() -> list:
    try:
        with db_cursor() as (conn, cur):
            cur.execute("SELECT * FROM sender_fingerprints ORDER BY sample_size DESC")
            rows = cur.fetchall()
            res = []
            for r in rows:
                d = dict(r)
                d["display_names"] = json.loads(d.get("display_names") or "[]")
                d["domains"] = json.loads(d.get("domains") or "[]")
                d["typical_sending_hours"] = json.loads(d.get("typical_sending_hours") or "[]")
                d["typical_recipients"] = json.loads(d.get("typical_recipients") or "{}")
                d["reply_to_addresses"] = json.loads(d.get("reply_to_addresses") or "[]")
                d["return_path_addresses"] = json.loads(d.get("return_path_addresses") or "[]")
                d["common_subjects"] = json.loads(d.get("common_subjects") or "[]")
                res.append(d)
            return res
    except Exception as e:
        logger.error("Error loading fingerprints: %s", e)
        return []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="127.0.0.1", port=8000, reload=True)
