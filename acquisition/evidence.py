"""
BEC-FORGE Evidence Acquisition Module

Handles:
- Generating unique Evidence IDs
- SHA-256 hashing
- Copying evidence to secure storage
- Recording acquisition metadata
- Integrity verification
"""

import hashlib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config.settings as app_settings
from database.db import db_cursor

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────────────────────

def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file without loading it all into memory."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────────────────────
# Evidence ID Generation
# ─────────────────────────────────────────────────────────────

def _next_evidence_id(year: int) -> str:
    """Generate the next sequential EVD-YYYY-NNNN id for the given year."""
    prefix = f"EVD-{year}-"
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT evidence_id FROM evidence WHERE evidence_id LIKE ? ORDER BY id DESC LIMIT 1",
            (f"{prefix}%",),
        )
        row = cur.fetchone()
        if row:
            last_num = int(row["evidence_id"].split("-")[-1])
            return f"{prefix}{last_num + 1:04d}"
        return f"{prefix}0001"


# ─────────────────────────────────────────────────────────────
# Core Acquisition
# ─────────────────────────────────────────────────────────────

def acquire_evidence(
    source_bytes: bytes,
    original_filename: str,
    case_id: str | None = None,
) -> dict:
    """
    Acquire a piece of evidence from raw bytes.

    Steps:
    1. Compute SHA-256
    2. Generate Evidence ID
    3. Store a read-only copy in the evidence directory
    4. Record in the database
    5. Return evidence metadata dict

    The original bytes are NEVER modified.
    """
    now = datetime.now(timezone.utc)
    year = now.year
    evidence_id = _next_evidence_id(year)
    sha256 = compute_sha256_bytes(source_bytes)

    # Persist evidence copy
    ev_dir = Path(app_settings.EVIDENCE_DIR)
    ev_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{evidence_id}_{original_filename}"
    stored_path = ev_dir / stored_name
    stored_path.write_bytes(source_bytes)
    stored_path.chmod(0o444)  # read-only

    # Verify integrity immediately after write
    written_hash = compute_sha256(stored_path)
    integrity = "VERIFIED" if written_hash == sha256 else "FAILED"

    metadata = {
        "evidence_id":   evidence_id,
        "filename":      original_filename,
        "stored_path":   str(stored_path),
        "sha256":        sha256,
        "file_size":     len(source_bytes),
        "acquired_at":   now.isoformat(),
        "integrity":     integrity,
        "case_id":       case_id,
    }

    with db_cursor() as (conn, cur):
        if case_id:
            cur.execute(
                """INSERT OR IGNORE INTO cases (case_id, name, created_at, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (case_id, f"Case {case_id}", now.isoformat(), now.isoformat()),
            )
        cur.execute(
            """INSERT OR IGNORE INTO evidence
               (evidence_id, case_id, filename, stored_path, sha256,
                file_size, acquired_at, integrity)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                evidence_id, case_id, original_filename,
                str(stored_path), sha256, len(source_bytes),
                now.isoformat(), integrity,
            ),
        )

    logger.info("Acquired evidence %s | SHA-256: %s | Integrity: %s",
                evidence_id, sha256, integrity)
    return metadata


def verify_evidence_integrity(evidence_id: str) -> dict:
    """
    Re-verify stored evidence against the recorded hash.
    Returns a dict with 'status', 'stored_hash', 'computed_hash'.
    """
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT sha256, stored_path FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        )
        row = cur.fetchone()

    if not row:
        return {"status": "NOT_FOUND", "stored_hash": None, "computed_hash": None}

    stored_path = Path(row["stored_path"])
    if not stored_path.exists():
        return {
            "status": "FILE_MISSING",
            "stored_hash": row["sha256"],
            "computed_hash": None,
        }

    computed = compute_sha256(stored_path)
    status = "VERIFIED" if computed == row["sha256"] else "TAMPERED"
    return {
        "status": status,
        "stored_hash": row["sha256"],
        "computed_hash": computed,
    }


def list_evidence() -> list[dict]:
    """Return all evidence records as a list of dicts."""
    with db_cursor() as (conn, cur):
        cur.execute(
            "SELECT * FROM evidence ORDER BY id DESC"
        )
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def audit_all_evidence() -> dict:
    """
    Forensic Chain of Custody Audit:
    Recalculates SHA-256 for all stored evidence on disk and verifies against the immutable database hash.
    Returns complete audit metrics conforming to ISO/IEC 27037 standards.
    """
    records = list_evidence()
    total = len(records)
    verified = 0
    tampered = 0
    missing = 0
    details = []

    for r in records:
        ev_id = r["evidence_id"]
        check = verify_evidence_integrity(ev_id)
        status = check["status"]
        if status == "VERIFIED":
            verified += 1
        elif status == "TAMPERED":
            tampered += 1
        elif status == "FILE_MISSING":
            missing += 1

        details.append({
            "evidence_id": ev_id,
            "filename": r.get("filename", ""),
            "stored_hash": check["stored_hash"],
            "computed_hash": check["computed_hash"],
            "status": status,
            "acquired_at": r.get("acquired_at", ""),
        })

    is_clean = (verified == total and total > 0)
    return {
        "total": total,
        "verified": verified,
        "tampered": tampered,
        "missing": missing,
        "chain_intact": is_clean or (total == 0),
        "details": details,
    }


def purge_all_evidence_vault() -> int:
    """Removes all stored evidence files from disk, restoring a clean vault."""
    ev_dir = Path(app_settings.EVIDENCE_DIR)
    if not ev_dir.exists():
        return 0
    count = 0
    for f in ev_dir.glob("*"):
        if f.is_file():
            try:
                f.chmod(0o666)  # allow deletion
                f.unlink()
                count += 1
            except Exception as e:
                logger.error("Failed to delete evidence file %s: %s", f, e)
    logger.info("Purged %d evidence file(s) from vault at %s", count, ev_dir)
    return count

