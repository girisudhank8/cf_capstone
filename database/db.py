"""BEC-FORGE Database Layer — Schema + Connection Helpers."""

import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config.settings as app_settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Schema DDL
# ─────────────────────────────────────────────────────────────

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT    UNIQUE NOT NULL,
    name            TEXT    NOT NULL,
    description     TEXT,
    investigator    TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    UNIQUE NOT NULL,   -- EVD-YYYY-NNNN
    case_id         TEXT    REFERENCES cases(case_id),
    filename        TEXT    NOT NULL,
    original_path   TEXT,
    stored_path     TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    file_size       INTEGER NOT NULL,
    acquired_at     TEXT    NOT NULL,
    integrity       TEXT    NOT NULL DEFAULT 'VERIFIED'
);

CREATE TABLE IF NOT EXISTS emails (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    UNIQUE NOT NULL REFERENCES evidence(evidence_id),
    message_id      TEXT,
    from_raw        TEXT,
    from_name       TEXT,
    from_address    TEXT,
    to_raw          TEXT,
    cc_raw          TEXT,
    subject         TEXT,
    date_raw        TEXT,
    date_parsed     TEXT,
    reply_to        TEXT,
    return_path     TEXT,
    in_reply_to     TEXT,
    user_agent      TEXT,
    x_mailer        TEXT,
    x_originating_ip TEXT,
    body_plain      TEXT,
    body_html       TEXT,
    parsed_at       TEXT
);

CREATE TABLE IF NOT EXISTS email_headers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL REFERENCES evidence(evidence_id),
    header_name     TEXT    NOT NULL,
    header_value    TEXT    NOT NULL,
    position        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS senders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_address   TEXT    UNIQUE NOT NULL,
    display_name    TEXT,
    domain          TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    email_count     INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sender_fingerprints (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_address          TEXT UNIQUE NOT NULL,
    display_names           TEXT NOT NULL, -- JSON list
    domains                 TEXT NOT NULL, -- JSON list
    typical_sending_hours   TEXT NOT NULL, -- JSON list of integers 0-23
    typical_recipients      TEXT NOT NULL, -- JSON dict of recipient: count
    reply_to_addresses      TEXT NOT NULL, -- JSON list
    return_path_addresses   TEXT NOT NULL, -- JSON list
    common_subjects         TEXT NOT NULL, -- JSON list
    auth_pass_rate          REAL DEFAULT 1.0,
    avg_urgency_score       REAL DEFAULT 0.0,
    avg_financial_score     REAL DEFAULT 0.0,
    sample_size             INTEGER DEFAULT 0,
    updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL REFERENCES evidence(evidence_id),
    email_address   TEXT    NOT NULL,
    recipient_type  TEXT    NOT NULL  -- TO, CC, BCC
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL REFERENCES evidence(evidence_id),
    category        TEXT    NOT NULL,
    severity        TEXT    NOT NULL,  -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    evidence_field  TEXT,              -- which header/field triggered it
    evidence_value  TEXT,              -- the actual value
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    UNIQUE NOT NULL REFERENCES evidence(evidence_id),
    total_score     REAL    NOT NULL,
    risk_level      TEXT    NOT NULL,
    identity_consistency_score REAL DEFAULT 100.0,
    threat_hypothesis TEXT DEFAULT 'BENIGN / NORMAL',
    identity_drift_score REAL DEFAULT 0.0,
    identity_drift_level TEXT DEFAULT 'NONE',
    component_scores TEXT   NOT NULL,  -- JSON
    explanation     TEXT    NOT NULL,  -- JSON list
    counterfactuals TEXT,              -- JSON
    assessed_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL REFERENCES evidence(evidence_id),
    filename        TEXT,
    extension       TEXT,
    mime_type       TEXT,
    file_size       INTEGER,
    sha256          TEXT,
    is_suspicious   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS urls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL REFERENCES evidence(evidence_id),
    url             TEXT    NOT NULL,
    domain          TEXT,
    is_ip_based     INTEGER DEFAULT 0,
    is_shortener    INTEGER DEFAULT 0,
    is_suspicious   INTEGER DEFAULT 0,
    source          TEXT   -- body_plain, body_html
);

CREATE TABLE IF NOT EXISTS communication_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    recipient       TEXT    NOT NULL,
    evidence_id     TEXT    REFERENCES evidence(evidence_id),
    subject         TEXT,
    timestamp       TEXT,
    is_new_relationship INTEGER DEFAULT 0,
    UNIQUE(sender, recipient, evidence_id)
);
"""


# ─────────────────────────────────────────────────────────────
# Connection helpers
# ─────────────────────────────────────────────────────────────

def _db_path() -> Path:
    p = Path(app_settings.DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_connection() -> sqlite3.Connection:
    """Return a sqlite3 connection with row_factory set."""
    conn = sqlite3.connect(str(_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor() -> Generator[tuple[sqlite3.Connection, sqlite3.Cursor], None, None]:
    """Context manager: yields (conn, cursor), commits on exit, rolls back on error."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database() -> None:
    """Create all tables if they don't exist and run incremental migrations."""
    with db_cursor() as (conn, cur):
        cur.executescript(SCHEMA_SQL)
        # Check and migrate columns if upgrading from Phase 1
        try:
            cur.execute("ALTER TABLE risk_assessments ADD COLUMN identity_consistency_score REAL DEFAULT 100.0")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE risk_assessments ADD COLUMN threat_hypothesis TEXT DEFAULT 'BENIGN / NORMAL'")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE risk_assessments ADD COLUMN identity_drift_score REAL DEFAULT 0.0")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE risk_assessments ADD COLUMN identity_drift_level TEXT DEFAULT 'NONE'")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE emails ADD COLUMN in_reply_to TEXT")
        except Exception:
            pass
    logger.info("Database initialised at %s", app_settings.DB_PATH)


def reset_database() -> None:
    """Wipes all active casework and records from the database, restoring a clean workspace."""
    tables = [
        "communication_edges", "urls", "attachments", "risk_assessments",
        "findings", "recipients", "sender_fingerprints", "senders",
        "email_headers", "emails", "evidence", "cases"
    ]
    with db_cursor() as (conn, cur):
        for t in tables:
            cur.execute(f"DELETE FROM {t}")
        conn.commit()
        try:
            cur.execute("VACUUM")
        except Exception:
            pass
    logger.info("Forensic database wiped and vacuumed clean.")
