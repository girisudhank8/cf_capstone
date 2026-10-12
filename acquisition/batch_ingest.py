"""
BEC-FORGE Batch Evidence Ingestion Engine

Provides DFIR forensic teams with bulk evidence ingestion:
- ZIP evidence containers (.zip containing .eml files)
- Mailbox dumps (.mbox)
- Directory trees of forensic .eml files

Performs cryptographic chain-of-custody acquisition and automated forensics on each item.
"""

import io
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.orchestrator import run_analysis
from parser.mbox_parser import parse_mbox_bytes

logger = logging.getLogger(__name__)


@dataclass
class BatchIngestItem:
    evidence_id: str
    original_filename: str
    sha256: str
    risk_score: float
    risk_level: str
    threat_hypothesis: str
    findings_count: int


@dataclass
class BatchIngestResult:
    total_processed: int = 0
    total_successful: int = 0
    total_failed: int = 0
    case_id: Optional[str] = None
    items: list[BatchIngestItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def ingest_zip_archive(zip_bytes: bytes, case_id: Optional[str] = None) -> BatchIngestResult:
    """Extract and ingest all .eml and .mbox files contained in a ZIP container."""
    result = BatchIngestResult(case_id=case_id)
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for zip_info in z.infolist():
                if zip_info.is_dir():
                    continue
                filename = Path(zip_info.filename).name
                lower_name = filename.lower()

                if lower_name.endswith(".eml"):
                    result.total_processed += 1
                    try:
                        raw = z.read(zip_info)
                        analysis = run_analysis(raw_bytes=raw, filename=filename, case_id=case_id)
                        result.total_successful += 1
                        result.items.append(
                            BatchIngestItem(
                                evidence_id=analysis.evidence["evidence_id"],
                                original_filename=filename,
                                sha256=analysis.evidence["sha256"],
                                risk_score=analysis.risk.total_score,
                                risk_level=analysis.risk.risk_level,
                                threat_hypothesis=analysis.risk.threat_hypothesis,
                                findings_count=len(analysis.risk.findings),
                            )
                        )
                    except Exception as exc:
                        result.total_failed += 1
                        result.errors.append(f"{filename}: {exc}")

                elif lower_name.endswith(".mbox"):
                    try:
                        mbox_data = z.read(zip_info)
                        mbox_res = ingest_mbox_stream(mbox_data, case_id=case_id)
                        result.total_processed += mbox_res.total_processed
                        result.total_successful += mbox_res.total_successful
                        result.total_failed += mbox_res.total_failed
                        result.items.extend(mbox_res.items)
                        result.errors.extend(mbox_res.errors)
                    except Exception as exc:
                        result.total_failed += 1
                        result.errors.append(f"{filename} (mbox): {exc}")

    except Exception as e:
        logger.error("Failed to parse ZIP archive: %s", e)
        result.errors.append(f"Invalid ZIP container: {e}")

    return result


def ingest_mbox_stream(mbox_bytes: bytes, case_id: Optional[str] = None) -> BatchIngestResult:
    """Parse and ingest all individual RFC-822 messages within an MBOX stream."""
    result = BatchIngestResult(case_id=case_id)
    try:
        for filename, raw in parse_mbox_bytes(mbox_bytes):
            result.total_processed += 1
            try:
                analysis = run_analysis(raw_bytes=raw, filename=filename, case_id=case_id)
                result.total_successful += 1
                result.items.append(
                    BatchIngestItem(
                        evidence_id=analysis.evidence["evidence_id"],
                        original_filename=filename,
                        sha256=analysis.evidence["sha256"],
                        risk_score=analysis.risk.total_score,
                        risk_level=analysis.risk.risk_level,
                        threat_hypothesis=analysis.risk.threat_hypothesis,
                        findings_count=len(analysis.risk.findings),
                    )
                )
            except Exception as exc:
                result.total_failed += 1
                result.errors.append(f"{filename}: {exc}")
    except Exception as e:
        logger.error("Error processing MBOX stream: %s", e)
        result.errors.append(f"MBOX parsing error: {e}")

    return result


def ingest_directory(directory_path: Path, case_id: Optional[str] = None) -> BatchIngestResult:
    """Scan and ingest all .eml files in an on-disk folder."""
    result = BatchIngestResult(case_id=case_id)
    p = Path(directory_path)
    if not p.is_dir():
        result.errors.append(f"Path is not a directory: {directory_path}")
        return result

    for f in p.glob("**/*"):
        if f.is_file() and f.suffix.lower() == ".eml":
            result.total_processed += 1
            try:
                raw = f.read_bytes()
                analysis = run_analysis(raw_bytes=raw, filename=f.name, case_id=case_id)
                result.total_successful += 1
                result.items.append(
                    BatchIngestItem(
                        evidence_id=analysis.evidence["evidence_id"],
                        original_filename=f.name,
                        sha256=analysis.evidence["sha256"],
                        risk_score=analysis.risk.total_score,
                        risk_level=analysis.risk.risk_level,
                        threat_hypothesis=analysis.risk.threat_hypothesis,
                        findings_count=len(analysis.risk.findings),
                    )
                )
            except Exception as exc:
                result.total_failed += 1
                result.errors.append(f"{f.name}: {exc}")

    return result
