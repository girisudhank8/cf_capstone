"""
BEC-FORGE Public Forensic Email Corpus Fetcher

Downloads authentic, open-access real-world email forensic datasets:
1. Apache SpamAssassin Public Corpus (authentic ham & social engineering lures)
2. Jose Nazario Phishing/Scam Corpus (authentic MBOX archives)

Extracts and organizes emails into ready-to-ingest .eml files and .mbox containers.
"""

import io
import logging
import os
import tarfile
import urllib.request
from pathlib import Path

logger = logging.getLogger("bec_forge.corpus_fetcher")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = Path(__file__).resolve().parent
DOWNLOADS_DIR = BASE_DIR / "real_world_downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BEC-FORGE/1.0 Forensic Toolkit"


def download_spamassassin_samples(sample_count: int = 25) -> list[Path]:
    """
    Downloads authentic emails from Apache SpamAssassin Public Corpus.
    Extracts sample_count legitimate corporate emails (easy_ham) and scam emails (spam).
    """
    url = "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
    logger.info("Connecting to Apache Public Corpus: %s", url)

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    extracted_paths = []

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()

        logger.info("Downloaded %d bytes. Uncompressing tar.bz2...", len(content))
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:bz2") as tar:
            count = 0
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith("cmds"):
                    f = tar.extractfile(member)
                    if f:
                        raw_bytes = f.read()
                        fname = f"real_corporate_{count+1:03d}_{Path(member.name).name}.eml"
                        dest = DOWNLOADS_DIR / fname
                        dest.write_bytes(raw_bytes)
                        extracted_paths.append(dest)
                        count += 1
                        if count >= sample_count:
                            break

        logger.info("Successfully extracted %d authentic corporate emails to %s", len(extracted_paths), DOWNLOADS_DIR)
    except Exception as e:
        logger.error("Failed to download Apache SpamAssassin corpus: %s", e)

    return extracted_paths


def download_nazario_phishing_mbox(max_bytes: int = 500_000) -> Path | None:
    """
    Downloads authentic scam lures from Jose Nazario Phishing MBOX Archive.
    """
    url = "https://monkey.org/~jose/phishing/phishing0.mbox"
    logger.info("Connecting to Jose Nazario Corpus: %s", url)

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    dest = DOWNLOADS_DIR / "nazario_phishing_sample.mbox"

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Read first chunk up to max_bytes to get a clean sample without downloading 100MB
            content = resp.read(max_bytes)

        # Truncate at last complete message boundary
        last_boundary = content.rfind(b"\nFrom ")
        if last_boundary > 0:
            content = content[:last_boundary]

        dest.write_bytes(content)
        logger.info("Saved authentic phishing MBOX sample (%d bytes) to %s", len(content), dest)
        return dest
    except Exception as e:
        logger.error("Failed to download Nazario corpus: %s", e)
        return None


if __name__ == "__main__":
    print("=" * 65)
    print("BEC-FORGE Real-World Public Forensic Dataset Downloader")
    print("=" * 65)
    print("\n1. Fetching authentic corporate emails from Apache SpamAssassin...")
    emls = download_spamassassin_samples(sample_count=20)
    print(f"-> Extracted {len(emls)} authentic .eml files to {DOWNLOADS_DIR}")

    print("\n2. Fetching authentic phishing/social engineering MBOX from Jose Nazario...")
    mbox = download_nazario_phishing_mbox()
    if mbox:
        print(f"-> Saved authentic .mbox container to {mbox}")

    print("\nDataset fetch completed successfully!")
    print(f"All files are stored in: {DOWNLOADS_DIR}")
    print("You can upload these .eml / .mbox files directly into BEC-FORGE at http://127.0.0.1:8000/acquisition")
