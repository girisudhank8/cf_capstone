"""
BEC-FORGE Main Entry Point (FastAPI Server)

Run with:
    python app.py
or
    uvicorn server.app:app --host 127.0.0.1 --port 8000 --reload
"""

import sys
from pathlib import Path
import uvicorn

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  BEC-FORGE — Forensic Investigation & Risk Assessment Engine")
    print("⚡ Starting FastAPI Server on http://127.0.0.1:8000")
    print("📖 OpenAPI Interactive API Docs at http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("server.app:app", host="127.0.0.1", port=8000, reload=False)
