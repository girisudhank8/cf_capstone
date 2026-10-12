# BEC-FORGE

## Business Email Compromise Forensic Investigation & Risk Assessment Engine

A comprehensive digital forensic platform for analyzing email evidence, detecting multi-layered BEC indicators, and reconstructing complex cyber fraud kill-chains.

Developed for Cyber Forensics Capstone. Built with **Python 3.11** + **FastAPI** + **Uvicorn** + **NetworkX** + **Cytoscape.js** + **Jinja2** + **SQLite**.

---

## Complete Core Innovations Architecture (Phases 1–7)

### 1. Sender Identity Fingerprinting & Drift Engine (Core Innovation #1)
- Dynamic behavioral baseline compilation stored in `sender_fingerprints`.
- Tracks typical sending hours ($0–23$ UTC), common recipients & frequencies, Reply-To & Return-Path routing history, and authentication consistency.
- Generates **Identity Drift Score ($0–100$)** and qualitative severity rating (`NONE`, `LOW`, `MODERATE`, `HIGH`, `CRITICAL`).

### 2. Interactive Communication Graph Analysis (Core Innovation #2)
- Network topology constructed via **NetworkX** (`graph/communication_graph.py`).
- Directed edges track frequency, timestamps, and interaction context.
- Detects **`🚨 NEW COMMUNICATION RELATIONSHIP`** for first-time sender-recipient interactions.
- Rendered in a high-performance interactive visual canvas via **Cytoscape.js** at `/graph`.

### 3. Multi-Layer Identity Consistency Engine (Core Innovation #3)
- Cryptographic verification of SPF, DKIM, DMARC, and Authenticated Received Chain (**ARC**) (`RFC 7489`).
- Categorizes threat hypotheses into:
  - **`POTENTIAL_SPOOFING`**: Triggered by header/domain mismatches and cryptographic validation failures.
  - **`POSSIBLE_COMPROMISE`**: Triggered when authentication checks pass, but high behavioral drift or Reply-To deviation is observed.
  - **`BENIGN / NORMAL`**: Baseline clean traffic.

### 4. BEC Attack-Chain Reconstruction (Core Innovation #4)
- Automated multi-stage forensic progression reconstruction (`detection/attack_chain.py`):
  1. *Normal Trust Baseline*
  2. *Behavioral Deviation*
  3. *New Entity / Recipient Injection*
  4. *Executive Impersonation / Authority Leverage*
  5. *Urgency & Confidentiality Mandate*
  6. *Financial Diversion Request*
  7. *Payment Execution Mandate*
- Visualized as an interactive chronological kill-chain progression timeline in the forensic dossier.

### 5. Conversation Hijacking Detection (Phase 6)
- Analyzes In-Reply-To and References header continuity (`detection/conversation_hijacking.py`).
- Flags vendor thread hijacking where attackers compromise an ongoing invoice discussion and secretly alter Reply-To or bank wire coordinates.

### 6. Explainable Risk Engine with Counterfactual Analysis (Core Innovation #5)
- Weighted scoring across 11 configurable components in `config/settings.py`.
- Generates transparent, human-readable forensic explanations.
- Computes analytical **Counterfactual Estimations** (e.g. *“If Reply-To matched historical sender: Risk would reduce from 84 to approximately 62”*).

---

## Quick Start

### 1. Install Dependencies

```bash
cd bec_forge
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

- **Forensic Console**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Network Graph**: [http://127.0.0.1:8000/graph](http://127.0.0.1:8000/graph)
- **Sender Intelligence**: [http://127.0.0.1:8000/senders](http://127.0.0.1:8000/senders)
- **OpenAPI Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Run Test Suite

```bash
# 67 unit and integration tests covering all modules
python -m pytest tests/ -v
```

---

## REST API Directory

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Operations Dashboard |
| `GET` | `/acquisition` | Evidence Ingestion Console |
| `GET` | `/analysis?id=...` | Forensic Dossier & Attack-Chain Timeline |
| `GET` | `/senders` | Sender Fingerprints & Drift Analytics |
| `GET` | `/graph` | Interactive Cytoscape.js Network Graph |
| `GET` | `/findings` | Findings Log with severity filters |
| `GET` | `/api/evidence` | Evidence Catalogue with SHA-256 hashes (JSON) |
| `GET` | `/api/analyses` | Risk assessments and threat classifications (JSON) |
| `GET` | `/api/analyses/{id}` | Detailed forensic evaluation for an evidence item (JSON) |
| `GET` | `/api/fingerprints` | Compiled sender behavioral profiles (JSON) |
| `GET` | `/api/fingerprints/{sender}` | Profile for a specific sender (JSON) |
| `GET` | `/api/graph` | Directed graph nodes, edges, and relationship metrics (JSON) |
| `GET` | `/api/attack-chain/{id}` | Reconstructed 7-stage BEC Attack Chain (JSON) |
| `POST` | `/api/analyze` | Programmatic `.eml` evidence submission (JSON) |
| `GET` | `/docs` | Interactive Swagger API Testing |
