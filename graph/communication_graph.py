"""
BEC-FORGE Communication Graph Module (Phase 5)

Core Innovation #2: COMMUNICATION GRAPH ANALYSIS

Builds and queries an email communication graph using NetworkX:
- Nodes: Email addresses (with metadata: role, email count, risk tags)
- Edges: Sender -> Recipient relationships (with count, subjects, timestamps)
- Anomaly Detection:
  - First-time / New Communication Relationships
  - Single-transaction isolated edges
  - Executive-to-Subordinate or Executive-to-Unknown relationships
- Graph Serialization:
  - Returns cytoscape/vis.js/D3-compatible JSON nodes and edges for rich visualization
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Set

import networkx as nx

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import db_cursor

logger = logging.getLogger(__name__)


@dataclass
class EdgeAnomaly:
    sender: str
    recipient: str
    anomaly_type: str    # "NEW_RELATIONSHIP", "UNUSUAL_EXECUTIVE_TARGET", "ISOLATED_TRANSACTION"
    severity: str        # INFO, MEDIUM, HIGH, CRITICAL
    description: str


@dataclass
class GraphAnalysisResult:
    total_nodes: int
    total_edges: int
    new_relationships_count: int
    anomalies: list[EdgeAnomaly] = field(default_factory=list)
    graph_data: dict = field(default_factory=dict) # nodes & edges JSON format


def record_communication_edge(
    sender: str,
    recipient: str,
    evidence_id: Optional[str] = None,
    subject: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> bool:
    """
    Record an observed sender -> recipient edge into SQLite communication_edges table.
    Returns True if this is a newly observed communication pair (first time ever).
    """
    if not sender or not recipient:
        return False

    s = sender.strip().lower()
    r = recipient.strip().lower()
    ts = timestamp or datetime.utcnow().isoformat()

    is_new = False
    with db_cursor() as (conn, cur):
        # Check if pair has been seen before
        cur.execute(
            "SELECT COUNT(*) as c FROM communication_edges WHERE sender = ? AND recipient = ?",
            (s, r),
        )
        existing_count = cur.fetchone()["c"]
        if existing_count == 0:
            is_new = True

        cur.execute(
            """INSERT OR IGNORE INTO communication_edges (
                sender, recipient, evidence_id, subject, timestamp, is_new_relationship
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (s, r, evidence_id, subject, ts, 1 if is_new else 0),
        )

    return is_new


def build_networkx_graph() -> nx.DiGraph:
    """Construct directed NetworkX graph from database records."""
    G = nx.DiGraph()

    with db_cursor() as (conn, cur):
        # Fetch sender info
        cur.execute("SELECT email_address, display_name, email_count FROM senders")
        for row in cur.fetchall():
            addr = row["email_address"]
            G.add_node(
                addr,
                label=row["display_name"] or addr,
                type="sender",
                email_count=row["email_count"],
            )

        # Fetch communication edges
        cur.execute(
            """SELECT sender, recipient, COUNT(*) as freq, 
                      MAX(is_new_relationship) as has_new,
                      GROUP_CONCAT(subject, ' || ') as subjects
               FROM communication_edges 
               GROUP BY sender, recipient"""
        )
        for row in cur.fetchall():
            s = row["sender"]
            r = row["recipient"]
            freq = row["freq"]
            is_new = bool(row["has_new"])
            subjs = row["subjects"] or ""

            if not G.has_node(s):
                G.add_node(s, label=s, type="sender", email_count=freq)
            if not G.has_node(r):
                G.add_node(r, label=r, type="recipient", email_count=freq)

            G.add_edge(
                s, r,
                weight=freq,
                is_new_relationship=is_new,
                subjects=subjs,
            )

    return G


def get_graph_visualization_data() -> dict:
    """
    Return nodes and edges formatted for HTML/Canvas/SVG network graph rendering.
    """
    G = build_networkx_graph()

    nodes = []
    edges = []

    # Map node degrees for sizing
    for n, attrs in G.nodes(data=True):
        degree = G.degree(n)
        is_exec = any(title in n.lower() for title in ["ceo", "cfo", "director", "exec", "president"])
        
        # Color coding
        if is_exec:
            color = "#f85149" # Red for execs
        elif attrs.get("type") == "sender":
            color = "#58a6ff" # Blue for senders
        else:
            color = "#39c5cf" # Cyan for recipients

        nodes.append({
            "id": n,
            "label": attrs.get("label", n),
            "type": attrs.get("type", "entity"),
            "degree": degree,
            "color": color,
            "is_executive": is_exec,
        })

    for u, v, attrs in G.edges(data=True):
        is_new = attrs.get("is_new_relationship", False)
        edges.append({
            "source": u,
            "target": v,
            "frequency": attrs.get("weight", 1),
            "is_new": is_new,
            "color": "#f85149" if is_new else "#30363d",
            "subjects": attrs.get("subjects", "")[:100],
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "new_relationships": sum(1 for e in edges if e["is_new"]),
        }
    }


def analyze_email_relationships(
    sender: str,
    recipients: list[str],
    evidence_id: Optional[str] = None,
    subject: Optional[str] = None,
) -> list[EdgeAnomaly]:
    """
    Inspect whether the email establishes a new/unusual relationship.
    Flags: 'NEW COMMUNICATION RELATIONSHIP'
    """
    anomalies = []
    if not sender or not recipients:
        return anomalies

    s = sender.strip().lower()
    for r in recipients:
        if not r:
            continue
        is_new = record_communication_edge(
            sender=s,
            recipient=r,
            evidence_id=evidence_id,
            subject=subject,
        )

        if is_new:
            # Check if sender is executive contacting someone new
            is_exec = any(t in s for t in ["ceo", "cfo", "director", "exec", "president"])
            sev = "HIGH" if is_exec else "MEDIUM"
            anomalies.append(EdgeAnomaly(
                sender=s,
                recipient=r,
                anomaly_type="NEW_RELATIONSHIP",
                severity=sev,
                description=f"First-time communication relationship established: '{s}' → '{r}'. New communication channels are a prime BEC reconnaissance/execution indicator.",
            ))

    return anomalies
