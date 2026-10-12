"""
BEC-FORGE Configuration Settings
All scoring weights, thresholds, and system constants are defined here
to make the system fully configurable without touching analysis code.
"""

# ─────────────────────────────────────────────
# EVIDENCE SETTINGS
# ─────────────────────────────────────────────
EVIDENCE_DIR = "evidence"
REPORT_DIR = "reports"
DB_PATH = "bec_forge.db"

# ─────────────────────────────────────────────
# RISK ENGINE WEIGHTS  (must sum to 1.0)
# ─────────────────────────────────────────────
RISK_WEIGHTS: dict[str, float] = {
    "display_name_spoofing":   0.10,
    "domain_anomaly":          0.10,
    "reply_to_mismatch":       0.10,
    "return_path_anomaly":     0.05,
    "auth_anomalies":          0.10,
    "behavioral_anomaly":      0.15,
    "communication_anomaly":   0.10,
    "urgency_language":        0.08,
    "financial_language":      0.10,
    "authority_secrecy":       0.05,
    "conversation_hijacking":  0.07,
}

# ─────────────────────────────────────────────
# RISK LEVEL THRESHOLDS
# ─────────────────────────────────────────────
RISK_LEVELS: list[tuple[int, str, str]] = [
    (85, "CRITICAL",    "#FF0000"),
    (70, "HIGH",        "#FF4500"),
    (50, "SUSPICIOUS",  "#FFA500"),
    (30, "MEDIUM",      "#FFD700"),
    (0,  "LOW",         "#00CC44"),
]

def get_risk_level(score: float) -> tuple[str, str]:
    """Return (label, colour) for a given score 0-100."""
    for threshold, label, colour in RISK_LEVELS:
        if score >= threshold:
            return label, colour
    return "LOW", "#00CC44"

# ─────────────────────────────────────────────
# NLP KEYWORD DICTIONARIES
# ─────────────────────────────────────────────
URGENCY_KEYWORDS: list[str] = [
    "urgent", "urgently", "immediately", "asap", "act now",
    "within 1 hour", "within an hour", "critical", "today",
    "right away", "as soon as possible", "time sensitive",
    "time-sensitive", "deadline", "last chance", "final notice",
    "do it now", "hurry", "no delay", "without delay", "emergency",
]

FINANCIAL_KEYWORDS: list[str] = [
    "payment", "invoice", "bank", "transfer", "wire", "account",
    "transaction", "funds", "money", "pay", "banking", "routing",
    "ach", "swift", "remittance", "wire transfer", "bank account",
    "beneficiary", "financial", "budget", "expense", "vendor payment",
    "outstanding", "overdue", "credit", "debit",
]

AUTHORITY_KEYWORDS: list[str] = [
    "ceo", "chief executive", "director", "manager", "president",
    "vice president", "vp", "cfo", "chief financial", "coo",
    "hr", "human resources", "finance", "executive", "board",
    "leadership", "i am authorizing", "on behalf of",
    "as per my instruction", "at my request",
]

SECRECY_KEYWORDS: list[str] = [
    "confidential", "keep this private", "do not tell",
    "don't contact", "secret", "between us", "off the record",
    "do not share", "keep it quiet", "don't discuss",
    "don't mention", "discreet", "privately",
]

CREDENTIAL_KEYWORDS: list[str] = [
    "password", "login", "otp", "one-time password",
    "verification code", "credentials", "verify your account",
    "sign in", "log in", "authenticate", "2fa", "two-factor",
    "reset your password", "confirm your identity",
]

# ─────────────────────────────────────────────
# DOMAIN ANALYSIS
# ─────────────────────────────────────────────
LOOKALIKE_SIMILARITY_THRESHOLD: float = 0.80   # Levenshtein ratio
SUSPICIOUS_TLDS: list[str] = [
    ".xyz", ".top", ".club", ".online", ".site",
    ".tk", ".ml", ".ga", ".cf", ".gq",
]

# ─────────────────────────────────────────────
# SUSPICIOUS ATTACHMENT EXTENSIONS
# ─────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS: list[str] = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".ps1", ".msi", ".com", ".pif", ".hta", ".jar",
    ".xlsm", ".docm", ".pptm", ".xlsb",
]

# ─────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────
APP_TITLE = "BEC-FORGE"
APP_SUBTITLE = "Business Email Compromise Forensic Investigation & Risk Assessment Engine"
APP_VERSION = "1.0.0-Phase1"
