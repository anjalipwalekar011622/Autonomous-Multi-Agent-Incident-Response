"""
Adapters that normalize Threat Hunter's and Forensics' real output into
the shapes the Risk Engine / Mitigation Agent expect, without requiring
any changes to their modules.
"""

# Exact-match lookup for known strings from anomaly_detector.py
EXACT_MATCHES = {
    "Brute Force Authentication": "Brute Force",
    "Suspicious Port Activity": "DDoS",
    "Obfuscated Command Execution": "Malware",
    "Resource Hijacking (CPU Anomaly)": "Malware",
    "Suspicious PowerShell": "Suspicious PowerShell",
    "Suspicious Process Access": "Suspicious Process Access",
    "Suspicious Registry Activity": "Suspicious Registry Activity",
}

# Substring/keyword fallback for patterns that vary (e.g. binary name
# embedded inside the string: "Unauthorized Binary (mimikatz.exe)")
KEYWORD_MATCHES = [
    ("unauthorized binary", "Malware"),
    ("brute force", "Brute Force"),
    ("phishing", "Phishing"),
    ("sql injection", "SQL Injection"),
    ("port scan", "Port Scan"),
    ("ransomware", "Ransomware"),
    ("ddos", "DDoS"),
    ("obfuscated", "Malware"),
    ("resource hijacking", "Malware"),
    ("suspicious port", "DDoS"),
    ("powershell", "Suspicious PowerShell"),
    ("process access", "Suspicious Process Access"),
    ("registry", "Suspicious Registry Activity"),
]


def normalize_attack_type(raw_attack_type: str) -> str:
    """
    Converts a raw attack_type string from Threat Hunter into one of the
    canonical categories used by ATTACK_TYPE_BASE_SCORE / ATTACK_TYPE_ACTION_MAP.
    Falls back to 'Unknown' only if nothing matches.
    """
    if not raw_attack_type:
        return "Unknown"

    if raw_attack_type in EXACT_MATCHES:
        return EXACT_MATCHES[raw_attack_type]

    lowered = raw_attack_type.lower()
    for keyword, canonical in KEYWORD_MATCHES:
        if keyword in lowered:
            return canonical

    return "Unknown"


def normalize_evidence(evidence_list: list) -> list:
    """
    Forensics currently returns evidence as a single concatenated string
    inside a list, e.g. ["event=X event_id=Y source_ip=Z ..."].
    This splits it into individual key=value items so the Risk Engine's
    evidence-count scoring reflects actual distinct evidence points,
    instead of always counting as 1.
    """
    if not evidence_list:
        return []

    expanded = []
    for item in evidence_list:
        if isinstance(item, str) and "=" in item and " " in item:
            parts = item.split()
            expanded.extend([p for p in parts if "=" in p])
        else:
            expanded.append(item)

    return expanded if expanded else evidence_list