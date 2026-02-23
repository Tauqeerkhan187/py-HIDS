# Author: TK
# Date: 24-02-2026
# Purpose: code which modifies alerts with MITRE ATT&CK technique IDs based
# on alert type and reason, adds threat intelligence context to alerts.

from typing import Any, Dict, List

def tag_alert(alert: Dict[str, Any], mappings: Dict[str, Dict[str, List[str]]]) -> Dict[str, Any]:
    """
    Add MITRE ATT&CK technique IDs (if any) based on alert type + reason.
    """
    a_type = alert.get("type")
    reason = alert.get("reason")

    techniques: List[str] = []
    if isinstance(mappings, dict):
        techniques = mappings.get(a_type, {}).get(reason, []) or []

    if techniques:
        # Add as a structured field that plays nice with JSONL/SIEM ingestion
        alert = dict(alert) # don't mutate caller dict unexpectedly
        alert["mitre_attack"] = techniques

    return alert
