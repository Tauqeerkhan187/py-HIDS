# Author: TK
# Date: 25-02-2026
# Purpose: code to implement risk scoring in the HIDS

from typing import Any, Dict, List

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
ORDER_SEV = {0: "low", 1: "medium", 2: "high"}

def _max_sev(a: str, b: str) -> str:
    return ORDER_SEV[max(SEV_ORDER.get(a, 0), SEV_ORDER.get(b, 0))]

def score_alert(alert: Dict[str, Any], risk_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add risk_score and optionally escalate severity based on configured threshold.
    """
    if not risk_cfg or not risk_cfg.get("enabled", False):
        return alert

    a_type = alert.get("type")
    reason = alert.get("reason")
    sev = alert.get("severity", "low")

    base_scores = (risk_cfg.get("base_scores") or {}).get(a_type, {}) or {}
    score = int(base_scores.get(reason, 0))

    # Add MITRE technique weights
    mitre_weights = risk_cfg.get("mitre_weights") or {}
    techniques: List[str] = alert.get("mitre_attack", []) or []
    for t in techniques:
        scores += int(mitre_weights.get(t, 0))

    # Escalate severity based on score
    thresholds = risk_cfg.get("severity_thresholds") or {}
    if score >= int(thresholds.get("high", 999999)):
        sev = _max_sev(sev, "high")
    elif score >= int(thresholds.get("medium", 999999)):
        sev = _max_sev(sev, "medium")

    out = dict(alert)
    out["risk_score"] = score
    out["severity"] = sev
    return out
