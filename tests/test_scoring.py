# Author: TK
# Date: 25-02-2026
# Purpose: Test for risk scoring and severity

from hids.scoring import score_alert

def test_scoring_escalates():
    risk = {
        "enabled": True,
        "base_scores": {"integrity": {"file_modified": 70}},
        "mitre_weights": {"T1565.001": 15},
        "severity_thresholds": {"medium": 40, "high": 70},
    }
    a = {"type": "integrity", "reason": "file_modified", "severity": "low", "mitre_attack": ["T1565.001"]}
    out = score_alert(a, risk)
    assert out["risk_score"] == 85
    assert out["severity"] == "high"
