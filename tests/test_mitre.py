# Author: TK
# Date: 25-02-2026
# Purpose: test for mitre tagging

from hids.mitre import tag_alert

def test_tag_alert_adds_mitre():
    mappings = {"integrity": {"file_modified": ["T1565.001"]}}
    a = {"type": "integrity", "reason": "file_modified", "severity": "high"}
    out = tag_alert(a, mappings)
    assert out["mitre_attack"] == ["T1565.001"]

def test_tag_alert_no_mapping():
    mappings = {"integrity": {}}
    a = {"type": "integrity", "reason": "file_modified"}
    out = tag_alert(a, mappings)
    assert "mitre_attack" not in out
