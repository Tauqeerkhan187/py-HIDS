# Author: TK
# Date: 25-02-2026
# Purpose: tests for generate_report func

import tempfile
from hids.report import generate_report

def test_report_runs():
    with tempfile.NamedTemporaryFile(mode="w+", delete=True) as file:
        file.write('{"ts": "x", "type": "integrity", "reason": "file_modified", "severity": "high", "mitre_attack":["T1565.001"]}\n')
        file.flush()
        text = generate_report(file.name)
        assert "Total alerts: 1" in text
        assert "T1565.001" in text

