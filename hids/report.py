# Author: TK
# Date: 24-02-2026
# Purpose: Generates a report on the alerts logged

import json
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

MITRE_NAMES = {
    "T1565.001": "Stored Data Manipulation",
    "T1070": "Indicator Removal on Host",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
}

def _read_alerts(alerts_file: str) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    try:
        with open(alerts_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodError:
                    continue

    except FileNotFoundError:
        return []

    return alerts

def generate_report(alerts_file: str) -> str:
    alerts = _read_alerts(alerts_file)

    by_type = Counter(a.get("type") for a in alerts)
    by_sev = Counter(a.get("severity") for a in alerts)
    by_reason = Counter(f"{a.get('type')}::{a.get('reason')}" for a in alerts)

    mitre = Counter()
    for a in alerts:
        for t in a.get("mitre_attack", []) or []:
            mitre[t] += 1

    lines: List[str] = []

    lines.append(f"TK-HIDS Summary Report ({datetime.utcnow().isoformat()}Z)")

    lines.append("=" * 60)

    lines.append(f"Total alerts: {len(alerts)}")

    lines.append("\n Counts by type:")
    for k, v in by_type.most_common():
        lines.append(f" - {k}: {v}")

    lines.append("\nCounts by severity:")
    for k, v in by_sev.most_common():
        lines.append(f" - {k}: {v}")

    lines.append("\nTop reasons:")
    for k, v in by_reason.most_common(10):
        lines.append(f" - {k}: {v}")

    if mitre:
        lines.append("\nMITRE ATT&CK techniques observed")
        for k, v in mitre.most_common(10):
            name = MITRE_NAMES.get(k, "")
            if name:
                lines.append(f"  - {k} ({name}): {v}")
            else:
                lines.append(f"  - {k}: {v}")

    # show last 5 alerts for quick view
    lines.append("\nLast 5 alerts:")
    for a in alerts[-5:]:
        mitre_list = a.get("mitre_attack", []) or []
        mitre_str = ",".join(mitre_list) if mitre_list else "-"

        lines.append(
            f"  - {a.get('ts')} "
            f"type={a.get('type')} "
            f"reason={a.get('reason')} "
            f"sev={a.get('severity')} "
            f"mitre={mitre_str}"
        )

    return "\n".join(lines)
