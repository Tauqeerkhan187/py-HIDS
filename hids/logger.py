# AUTHOR: TK
# DATE: 20/02/2026
# Purpose:

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

class AlertLogger:
    def __init__(self, alerts_file: str, agent_name: str):
        self.alerts_file = alerts_file
        self.agent_name = agent_name
        os.makedirs(os.path.dirname(alerts_file), exist_ok=True)

    def log(self, alert: Dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat()
            "agent": self.agent_name,
            **alert,
        }
        with open(self.alerts_file, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")

