# Author: TK
# Date: 22-02-2026
# Purpose Monitors new processes and flags sus names.
"""
Monitors system processes using psutil.

Features:
- Detects newly spawned processes
- Flags suspicious process names (config-driven)
- Tracks previously seen PIDs to avoid duplicate alerts

Simulates behavioral host-based detection.

"""
import psutil
from typing import Dict, Set, List

class ProcessWatcher:
    def __init__(self, suspicious_names: List[str], allow_names: List[str]):
        self.suspicious = {s.lower() for s in suspicious_names}
        self.allow = {a.lower() for a in (allow_names or [])}
        self.seen_pids: Set[int] = set()

    def snapshot(self) -> Dict[int, Dict]:
        procs = {}
        for p in psutil.process_iter(attrs=["pid", "name", "exe", "username", "create_time"]):
            try:
                procs[p.info["pid"]] = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs

    def detect_new(self) -> List[Dict]:
        alerts = []
        current = self.snapshot()
        current_pids = set(current.keys())

        new_pids = current_pids - self.seen_pids
        for pid in new_pids:
            info = current.get(pid, {})
            name = (info.get("name") or "").lower()
            # Drop noise early
            if name in self.allow:
                continue

            severity = "low"
            reason = "new_process"

            if any(s in name for s in self.suspicious):
                severity = "high"
                reason = "suspicious_process_name"

            alerts.append({
                "type": "process",
                "severity": severity,
                "reason": reason,
                "pid": pid,
                "name": info.get("name"),
                "exe": info.get("exe"),
                "user": info.get("username"),
            })

        self.seen_pids = current_pids
        return alerts
