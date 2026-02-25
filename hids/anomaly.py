# Author: TK
# Date: 25-02-2026
# Purpose: detects anomaly burst (process and network burst)

import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List

class AnomalyEngine:
    """
    Simple burst detector for polling-based telemetry.
    - process burst: many new_process for same name within window
    - network burst: many new_connection for same remote endpoint within window

    """
    def __init__(
        self,
        enabled: bool = True,
        window_sec: int = 60,
        process_burst_threshold: int = 10,
        network_burst_threshold: int = 20,
        time_fn =time.time,
    ):
        self.enabled = enabled
        self.window_sec = int(window_sec)
        self.proc_thr = int(process_burst_threshold)
        self.net_thr = int(network_burst_threshold)
        self.time_fn = time_fn

        self.proc_hits: Dict[str, Deque[float]] = defaultdict(deque)
        self.net_hits: Dict[str, Deque[float]] = defaultdict(deque)

        # simple cooldown so you don't spam the same anomaly alert
        self._last_fired: Dict[str, float] = {}

    def _prune(self, dq: Deque[float], now: float) -> None:
        while dq and (now - dq[0]) > self.window_sec:
            dq.popleft()

    def _cooldown_ok(self, key: str, now: float, cooldown: int = 30) -> bool:
        last = self._last_fired.get(key, 0.0)
        if (now - last) >= cooldown:
            self._last_fired[key] = now
            return True
        return False

    def ingest(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        now = self.time_fn()
        out: List[Dict[str, Any]] = []

        a_type = alert.get("type")
        reason = alert.get("reason")

        if a_type == "process" and reason == "new_process":
            name = (alert.get("name") or "").lower()
            if name:
                dq = self.proc_hits[name]
                dq.append(now)
                self._prune(dq, now)
                if len(dq) >= self.proc_thr:
                    key = f"proc:{name}"
                    if self.cooldown_ok(key, now):
                        out.append({
                            "type": "anomaly",
                            "severity": "medium",
                            "reason": "process_burst"
                            "name": name,
                            "count": len(dq)
                            "window_sec": self.window_sec,
                        })

        if a_type == "network" and reason == "new_connection":
            remote = alert.get("remote")
            if isinstance(remote, list) and len(remote) == 2:
                remote_key = f"{remote[0]}:{remote[1]}"
                dq = self.net_hits[remote_key]
                dq.append(now)
                self._prune(dq, now)
                if len(dq) >= self.net_thr:
                    key = f"net:{remote_key}"
                    if self._cooldown_ok(key, now):
                        out.append({
                            "type": "anomaly",
                            "severity": "medium",
                            "reason": "connection_burst",
                            "remote": remote,
                            "count": len(dq),
                            "window_sec": self.window_sec,

                        })
        return out