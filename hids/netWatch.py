# Author: TK
# Date: 22-02-2026
# Purpose: Monitors net connections and flags suspicious remote ports.
"""
Monitors active network connections using psutil.

Features:
- Detects newly observed outbound connections
- Flags connections to suspicious remote ports
- Tracks previous connection state

Simulates lightweight network anomaly detection.

"""
import psutil
from typing import Dict, List, Set, Tuple

class NetWatcher:
    def __init__(self, suspicious_ports: List[int], allow_remote_ports: List[int], watch_outbound: bool = True):
        self.suspicious_ports = set(suspicious_ports)
        self.allow_ports = set(allow_remote_ports or [])
        self.watch_outbound = watch_outbound
        self.seen: Set[Tuple] = set()

    def snapshot(self) -> Set[Tuple]:
        conns = set()
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            laddr = (c.laddr.ip, c.laddr.port) if c.laddr else None
            raddr = (c.raddr.ip, c.raddr.port) if c.raddr else None
            conns.add((c.pid, laddr, raddr, c.status))
        return conns

    def detect_new(self) -> List[Dict]:
        alerts = []
        current = self.snapshot()
        new_conns = current - self.seen

        for pid, laddr, raddr, status in new_conns:
            rport = raddr[1] if raddr else None

            severity = "low"
            reason = "new_connection"

            if rport in self.suspicious_ports:
                severity = "high"
                reason = "suspicious_remote_port"

            if rport in self.allow_ports:
                continue

            alerts.append({
                "type": "network",
                "severity": severity,
                "reason": reason,
                "pid": pid,
                "local": laddr,
                "remote": raddr,
                "status": status,
            })

        self.seen = current
        return alerts

