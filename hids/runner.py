# Author: TK
# Date: 22-02-2026
# Purpose: Initializes modules, orchestator program.
"""
Main orchestration engine for the HIDS.

Responsibilities:
- Initialize detection modules
- Load and maintain integrity baseline
- Run polling loop
- Collect alerts
- Forward alerts to logger

This module coordinates all security checks.

"""

import time
from typing import Optional

from hids.config import AppConfig
from hids.logger import AlertLogger
from hids.integrity import(
    build_baseline, load_baseline, save_baseline, diff_baseline
)
from hids.processWatch import ProcessWatcher
from hids.netWatch import NetWatcher

def run(cfg: AppConfig) -> None:
    logger = AlertLogger(cfg.logging.alerts_file, cfg.agent.name)

    proc_watcher: Optional[ProcessWatcher] = None
    net_watcher: Optional[NetWatcher] = None

    # Integrity baseline load
    baseline = load_baseline(cfg.integrity.baseline_file)

    if cfg.processWatch.enabled:
        proc_watcher = ProcessWatcher(
            cfg.processWatch.suspicious_names,
            cfg.processWatch.allow_names)

        proc_watcher.detect_new() # prime

    if cfg.netWatch.enabled:
        net_watcher = NetWatcher(
            cfg.netWatch.suspicious_ports,
            cfg.netWatch.allow_remote_ports,
            cfg.netWatch.watch_outbound,
        )
        net_watcher.detect_new() # prime

    print(f"[+] {cfg.agent.name} running. Logging to {cfg.logging.alerts_file}")
    print("[+] Press Ctrl+C to stop program.")

    while True:
        # Integ scan
        if cfg.integrity.enabled:
            new_map = build_baseline(cfg.integrity.paths, cfg.integrity.hash_algo)

            if baseline:
                added, removed, modified = diff_baseline(baseline, new_map)

                for fp in added:
                    logger.log({"type": "integrity", "severity": "medium", "reason": "file_added",
                                "path": fp})
                for fp in removed:
                    logger.log({"type": "integrity", "severity": "medium", "reason": "file_removed",
                                "path": fp})
                for fp in modified:
                    logger.log({"type": "integrity", "severity": "high", "reason": "file_modified",
                                "path": fp})

            baseline = new_map
            save_baseline(cfg.integrity.baseline_file, baseline)

        # Process scan
        if proc_watcher:
            for a in proc_watcher.detect_new():
                logger.log(a)

        # net scan
        if net_watcher:
            for a in net_watcher.detect_new():
                logger.log(a)

        time.sleep(cfg.agent.poll_interval_sec)

