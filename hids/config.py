# Author: TK
# Date: 22/02/2026
# Purpose: Load YAML config and map it to structured data classes
"""
Loads YAML configuration and maps it into structured dataclasses.
This allows:
- Type-safe access to settings
- Clean separation between config and runtime logic
- Easy extension of detection modules

All runtime behavior is driven by config.yaml.

"""

from dataclasses import dataclass
from typing import List, Dict, Any
import yaml

@dataclass
class IntegrityConfig:
    enabled: bool
    paths: List[str]
    hash_algo: str
    baseline_file: str

@dataclass
class ProcessWatchConfig:
    enabled: bool
    suspicious_names: List[str]
    allow_names: List[str] = None

@dataclass
class NetWatchConfig:
    enabled: bool
    watch_outbound: bool
    suspicious_ports: List[int]
    allow_remote_ports: List[int] = None

@dataclass
class MitreConfig:
    mappings: Dict[str, Dict[str, List[str]]]

@dataclass
class RiskConfig:
    enabled: bool
    base_scores: Dict[str, Dict[str, int]]
    mitre_weights: Dict[str, int]
    severity_thresholds: Dict[str, int]

@dataclass
class AnomalyConfig:
    enabled: bool
    window_sec: int
    process_burst_threshold: int
    network_burst_threshold: int

@dataclass
class LoggingConfig:
    alerts_file: str
    dedupe_sec: int = 0


@dataclass
class AgentConfig:
    name: str
    poll_interval_sec: int


@dataclass
class AppConfig:
    agent: AgentConfig
    integrity: IntegrityConfig
    processWatch: ProcessWatchConfig
    netWatch: NetWatchConfig
    logging: LoggingConfig
    mitre: MitreConfig
    risk: RiskConfig
    anomaly: AnomalyConfig

def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as file:
        cfg: Dict[str, Any] = yaml.safe_load(file)

    pw = cfg["processWatch"]
    nw = cfg["netWatch"]
    mitre_cfg = cfg.get("mitre", {"mappings": {}})
    risk_cfg = cfg.get("risk", {})
    an_cfg = cfg.get("anomaly", {})

    return AppConfig(
        agent=AgentConfig(**cfg["agent"]),
        integrity=IntegrityConfig(**cfg["integrity"]),
        processWatch=ProcessWatchConfig(
            enabled=pw["enabled"],
            suspicious_names=pw["suspicious_names"],
            allow_names=pw.get("allow_names", []),
        ),
        netWatch=NetWatchConfig(
            enabled=nw["enabled"],
            watch_outbound=nw["watch_outbound"],
            suspicious_ports=nw["suspicious_ports"],
            allow_remote_ports=nw.get("allow_remote_ports", []),
        ),
        logging=LoggingConfig(**cfg["logging"]),

        mitre=MitreConfig(mappings=mitre_cfg.get("mappings", {})),

        risk=RiskConfig(
            enabled=risk_cfg.get("enabled", True),
            base_scores=risk_cfg.get("base_scores", {}),
            mitre_weights=risk_cfg.get("mitre_weights", {}),
            severity_thresholds=risk_cfg.get("severity_thresholds", {"medium": 40, "high": 70}),
        ),

        anomaly=AnomalyConfig(
            enabled=an_cfg.get("enabled", True),
            window_sec=an_cfg.get("window_sec", 60),
            process_burst_threshold=an_cfg.get("process_burst_threshold", 10),
            network_burst_threshold=an_cfg.get("network_burst_threshold", 20),
        )
    )
