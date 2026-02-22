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

@dataclass
class NetWatchConfig:
    enabled: bool
    watch_outbound: bool
    suspicious_ports: List[int]

@dataclass
class LoggingConfig:
    alerts_file: str


@dataclass
class AgentConfig:
    name: str
    poll_interval_sec: int


@dataclass
class AppConfig:
    agent: AgentConfig
    integrity: IntegrityConfig
    process_watch: ProcessWatchConfig
    net_watch: NetWatchConfig
    logging: LoggingConfig

def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as file:
        cfg: Dict[str, Any] = yaml.safe_load(file)

    return AppConfig(
        agent=AgentConfig(**cfg["agent"]),
        integrity=IntegrityConfig(**cfg["integrity"]),
        process_watch=ProcessWatchConfig(**cfg["process_watch"]),
        net_watch=NetWatchConfig(**cfg["net_watch"]),
        logging=LoggingConfig(**cfg["logging"]),
    )
