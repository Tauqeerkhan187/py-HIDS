# Author: TK
# Date: 23-02-2026
# Purpose: CLI entry point
"""
CLI entry point for the Python Host-Based Intrusion Detection System.

Loads configuration file and starts the detection engine.

Usage:
    python hids_main.py --config configs/config.yaml
"""

import argparse
from hids.config import load_config
from hids.runner import run

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/config.yaml", help="Path to config YAML")
    args = ap.parse_args()

    cfg = load_config(args.config)
    run(cfg)


if __name__ == "__main__":
    main()

