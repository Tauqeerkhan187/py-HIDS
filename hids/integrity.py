# Author: TK
# Date: 22-02-2026
# Purpose: File integrity monitoring (FIM) (hash + diff)
"""
Features:
- Recursively collects files from configured paths
- Generates cryptographic hashes (default: SHA-256)
- Stores baseline state
- Detects added, removed, and modified files

This simulates host-based tamper detection mechanisms.

"""

import hashlib
import json
import os
from typing import Dict, List, Tuple

def hash_file(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def collect_files(paths: List[str]) -> List[str]:
    files = []
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                files.append(os.path.join(dirpath, fn))
    return files

def build_baseline(paths: List[str], algo: str) -> Dict[str, str]:
    baseline: Dict[str, str] = {}
    for fp in collect_files(paths):
        try:
            baseline[fp] = hash_file(fp, algo)
        except (PermissionError, FileNotFoundError):
            # file disappeared or can't be read
            continue
    return baseline

def load_baseline(baseline_file: str) -> Dict[str, str]:
    """
    Loads the baseline JSON map from disk now.

    if the file doesn't exist, is empty, or is corrupted, return an empty baseline.
    This prevents the agent from crashing and allows it to rebuild baseline cleanly.
    """
    if not os.path.exists(baseline_file):
        return {}

    try:
        # Handle empty files
        if os.path.getsize(baseline_file) == 0:
            return {}

        with open(baseline__file, "r", encoding="utf-8") as file:
            data = json.load(file)

def save_baseline(baseline_file: str, baseline: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)


def diff_baseline(old: Dict[str, str], new: Dict[str, str]) -> Tuple[List[str],  List[str],                                                                 List[str]]:
    old_set = set(old.keys())
    new_set = set(new.keys())

    added = sorted(list(new_set - old_set))
    removed = sorted(list(old_set - new_set))

    modified = []
    for fp in sorted(list(old_set & new_set)):
        if old.get(fp) != new.get(fp):
            modified.append(fp)

    return added, removed, modified

