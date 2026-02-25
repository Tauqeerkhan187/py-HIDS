# Author: TK
# Date: 25-02-2026
# Purpose: Tests for anomaly engine (tests process and network burst)

from hids.anomaly import AnomalyEngine

def test_process_burst_triggers():
    t = [0]
    def time_fn():
        return t[0]

    engine = AnomalyEngine(enabled=True, window_sec=60, process_burst_threshold=3, time_fn=time_fn)
    base = {"type": "process", "reason": "new_process", "severity": "low", "name": "bash"}

    assert engine.ingest(base) == []
    t[0] += 1

    assert engine.ingest(base) == []
    t[0] += 1

    out = engine.ingest(base)
    assert out and out[0]["reason"] == "process_burst"
