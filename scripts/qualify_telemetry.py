#!/usr/bin/env python3
"""Local P8 pre-qualification for bounded telemetry producer behavior."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from obstacle_bridge.bridge_telemetry import TelemetryEmitter


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--capacity", type=int, default=16)
    parser.add_argument("--max-p99-ms", type=float, default=5.0)
    args = parser.parse_args()
    emitter = TelemetryEmitter("qualification", "local", capacity=args.capacity)
    samples = []
    for index in range(max(1, args.events)):
        started = time.perf_counter_ns()
        emitter.emit_load(queue_depth=index, dropped=0)
        samples.append((time.perf_counter_ns() - started) / 1_000_000.0)
    samples.sort()
    p99 = samples[min(len(samples) - 1, int(len(samples) * 0.99))]
    result = {"events": len(samples), "p99_emit_ms": p99, "drops": dict(emitter.dropped), "capacity": args.capacity}
    print(json.dumps(result, sort_keys=True))
    return 0 if p99 <= args.max_p99_ms else 1


if __name__ == "__main__":
    raise SystemExit(main())
