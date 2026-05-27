from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from obstacle_bridge.bridge import BaseFrameV2, DataPacket, FRAME_CONT, Protocol, Session


_SNAPSHOT_RE = re.compile(
    r"\[RX\] pending=\[(?P<pending>[^\]]*)\](?:…)? missing=\[(?P<missing>[^\]]*)\](?:…)? expected=(?P<expected>\d+)"
)
_QUEUED_RE = re.compile(
    r"\[RX\] ctr=(?P<ctr>\d+) QUEUED \(gap\); frame_type=(?P<frame_type>\d+) off/len=(?P<off_len>\d+) chunk_len=(?P<chunk_len>\d+)"
)
_IN_ORDER_RE = re.compile(r"\[RX\] ctr=(?P<ctr>\d+) IN-ORDER -> advance expected=(?P<expected>\d+)")
_POP_RE = re.compile(r"\[RX\] ctr=(?P<ctr>\d+) POP from pending -> advance expected=(?P<expected>\d+)")


def _parse_int_list(blob: str) -> list[int]:
    blob = str(blob or "").strip()
    if not blob:
        return []
    out: list[int] = []
    for token in blob.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(int(token))
        except Exception:
            continue
    return out


@dataclass
class Snapshot:
    line_no: int
    expected: int
    pending: list[int]
    missing: list[int]


@dataclass
class DataEvent:
    line_no: int
    kind: str
    ctr: int
    frame_type: int = FRAME_CONT
    off_len: int = 0
    chunk_len: int = 1
    observed: Optional[Snapshot] = None
    popped: list[int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.popped is None:
            self.popped = []


def parse_log_events(path: Path) -> tuple[list[DataEvent], list[dict[str, Any]]]:
    events: list[DataEvent] = []
    anomalies: list[dict[str, Any]] = []
    current_inorder: Optional[DataEvent] = None
    pending_snapshot: Optional[Snapshot] = None
    last_snapshot: Optional[Snapshot] = None

    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = str(raw)

        snap_m = _SNAPSHOT_RE.search(line)
        if snap_m:
            snap = Snapshot(
                line_no=line_no,
                expected=int(snap_m.group("expected")),
                pending=_parse_int_list(snap_m.group("pending")),
                missing=_parse_int_list(snap_m.group("missing")),
            )
            if (
                last_snapshot is not None
                and snap.expected < last_snapshot.expected
                and snap.expected == 1
            ):
                anomalies.append(
                    {
                        "type": "expected_regressed",
                        "line_no": line_no,
                        "from_expected": last_snapshot.expected,
                        "to_expected": snap.expected,
                        "pending_head": snap.pending[:12],
                        "missing_head": snap.missing[:12],
                    }
                )
            last_snapshot = snap
            if current_inorder is not None and current_inorder.observed is None:
                current_inorder.observed = snap
                events.append(current_inorder)
                current_inorder = None
            else:
                pending_snapshot = snap
            continue

        queued_m = _QUEUED_RE.search(line)
        if queued_m:
            ev = DataEvent(
                line_no=line_no,
                kind="queued",
                ctr=int(queued_m.group("ctr")),
                frame_type=int(queued_m.group("frame_type")),
                off_len=int(queued_m.group("off_len")),
                chunk_len=int(queued_m.group("chunk_len")),
                observed=pending_snapshot,
            )
            pending_snapshot = None
            events.append(ev)
            continue

        inorder_m = _IN_ORDER_RE.search(line)
        if inorder_m:
            if current_inorder is not None:
                events.append(current_inorder)
            current_inorder = DataEvent(
                line_no=line_no,
                kind="in_order",
                ctr=int(inorder_m.group("ctr")),
            )
            pending_snapshot = None
            continue

        pop_m = _POP_RE.search(line)
        if pop_m and current_inorder is not None:
            current_inorder.popped.append(int(pop_m.group("ctr")))
            continue

    if current_inorder is not None:
        events.append(current_inorder)

    return events, anomalies


def _build_packet(event: DataEvent) -> DataPacket:
    data = bytes(max(0, int(event.chunk_len)))
    return DataPacket.build_full(event.ctr, int(event.frame_type), int(event.off_len), data)


def replay_events(
    events: list[DataEvent],
    *,
    inject_reset_on_regression: bool = False,
) -> dict[str, Any]:
    session = Session(proto=Protocol(BaseFrameV2))
    results: list[dict[str, Any]] = []
    previous_observed_expected: Optional[int] = None

    for ev in events:
        if (
            inject_reset_on_regression
            and ev.observed is not None
            and previous_observed_expected is not None
            and ev.observed.expected == 1
            and previous_observed_expected > 1
            and session.expected > 1
        ):
            session.expected = 1
            session.pending.clear()
            session.missing.clear()
            session.reass = None

        previous_observed_expected = ev.observed.expected if ev.observed is not None else previous_observed_expected

        pkt = _build_packet(ev)
        _advanced, _completed = session.process_data(pkt)

        replay_snapshot = {
            "expected": int(session.expected),
            "pending_head": sorted(session.pending.keys())[:12],
            "missing_head": sorted(session.missing)[:12],
            "pending_count": len(session.pending),
            "missing_count": len(session.missing),
        }
        observed_snapshot = None
        match = None
        if ev.observed is not None:
            observed_snapshot = {
                "expected": ev.observed.expected,
                "pending_head": ev.observed.pending[:12],
                "missing_head": ev.observed.missing[:12],
                "pending_count": len(ev.observed.pending),
                "missing_count": len(ev.observed.missing),
            }
            match = (
                replay_snapshot["expected"] == observed_snapshot["expected"]
                and replay_snapshot["pending_head"] == observed_snapshot["pending_head"]
                and replay_snapshot["missing_head"] == observed_snapshot["missing_head"]
            )
        results.append(
            {
                "line_no": ev.line_no,
                "kind": ev.kind,
                "ctr": ev.ctr,
                "popped": list(ev.popped),
                "observed": observed_snapshot,
                "replayed": replay_snapshot,
                "match": match,
            }
        )

    compared = [r for r in results if r["match"] is not None]
    matched = [r for r in compared if r["match"]]
    return {
        "event_count": len(events),
        "compared_count": len(compared),
        "matched_count": len(matched),
        "mismatch_count": len(compared) - len(matched),
        "match_ratio": (len(matched) / len(compared)) if compared else 0.0,
        "results": results,
        "final": results[-1]["replayed"] if results else {},
    }


def analyze_log(path: Path) -> dict[str, Any]:
    events, anomalies = parse_log_events(path)
    baseline = replay_events(events, inject_reset_on_regression=False)
    with_reset = replay_events(events, inject_reset_on_regression=True)
    return {
        "path": str(path),
        "anomalies": anomalies,
        "baseline": {
            "event_count": baseline["event_count"],
            "compared_count": baseline["compared_count"],
            "matched_count": baseline["matched_count"],
            "mismatch_count": baseline["mismatch_count"],
            "match_ratio": baseline["match_ratio"],
            "final": baseline["final"],
        },
        "with_reset": {
            "event_count": with_reset["event_count"],
            "compared_count": with_reset["compared_count"],
            "matched_count": with_reset["matched_count"],
            "mismatch_count": with_reset["mismatch_count"],
            "match_ratio": with_reset["match_ratio"],
            "final": with_reset["final"],
        },
        "first_mismatches_baseline": [r for r in baseline["results"] if r["match"] is False][:12],
        "first_mismatches_with_reset": [r for r in with_reset["results"] if r["match"] is False][:12],
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Semantically replay myudp RX state from vpn-obstaclebridge.log")
    parser.add_argument("log_path", help="Path to vpn-obstaclebridge.log")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    args = parser.parse_args(argv)

    report = analyze_log(Path(args.log_path))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"log: {report['path']}")
        print(f"anomalies: {len(report['anomalies'])}")
        print(f"baseline match_ratio: {report['baseline']['match_ratio']:.3f} ({report['baseline']['matched_count']}/{report['baseline']['compared_count']})")
        print(f"with_reset match_ratio: {report['with_reset']['match_ratio']:.3f} ({report['with_reset']['matched_count']}/{report['with_reset']['compared_count']})")
        if report["anomalies"]:
            first = report["anomalies"][0]
            print(f"first anomaly: line {first['line_no']} expected {first['from_expected']} -> {first['to_expected']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
