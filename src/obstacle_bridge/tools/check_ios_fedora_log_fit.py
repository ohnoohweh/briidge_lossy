from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")
_IOS_CONN_RE = re.compile(
    r"\[UDP/PROTO\] connection_made; local=\('(?P<host>[^']+)', (?P<port>\d+)\)"
)
_IOS_RAW_RE = re.compile(
    r"transport_sock=\('(?P<host>[^']+)', (?P<port>\d+)\)"
)
_FEDORA_ACCEPT_RE = re.compile(
    r"\[UDP/SESSION\] listener accepted peer_id=(?P<peer_id>\d+) peer=\('(?P<host>[^']+)', (?P<port>\d+)\)"
)
_FEDORA_PEER_RE = re.compile(
    r"\('(?P<host>[^']+)', (?P<port>\d+)\)"
)


@dataclass
class PortEpoch:
    port: int
    first_line: int
    first_ts: str
    last_line: int
    last_ts: str
    line_count: int = 0

    def touch(self, line_no: int, ts: str) -> None:
        self.last_line = line_no
        self.last_ts = ts
        self.line_count += 1


def _timestamp(line: str) -> str:
    match = _TS_RE.match(line)
    return match.group("ts") if match else ""


def _record_epoch(store: dict[int, PortEpoch], port: int, line_no: int, ts: str) -> None:
    epoch = store.get(port)
    if epoch is None:
        epoch = PortEpoch(port=port, first_line=line_no, first_ts=ts, last_line=line_no, last_ts=ts, line_count=0)
        store[port] = epoch
    epoch.touch(line_no, ts)


def parse_ios_epochs(path: Path) -> dict[int, PortEpoch]:
    epochs: dict[int, PortEpoch] = {}
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        ts = _timestamp(raw)
        match = _IOS_CONN_RE.search(raw)
        if match:
            _record_epoch(epochs, int(match.group("port")), line_no, ts)
            continue
        raw_match = _IOS_RAW_RE.search(raw)
        if raw_match:
            _record_epoch(epochs, int(raw_match.group("port")), line_no, ts)
    return epochs


def parse_fedora_epochs(path: Path) -> dict[int, PortEpoch]:
    epochs: dict[int, PortEpoch] = {}
    tracked_ports: set[int] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        ts = _timestamp(raw)
        accept_match = _FEDORA_ACCEPT_RE.search(raw)
        if accept_match:
            port = int(accept_match.group("port"))
            tracked_ports.add(port)
            _record_epoch(epochs, port, line_no, ts)
            continue
        for peer_match in _FEDORA_PEER_RE.finditer(raw):
            port = int(peer_match.group("port"))
            if port in tracked_ports:
                _record_epoch(epochs, port, line_no, ts)
    return epochs


def analyze_log_fit(ios_log: Path, fedora_log: Path) -> dict[str, Any]:
    ios_epochs = parse_ios_epochs(ios_log)
    fedora_epochs = parse_fedora_epochs(fedora_log)
    ios_ports = sorted(ios_epochs)
    fedora_ports = sorted(fedora_epochs)
    matching_ports = sorted(set(ios_ports) & set(fedora_ports))

    warnings: list[str] = []
    ok = bool(matching_ports)

    if not ios_ports:
        warnings.append("No iPhone UDP local ports found in iPhone log.")
    if not fedora_ports:
        warnings.append("No accepted peer epochs found in Fedora log.")
    if ios_ports and len(ios_ports) > 1:
        warnings.append(f"Multiple iPhone UDP ports found: {ios_ports}.")
    if fedora_ports and len(fedora_ports) > 1:
        warnings.append(f"Multiple Fedora peer epochs found: {fedora_ports}.")
    if not matching_ports and ios_ports and fedora_ports:
        warnings.append(
            f"No shared UDP port between iPhone log {ios_ports} and Fedora log {fedora_ports}."
        )
    if len(matching_ports) == 1 and len(fedora_ports) > 1:
        warnings.append(
            f"Use Fedora peer epoch {matching_ports[0]} for cross-log analysis; ignore other accepted peers."
        )

    active_port = matching_ports[-1] if matching_ports else (ios_ports[-1] if ios_ports else None)

    return {
        "ok": ok,
        "ios_log": str(ios_log),
        "fedora_log": str(fedora_log),
        "ios_ports": ios_ports,
        "fedora_ports": fedora_ports,
        "matching_ports": matching_ports,
        "active_port": active_port,
        "ios_epochs": {str(k): asdict(v) for k, v in sorted(ios_epochs.items())},
        "fedora_epochs": {str(k): asdict(v) for k, v in sorted(fedora_epochs.items())},
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check whether an iPhone udp_session log and a Fedora listener log belong to the same UDP peer epoch."
    )
    parser.add_argument("ios_log", type=Path)
    parser.add_argument("fedora_log", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)

    report = analyze_log_fit(args.ios_log, args.fedora_log)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"iPhone ports: {report['ios_ports']}")
        print(f"Fedora ports: {report['fedora_ports']}")
        print(f"Matching ports: {report['matching_ports']}")
        print(f"Active port: {report['active_port']}")
        for warning in report["warnings"]:
            print(f"warning: {warning}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
