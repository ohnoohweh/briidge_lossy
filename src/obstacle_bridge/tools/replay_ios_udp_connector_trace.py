#!/usr/bin/env python3
"""Replay raw-IP UDP connector captures back into a localhost ChannelMux UDP listener."""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Iterator, List, Optional


_GLOBAL_HDR = struct.Struct("<IHHIIII")
_GLOBAL_HDR_BE = struct.Struct(">IHHIIII")
_RECORD_HDR = struct.Struct("<IIII")
_RECORD_HDR_BE = struct.Struct(">IIII")
_MAGIC_LE = 0xA1B2C3D4
_MAGIC_BE = 0xD4C3B2A1
_DLT_RAW = 101


def _iter_pcap_packets(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb") as fh:
        global_prefix = fh.read(24)
        if len(global_prefix) != 24:
            raise ValueError(f"{path} is too short to be a pcap file")

        magic_le = _GLOBAL_HDR.unpack(global_prefix)[0]
        if magic_le == _MAGIC_LE:
            global_hdr = _GLOBAL_HDR
            record_hdr = _RECORD_HDR
        else:
            magic_be = _GLOBAL_HDR_BE.unpack(global_prefix)[0]
            if magic_be != _MAGIC_BE:
                raise ValueError(f"{path} has unsupported pcap magic")
            global_hdr = _GLOBAL_HDR_BE
            record_hdr = _RECORD_HDR_BE

        _magic, _major, _minor, _tz, _sigfigs, _snaplen, network = global_hdr.unpack(global_prefix)
        if int(network) != _DLT_RAW:
            raise ValueError(f"{path} uses unsupported pcap network type {network}, expected {_DLT_RAW}")

        while True:
            prefix = fh.read(16)
            if not prefix:
                return
            if len(prefix) != 16:
                raise ValueError(f"{path} ended mid-record")
            ts_sec, ts_usec, incl_len, _orig_len = record_hdr.unpack(prefix)
            payload = fh.read(incl_len)
            if len(payload) != incl_len:
                raise ValueError(f"{path} ended mid-packet")
            yield (float(ts_sec) + (float(ts_usec) / 1_000_000.0), payload)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replay raw IPv4/IPv6 packets captured at the iOS UDP connector seam. "
            "Use the connector's 'to-mux' pcap to reproduce ChannelMux and lower-layer crashes "
            "without the PacketTunnel provider."
        )
    )
    parser.add_argument("pcap", help="Path to ipserver-udp-connector-to-mux-*.pcap")
    parser.add_argument("--host", default="127.0.0.1", help="Target UDP host for replay (default: 127.0.0.1)")
    parser.add_argument("--port", required=True, type=int, help="Target UDP port for replay")
    parser.add_argument(
        "--preserve-timing",
        action="store_true",
        help="Sleep between packets using capture deltas",
    )
    parser.add_argument(
        "--time-scale",
        type=float,
        default=1.0,
        help="Multiplier applied to preserved delays (default: 1.0)",
    )
    parser.add_argument(
        "--max-delay-ms",
        type=float,
        default=2000.0,
        help="Cap preserved per-packet delay in milliseconds (default: 2000)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Replay only the first N packets (0 means all packets)",
    )
    args = parser.parse_args(argv)

    if not (1 <= int(args.port) <= 65535):
        raise SystemExit("--port must be in 1..65535")
    if float(args.time_scale) <= 0:
        raise SystemExit("--time-scale must be > 0")
    if float(args.max_delay_ms) < 0:
        raise SystemExit("--max-delay-ms must be >= 0")

    path = Path(args.pcap)
    packets = list(_iter_pcap_packets(path))
    if not packets:
        print("No packets found.", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET6 if ":" in str(args.host) else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        previous_ts: Optional[float] = None
        sent = 0
        total_bytes = 0
        for ts, payload in packets:
            if args.limit and sent >= int(args.limit):
                break
            if args.preserve_timing and previous_ts is not None:
                delay = max(0.0, ts - previous_ts) * float(args.time_scale)
                delay = min(delay, float(args.max_delay_ms) / 1000.0)
                if delay > 0:
                    time.sleep(delay)
            sock.sendto(payload, (str(args.host), int(args.port)))
            previous_ts = ts
            sent += 1
            total_bytes += len(payload)
            if sent <= 3 or (sent % 128) == 0:
                print(f"replayed packet={sent} bytes={len(payload)}", file=sys.stderr)
        print(
            f"Replay completed: packets={sent} bytes={total_bytes} target={args.host}:{int(args.port)} source={path}",
            file=sys.stderr,
        )
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
