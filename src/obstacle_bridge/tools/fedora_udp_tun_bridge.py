#!/usr/bin/env python3
"""Minimal Fedora-side UDP <-> TUN bridge for the iOS packet-flow simplification experiment."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import selectors
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import fcntl
except Exception as exc:  # pragma: no cover - non-Linux import path
    fcntl = None
    _FCNTL_IMPORT_ERROR = exc
else:
    _FCNTL_IMPORT_ERROR = None


IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCSIFMTU = 0x8922
IFF_UP = 0x1
IFF_RUNNING = 0x40
TUN_READ_SIZE_MAX = 65535
PCAP_GLOBAL_HDR = struct.Struct("<IHHIIII")
PCAP_RECORD_HDR = struct.Struct("<IIII")
DLT_RAW = 101


def _now_ts() -> float:
    return time.time()


def _iso_ts(ts: Optional[float] = None) -> str:
    stamp = _now_ts() if ts is None else float(ts)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def _append_jsonl(path: Optional[Path], payload: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True, default=repr) + "\n")


def _packet_summary(packet: bytes) -> dict[str, object]:
    data = bytes(packet or b"")
    summary: dict[str, object] = {"len": len(data), "ipver": -1}
    if not data:
        return summary
    ipver = (data[0] >> 4) & 0xF
    summary["ipver"] = ipver
    if ipver == 4 and len(data) >= 20:
        ihl = max(20, (data[0] & 0x0F) * 4)
        proto = int(data[9])
        summary["proto"] = proto
        summary["src"] = ".".join(str(b) for b in data[12:16])
        summary["dst"] = ".".join(str(b) for b in data[16:20])
        if len(data) >= ihl + 4 and proto in {6, 17}:
            summary["src_port"] = int.from_bytes(data[ihl : ihl + 2], "big")
            summary["dst_port"] = int.from_bytes(data[ihl + 2 : ihl + 4], "big")
    elif ipver == 6 and len(data) >= 40:
        proto = int(data[6])
        summary["proto"] = proto
        with contextlib.suppress(Exception):
            summary["src"] = socket.inet_ntop(socket.AF_INET6, data[8:24])
            summary["dst"] = socket.inet_ntop(socket.AF_INET6, data[24:40])
        if len(data) >= 44 and proto in {6, 17}:
            summary["src_port"] = int.from_bytes(data[40:42], "big")
            summary["dst_port"] = int.from_bytes(data[42:44], "big")
    return summary


def _packet_ip_version(packet: bytes) -> int:
    data = bytes(packet or b"")
    if not data:
        return -1
    return (data[0] >> 4) & 0xF


class RawPacketPCAPWriter:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        self._fh.write(PCAP_GLOBAL_HDR.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_RAW))
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def write_packet(self, packet: bytes, *, timestamp: Optional[float] = None) -> None:
        payload = bytes(packet or b"")
        stamp = _now_ts() if timestamp is None else float(timestamp)
        seconds = int(stamp)
        micros = max(0, min(999_999, int((stamp - seconds) * 1_000_000.0)))
        length = min(len(payload), 0xFFFFFFFF)
        self._fh.write(PCAP_RECORD_HDR.pack(seconds, micros, length, length))
        self._fh.write(payload[:length])
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.flush()
            os.fsync(self._fh.fileno())
        with contextlib.suppress(Exception):
            self._fh.close()


def _tun_ifreq_name(name: str) -> bytes:
    return str(name).encode("utf-8", "ignore")[:15].ljust(16, b"\x00")


def _require_linux_tun() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("This tool requires Linux")
    if fcntl is None:
        raise RuntimeError(f"fcntl unavailable: {_FCNTL_IMPORT_ERROR!r}")


def _set_iface_mtu(ifname: str, mtu: int) -> None:
    assert fcntl is not None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifr = struct.pack("16sI12x", _tun_ifreq_name(ifname), int(mtu))
        fcntl.ioctl(sock.fileno(), SIOCSIFMTU, ifr)


def _set_iface_up(ifname: str) -> None:
    assert fcntl is not None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        req = _tun_ifreq_name(ifname) + (b"\x00" * 24)
        res = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, req)
        flags = struct.unpack("16xH", res[:18])[0]
        ifr = struct.pack("16sH14x", _tun_ifreq_name(ifname), flags | IFF_UP | IFF_RUNNING)
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)


def open_tun_device(ifname: str, mtu: int) -> tuple[int, str]:
    _require_linux_tun()
    assert fcntl is not None
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    try:
        ifr = struct.pack("16sH14x", _tun_ifreq_name(ifname), IFF_TUN | IFF_NO_PI)
        res = fcntl.ioctl(fd, TUNSETIFF, ifr)
        actual = bytes(res[:16]).split(b"\x00", 1)[0].decode("utf-8", "ignore") or ifname
        os.set_blocking(fd, False)
        _set_iface_mtu(actual, mtu)
        _set_iface_up(actual)
        return fd, actual
    except Exception:
        with contextlib.suppress(Exception):
            os.close(fd)
        raise


@dataclass
class Stats:
    tun_to_udp_packets: int = 0
    tun_to_udp_bytes: int = 0
    udp_to_tun_packets: int = 0
    udp_to_tun_bytes: int = 0
    dropped_udp_from_unexpected_peer: int = 0
    dropped_ipv6_tun_to_udp: int = 0
    dropped_ipv6_udp_to_tun: int = 0
    started_at: float = 0.0
    last_tun_to_udp_ts: float = 0.0
    last_udp_to_tun_ts: float = 0.0


def _event(log_path: Optional[Path], event: str, **fields: object) -> None:
    payload = {"ts": _now_ts(), "timestamp": _iso_ts(), "event": event, **fields}
    _append_jsonl(log_path, payload)


def _print(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open a Linux TUN interface and bridge raw IP packets to a UDP peer. "
            "This is intentionally small and heavily logged so the iOS PacketTunnel "
            "experiment can move almost all packet processing off-device."
        )
    )
    parser.add_argument("--ifname", default="obexp0", help="Linux TUN interface name to create")
    parser.add_argument("--mtu", type=int, default=1280, help="TUN MTU (default: 1280)")
    parser.add_argument("--bind-host", default="0.0.0.0", help="Local UDP bind host")
    parser.add_argument("--bind-port", type=int, required=True, help="Local UDP bind port")
    parser.add_argument("--peer-host", required=True, help="Expected iPhone UDP source/destination host")
    parser.add_argument("--peer-port", type=int, required=True, help="Expected iPhone UDP source/destination port")
    parser.add_argument("--log-jsonl", default="", help="Optional JSONL event log path")
    parser.add_argument("--pcap-tun-to-udp", default="", help="Optional raw-IP pcap for TUN -> UDP packets")
    parser.add_argument("--pcap-udp-to-tun", default="", help="Optional raw-IP pcap for UDP -> TUN packets")
    parser.add_argument("--allow-any-peer", action="store_true", help="Accept the first UDP sender and stick to it")
    parser.add_argument("--heartbeat-sec", type=float, default=5.0, help="Heartbeat interval in seconds")
    parser.add_argument("--drop-ipv6", action="store_true", help="Drop IPv6 packets in both directions for IPv4-only experiments")
    return parser


def run(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not (1 <= int(args.bind_port) <= 65535):
        raise SystemExit("--bind-port must be in 1..65535")
    if not (1 <= int(args.peer_port) <= 65535):
        raise SystemExit("--peer-port must be in 1..65535")
    if int(args.mtu) < 68:
        raise SystemExit("--mtu must be >= 68")

    log_path = Path(args.log_jsonl).expanduser() if str(args.log_jsonl).strip() else None
    tun_to_udp_pcap = RawPacketPCAPWriter(Path(args.pcap_tun_to_udp).expanduser()) if str(args.pcap_tun_to_udp).strip() else None
    udp_to_tun_pcap = RawPacketPCAPWriter(Path(args.pcap_udp_to_tun).expanduser()) if str(args.pcap_udp_to_tun).strip() else None

    sock_family = socket.AF_INET6 if ":" in str(args.bind_host) or ":" in str(args.peer_host) else socket.AF_INET
    udp_sock = socket.socket(sock_family, socket.SOCK_DGRAM)
    udp_sock.setblocking(False)
    udp_sock.bind((str(args.bind_host), int(args.bind_port)))

    tun_fd, actual_ifname = open_tun_device(str(args.ifname), int(args.mtu))
    stats = Stats(started_at=_now_ts())
    selector = selectors.DefaultSelector()
    selector.register(udp_sock, selectors.EVENT_READ, data="udp")
    selector.register(tun_fd, selectors.EVENT_READ, data="tun")
    stop = False
    peer_addr: tuple[str, int] = (str(args.peer_host), int(args.peer_port))
    last_heartbeat = 0.0

    def _handle_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _handle_stop)

    _print(
        f"[fedora-udp-tun] start ifname={actual_ifname} mtu={args.mtu} "
        f"udp_bind={udp_sock.getsockname()} peer={peer_addr}"
    )
    _event(
        log_path,
        "bridge_started",
        ifname=actual_ifname,
        mtu=int(args.mtu),
        udp_bind=list(udp_sock.getsockname()[:2]),
        peer_addr=list(peer_addr),
        allow_any_peer=bool(args.allow_any_peer),
    )

    try:
        while not stop:
            timeout = max(0.1, float(args.heartbeat_sec))
            for key, _mask in selector.select(timeout=timeout):
                if key.data == "tun":
                    while True:
                        try:
                            packet = os.read(tun_fd, max(68, min(TUN_READ_SIZE_MAX, int(args.mtu) + 4)))
                        except BlockingIOError:
                            break
                        if not packet:
                            break
                        if args.drop_ipv6 and _packet_ip_version(packet) == 6:
                            stats.dropped_ipv6_tun_to_udp += 1
                            if stats.dropped_ipv6_tun_to_udp <= 3 or (stats.dropped_ipv6_tun_to_udp % 64) == 0:
                                summary = _packet_summary(packet)
                                _event(
                                    log_path,
                                    "drop_ipv6_tun_to_udp",
                                    packet_index=stats.tun_to_udp_packets + stats.dropped_ipv6_tun_to_udp,
                                    packet_bytes=len(packet),
                                    packet_summary=summary,
                                    dropped_ipv6_tun_to_udp=stats.dropped_ipv6_tun_to_udp,
                                )
                                _print(
                                    f"[fedora-udp-tun] drop ipv6 tun->udp count={stats.dropped_ipv6_tun_to_udp} "
                                    f"bytes={len(packet)} summary={summary}"
                                )
                            continue
                        udp_sock.sendto(packet, peer_addr)
                        now = _now_ts()
                        stats.tun_to_udp_packets += 1
                        stats.tun_to_udp_bytes += len(packet)
                        stats.last_tun_to_udp_ts = now
                        if tun_to_udp_pcap is not None:
                            tun_to_udp_pcap.write_packet(packet, timestamp=now)
                        if stats.tun_to_udp_packets <= 3 or (stats.tun_to_udp_packets % 128) == 0:
                            summary = _packet_summary(packet)
                            _print(
                                f"[fedora-udp-tun] tun->udp packets={stats.tun_to_udp_packets} "
                                f"bytes={len(packet)} summary={summary}"
                            )
                            _event(
                                log_path,
                                "tun_to_udp",
                                packet_index=stats.tun_to_udp_packets,
                                packet_bytes=len(packet),
                                packet_summary=summary,
                                peer_addr=list(peer_addr),
                            )
                elif key.data == "udp":
                    while True:
                        try:
                            payload, addr = udp_sock.recvfrom(65535)
                        except BlockingIOError:
                            break
                        addr2 = (str(addr[0]), int(addr[1]))
                        if args.allow_any_peer and stats.udp_to_tun_packets == 0 and stats.tun_to_udp_packets == 0:
                            peer_addr = addr2
                            _event(log_path, "peer_locked_from_first_datagram", peer_addr=list(peer_addr))
                        if addr2 != peer_addr:
                            stats.dropped_udp_from_unexpected_peer += 1
                            _event(
                                log_path,
                                "udp_from_unexpected_peer",
                                from_addr=list(addr2),
                                expected_peer_addr=list(peer_addr),
                                packet_bytes=len(payload),
                                dropped_udp_from_unexpected_peer=stats.dropped_udp_from_unexpected_peer,
                            )
                            continue
                        if args.drop_ipv6 and _packet_ip_version(payload) == 6:
                            stats.dropped_ipv6_udp_to_tun += 1
                            if stats.dropped_ipv6_udp_to_tun <= 3 or (stats.dropped_ipv6_udp_to_tun % 64) == 0:
                                summary = _packet_summary(payload)
                                _event(
                                    log_path,
                                    "drop_ipv6_udp_to_tun",
                                    packet_index=stats.udp_to_tun_packets + stats.dropped_ipv6_udp_to_tun,
                                    packet_bytes=len(payload),
                                    packet_summary=summary,
                                    from_addr=list(addr2),
                                    dropped_ipv6_udp_to_tun=stats.dropped_ipv6_udp_to_tun,
                                )
                                _print(
                                    f"[fedora-udp-tun] drop ipv6 udp->tun count={stats.dropped_ipv6_udp_to_tun} "
                                    f"bytes={len(payload)} summary={summary}"
                                )
                            continue
                        os.write(tun_fd, payload)
                        now = _now_ts()
                        stats.udp_to_tun_packets += 1
                        stats.udp_to_tun_bytes += len(payload)
                        stats.last_udp_to_tun_ts = now
                        if udp_to_tun_pcap is not None:
                            udp_to_tun_pcap.write_packet(payload, timestamp=now)
                        if stats.udp_to_tun_packets <= 3 or (stats.udp_to_tun_packets % 128) == 0:
                            summary = _packet_summary(payload)
                            _print(
                                f"[fedora-udp-tun] udp->tun packets={stats.udp_to_tun_packets} "
                                f"bytes={len(payload)} summary={summary}"
                            )
                            _event(
                                log_path,
                                "udp_to_tun",
                                packet_index=stats.udp_to_tun_packets,
                                packet_bytes=len(payload),
                                packet_summary=summary,
                                from_addr=list(addr2),
                            )
            now = _now_ts()
            if now - last_heartbeat >= float(args.heartbeat_sec):
                last_heartbeat = now
                heartbeat = {
                    "uptime_sec": round(now - stats.started_at, 3),
                    "ifname": actual_ifname,
                    "peer_addr": list(peer_addr),
                    "tun_to_udp_packets": stats.tun_to_udp_packets,
                    "tun_to_udp_bytes": stats.tun_to_udp_bytes,
                    "udp_to_tun_packets": stats.udp_to_tun_packets,
                    "udp_to_tun_bytes": stats.udp_to_tun_bytes,
                    "dropped_udp_from_unexpected_peer": stats.dropped_udp_from_unexpected_peer,
                    "dropped_ipv6_tun_to_udp": stats.dropped_ipv6_tun_to_udp,
                    "dropped_ipv6_udp_to_tun": stats.dropped_ipv6_udp_to_tun,
                    "last_tun_to_udp_ts": stats.last_tun_to_udp_ts or None,
                    "last_udp_to_tun_ts": stats.last_udp_to_tun_ts or None,
                }
                _print(f"[fedora-udp-tun] heartbeat {heartbeat}")
                _event(log_path, "heartbeat", **heartbeat)
    finally:
        selector.close()
        with contextlib.suppress(Exception):
            udp_sock.close()
        with contextlib.suppress(Exception):
            os.close(tun_fd)
        if tun_to_udp_pcap is not None:
            tun_to_udp_pcap.close()
        if udp_to_tun_pcap is not None:
            udp_to_tun_pcap.close()
        summary = {
            "uptime_sec": round(_now_ts() - stats.started_at, 3),
            "ifname": actual_ifname,
            "peer_addr": list(peer_addr),
            "tun_to_udp_packets": stats.tun_to_udp_packets,
            "tun_to_udp_bytes": stats.tun_to_udp_bytes,
            "udp_to_tun_packets": stats.udp_to_tun_packets,
            "udp_to_tun_bytes": stats.udp_to_tun_bytes,
            "dropped_udp_from_unexpected_peer": stats.dropped_udp_from_unexpected_peer,
            "dropped_ipv6_tun_to_udp": stats.dropped_ipv6_tun_to_udp,
            "dropped_ipv6_udp_to_tun": stats.dropped_ipv6_udp_to_tun,
        }
        _print(f"[fedora-udp-tun] stop {summary}")
        _event(log_path, "bridge_stopped", **summary)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
