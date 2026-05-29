from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import logging
import os
import socket
import struct
import sys
import time
from collections import deque
from ctypes import POINTER, c_bool, c_char, c_char_p, c_int, c_size_t, c_void_p, cast
from ctypes.util import find_library
from pathlib import Path
from typing import Any, Optional, Tuple


def _load_cdll(name: str) -> Any:
    path = find_library(name)
    if path:
        return ctypes.CDLL(path)
    for candidate in (
        f"/usr/lib/lib{name}.dylib",
        f"/System/Library/Frameworks/{name}.framework/{name}",
    ):
        try:
            return ctypes.CDLL(candidate)
        except OSError:
            continue
    raise OSError(f"library not found: {name}")


def _objc_callable(libobjc: Any, restype: Any, argtypes: list[Any]) -> Any:
    return ctypes.CFUNCTYPE(restype, c_void_p, c_void_p, *argtypes)(("objc_msgSend", libobjc))


class _PacketFlowBridgeBackend:
    def __init__(self) -> None:
        self._libobjc = _load_cdll("objc")
        self._libobjc.objc_getClass.restype = c_void_p
        self._libobjc.objc_getClass.argtypes = [c_char_p]
        self._libobjc.sel_registerName.restype = c_void_p
        self._libobjc.sel_registerName.argtypes = [c_char_p]
        self._nsdata_cls = self._class("NSData")
        self._bridge_cls = self._class("ObstacleBridgePacketFlowBridge")

    def _class(self, name: str) -> c_void_p:
        ptr = self._libobjc.objc_getClass(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C class not found: {name}")
        return ptr

    def _sel(self, name: str) -> c_void_p:
        ptr = self._libobjc.sel_registerName(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C selector not found: {name}")
        return ptr

    def _send(self, target: c_void_p, selector: str, restype: Any, *args: Any, argtypes: list[Any]) -> Any:
        fn = _objc_callable(self._libobjc, restype, argtypes)
        return fn(target, self._sel(selector), *args)

    def _wrap(self, value: bytes) -> c_void_p:
        payload = bytes(value or b"")
        buf = ctypes.create_string_buffer(payload, len(payload))
        return self._send(
            self._nsdata_cls,
            "dataWithBytes:length:",
            c_void_p,
            cast(buf, c_void_p),
            c_size_t(len(payload)),
            argtypes=[c_void_p, c_size_t],
        )

    def _unwrap_optional_data(self, value: Any) -> Optional[bytes]:
        if not value:
            return None
        target = c_void_p(value) if not isinstance(value, c_void_p) else value
        length = self._send(target, "length", c_size_t, argtypes=[])
        bytes_ptr = self._send(target, "bytes", c_void_p, argtypes=[])
        return bytes(cast(bytes_ptr, POINTER(c_char))[: int(length)])

    def dequeue_packet(self) -> Optional[bytes]:
        data = self._send(self._bridge_cls, "dequeueIncomingPacket", c_void_p, argtypes=[])
        return self._unwrap_optional_data(data)

    def write_packet(self, packet: bytes) -> bool:
        return bool(
            self._send(
                self._bridge_cls,
                "writePacket:",
                c_bool,
                self._wrap(packet),
                argtypes=[c_void_p],
            )
        )

    def bridge_state(self) -> dict[str, Any]:
        raw = self._send(self._bridge_cls, "bridgeStateJSONData", c_void_p, argtypes=[])
        data = self._unwrap_optional_data(raw)
        if not data:
            return {}
        try:
            decoded = json.loads(data.decode("utf-8"))
        except Exception:
            return {}
        return decoded if isinstance(decoded, dict) else {}

    def register_wakeup_fd(self, fd: int) -> bool:
        return bool(
            self._send(
                self._bridge_cls,
                "registerWakeupFD:",
                c_bool,
                c_int(int(fd)),
                argtypes=[c_int],
            )
        )

    def reset_wakeup_fd(self) -> None:
        self._send(self._bridge_cls, "resetWakeupFD", None, argtypes=[])


_BACKEND: Optional[_PacketFlowBridgeBackend] = None


def _backend() -> _PacketFlowBridgeBackend:
    global _BACKEND
    if _BACKEND is None:
        _BACKEND = _PacketFlowBridgeBackend()
    return _BACKEND


def _bridge_state() -> dict[str, Any]:
    try:
        return _backend().bridge_state()
    except Exception:
        return {}


def _debug_enabled(log: Any) -> bool:
    checker = getattr(log, "isEnabledFor", None)
    if callable(checker):
        try:
            return bool(checker(logging.DEBUG))
        except Exception:
            return False
    return False


def _log_packet_debug(log: Any, *, stage: str, ifname: str, packet: bytes) -> None:
    if not _debug_enabled(log):
        return
    payload = bytes(packet or b"")
    ip_version = (payload[0] >> 4) if payload else -1
    log.debug(
        "[TUN/IOS/PKT] stage=%s if=%s len=%s ipver=%s hex=%s",
        stage,
        ifname,
        len(payload),
        ip_version,
        payload.hex(),
    )


def _option_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "udp"}:
        return True
    if text in {"0", "false", "no", "off", "direct"}:
        return False
    return None


def _udp_connector_enabled(dev: Optional[Any] = None) -> bool:
    mode = _packetflow_connector_mode(dev)
    return mode in {"udp", "simple_udp_peer"}


def _packetflow_connector_mode(dev: Optional[Any] = None) -> str:
    options = getattr(dev, "ios_packetflow_options", None)
    if isinstance(options, dict):
        for key in ("ios_packetflow_udp", "packetflow_udp", "udp_connector"):
            chosen = _option_bool(options.get(key))
            if chosen is not None:
                return "udp" if chosen else "direct"
        mode = str(options.get("ios_packetflow_connector", "") or "").strip().lower()
        if mode:
            if mode in {"udp", "direct", "simple_udp_peer"}:
                return mode
    mode = os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "")
    if mode.strip():
        selected = mode.strip().lower()
        if selected in {"udp", "direct", "simple_udp_peer"}:
            return selected
    return "udp" if _option_bool(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP")) is True else "direct"


def _udp_option(options: dict[str, Any], key: str, env_key: str, default: Any) -> Any:
    if env_key in os.environ:
        return os.environ[env_key]
    if key in options:
        return options[key]
    return default


class _RawPacketPCAPWriter:
    _GLOBAL_HDR = struct.Struct("<IHHIIII")
    _RECORD_HDR = struct.Struct("<IIII")
    _DLT_RAW = 101

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        self._fh.write(self._GLOBAL_HDR.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, self._DLT_RAW))
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def write_packet(self, packet: bytes, *, timestamp: Optional[float] = None) -> None:
        payload = bytes(packet or b"")
        stamp = time.time() if timestamp is None else float(timestamp)
        seconds = int(stamp)
        micros = max(0, min(999_999, int((stamp - seconds) * 1_000_000.0)))
        length = min(len(payload), 0xFFFFFFFF)
        self._fh.write(self._RECORD_HDR.pack(seconds, micros, length, length))
        self._fh.write(payload[:length])
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except Exception:
            pass
        self._fh.close()


def _capture_timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _connector_logs_root() -> Optional[Path]:
    root = str(os.environ.get("OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT", "") or "").strip()
    if root:
        return Path(root)
    state = _bridge_state()
    for key in ("incoming_pcap_path", "outgoing_pcap_path"):
        raw = str(state.get(key, "") or "").strip()
        if raw:
            return Path(raw).expanduser().resolve().parent
    return None


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True, default=repr) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=repr) + "\n", encoding="utf-8")


def _packet_summary(packet: bytes) -> dict[str, Any]:
    data = bytes(packet or b"")
    summary: dict[str, Any] = {"len": len(data), "ipver": -1}
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


def _connector_trace_paths(stamp: str) -> dict[str, Path]:
    root = _connector_logs_root()
    if root is None:
        raise RuntimeError("iOS UDP connector diagnostics root is unavailable")
    return {
        "event_log": root / "ipserver-udp-connector.jsonl",
        "manifest": root / f"ipserver-udp-connector-session-{stamp}.json",
        "state": root / "ipserver-udp-connector-state.json",
        "to_mux_pcap": root / f"ipserver-udp-connector-to-mux-{stamp}.pcap",
        "from_mux_pcap": root / f"ipserver-udp-connector-from-mux-{stamp}.pcap",
    }


def _connector_event(dev: Any, event: str, **fields: Any) -> None:
    trace = getattr(dev, "udp_connector_trace", None)
    if not isinstance(trace, dict):
        return
    payload = {
        "ts": time.time(),
        "pid": os.getpid(),
        "event": str(event),
        "ifname": str(getattr(dev, "ifname", "") or ""),
        "mtu": int(getattr(dev, "mtu", 0) or 0),
        **fields,
    }
    try:
        _append_jsonl(trace["event_log"], payload)
    except Exception:
        pass


def _write_connector_manifest(dev: Any, *, final: bool = False) -> None:
    trace = getattr(dev, "udp_connector_trace", None)
    if not isinstance(trace, dict):
        return
    connector = getattr(dev, "udp_connector", None)
    payload = {
        "updated_unix_ts": time.time(),
        "pid": os.getpid(),
        "final": bool(final),
        "ifname": str(getattr(dev, "ifname", "") or ""),
        "mtu": int(getattr(dev, "mtu", 0) or 0),
        "packetflow_connector_enabled": True,
        "connector_mode": str(getattr(dev, "udp_connector_mode", "") or ""),
        "connector_bind": getattr(dev, "udp_connector_bind_addr", None),
        "channelmux_bind": getattr(dev, "udp_connector_mux_addr", None),
        "peer_addr": getattr(dev, "udp_connector_peer_addr", None),
        "service_key": list(getattr(dev, "service_key", ()) or ()),
        "udp_service_key": list(getattr(dev, "udp_connector_service_key", ()) or ()),
        "trace_files": {
            "event_log": str(trace["event_log"]),
            "manifest": str(trace["manifest"]),
            "to_mux_pcap": str(trace["to_mux_pcap"]),
            "from_mux_pcap": str(trace["from_mux_pcap"]),
        },
        "counters": {
            "to_mux_packets": int(getattr(connector, "tx_packets", 0) or 0),
            "from_mux_packets": int(getattr(connector, "rx_packets", 0) or 0),
            "pending_packets": int(len(getattr(connector, "pending", []) or [])) if connector is not None else 0,
        },
        "bridge_state": _bridge_state(),
    }
    try:
        _write_json(trace["manifest"], payload)
    except Exception:
        pass


def _write_connector_state(dev: Any, *, component_state: str = "running") -> None:
    trace = getattr(dev, "udp_connector_trace", None)
    if not isinstance(trace, dict):
        return
    connector = getattr(dev, "udp_connector", None)
    payload = {
        "updated_unix_ts": time.time(),
        "pid": os.getpid(),
        "component": "udp-connector",
        "state": str(component_state),
        "ifname": str(getattr(dev, "ifname", "") or ""),
        "mtu": int(getattr(dev, "mtu", 0) or 0),
        "connector_mode": str(getattr(dev, "udp_connector_mode", "") or ""),
        "connector_bind": getattr(dev, "udp_connector_bind_addr", None),
        "channelmux_bind": getattr(dev, "udp_connector_mux_addr", None),
        "peer_addr": getattr(dev, "udp_connector_peer_addr", None),
        "heartbeat_count": int(getattr(dev, "udp_connector_heartbeat_count", 0) or 0),
        "last_to_mux_unix_ts": getattr(dev, "udp_connector_last_to_mux_ts", None),
        "last_from_mux_unix_ts": getattr(dev, "udp_connector_last_from_mux_ts", None),
        "bridge_queue_last_drain_unix_ts": getattr(dev, "udp_connector_last_bridge_drain_ts", None),
        "bridge_queue_last_drain_packets": int(getattr(dev, "udp_connector_last_bridge_drain_packets", 0) or 0),
        "bridge_queue_max_drain_packets": int(getattr(dev, "udp_connector_max_bridge_drain_packets", 0) or 0),
        "yield_gaps": {
            "bridge_queue": {
                "count": int(getattr(dev, "udp_connector_bridge_yield_count", 0) or 0),
                "last_gap_ms": float(getattr(dev, "udp_connector_bridge_last_yield_gap_ms", 0.0) or 0.0),
                "max_gap_ms": float(getattr(dev, "udp_connector_bridge_max_yield_gap_ms", 0.0) or 0.0),
            },
            "from_mux_flush": {
                "count": int(getattr(dev, "udp_connector_from_mux_yield_count", 0) or 0),
                "last_gap_ms": float(getattr(dev, "udp_connector_from_mux_last_yield_gap_ms", 0.0) or 0.0),
                "max_gap_ms": float(getattr(dev, "udp_connector_from_mux_max_yield_gap_ms", 0.0) or 0.0),
            },
            "connector_pending_flush": {
                "count": int(getattr(dev, "udp_connector_pending_yield_count", 0) or 0),
                "last_gap_ms": float(getattr(dev, "udp_connector_pending_last_yield_gap_ms", 0.0) or 0.0),
                "max_gap_ms": float(getattr(dev, "udp_connector_pending_max_yield_gap_ms", 0.0) or 0.0),
            },
        },
        "counters": {
            "to_mux_packets": int(getattr(connector, "tx_packets", 0) or 0),
            "from_mux_packets": int(getattr(connector, "rx_packets", 0) or 0),
            "pending_packets": int(len(getattr(connector, "pending", []) or [])) if connector is not None else 0,
            "pending_from_mux_packets": int(len(getattr(dev, "udp_connector_pending_from_mux", []) or [])),
            "pending_drop_count": int(getattr(dev, "udp_connector_pending_drop_count", 0) or 0),
            "pending_from_mux_drop_count": int(getattr(dev, "udp_connector_pending_from_mux_drop_count", 0) or 0),
            "packetflow_write_failures": int(getattr(dev, "udp_connector_packetflow_write_failures", 0) or 0),
            "packetflow_write_slow_count": int(getattr(dev, "udp_connector_packetflow_write_slow_count", 0) or 0),
            "packetflow_write_max_ms": float(getattr(dev, "udp_connector_packetflow_write_max_ms", 0.0) or 0.0),
        },
        "last_packets": {
            "to_mux": list(getattr(dev, "udp_connector_last_to_mux", ()) or ()),
            "from_mux": list(getattr(dev, "udp_connector_last_from_mux", ()) or ()),
        },
        "bridge_state": _bridge_state(),
        "trace_files": {
            "event_log": str(trace["event_log"]),
            "manifest": str(trace["manifest"]),
            "state": str(trace["state"]),
            "to_mux_pcap": str(trace["to_mux_pcap"]),
            "from_mux_pcap": str(trace["from_mux_pcap"]),
        },
    }
    try:
        _write_json(trace["state"], payload)
    except Exception:
        pass


def _remember_connector_packet(dev: Any, direction: str, packet: bytes, *, addr: Any = None) -> None:
    key = "udp_connector_last_to_mux" if direction == "to_mux" else "udp_connector_last_from_mux"
    ring = getattr(dev, key, None)
    if ring is None:
        ring = deque(maxlen=24)
        setattr(dev, key, ring)
    if not isinstance(ring, deque):
        ring = deque(ring, maxlen=24)
        setattr(dev, key, ring)
    item = {
        "ts": time.time(),
        "summary": _packet_summary(packet),
    }
    if addr is not None:
        item["addr"] = addr
    ring.append(item)


def _record_yield_gap(log: Any, owner: Any, *, prefix: str, scheduled_at: float, stage: str) -> None:
    gap_ms = max(0.0, (time.perf_counter() - float(scheduled_at)) * 1000.0)
    count_attr = f"{prefix}_yield_count"
    last_attr = f"{prefix}_last_yield_gap_ms"
    max_attr = f"{prefix}_max_yield_gap_ms"
    count = int(getattr(owner, count_attr, 0) or 0) + 1
    setattr(owner, count_attr, count)
    setattr(owner, last_attr, gap_ms)
    setattr(owner, max_attr, max(float(getattr(owner, max_attr, 0.0) or 0.0), gap_ms))
    if gap_ms >= 20.0 or count <= 3 or (count % 256) == 0:
        log.info("[IOS/YIELD] stage=%s count=%s gap_ms=%.3f", stage, count, gap_ms)


def _schedule_bridge_queue_drain(mux: Any, dev: Any) -> None:
    if getattr(dev, "udp_connector_bridge_drain_scheduled", False):
        return
    setattr(dev, "udp_connector_bridge_drain_scheduled", True)
    scheduled_at = time.perf_counter()

    def _run() -> None:
        setattr(dev, "udp_connector_bridge_drain_scheduled", False)
        _record_yield_gap(mux.log, dev, prefix="udp_connector_bridge", scheduled_at=scheduled_at, stage="packetflow_bridge_queue")
        _drain_bridge_queue(mux, dev)

    mux.loop.call_soon(_run)


def _schedule_pending_from_mux_flush(mux: Any, dev: Any) -> None:
    if getattr(dev, "udp_connector_pending_from_mux_scheduled", False):
        return
    setattr(dev, "udp_connector_pending_from_mux_scheduled", True)
    scheduled_at = time.perf_counter()

    def _run() -> None:
        setattr(dev, "udp_connector_pending_from_mux_scheduled", False)
        _record_yield_gap(mux.log, dev, prefix="udp_connector_from_mux", scheduled_at=scheduled_at, stage="packetflow_from_mux_flush")
        _flush_pending_from_mux(mux, dev)

    mux.loop.call_soon(_run)


class _PacketFlowUDPConnector(asyncio.DatagramProtocol):
    def __init__(self, mux: Any, dev: Any) -> None:
        self.mux = mux
        self.dev = dev
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.mux_addr: Optional[Tuple[str, int]] = None
        self.mode = str(getattr(dev, "udp_connector_mode", "") or "")
        self.ready = False
        self.closed = False
        self.pending: list[bytes] = []
        self.max_pending = 1024
        self.rx_packets = 0
        self.tx_packets = 0
        self.expected_peer_addr: Optional[Tuple[str, int]] = None
        self.pending_flush_scheduled = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        setattr(self.dev, "udp_connector_bind_addr", sockname)
        _connector_event(self.dev, "udp_connector_socket_ready", bind_addr=sockname)
        _write_connector_manifest(self.dev)
        _write_connector_state(self.dev)
        self.mux.log.info("[TUN/IOS/UDP] connector listening if=%s addr=%s", self.dev.ifname, sockname)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.closed:
            return
        if self.expected_peer_addr is not None:
            actual = (str(addr[0]), int(addr[1]))
            if actual != self.expected_peer_addr:
                _connector_event(
                    self.dev,
                    "udp_connector_unexpected_peer_datagram",
                    from_addr=list(actual),
                    expected_peer_addr=list(self.expected_peer_addr),
                    packet_bytes=len(data),
                )
                self.mux.log.info(
                    "[TUN/IOS/UDP] ignoring unexpected datagram if=%s from=%s expected=%s",
                    self.dev.ifname,
                    actual,
                    self.expected_peer_addr,
                )
                return
        self.rx_packets += 1
        packet = bytes(data)
        setattr(self.dev, "udp_connector_last_from_mux_ts", time.time())
        _remember_connector_packet(self.dev, "from_mux", packet, addr=addr)
        trace = getattr(self.dev, "udp_connector_trace", None)
        if isinstance(trace, dict):
            try:
                trace["from_mux_writer"].write_packet(packet)
            except Exception as exc:
                self.mux.log.info("[TUN/IOS/UDP] from-mux pcap write failed if=%s: %r", self.dev.ifname, exc)
        _log_packet_debug(self.mux.log, stage="udp_connector_to_packet_flow", ifname=self.dev.ifname, packet=packet)
        if self.rx_packets <= 3 or (self.rx_packets % 128) == 0:
            _connector_event(
                self.dev,
                "udp_connector_datagram_from_mux",
                packet_bytes=len(packet),
                from_addr=addr,
                from_mux_packets=self.rx_packets,
            )
            _write_connector_manifest(self.dev)
            _write_connector_state(self.dev)
        started = time.perf_counter()
        try:
            if not _backend().write_packet(packet):
                setattr(
                    self.dev,
                    "udp_connector_packetflow_write_failures",
                    int(getattr(self.dev, "udp_connector_packetflow_write_failures", 0) or 0) + 1,
                )
                self.mux.log.info("[TUN/IOS/UDP] packet flow rejected datagram if=%s len=%s from=%s", self.dev.ifname, len(packet), addr)
        except Exception as exc:
            setattr(
                self.dev,
                "udp_connector_packetflow_write_failures",
                int(getattr(self.dev, "udp_connector_packetflow_write_failures", 0) or 0) + 1,
            )
            self.mux.log.info("[TUN/IOS/UDP] packet flow write failed if=%s from=%s: %r", self.dev.ifname, addr, exc)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        setattr(
            self.dev,
            "udp_connector_packetflow_write_max_ms",
            max(float(getattr(self.dev, "udp_connector_packetflow_write_max_ms", 0.0) or 0.0), elapsed_ms),
        )
        if elapsed_ms >= 20.0:
            setattr(
                self.dev,
                "udp_connector_packetflow_write_slow_count",
                int(getattr(self.dev, "udp_connector_packetflow_write_slow_count", 0) or 0) + 1,
            )
            _connector_event(
                self.dev,
                "udp_connector_packetflow_write_slow",
                elapsed_ms=round(elapsed_ms, 3),
                packet_bytes=len(packet),
                from_addr=addr,
            )

    def error_received(self, exc: Exception) -> None:
        self.mux.log.info("[TUN/IOS/UDP] connector transport error if=%s: %r", self.dev.ifname, exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.closed = True
        _connector_event(self.dev, "udp_connector_socket_closed", error=repr(exc) if exc is not None else "")
        _write_connector_manifest(self.dev)
        _write_connector_state(self.dev, component_state="socket_closed")
        self.mux.log.info("[TUN/IOS/UDP] connector lost if=%s: %r", self.dev.ifname, exc)

    def set_mux_addr(self, addr: tuple[str, int]) -> None:
        self.mux_addr = (str(addr[0]), int(addr[1]))
        self.ready = True
        setattr(self.dev, "udp_connector_mux_addr", self.mux_addr)
        _connector_event(self.dev, "udp_connector_mux_bound", mux_addr=self.mux_addr)
        _write_connector_manifest(self.dev)
        _write_connector_state(self.dev)
        pending = self.pending
        self.pending = []
        if pending:
            self.pending.extend(pending)
            self._schedule_pending_flush()

    def set_expected_peer_addr(self, addr: Optional[tuple[str, int]]) -> None:
        self.expected_peer_addr = None if addr is None else (str(addr[0]), int(addr[1]))

    def send_packet(self, packet: bytes) -> None:
        data = bytes(packet)
        if self.transport is None or self.mux_addr is None or not self.ready:
            if len(self.pending) < self.max_pending:
                self.pending.append(data)
            else:
                setattr(
                    self.dev,
                    "udp_connector_pending_drop_count",
                    int(getattr(self.dev, "udp_connector_pending_drop_count", 0) or 0) + 1,
                )
                _connector_event(
                    self.dev,
                    "udp_connector_pending_drop",
                    packet_bytes=len(data),
                    pending_packets=len(self.pending),
                )
                self.mux.log.warning("[TUN/IOS/UDP] drop packet before connector ready if=%s len=%s", self.dev.ifname, len(data))
            return
        trace = getattr(self.dev, "udp_connector_trace", None)
        if isinstance(trace, dict):
            try:
                trace["to_mux_writer"].write_packet(data)
            except Exception as exc:
                self.mux.log.info("[TUN/IOS/UDP] to-mux pcap write failed if=%s: %r", self.dev.ifname, exc)
        _log_packet_debug(self.mux.log, stage="packet_flow_to_udp_connector", ifname=self.dev.ifname, packet=data)
        self.transport.sendto(data, self.mux_addr)
        self.tx_packets += 1
        setattr(self.dev, "udp_connector_last_to_mux_ts", time.time())
        _remember_connector_packet(self.dev, "to_mux", data, addr=self.mux_addr)
        if self.tx_packets <= 3 or (self.tx_packets % 128) == 0:
            _connector_event(
                self.dev,
                "udp_connector_datagram_to_mux",
                packet_bytes=len(data),
                mux_addr=self.mux_addr,
                to_mux_packets=self.tx_packets,
            )
            _write_connector_manifest(self.dev)
            _write_connector_state(self.dev)

    def _schedule_pending_flush(self) -> None:
        if self.pending_flush_scheduled:
            return
        self.pending_flush_scheduled = True
        scheduled_at = time.perf_counter()

        def _run() -> None:
            self.pending_flush_scheduled = False
            _record_yield_gap(self.mux.log, self.dev, prefix="udp_connector_pending", scheduled_at=scheduled_at, stage="packetflow_connector_pending_flush")
            self._flush_one_pending_packet()

        self.mux.loop.call_soon(_run)

    def _flush_one_pending_packet(self) -> None:
        if self.closed or self.transport is None or self.mux_addr is None or not self.ready or not self.pending:
            return
        packet = self.pending.pop(0)
        self.send_packet(packet)
        if self.pending:
            self._schedule_pending_flush()

    def close(self) -> None:
        self.closed = True
        if self.transport is not None:
            self.transport.close()
        self.transport = None
        self.pending = []


class _PacketFlowMuxUDPRelay(asyncio.DatagramProtocol):
    def __init__(self, mux: Any, dev: Any) -> None:
        self.mux = mux
        self.dev = dev
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        setattr(self.dev, "udp_connector_mux_transport", self.transport)
        setattr(self.dev, "udp_connector_mux_addr", sockname)
        _connector_event(self.dev, "udp_connector_mux_bound", mux_addr=sockname)
        _write_connector_manifest(self.dev)
        self.mux.log.info("[TUN/IOS/UDP] mux relay listening if=%s addr=%s", self.dev.ifname, sockname)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        packet = bytes(data)
        _log_packet_debug(self.mux.log, stage="udp_connector_to_mux_relay", ifname=self.dev.ifname, packet=packet)
        self.mux._on_local_tun_packet(self.dev, packet)

    def error_received(self, exc: Exception) -> None:
        self.mux.log.info("[TUN/IOS/UDP] mux relay transport error if=%s: %r", self.dev.ifname, exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.mux.log.info("[TUN/IOS/UDP] mux relay lost if=%s: %r", self.dev.ifname, exc)
        setattr(self.dev, "udp_connector_mux_transport", None)


async def _udp_connector_heartbeat(mux: Any, dev: Any) -> None:
    while True:
        await asyncio.sleep(1.0)
        count = int(getattr(dev, "udp_connector_heartbeat_count", 0) or 0) + 1
        setattr(dev, "udp_connector_heartbeat_count", count)
        if count <= 3 or (count % 5) == 0:
            _connector_event(
                dev,
                "udp_connector_heartbeat",
                heartbeat_count=count,
                pending_packets=int(len(getattr(getattr(dev, "udp_connector", None), "pending", []) or [])),
                pending_from_mux_packets=int(len(getattr(dev, "udp_connector_pending_from_mux", []) or [])),
            )
        _write_connector_state(dev)


def _flush_pending_from_mux(mux: Any, dev: Any) -> None:
    transport = getattr(dev, "udp_connector_mux_transport", None)
    bind_addr = getattr(dev, "udp_connector_bind_addr", None)
    if transport is None or not (isinstance(bind_addr, tuple) and len(bind_addr) >= 2):
        return
    pending = list(getattr(dev, "udp_connector_pending_from_mux", []) or [])
    if not pending:
        return
    packet = pending.pop(0)
    setattr(dev, "udp_connector_pending_from_mux", pending)
    transport.sendto(bytes(packet), bind_addr)
    if pending:
        _schedule_pending_from_mux_flush(mux, dev)
        _write_connector_state(dev)


def _write_packet_to_bridge_backend(mux: Any, dev: Any, data: bytes) -> None:
    try:
        ok = _backend().write_packet(data)
    except Exception as exc:
        mux.log.info("[TUN/IOS] write failed if=%s: %r", dev.ifname, exc)
        raise
    if not ok:
        raise RuntimeError("iOS packet flow bridge rejected outbound packet write")


def require_tun_support(_mux: Any) -> None:
    if sys.platform != "ios":
        raise RuntimeError("iOS TUN support requested on a non-iOS platform")
    state = _bridge_state()
    if not state.get("active"):
        raise RuntimeError("iOS packet flow bridge is not active inside the packet tunnel provider")


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    require_tun_support(mux)
    if getattr(mux, "_svc_tun_devices", {}):
        raise RuntimeError(
            "iOS packet tunnel currently supports one live NEPacketTunnelFlow-backed TUN device at a time"
        )
    state = _bridge_state()
    mux.log.info("[TUN/IOS] open if=%s mtu=%s bridge_state=%s", ifname, mtu, state)
    dev = mux.TunDevice(fd=-1, ifname=ifname, mtu=int(mtu), service_key=svc_key)
    spec = mux._effective_services_by_id().get(svc_key) if svc_key is not None and hasattr(mux, "_effective_services_by_id") else None
    options = getattr(spec, "options", None) if spec is not None else None
    setattr(dev, "ios_packetflow_options", options if isinstance(options, dict) else {})
    return dev


async def _start_udp_connector(mux: Any, dev: Any) -> None:
    if getattr(dev, "udp_connector", None) is not None:
        return
    options = getattr(dev, "ios_packetflow_options", None)
    options = options if isinstance(options, dict) else {}
    stamp = _capture_timestamp()
    trace_paths = _connector_trace_paths(stamp)
    trace = {
        "stamp": stamp,
        **trace_paths,
        "to_mux_writer": _RawPacketPCAPWriter(trace_paths["to_mux_pcap"]),
        "from_mux_writer": _RawPacketPCAPWriter(trace_paths["from_mux_pcap"]),
    }
    setattr(dev, "udp_connector_trace", trace)
    _connector_event(dev, "udp_connector_trace_opened", trace_files={key: str(value) for key, value in trace_paths.items()})
    _write_connector_manifest(dev)
    _write_connector_state(dev, component_state="starting")
    connector_transport = None
    relay_transport = None
    try:
        mode = _packetflow_connector_mode(dev)
        setattr(dev, "udp_connector_mode", mode)
        bind_host_default = "127.0.0.1" if mode == "udp" else "0.0.0.0"
        host = str(_udp_option(options, "ios_packetflow_udp_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST", bind_host_default)).strip() or bind_host_default
        port_default = max(1024, min(65535, int(getattr(dev, "mtu", 1500) or 1500)))
        connector_port = int(_udp_option(options, "ios_packetflow_udp_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT", port_default))
        mux_host = str(_udp_option(options, "ios_packetflow_udp_mux_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_MUX_HOST", host)).strip() or host
        mux_port = int(_udp_option(options, "ios_packetflow_udp_mux_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_MUX_PORT", 0))
        peer_host = str(_udp_option(options, "ios_packetflow_peer_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", "")).strip()
        peer_port_raw = _udp_option(options, "ios_packetflow_peer_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", 0)
        peer_port = int(peer_port_raw) if str(peer_port_raw).strip() else 0

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        relay_sockname: tuple[str, int] | None = None
        expected_peer_addr: tuple[str, int] | None = None
        if mode == "udp":
            relay_sock = socket.socket(
                socket.AF_INET6 if ":" in mux_host else socket.AF_INET,
                socket.SOCK_DGRAM,
            )
            relay_sock.setblocking(False)
            if hasattr(socket, "SO_NOSIGPIPE"):
                relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
            relay_sock.bind((mux_host, mux_port))
            relay_transport, relay_protocol = await mux.loop.create_datagram_endpoint(
                lambda: _PacketFlowMuxUDPRelay(mux, dev),
                sock=relay_sock,
            )
            relay_sockname = relay_transport.get_extra_info("sockname")
            if not (isinstance(relay_sockname, tuple) and len(relay_sockname) >= 2):
                raise RuntimeError("iOS UDP packet-flow connector could not discover internal mux relay address")
            expected_peer_addr = (str(relay_sockname[0]), int(relay_sockname[1]))
        elif mode == "simple_udp_peer":
            if not peer_host or peer_port <= 0:
                raise RuntimeError("simple_udp_peer mode requires ios_packetflow_peer_host and ios_packetflow_peer_port")
            relay_sockname = (str(peer_host), int(peer_port))
            expected_peer_addr = relay_sockname
            setattr(dev, "udp_connector_peer_addr", [relay_sockname[0], relay_sockname[1]])
        else:
            raise RuntimeError(f"unsupported iOS packet-flow connector mode: {mode}")

        protocol = _PacketFlowUDPConnector(mux, dev)
        connector_sock = socket.socket(family, socket.SOCK_DGRAM)
        connector_sock.setblocking(False)
        if hasattr(socket, "SO_NOSIGPIPE"):
            connector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
        connector_sock.bind((host, connector_port))
        connector_transport, _ = await mux.loop.create_datagram_endpoint(
            lambda: protocol,
            sock=connector_sock,
        )
        setattr(dev, "udp_connector", protocol)
        setattr(dev, "udp_connector_transport", connector_transport)
        setattr(dev, "udp_connector_last_to_mux", deque(maxlen=24))
        setattr(dev, "udp_connector_last_from_mux", deque(maxlen=24))
        setattr(dev, "udp_connector_heartbeat_count", 0)
        setattr(dev, "udp_connector_pending_drop_count", 0)
        setattr(dev, "udp_connector_pending_from_mux_drop_count", 0)
        setattr(dev, "udp_connector_packetflow_write_failures", 0)
        setattr(dev, "udp_connector_packetflow_write_slow_count", 0)
        setattr(dev, "udp_connector_packetflow_write_max_ms", 0.0)
        protocol.set_mux_addr((str(relay_sockname[0]), int(relay_sockname[1])))
        protocol.set_expected_peer_addr(expected_peer_addr)
        if mode == "udp":
            _schedule_pending_from_mux_flush(mux, dev)
        heartbeat_task = mux.loop.create_task(_udp_connector_heartbeat(mux, dev))
        setattr(dev, "udp_connector_heartbeat_task", heartbeat_task)
        mux.log.info(
            "[TUN/IOS/UDP] connector ready if=%s mode=%s packetflow=%s:%s target=%s:%s",
            dev.ifname,
            mode,
            host,
            connector_port,
            relay_sockname[0],
            int(relay_sockname[1]),
        )
        _connector_event(
            dev,
            "udp_connector_ready",
            connector_mode=mode,
            packetflow_bind=[host, connector_port],
            mux_bind=[relay_sockname[0], int(relay_sockname[1])],
            peer_addr=[relay_sockname[0], int(relay_sockname[1])],
        )
        _write_connector_manifest(dev)
        _write_connector_state(dev)
        _drain_bridge_queue(mux, dev)
    except Exception as exc:
        _connector_event(dev, "udp_connector_start_failed", error=repr(exc))
        _write_connector_manifest(dev, final=True)
        _write_connector_state(dev, component_state="start_failed")
        if connector_transport is not None:
            with contextlib.suppress(Exception):
                connector_transport.close()
        if relay_transport is not None:
            with contextlib.suppress(Exception):
                relay_transport.close()
        trace = getattr(dev, "udp_connector_trace", None)
        if isinstance(trace, dict):
            for key in ("to_mux_writer", "from_mux_writer"):
                writer = trace.get(key)
                if writer is not None:
                    with contextlib.suppress(Exception):
                        writer.close()
        setattr(dev, "udp_connector", None)
        setattr(dev, "udp_connector_transport", None)
        setattr(dev, "udp_connector_mux_transport", None)
        setattr(dev, "udp_connector_heartbeat_task", None)
        setattr(dev, "udp_connector_service_key", None)
        setattr(dev, "udp_connector_registered_local_service", False)
        raise


def _drain_bridge_queue(mux: Any, dev: Any) -> int:
    delivered = 0
    packets_seen = int(getattr(dev, "packets_seen", 0))
    while True:
        packet = _backend().dequeue_packet()
        if packet is None:
            break
        delivered += 1
        packets_seen += 1
        _log_packet_debug(mux.log, stage="packet_flow_read", ifname=dev.ifname, packet=packet)
        if packets_seen <= 3 or packets_seen % 64 == 0:
            mux.log.info(
                "[TUN/IOS] inbound packet if=%s len=%s total_packets=%s",
                dev.ifname,
                len(packet),
                packets_seen,
            )
        connector = getattr(dev, "udp_connector", None)
        if connector is not None:
            connector.send_packet(packet)
        else:
            mux._on_local_tun_packet(dev, packet)
    setattr(dev, "packets_seen", packets_seen)
    setattr(dev, "udp_connector_last_bridge_drain_ts", time.time())
    setattr(dev, "udp_connector_last_bridge_drain_packets", delivered)
    setattr(
        dev,
        "udp_connector_max_bridge_drain_packets",
        max(int(getattr(dev, "udp_connector_max_bridge_drain_packets", 0) or 0), delivered),
    )
    if getattr(dev, "udp_connector", None) is not None and delivered:
        _write_connector_state(dev)
    if delivered:
        _schedule_bridge_queue_drain(mux, dev)
    return delivered


def _on_wakeup_fd_readable(mux: Any, dev: Any) -> None:
    read_fd = getattr(dev, "wakeup_read_fd", None)
    if read_fd is None:
        return
    try:
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk or len(chunk) < 4096:
                break
    except BlockingIOError:
        pass
    except OSError as exc:
        mux.log.info("[TUN/IOS] wakeup pipe read failed if=%s: %r", dev.ifname, exc)
        return
    try:
        _drain_bridge_queue(mux, dev)
    except Exception as exc:
        mux.log.exception("[TUN/IOS] bridge queue drain failed if=%s: %r", dev.ifname, exc)


def register_tun_reader(mux: Any, dev: Any) -> None:
    if getattr(dev, "reader_registered", False):
        return
    if _udp_connector_enabled(dev):
        task = mux.loop.create_task(_start_udp_connector(mux, dev))
        def _log_udp_connector_done(done_task: Any) -> None:
            if done_task.cancelled():
                return
            exc = done_task.exception()
            if exc is not None:
                mux.log.info("[TUN/IOS/UDP] connector startup failed if=%s: %r", dev.ifname, exc)

        task.add_done_callback(_log_udp_connector_done)
        setattr(dev, "udp_connector_task", task)
        mux.log.info("[TUN/IOS/UDP] connector startup scheduled if=%s", dev.ifname)
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    os.set_blocking(write_fd, False)
    try:
        if not _backend().register_wakeup_fd(write_fd):
            raise RuntimeError("iOS packet flow bridge rejected wakeup fd registration")
        mux.loop.add_reader(read_fd, _on_wakeup_fd_readable, mux, dev)
    except Exception:
        with contextlib.suppress(Exception):
            _backend().reset_wakeup_fd()
        with contextlib.suppress(Exception):
            os.close(read_fd)
        with contextlib.suppress(Exception):
            os.close(write_fd)
        raise
    setattr(dev, "wakeup_read_fd", read_fd)
    setattr(dev, "wakeup_write_fd", write_fd)
    setattr(dev, "packets_seen", 0)
    setattr(dev, "reader_registered", True)
    mux.log.info("[TUN/IOS] reader registered if=%s bridge_state=%s", dev.ifname, _bridge_state())
    if not _udp_connector_enabled(dev):
        _drain_bridge_queue(mux, dev)


def close_tun_device(mux: Any, dev: Any) -> None:
    read_fd = getattr(dev, "wakeup_read_fd", None)
    write_fd = getattr(dev, "wakeup_write_fd", None)
    if read_fd is not None:
        with contextlib.suppress(Exception):
            mux.loop.remove_reader(read_fd)
    with contextlib.suppress(Exception):
        _backend().reset_wakeup_fd()
    if read_fd is not None:
        with contextlib.suppress(Exception):
            os.close(read_fd)
    if write_fd is not None:
        with contextlib.suppress(Exception):
            os.close(write_fd)
    task = getattr(dev, "udp_connector_task", None)
    if task is not None:
        with contextlib.suppress(Exception):
            task.cancel()
    heartbeat_task = getattr(dev, "udp_connector_heartbeat_task", None)
    if heartbeat_task is not None:
        with contextlib.suppress(Exception):
            heartbeat_task.cancel()
    connector = getattr(dev, "udp_connector", None)
    if connector is not None:
        with contextlib.suppress(Exception):
            connector.close()
    udp_key = getattr(dev, "udp_connector_service_key", None)
    tr = getattr(dev, "udp_connector_mux_transport", None)
    if tr is not None:
        with contextlib.suppress(Exception):
            tr.close()
    trace = getattr(dev, "udp_connector_trace", None)
    if isinstance(trace, dict):
        _connector_event(
            dev,
            "udp_connector_closed",
            to_mux_packets=int(getattr(getattr(dev, "udp_connector", None), "tx_packets", 0) or 0),
            from_mux_packets=int(getattr(getattr(dev, "udp_connector", None), "rx_packets", 0) or 0),
        )
        _write_connector_manifest(dev, final=True)
        _write_connector_state(dev, component_state="closed")
        for key in ("to_mux_writer", "from_mux_writer"):
            writer = trace.get(key)
            if writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
    setattr(dev, "wakeup_read_fd", None)
    setattr(dev, "wakeup_write_fd", None)
    setattr(dev, "udp_connector", None)
    setattr(dev, "udp_connector_transport", None)
    setattr(dev, "udp_connector_mux_transport", None)
    setattr(dev, "udp_connector_task", None)
    setattr(dev, "udp_connector_heartbeat_task", None)
    setattr(dev, "udp_connector_service_key", None)
    setattr(dev, "udp_connector_registered_local_service", False)
    setattr(dev, "udp_connector_mode", "")
    setattr(dev, "udp_connector_bind_addr", None)
    setattr(dev, "udp_connector_mux_addr", None)
    setattr(dev, "udp_connector_peer_addr", None)
    setattr(dev, "udp_connector_trace", None)
    setattr(dev, "udp_connector_pending_from_mux", [])
    setattr(dev, "udp_connector_bridge_drain_scheduled", False)
    setattr(dev, "udp_connector_pending_from_mux_scheduled", False)
    setattr(dev, "reader_registered", False)
    mux.log.info("[TUN/IOS] close if=%s bridge_state=%s", dev.ifname, _bridge_state())


def write_tun_packet(mux: Any, dev: Any, data: bytes) -> None:
    _log_packet_debug(mux.log, stage="packet_flow_write", ifname=dev.ifname, packet=data)
    mode = _packetflow_connector_mode(dev)
    if mode == "simple_udp_peer":
        _write_packet_to_bridge_backend(mux, dev, data)
        return
    if mode == "udp":
        transport = getattr(dev, "udp_connector_mux_transport", None)
        bind_addr = getattr(dev, "udp_connector_bind_addr", None)
        payload = bytes(data)
        if transport is not None and isinstance(bind_addr, tuple) and len(bind_addr) >= 2:
            transport.sendto(payload, bind_addr)
            return
        pending = list(getattr(dev, "udp_connector_pending_from_mux", []) or [])
        if len(pending) < 1024:
            pending.append(payload)
            setattr(dev, "udp_connector_pending_from_mux", pending)
            _write_connector_state(dev)
            return
        setattr(
            dev,
            "udp_connector_pending_from_mux_drop_count",
            int(getattr(dev, "udp_connector_pending_from_mux_drop_count", 0) or 0) + 1,
        )
        _connector_event(
            dev,
            "udp_connector_pending_from_mux_drop",
            packet_bytes=len(payload),
            pending_from_mux_packets=len(pending),
        )
        _write_connector_state(dev)
        raise RuntimeError("iOS UDP packet-flow connector pending queue is full")
    _write_packet_to_bridge_backend(mux, dev, data)
