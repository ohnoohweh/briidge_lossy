from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import time
from typing import Any, Mapping, Optional, Tuple

from . import bridge_tun_ios as platform


class PacketFlowOnlyMux:
    class TunDevice:
        def __init__(self, fd: int, ifname: str, mtu: int, service_key: object | None = None) -> None:
            self.fd = fd
            self.ifname = ifname
            self.mtu = mtu
            self.service_key = service_key
            self.reader_registered = False
            self.chan_id = None

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.log = platform.logging.getLogger("runner")

    def _effective_services_by_id(self) -> dict[object, object]:
        return {}

    def _on_local_tun_packet(self, dev: Any, packet: bytes) -> None:
        self.log.info(
            "[TUN/IOS/CONNECTOR] unexpected local packet callback if=%s len=%s",
            getattr(dev, "ifname", ""),
            len(packet),
        )


class SimpleUDPPeerRuntime:
    def __init__(self, documents_root: platform.Path, loop: asyncio.AbstractEventLoop) -> None:
        self.documents_root = platform.Path(documents_root)
        self.loop = loop
        self.mux = PacketFlowOnlyMux(loop)
        self.dev: Any | None = None
        self.config: dict[str, Any] = {}
        self.settings: dict[str, Any] = {}
        self.started = False
        self.started_unix_ts: float | None = None

    @staticmethod
    def _apply_environment(settings: Mapping[str, Any], documents_root: platform.Path, tunnel_address: str) -> None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR"] = "simple_udp_peer"
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST"] = str(settings.get("bind_host") or "0.0.0.0")
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT"] = str(int(settings.get("bind_port") or 5555))
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST"] = str(settings.get("peer_host") or "")
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT"] = str(int(settings.get("peer_port") or 0))
        os.environ["OBSTACLEBRIDGE_IOS_TUNNEL_ADDRESS"] = str(tunnel_address)
        os.environ["OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT"] = str(platform.Path(documents_root) / "logs")

    async def start(self, config: Mapping[str, Any], *, tunnel_address: str) -> None:
        if self.started:
            return
        settings = platform.simple_udp_peer_settings(config)
        if settings is None:
            raise ValueError("simple_udp_peer runtime requested without matching settings")
        self.config = dict(config)
        self.settings = dict(settings)
        self._apply_environment(settings, self.documents_root, tunnel_address)
        self.dev = open_tun_device(self.mux, str(settings["ifname"]), int(settings["mtu"]))
        register_tun_reader(self.mux, self.dev)
        task = getattr(self.dev, "udp_connector_task", None)
        if task is not None:
            await task
        self.started = True
        self.started_unix_ts = time.time()

    async def stop(self) -> None:
        if self.dev is not None:
            close_tun_device(self.mux, self.dev)
            await asyncio.sleep(0)
        self.dev = None
        self.started = False

    def snapshot(self) -> dict[str, Any]:
        status = {
            "runtime_mode": "simple_udp_peer",
            "peer_addr": [self.settings.get("peer_host"), self.settings.get("peer_port")] if self.settings else None,
            "bind_addr": getattr(self.dev, "udp_connector_bind_addr", None) if self.dev is not None else None,
            "started_unix_ts": self.started_unix_ts,
        }
        if self.dev is not None:
            connector = getattr(self.dev, "udp_connector", None)
            status["counters"] = {
                "to_peer_packets": int(getattr(connector, "tx_packets", 0) or 0),
                "from_peer_packets": int(getattr(connector, "rx_packets", 0) or 0),
            }
        return {
            "started": self.started,
            "status": status,
            "connections": {"tcp": [], "udp": [], "tun": []},
            "config": dict(self.config),
        }


def _append_jsonl(path: platform.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(platform.json.dumps(payload, sort_keys=True, default=repr) + "\n")


def _write_json(path: platform.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(platform.json.dumps(payload, indent=2, sort_keys=True, default=repr) + "\n", encoding="utf-8")


def _connector_trace_paths(stamp: str) -> dict[str, platform.Path]:
    root = platform._connector_logs_root()
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
        "bridge_state": platform._bridge_state(),
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
        "bridge_state": platform._bridge_state(),
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
        ring = platform.deque(maxlen=24)
        setattr(dev, key, ring)
    if not isinstance(ring, platform.deque):
        ring = platform.deque(ring, maxlen=24)
        setattr(dev, key, ring)
    item = {
        "ts": time.time(),
        "summary": platform._packet_summary(packet),
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
        platform._log_packet_debug(self.mux.log, stage="udp_connector_to_packet_flow", ifname=self.dev.ifname, packet=packet)
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
            if not platform._backend().write_packet(packet):
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
        platform._log_packet_debug(self.mux.log, stage="packet_flow_to_udp_connector", ifname=self.dev.ifname, packet=data)
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
        platform._log_packet_debug(self.mux.log, stage="udp_connector_to_mux_relay", ifname=self.dev.ifname, packet=packet)
        self.mux._on_local_tun_packet(self.dev, packet)

    def error_received(self, exc: Exception) -> None:
        self.mux.log.info("[TUN/IOS/UDP] mux relay transport error if=%s: %r", self.dev.ifname, exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.mux.log.info("[TUN/IOS/UDP] mux relay lost if=%s: %r", self.dev.ifname, exc)
        setattr(self.dev, "udp_connector_mux_transport", None)


class _SwiftUDPLocalShim(asyncio.DatagramProtocol):
    def __init__(self, mux: Any, dev: Any, swift_addr: tuple[str, int]) -> None:
        self.mux = mux
        self.dev = dev
        self.swift_addr = (str(swift_addr[0]), int(swift_addr[1]))
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.closed = False
        self.pending: list[bytes] = []

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        setattr(self.dev, "swift_udp_shim_bind_addr", sockname)
        self.mux.log.info(
            "[TUN/IOS/SWIFT-UDP] shim listening if=%s addr=%s swift_addr=%s",
            self.dev.ifname,
            sockname,
            self.swift_addr,
        )
        while self.pending:
            self.send_packet(self.pending.pop(0))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.closed:
            return
        packet = bytes(data)
        platform._log_packet_debug(self.mux.log, stage="swift_udp_to_mux", ifname=self.dev.ifname, packet=packet)
        self.mux._on_local_tun_packet(self.dev, packet)

    def error_received(self, exc: Exception) -> None:
        self.mux.log.info("[TUN/IOS/SWIFT-UDP] shim transport error if=%s: %r", self.dev.ifname, exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.closed = True
        self.transport = None
        self.mux.log.info("[TUN/IOS/SWIFT-UDP] shim lost if=%s: %r", self.dev.ifname, exc)

    def send_packet(self, packet: bytes) -> None:
        payload = bytes(packet)
        if self.closed or self.transport is None:
            self.pending.append(payload)
            return
        platform._log_packet_debug(self.mux.log, stage="mux_to_swift_udp", ifname=self.dev.ifname, packet=payload)
        self.transport.sendto(payload, self.swift_addr)

    def close(self) -> None:
        self.closed = True
        if self.transport is not None:
            self.transport.close()
        self.transport = None
        self.pending = []


async def start_swift_udp_shim(mux: Any, dev: Any) -> None:
    if getattr(dev, "swift_udp_shim", None) is not None:
        return
    settings = platform.swift_udp_shim_settings(None)
    if settings is None:
        raise RuntimeError("swift_udp shim requested without swift_udp connector mode")
    shim_host = str(settings["shim_host"])
    shim_port = int(settings["shim_port"])
    swift_addr = (str(settings["swift_bind_host"]), int(settings["swift_bind_port"]))
    shim_sock = socket.socket(socket.AF_INET6 if ":" in shim_host else socket.AF_INET, socket.SOCK_DGRAM)
    shim_sock.setblocking(False)
    if hasattr(socket, "SO_NOSIGPIPE"):
        shim_sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
    shim_sock.bind((shim_host, shim_port))
    protocol = _SwiftUDPLocalShim(mux, dev, swift_addr)
    transport, _ = await mux.loop.create_datagram_endpoint(lambda: protocol, sock=shim_sock)
    protocol.pending.extend(list(getattr(dev, "swift_udp_shim_pending", []) or []))
    setattr(dev, "swift_udp_shim_pending", [])
    setattr(dev, "swift_udp_shim", protocol)
    setattr(dev, "swift_udp_shim_transport", transport)
    setattr(dev, "swift_udp_shim_target_addr", [swift_addr[0], swift_addr[1]])


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


def _write_packet_to_bridge_backend(mux: Any, dev: Any, data: bytes) -> None:
    try:
        ok = platform._backend().write_packet(data)
    except Exception as exc:
        mux.log.info("[TUN/IOS] write failed if=%s: %r", dev.ifname, exc)
        raise
    if not ok:
        raise RuntimeError("iOS packet flow bridge rejected outbound packet write")


async def start_udp_connector(mux: Any, dev: Any) -> None:
    if getattr(dev, "udp_connector", None) is not None:
        return
    options = getattr(dev, "ios_packetflow_options", None)
    options = options if isinstance(options, dict) else {}
    stamp = platform._capture_timestamp()
    trace_paths = _connector_trace_paths(stamp)
    trace = {
        "stamp": stamp,
        **trace_paths,
        "to_mux_writer": platform._RawPacketPCAPWriter(trace_paths["to_mux_pcap"]),
        "from_mux_writer": platform._RawPacketPCAPWriter(trace_paths["from_mux_pcap"]),
    }
    setattr(dev, "udp_connector_trace", trace)
    _connector_event(dev, "udp_connector_trace_opened", trace_files={key: str(value) for key, value in trace_paths.items()})
    _write_connector_manifest(dev)
    _write_connector_state(dev, component_state="starting")
    connector_transport = None
    relay_transport = None
    try:
        mode = platform._packetflow_connector_mode(dev)
        setattr(dev, "udp_connector_mode", mode)
        bind_host_default = "127.0.0.1" if mode == "udp" else "0.0.0.0"
        host = str(platform._udp_option(options, "ios_packetflow_udp_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST", bind_host_default)).strip() or bind_host_default
        port_default = max(1024, min(65535, int(getattr(dev, "mtu", 1500) or 1500)))
        connector_port = int(platform._udp_option(options, "ios_packetflow_udp_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT", port_default))
        mux_host = str(platform._udp_option(options, "ios_packetflow_udp_mux_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_MUX_HOST", host)).strip() or host
        mux_port = int(platform._udp_option(options, "ios_packetflow_udp_mux_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_MUX_PORT", 0))
        peer_host = str(platform._udp_option(options, "ios_packetflow_peer_host", "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", "")).strip()
        peer_port_raw = platform._udp_option(options, "ios_packetflow_peer_port", "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", 0)
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
            relay_transport, _relay_protocol = await mux.loop.create_datagram_endpoint(
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
        setattr(dev, "udp_connector_last_to_mux", platform.deque(maxlen=24))
        setattr(dev, "udp_connector_last_from_mux", platform.deque(maxlen=24))
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
        setattr(dev, "udp_connector_heartbeat_task", None)
        setattr(dev, "udp_connector_service_key", None)
        setattr(dev, "udp_connector_registered_local_service", False)
        raise


def _drain_bridge_queue(mux: Any, dev: Any) -> int:
    delivered = 0
    packets_seen = int(getattr(dev, "packets_seen", 0))
    while True:
        packet = platform._backend().dequeue_packet()
        if packet is None:
            break
        delivered += 1
        packets_seen += 1
        platform._log_packet_debug(mux.log, stage="packet_flow_read", ifname=dev.ifname, packet=packet)
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


def on_wakeup_fd_readable(mux: Any, dev: Any) -> None:
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


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    state = platform._bridge_state()
    mux.log.info("[TUN/IOS] open if=%s mtu=%s bridge_state=%s", ifname, mtu, state)
    dev = mux.TunDevice(fd=-1, ifname=ifname, mtu=int(mtu), service_key=svc_key)
    spec = mux._effective_services_by_id().get(svc_key) if svc_key is not None and hasattr(mux, "_effective_services_by_id") else None
    options = getattr(spec, "options", None) if spec is not None else None
    setattr(dev, "ios_packetflow_options", options if isinstance(options, dict) else {})
    return dev


def register_tun_reader(mux: Any, dev: Any) -> None:
    if getattr(dev, "reader_registered", False):
        return
    if platform._packetflow_connector_mode(dev) == "swift_udp":
        task = mux.loop.create_task(start_swift_udp_shim(mux, dev))

        def _log_swift_udp_shim_done(done_task: Any) -> None:
            if done_task.cancelled():
                return
            exc = done_task.exception()
            if exc is not None:
                mux.log.info("[TUN/IOS/SWIFT-UDP] shim startup failed if=%s: %r", dev.ifname, exc)

        task.add_done_callback(_log_swift_udp_shim_done)
        setattr(dev, "swift_udp_shim_task", task)
        setattr(dev, "swift_udp_shim_pending", [])
        setattr(dev, "reader_registered", True)
        mux.log.info("[TUN/IOS/SWIFT-UDP] shim startup scheduled if=%s", dev.ifname)
        return
    if platform._udp_connector_enabled(dev):
        task = mux.loop.create_task(start_udp_connector(mux, dev))

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
        if not platform._backend().register_wakeup_fd(write_fd):
            raise RuntimeError("iOS packet flow bridge rejected wakeup fd registration")
        mux.loop.add_reader(read_fd, on_wakeup_fd_readable, mux, dev)
    except Exception:
        with contextlib.suppress(Exception):
            platform._backend().reset_wakeup_fd()
        with contextlib.suppress(Exception):
            os.close(read_fd)
        with contextlib.suppress(Exception):
            os.close(write_fd)
        raise
    setattr(dev, "wakeup_read_fd", read_fd)
    setattr(dev, "wakeup_write_fd", write_fd)
    setattr(dev, "packets_seen", 0)
    setattr(dev, "reader_registered", True)
    mux.log.info("[TUN/IOS] reader registered if=%s bridge_state=%s", dev.ifname, platform._bridge_state())
    if not platform._udp_connector_enabled(dev):
        _drain_bridge_queue(mux, dev)


def close_tun_device(mux: Any, dev: Any) -> None:
    read_fd = getattr(dev, "wakeup_read_fd", None)
    write_fd = getattr(dev, "wakeup_write_fd", None)
    if read_fd is not None:
        with contextlib.suppress(Exception):
            mux.loop.remove_reader(read_fd)
    if read_fd is not None or write_fd is not None:
        with contextlib.suppress(Exception):
            platform._backend().reset_wakeup_fd()
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
    swift_udp_shim_task = getattr(dev, "swift_udp_shim_task", None)
    if swift_udp_shim_task is not None:
        with contextlib.suppress(Exception):
            swift_udp_shim_task.cancel()
    connector = getattr(dev, "udp_connector", None)
    if connector is not None:
        with contextlib.suppress(Exception):
            connector.close()
    swift_udp_shim = getattr(dev, "swift_udp_shim", None)
    if swift_udp_shim is not None:
        with contextlib.suppress(Exception):
            swift_udp_shim.close()
    tr = getattr(dev, "udp_connector_mux_transport", None)
    if tr is not None:
        with contextlib.suppress(Exception):
            tr.close()
    swift_udp_shim_transport = getattr(dev, "swift_udp_shim_transport", None)
    if swift_udp_shim_transport is not None:
        with contextlib.suppress(Exception):
            swift_udp_shim_transport.close()
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
    setattr(dev, "swift_udp_shim", None)
    setattr(dev, "swift_udp_shim_task", None)
    setattr(dev, "swift_udp_shim_transport", None)
    setattr(dev, "swift_udp_shim_bind_addr", None)
    setattr(dev, "swift_udp_shim_target_addr", None)
    setattr(dev, "swift_udp_shim_pending", [])
    setattr(dev, "reader_registered", False)
    mux.log.info("[TUN/IOS] close if=%s bridge_state=%s", dev.ifname, platform._bridge_state())


def write_tun_packet(mux: Any, dev: Any, data: bytes) -> None:
    platform._log_packet_debug(mux.log, stage="packet_flow_write", ifname=dev.ifname, packet=data)
    mode = platform._packetflow_connector_mode(dev)
    if mode == "swift_udp":
        shim = getattr(dev, "swift_udp_shim", None)
        payload = bytes(data)
        if shim is not None:
            shim.send_packet(payload)
            return
        pending = list(getattr(dev, "swift_udp_shim_pending", []) or [])
        pending.append(payload)
        setattr(dev, "swift_udp_shim_pending", pending)
        return
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