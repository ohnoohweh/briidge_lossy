from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import os
import socket
from typing import Optional

from obstacle_bridge import bridge_tun_ios


@dataclass(frozen=True)
class _ServiceSpec:
    svc_id: int
    l_proto: str
    l_bind: str
    l_port: int
    r_proto: str
    r_host: str
    r_port: int
    name: Optional[str] = None
    lifecycle_hooks: Optional[dict] = None
    options: Optional[dict] = None


class _FakeBackend:
    def __init__(self, packets=None, *, active=True):
        self._packets = list(packets or [])
        self._active = active
        self.written: list[bytes] = []
        self.wakeup_fd: Optional[int] = None

    def dequeue_packet(self):
        if self._packets:
            return self._packets.pop(0)
        return None

    def write_packet(self, packet: bytes) -> bool:
        self.written.append(bytes(packet))
        return True

    def bridge_state(self) -> dict:
        return {
            "active": self._active,
            "queued_packets": len(self._packets),
            "packets_from_system": len(self._packets),
        }

    def register_wakeup_fd(self, fd: int) -> bool:
        self.wakeup_fd = int(fd)
        return True

    def reset_wakeup_fd(self) -> None:
        self.wakeup_fd = None

    def push_packet(self, packet: bytes) -> None:
        self._packets.append(bytes(packet))
        if self.wakeup_fd is not None:
            os.write(self.wakeup_fd, b"\x01")


class _FakeLog:
    def __init__(self):
        self.rows: list[tuple[str, tuple, dict]] = []

    def isEnabledFor(self, level):
        return level == logging.DEBUG

    def info(self, message, *args, **kwargs):
        self.rows.append((message, args, kwargs))

    def debug(self, message, *args, **kwargs):
        self.rows.append((message, args, kwargs))

    def exception(self, message, *args, **kwargs):
        self.rows.append((message, args, kwargs))


class _FakeMux:
    ServiceSpec = _ServiceSpec

    class TunDevice:
        def __init__(self, fd, ifname, mtu, service_key=None):
            self.fd = fd
            self.ifname = ifname
            self.mtu = mtu
            self.service_key = service_key
            self.reader_registered = False
            self.chan_id = None

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.log = _FakeLog()
        self.packets = []
        self._services = {}

    def _on_local_tun_packet(self, dev, packet):
        self.packets.append((dev.ifname, bytes(packet)))

    def _effective_services_by_id(self):
        return self._services


def test_open_tun_device_uses_active_bridge(monkeypatch):
    backend = _FakeBackend(active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1500, svc_key=("local", 0, 1))
        assert dev.ifname == "obtun-ios"
        assert dev.mtu == 1500
        assert dev.fd == -1
    finally:
        mux.loop.close()


def test_write_tun_packet_uses_bridge_backend(monkeypatch):
    backend = _FakeBackend(active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400)
        bridge_tun_ios.write_tun_packet(mux, dev, b"\x45hello")
        assert backend.written == [b"\x45hello"]
        assert any(row[0].startswith("[TUN/IOS/PKT]") for row in mux.log.rows)
    finally:
        mux.loop.close()


def test_open_tun_device_rejects_swift_udp_native_ownership(monkeypatch):
    backend = _FakeBackend(active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "swift_udp_peer")

    mux = _FakeMux()
    try:
        try:
            bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400)
        except RuntimeError as exc:
            assert "native swift_udp connector" in str(exc)
        else:
            raise AssertionError("swift_udp should prevent Python from opening the iOS packet-flow bridge")
    finally:
        mux.loop.close()


def test_register_tun_reader_drains_bridge_queue(monkeypatch):
    backend = _FakeBackend([b"\x45one", b"\x45two"], active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400)
        bridge_tun_ios.register_tun_reader(mux, dev)
        assert mux.packets == [("obtun-ios", b"\x45one"), ("obtun-ios", b"\x45two")]
        assert any(row[0].startswith("[TUN/IOS/PKT]") for row in mux.log.rows)
        backend.push_packet(b"\x45three")
        mux.loop.run_until_complete(asyncio.sleep(0))
        assert mux.packets[-1] == ("obtun-ios", b"\x45three")
        bridge_tun_ios.close_tun_device(mux, dev)
        assert backend.wakeup_fd is None
    finally:
        mux.loop.close()


def test_udp_connector_routes_bridge_queue_through_local_udp(monkeypatch, tmp_path):
    backend = _FakeBackend([b"\x45one"], active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "udp")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT", "0")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT", str(tmp_path))

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400, svc_key=("local", 0, 7))
        bridge_tun_ios.register_tun_reader(mux, dev)
        task = getattr(dev, "udp_connector_task")
        mux.loop.run_until_complete(task)
        mux.loop.run_until_complete(asyncio.sleep(0.05))

        assert mux.packets == [("obtun-ios", b"\x45one")]
        bridge_tun_ios.write_tun_packet(mux, dev, b"echo:\x45one")
        mux.loop.run_until_complete(asyncio.sleep(0.05))
        assert backend.written == [b"echo:\x45one"]
        assert getattr(dev, "udp_connector").tx_packets == 1
        assert getattr(dev, "udp_connector").rx_packets == 1
        trace = getattr(dev, "udp_connector_trace")
        assert trace["to_mux_pcap"].is_file()
        assert trace["from_mux_pcap"].is_file()
        assert trace["manifest"].is_file()
        assert trace["state"].is_file()
        assert getattr(dev, "udp_connector_service_key", None) is None
        bridge_tun_ios.close_tun_device(mux, dev)
        mux.loop.run_until_complete(asyncio.sleep(0))
        assert backend.wakeup_fd is None
        assert "to_mux_packets" in trace["manifest"].read_text(encoding="utf-8")
        assert '"component": "udp-connector"' in trace["state"].read_text(encoding="utf-8")
    finally:
        mux.loop.close()


def test_simple_udp_peer_routes_bridge_queue_to_external_peer(monkeypatch, tmp_path):
    backend = _FakeBackend([b"\x45one"], active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "simple_udp_peer")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST", "127.0.0.1")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT", "0")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT", str(tmp_path))

    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer_sock.bind(("127.0.0.1", 0))
    peer_sock.settimeout(0.5)
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", "127.0.0.1")
    monkeypatch.setenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", str(peer_sock.getsockname()[1]))

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400, svc_key=("local", 0, 8))
        bridge_tun_ios.register_tun_reader(mux, dev)
        task = getattr(dev, "udp_connector_task")
        mux.loop.run_until_complete(task)
        mux.loop.run_until_complete(asyncio.sleep(0.05))

        payload, source = peer_sock.recvfrom(4096)
        assert payload == b"\x45one"

        peer_sock.sendto(b"reply:\x45one", source)
        mux.loop.run_until_complete(asyncio.sleep(0.05))

        assert backend.written == [b"reply:\x45one"]
        connector = getattr(dev, "udp_connector")
        assert connector.tx_packets == 1
        assert connector.rx_packets == 1
        assert getattr(dev, "udp_connector_peer_addr", None) == ["127.0.0.1", peer_sock.getsockname()[1]]
        trace = getattr(dev, "udp_connector_trace")
        assert trace["to_mux_pcap"].is_file()
        assert trace["from_mux_pcap"].is_file()
        manifest = json.loads(trace["manifest"].read_text(encoding="utf-8"))
        state = json.loads(trace["state"].read_text(encoding="utf-8"))
        assert manifest["connector_mode"] == "simple_udp_peer"
        assert manifest["peer_addr"] == ["127.0.0.1", peer_sock.getsockname()[1]]
        assert state["connector_mode"] == "simple_udp_peer"
        bridge_tun_ios.close_tun_device(mux, dev)
        mux.loop.run_until_complete(asyncio.sleep(0))
        assert backend.wakeup_fd is None
    finally:
        peer_sock.close()
        mux.loop.close()


def test_packet_summary_extracts_ip_metadata():
    packet = bytes.fromhex("450000341234400040060000c0a8690113d2d243c350005000000000000000005000000000000000")
    summary = bridge_tun_ios._packet_summary(packet)

    assert summary["ipver"] == 4
    assert summary["proto"] == 6
    assert summary["src"] == "192.168.105.1"
    assert summary["dst"] == "19.210.210.67"
    assert summary["src_port"] == 50000
    assert summary["dst_port"] == 80
