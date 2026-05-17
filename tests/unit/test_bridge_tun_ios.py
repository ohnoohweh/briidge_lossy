from __future__ import annotations

import asyncio
import logging

from obstacle_bridge import bridge_tun_ios


class _FakeBackend:
    def __init__(self, packets=None, *, active=True):
        self._packets = list(packets or [])
        self._active = active
        self.written: list[bytes] = []

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

    def _on_local_tun_packet(self, dev, packet):
        self.packets.append((dev.ifname, bytes(packet)))


def test_open_tun_device_uses_active_bridge(monkeypatch):
    backend = _FakeBackend(active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")

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

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400)
        bridge_tun_ios.write_tun_packet(mux, dev, b"\x45hello")
        assert backend.written == [b"\x45hello"]
        assert any(row[0].startswith("[TUN/IOS/PKT]") for row in mux.log.rows)
    finally:
        mux.loop.close()


def test_register_tun_reader_drains_bridge_queue(monkeypatch):
    backend = _FakeBackend([b"\x45one", b"\x45two"], active=True)
    monkeypatch.setattr(bridge_tun_ios, "_BACKEND", backend)
    monkeypatch.setattr(bridge_tun_ios.sys, "platform", "ios")

    mux = _FakeMux()
    try:
        dev = bridge_tun_ios.open_tun_device(mux, "obtun-ios", 1400)
        bridge_tun_ios.register_tun_reader(mux, dev)
        mux.loop.run_until_complete(asyncio.sleep(0.02))
        assert mux.packets == [("obtun-ios", b"\x45one"), ("obtun-ios", b"\x45two")]
        assert any(row[0].startswith("[TUN/IOS/PKT]") for row in mux.log.rows)
        bridge_tun_ios.close_tun_device(mux, dev)
        task = getattr(dev, "reader_task")
        mux.loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
    finally:
        mux.loop.close()
