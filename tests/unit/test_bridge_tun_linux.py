from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from obstacle_bridge import bridge_tun_linux


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


class _FakeLog:
    def __init__(self):
        self.rows: list[tuple[str, tuple, dict]] = []

    def isEnabledFor(self, level):
        return level == logging.DEBUG

    def info(self, message, *args, **kwargs):
        self.rows.append((message, args, kwargs))

    def debug(self, message, *args, **kwargs):
        self.rows.append((message, args, kwargs))


class _FakeMux:
    ServiceSpec = _ServiceSpec
    TUN_READ_SIZE_MAX = 65535

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
        self.packets: list[tuple[str, bytes]] = []

    def _on_local_tun_packet(self, dev, packet):
        self.packets.append((dev.ifname, bytes(packet)))


def test_on_tun_fd_readable_yields_after_burst_limit(monkeypatch):
    monkeypatch.setattr(bridge_tun_linux.sys, "platform", "linux")
    monkeypatch.setattr(bridge_tun_linux, "TUN_READ_BURST_MAX", 1)
    packet1 = bytes.fromhex("450000150000000040010000c0a80101c0a8010208")
    packet2 = bytes.fromhex("450000150000000040010000c0a80101c0a8010209")
    reads = [packet1, packet2, BlockingIOError()]

    def _fake_read(fd, size):
        item = reads.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(bridge_tun_linux.os, "read", _fake_read)

    mux = _FakeMux()
    try:
        dev = mux.TunDevice(fd=33, ifname="obtun0", mtu=1500)
        bridge_tun_linux.on_tun_fd_readable(mux, dev)
        assert mux.packets == [("obtun0", packet1)]
        mux.loop.run_until_complete(asyncio.sleep(0))
    finally:
        mux.loop.close()

    assert mux.packets == [("obtun0", packet1), ("obtun0", packet2)]
    assert any("yielding after burst" in row[0] for row in mux.log.rows)
