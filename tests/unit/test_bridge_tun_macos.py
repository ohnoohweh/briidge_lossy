from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Optional

from obstacle_bridge import bridge_tun_macos


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


class _FakeSocket:
    def __init__(self, fd=77, ifname=b"utun9\x00"):
        self._fd = fd
        self._ifname = ifname
        self.closed = False
        self.detached = False

    def fileno(self):
        return self._fd

    def getsockopt(self, level, optname, buflen):
        assert level == bridge_tun_macos.SYSPROTO_CONTROL
        assert optname == bridge_tun_macos.UTUN_OPT_IFNAME
        return self._ifname.ljust(buflen, b"\x00")

    def detach(self):
        self.detached = True
        return self._fd

    def close(self):
        self.closed = True


def test_open_tun_device_connects_utun_and_returns_actual_ifname(monkeypatch):
    monkeypatch.setattr(bridge_tun_macos.sys, "platform", "darwin")
    fake_sock = _FakeSocket()
    real_socket_ctor = bridge_tun_macos.socket.socket

    def _fake_socket(*args, **kwargs):
        if args[:3] == (
            bridge_tun_macos.PF_SYSTEM,
            bridge_tun_macos.socket.SOCK_DGRAM,
            bridge_tun_macos.SYSPROTO_CONTROL,
        ):
            return fake_sock
        return real_socket_ctor(*args, **kwargs)

    monkeypatch.setattr(bridge_tun_macos.socket, "socket", _fake_socket)
    monkeypatch.setattr(bridge_tun_macos, "_lookup_utun_control_id", lambda fd: 5)
    seen_connect: list[tuple[int, int]] = []
    monkeypatch.setattr(bridge_tun_macos, "_connect_utun", lambda fd, control_id: seen_connect.append((fd, control_id)))
    set_blocking_calls: list[tuple[int, bool]] = []
    monkeypatch.setattr(bridge_tun_macos.os, "set_blocking", lambda fd, flag: set_blocking_calls.append((fd, flag)))
    mtu_calls: list[tuple[str, int]] = []
    monkeypatch.setattr(bridge_tun_macos, "_set_iface_mtu_and_up", lambda mux, ifname, mtu: mtu_calls.append((ifname, mtu)))

    mux = _FakeMux()
    try:
        dev = bridge_tun_macos.open_tun_device(mux, "obtun9", 1400, svc_key=("local", 0, 9))
    finally:
        mux.loop.close()

    assert seen_connect == [(77, 5)]
    assert set_blocking_calls == [(77, False)]
    assert mtu_calls == [("utun9", 1400)]
    assert fake_sock.detached is True
    assert dev.fd == 77
    assert dev.ifname == "utun9"
    assert dev.mtu == 1400
    assert dev.service_key == ("local", 0, 9)


def test_write_tun_packet_prefixes_utun_family_header(monkeypatch):
    monkeypatch.setattr(bridge_tun_macos.sys, "platform", "darwin")
    writes: list[tuple[int, bytes]] = []
    monkeypatch.setattr(bridge_tun_macos.os, "write", lambda fd, payload: writes.append((fd, bytes(payload))))

    mux = _FakeMux()
    try:
        dev = mux.TunDevice(fd=55, ifname="utun5", mtu=1500)
        packet = bytes.fromhex("6000000000011140") + (b"\x00" * 32) + b"\xaa"
        bridge_tun_macos.write_tun_packet(mux, dev, packet)
    finally:
        mux.loop.close()

    assert writes == [
        (55, struct.pack("!I", bridge_tun_macos.socket.AF_INET6) + packet)
    ]
    assert any(row[0].startswith("[TUN/MACOS/PKT]") for row in mux.log.rows)


def test_on_tun_fd_readable_strips_family_header_before_forwarding(monkeypatch):
    monkeypatch.setattr(bridge_tun_macos.sys, "platform", "darwin")
    packet = bytes.fromhex("450000150000000040010000c0a80101c0a8010208")
    frame = struct.pack("!I", bridge_tun_macos.socket.AF_INET) + packet
    reads = [frame, BlockingIOError()]

    def _fake_read(fd, size):
        item = reads.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(bridge_tun_macos.os, "read", _fake_read)

    mux = _FakeMux()
    try:
        dev = mux.TunDevice(fd=44, ifname="utun4", mtu=1500)
        bridge_tun_macos.on_tun_fd_readable(mux, dev)
    finally:
        mux.loop.close()

    assert mux.packets == [("utun4", packet)]
    assert any(row[0].startswith("[TUN/MACOS/PKT]") for row in mux.log.rows)


def test_require_tun_support_rejects_non_darwin(monkeypatch):
    monkeypatch.setattr(bridge_tun_macos.sys, "platform", "linux")
    mux = _FakeMux()
    try:
        try:
            bridge_tun_macos.require_tun_support(mux)
        except RuntimeError as exc:
            assert "non-macOS" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")
    finally:
        mux.loop.close()
