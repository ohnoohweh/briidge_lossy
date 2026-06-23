import argparse
import errno
import logging
import socket

import pytest

from obstacle_bridge.bridge import _resolve_peer_endpoint
from obstacle_bridge.bridge_transport_udp import SendPort, UdpSession


def test_resolve_localhost_ipv6_uses_loopback_fallback_on_gaierror(monkeypatch: pytest.MonkeyPatch) -> None:
    def _always_fail(*_args, **_kwargs):
        raise socket.gaierror(-5, "No address associated with hostname")

    monkeypatch.setattr(socket, "getaddrinfo", _always_fail)
    host, port, family = _resolve_peer_endpoint("localhost", 443, resolve_mode="ipv6", socktype=socket.SOCK_STREAM)
    assert (host, port, family) == ("::1", 443, socket.AF_INET6)


def test_resolve_localhost_ipv4_uses_loopback_fallback_on_gaierror(monkeypatch: pytest.MonkeyPatch) -> None:
    def _always_fail(*_args, **_kwargs):
        raise socket.gaierror(-5, "No address associated with hostname")

    monkeypatch.setattr(socket, "getaddrinfo", _always_fail)
    host, port, family = _resolve_peer_endpoint("localhost", 443, resolve_mode="ipv4", socktype=socket.SOCK_DGRAM)
    assert (host, port, family) == ("127.0.0.1", 443, socket.AF_INET)


def test_resolve_non_localhost_propagates_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _always_fail(*_args, **_kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _always_fail)
    with pytest.raises(RuntimeError, match="Could not resolve overlay peer 'example.invalid'"):
        _resolve_peer_endpoint("example.invalid", 443, resolve_mode="ipv4", socktype=socket.SOCK_STREAM)


def test_resolve_multi_peer_prefers_ipv6_literal_when_available() -> None:
    host, port, family = _resolve_peer_endpoint(
        "192.0.2.10,[2001:db8::10]",
        443,
        resolve_mode="prefer-ipv6",
        socktype=socket.SOCK_DGRAM,
    )
    assert (host, port, family) == ("2001:db8::10", 443, socket.AF_INET6)


def test_resolve_multi_peer_falls_back_to_ipv4_when_ipv6_candidate_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    original_getaddrinfo = socket.getaddrinfo

    def _fake_getaddrinfo(host, *args, **kwargs):
        if host == "bad.example.invalid":
            raise socket.gaierror(-2, "Name or service not known")
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    host, port, family = _resolve_peer_endpoint(
        "bad.example.invalid,192.0.2.10",
        443,
        resolve_mode="ipv6",
        socktype=socket.SOCK_DGRAM,
    )
    assert (host, port, family) == ("192.0.2.10", 443, socket.AF_INET)


def test_resolve_multi_peer_honors_bind_family_constraint() -> None:
    host, port, family = _resolve_peer_endpoint(
        "192.0.2.10,[2001:db8::10]",
        443,
        resolve_mode="prefer-ipv6",
        bind_host="0.0.0.0",
        socktype=socket.SOCK_DGRAM,
    )
    assert (host, port, family) == ("192.0.2.10", 443, socket.AF_INET)


def test_udp_session_immediately_falls_back_to_ipv4_on_unreachable_ipv6_send_error() -> None:
    args = argparse.Namespace(
        max_inflight=32,
        udp_bind="::",
        udp_own_port=4433,
        udp_peer="[2001:db8::10],192.0.2.10",
        udp_peer_port=4433,
        udp_peer_resolve_family="prefer-ipv6",
    )
    session = UdpSession(args)
    session._listener_mode = False
    session._peer_candidates = [
        ("2001:db8::10", 4433, socket.AF_INET6),
        ("192.0.2.10", 4433, socket.AF_INET),
    ]
    session._peer_candidate_index = 0

    class _FakeRuntime:
        def __init__(self) -> None:
            self._conn_evt = type("_Evt", (), {"clear": lambda self: None})()
            self._conn_state = True
            self._next_probe_due_ns = 123
            self.sent_initial = False

        def _send_idle_probe(self, initial: bool = False) -> None:
            self.sent_initial = bool(initial)

    class _FakeSendPort:
        def __init__(self) -> None:
            self.peer_addr = ("2001:db8::10", 4433)

        def set_peer(self, addr) -> None:
            self.peer_addr = addr

    fake_runtime = _FakeRuntime()
    fake_send_port = _FakeSendPort()
    session._proto = type("_Proto", (), {"send_port": fake_send_port, "_proto_rt": fake_runtime})()

    learned = []
    session._on_peer_set = lambda host, port: learned.append((host, port))

    session._on_peer_send_error(OSError(errno.ENETUNREACH, "Network is unreachable"))

    assert session._peer_candidate_index == 1
    assert fake_send_port.peer_addr == ("192.0.2.10", 4433)
    assert learned == [("192.0.2.10", 4433)]
    assert fake_runtime._conn_state is False
    assert fake_runtime._next_probe_due_ns == 0
    assert fake_runtime.sent_initial is True


class _FakeSocket:
    family = socket.AF_INET6


class _FakeTransport:
    def __init__(self) -> None:
        self.sent = []

    def get_extra_info(self, name: str):
        if name == "socket":
            return _FakeSocket()
        return None

    def sendto(self, payload: bytes, dst) -> None:
        self.sent.append((payload, dst))


def test_send_port_prefer_ipv6_keeps_native_ipv4_destination() -> None:
    transport = _FakeTransport()
    send_port = SendPort(
        transport,
        logging.getLogger("test"),
        initial_peer=("192.0.2.10", 4433),
        allow_ipv4_mapped_send=False,
    )

    send_port.sendto(b"payload")

    assert transport.sent == [(b"payload", ("192.0.2.10", 4433))]


def test_send_port_ipv6_mode_allows_ipv4_mapped_destination() -> None:
    transport = _FakeTransport()
    send_port = SendPort(
        transport,
        logging.getLogger("test"),
        initial_peer=("192.0.2.10", 4433),
        allow_ipv4_mapped_send=True,
    )

    send_port.sendto(b"payload")

    assert transport.sent == [(b"payload", ("::ffff:192.0.2.10", 4433, 0, 0))]
