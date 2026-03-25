import socket

import pytest

from obstacle_bridge.bridge import _resolve_peer_endpoint


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
