from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import socket
import struct
import sys
import time
from typing import Callable, List, Optional, Tuple

def _strip_brackets(host: str) -> str:
    if host and host.startswith('[') and host.endswith(']'):
        return host[1:-1]
    return host


def _split_configured_peer_hosts(host: str) -> List[str]:
    raw = str(host or "").strip()
    if not raw:
        return []
    if "," not in raw and ";" not in raw:
        return [raw]
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def _peer_resolve_mode(args: argparse.Namespace, resolve_attr: str) -> str:
    return str(getattr(args, resolve_attr, "prefer-ipv6") or "prefer-ipv6")


def _host_ip_family(host: Optional[str]) -> int:
    host = _strip_brackets(host or "")
    if not host:
        return socket.AF_UNSPEC
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return socket.AF_UNSPEC
    return socket.AF_INET6 if addr.version == 6 else socket.AF_INET


def _bind_family_constraint(bind_host: Optional[str]) -> Optional[int]:
    host = _strip_brackets(bind_host or "")
    if not host or host == "::":
        return None
    fam = _host_ip_family(host)
    return fam if fam != socket.AF_UNSPEC else None


def _wildcard_host_for_family(family: int) -> str:
    return "::" if family == socket.AF_INET6 else "0.0.0.0"


def _localhost_fallback(resolve_mode: str) -> Optional[Tuple[str, int]]:
    mode = (resolve_mode or "").strip().lower()
    if mode == "ipv4":
        return ("127.0.0.1", socket.AF_INET)
    if mode == "ipv6":
        return ("::1", socket.AF_INET6)
    return None


def _prefer_unspec_listener_family() -> bool:
    """
    Python 3.9 needs explicit AF_INET/AF_INET6 in several asyncio listener paths.
    Newer runtimes handle AF_UNSPEC correctly, so we can let the stack decide.
    """
    return sys.version_info >= (3, 10)


def _listener_family_for_host(host: str) -> int:
    host = _strip_brackets(host or "")
    if _prefer_unspec_listener_family():
        return socket.AF_UNSPEC
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _resolve_hostalias(host: str) -> str:
    alias_path = os.environ.get("HOSTALIASES", "").strip()
    if not alias_path:
        return host
    alias_key = str(host or "").strip()
    if not alias_key or "." in alias_key or ":" in alias_key:
        return host
    try:
        with open(alias_path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[0] == alias_key:
                    return parts[1]
    except OSError:
        return host
    return host


def _ipv4_to_mapped_ipv6(host: str) -> str:
    return f"::ffff:{host}"


def _family_preference_rank(family: int, resolve_mode: str) -> int:
    mode = (resolve_mode or "").strip().lower()
    if mode in ("prefer-ipv6", "ipv6"):
        return 0 if family == socket.AF_INET6 else 1
    if mode == "ipv4":
        return 0 if family == socket.AF_INET else 1
    return 0


def _resolve_peer_candidates(
    host: str,
    port: int,
    *,
    resolve_mode: str = "prefer-ipv6",
    socktype: int = 0,
    strict_family: bool = True,
) -> List[Tuple[str, int, int]]:
    host = _strip_brackets(host)
    if not host:
        raise RuntimeError("overlay peer requires a non-empty host name")

    host = _resolve_hostalias(host)

    family = _host_ip_family(host)
    if family != socket.AF_UNSPEC:
        if strict_family:
            if resolve_mode == "ipv4" and family != socket.AF_INET:
                raise RuntimeError(f"overlay peer {host!r} is not an IPv4 address")
            if resolve_mode == "ipv6" and family != socket.AF_INET6:
                if family == socket.AF_INET:
                    host = _ipv4_to_mapped_ipv6(host)
                    family = socket.AF_INET6
                else:
                    raise RuntimeError(f"overlay peer {host!r} is not an IPv6 address")
        return [(host, int(port), family)]

    lookup_family = socket.AF_UNSPEC
    if strict_family:
        if resolve_mode == "ipv4":
            lookup_family = socket.AF_INET
        elif resolve_mode == "ipv6":
            lookup_family = socket.AF_INET6

    try:
        infos = socket.getaddrinfo(host, int(port), family=lookup_family, type=socktype)
    except socket.gaierror as exc:
        localhost_fallback = _localhost_fallback(resolve_mode)
        if localhost_fallback and host.lower() == "localhost":
            fallback_host, fallback_family = localhost_fallback
            return [(fallback_host, int(port), fallback_family)]
        raise RuntimeError(f"Could not resolve overlay peer {host!r}: {exc}") from exc
    candidates: List[Tuple[str, int, int]] = []
    for fam, _socktype, _proto, _canonname, sockaddr in infos:
        if fam not in (socket.AF_INET, socket.AF_INET6):
            continue
        if not isinstance(sockaddr, tuple) or len(sockaddr) < 2:
            continue
        candidate = (str(sockaddr[0]), int(sockaddr[1]), fam)
        if candidate not in candidates:
            candidates.append(candidate)

    if not candidates:
        raise RuntimeError(f"Could not resolve overlay peer {host!r}")

    return candidates


def _resolve_peer_endpoint(
    host: str,
    port: int,
    *,
    resolve_mode: str = "prefer-ipv6",
    bind_host: Optional[str] = None,
    socktype: int = 0,
) -> Tuple[str, int, int]:
    configured_hosts = _split_configured_peer_hosts(host)
    if not configured_hosts:
        raise RuntimeError("overlay peer requires a non-empty host name")
    strict_family = len(configured_hosts) == 1
    if strict_family:
        candidates = _resolve_peer_candidates(
            configured_hosts[0],
            int(port),
            resolve_mode=resolve_mode,
            socktype=socktype,
            strict_family=True,
        )
    else:
        candidates = []
        for candidate_host in configured_hosts:
            try:
                candidates.extend(
                    _resolve_peer_candidates(
                        candidate_host,
                        int(port),
                        resolve_mode=resolve_mode,
                        socktype=socktype,
                        strict_family=False,
                    )
                )
            except RuntimeError:
                continue
        if not candidates:
            raise RuntimeError(f"Could not resolve overlay peer {host!r}")

    candidates.sort(key=lambda item: _family_preference_rank(item[2], resolve_mode))

    bind_family = _bind_family_constraint(bind_host)
    if bind_family is not None:
        matching = [item for item in candidates if item[2] == bind_family]
        if matching:
            candidates = matching
        else:
            fam_name = "IPv6" if bind_family == socket.AF_INET6 else "IPv4"
            raise RuntimeError(
                f"overlay peer {host!r} resolved, but no {fam_name} address is compatible with bind {bind_host!r}"
            )

    return candidates[0]


def _resolve_cli_peer(
    args: argparse.Namespace,
    *,
    peer_attr: str = "peer",
    peer_port_attr: str = "peer_port",
    resolve_attr: str,
    bind_host: Optional[str] = None,
    socktype: int = 0,
) -> Optional[Tuple[str, int, int]]:
    peer = getattr(args, peer_attr, None)
    if not peer and peer_attr != "peer":
        peer = getattr(args, "peer", None)
    if not peer:
        return None
    peer_port = getattr(args, peer_port_attr, None)
    if (peer_port is None) and peer_port_attr != "peer_port":
        peer_port = getattr(args, "peer_port", 443)
    return _resolve_peer_endpoint(
        str(peer),
        int(peer_port if peer_port is not None else 443),
        resolve_mode=_peer_resolve_mode(args, resolve_attr),
        bind_host=bind_host,
        socktype=socktype,
    )


def _overlay_cli_attrs(transport: str) -> Tuple[str, str, str, str]:
    transport = (transport or "myudp").strip().lower()
    if transport == "myudp":
        return ("udp_bind", "udp_peer", "udp_peer_port", "udp_own_port")
    if transport == "tcp":
        return ("tcp_bind", "tcp_peer", "tcp_peer_port", "tcp_own_port")
    if transport == "quic":
        return ("quic_bind", "quic_peer", "quic_peer_port", "quic_own_port")
    if transport == "ws":
        return ("ws_bind", "ws_peer", "ws_peer_port", "ws_own_port")
    return ("udp_bind", "udp_peer", "udp_peer_port", "udp_own_port")


def _has_configured_overlay_peer(args: argparse.Namespace, transport: Optional[str] = None) -> bool:
    if transport:
        _, peer_attr, _, _ = _overlay_cli_attrs(transport)
        return bool(getattr(args, peer_attr, None) or getattr(args, "peer", None))
    for proto in ("myudp", "tcp", "quic", "ws"):
        _, peer_attr, _, _ = _overlay_cli_attrs(proto)
        if getattr(args, peer_attr, None):
            return True
    return bool(getattr(args, "peer", None))


def _now_ns() -> int:
    return time.monotonic_ns()


class StreamRTT:
    """
    Transport-agnostic RTT estimator & 'connectedness' window.

    PING : [tx_ns:Q][echo_ns:Q]  (echo_ns may be 0 if unknown)
    PONG : [echo_tx_ns:Q]
    """
    def __init__(self, alpha: float = 0.125, connected_loss_s: float = 20.0,
                 log: Optional[logging.Logger] = None):
        self.rtt_est_ms: float = 0.0
        self.rtt_sample_ms: float = 0.0
        self.last_rtt_ok_ns: int = 0
        self._alpha = float(alpha)
        self._loss_window_ns = int(connected_loss_s * 1e9)
        # For echo computation on our next PING
        self._last_rx_tx_ns: int = 0
        self._last_rx_wall_ns: int = 0
        self._log = log

    def is_connected(self, now_ns_val: Optional[int] = None) -> bool:
        if self.last_rtt_ok_ns == 0:
            return False
        now_v = now_ns_val or _now_ns()
        return (now_v - self.last_rtt_ok_ns) <= self._loss_window_ns

    # --- echo helpers ---
    def on_ping_received(self, tx_ns: int) -> None:
        self._last_rx_tx_ns = int(tx_ns)
        self._last_rx_wall_ns = _now_ns()
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(f"[RTT] PING rx: tx_ns={tx_ns} wall_ns={self.last_rtt_ok_ns}")

    def build_ping_bytes(self) -> bytes:
        tx_ns = _now_ns()
        echo_ns = 0
        if self._last_rx_tx_ns and self._last_rx_wall_ns:
            echo_ns = self._last_rx_tx_ns + (tx_ns - self._last_rx_wall_ns)
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(f"[RTT] PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        return struct.pack(">QQ", tx_ns, echo_ns)

    def build_pong_bytes(self, echo_tx_ns: int) -> bytes:
        return struct.pack(">Q", int(echo_tx_ns))

    def on_pong_received(self, echo_tx_ns: int) -> None:
        if not echo_tx_ns:
            return
        sample_ms = (_now_ns() - int(echo_tx_ns)) / 1e6
        self.rtt_sample_ms = sample_ms
        self.last_rtt_ok_ns = _now_ns()
        if self.rtt_est_ms < sample_ms:
            self.rtt_est_ms = sample_ms
        else:
            self.rtt_est_ms = (1.0 - self._alpha) * self.rtt_est_ms + self._alpha * sample_ms
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(
                f"[RTT] PONG rx: echo_tx_ns={echo_tx_ns} "
                f"sample_ms={sample_ms:.3f} est_ms={self.rtt_est_ms:.3f} last_ok={self.last_rtt_ok_ns}"
            )

    def reset(self) -> None:
        self.rtt_est_ms = 0.0
        self.rtt_sample_ms = 0.0
        self.last_rtt_ok_ns = 0
        self._last_rx_tx_ns = 0
        self._last_rx_wall_ns = 0

class StreamRTTRuntime:
    """
    Timer that drives initial and periodic pings and exposes connection events
    based on StreamRTT.is_connected(). Behavior mirrors ProtocolRuntime.
    """
    def __init__(self, rtt: StreamRTT):
        self.rtt = rtt
        self._send_ping_fn: Optional[Callable[[bytes], None]] = None
        self._on_state_change: Optional[Callable[[bool], None]] = None
        self._task: Optional[asyncio.Task] = None
        self._conn_evt = asyncio.Event()
        self._conn_state = False
        self._probe_interval_s = 1.0
        self._idle_check_s = 0.2
        self._rtt_timeout_ns = int(2.0 * 1e9)
        self._next_probe_due_ns = 0

    def attach(self, send_ping_fn: Optional[Callable[[bytes], None]], on_state_change=None):
        self._send_ping_fn = send_ping_fn
        self._on_state_change = on_state_change
        if self._task is None:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._tick())

    def detach(self):
        if self._task:
            self._task.cancel()
            self._task = None
        self._send_ping_fn = None
        self._on_state_change = None
        self._conn_evt.clear()
        self._conn_state = False
        self._next_probe_due_ns = 0

    def reset(self) -> None:
        self._conn_evt.clear()
        self._conn_state = False
        self._next_probe_due_ns = 0

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if self.rtt.is_connected():
            return True
        try:
            await asyncio.wait_for(self._conn_evt.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _send_ping(self) -> None:
        if not self._send_ping_fn:
            return
        try:
            payload = self.rtt.build_ping_bytes()
            self._send_ping_fn(payload)  # Session will wrap as PING frame
        except Exception:
            pass

    async def _tick(self):
        try:
            while True:
                connected_now = self.rtt.is_connected()
                if connected_now != self._conn_state:
                    self._conn_state = connected_now
                    if connected_now:
                        last_ok = self.rtt.last_rtt_ok_ns or _now_ns()
                        self._next_probe_due_ns = last_ok + self._rtt_timeout_ns
                        self._conn_evt.set()
                    else:
                        self._conn_evt.clear()
                        self._next_probe_due_ns = 0
                    if callable(self._on_state_change):
                        try: self._on_state_change(connected_now)
                        except Exception: pass

                if not connected_now:
                    self._send_ping()
                    await asyncio.sleep(self._probe_interval_s)
                    continue

                now = _now_ns()
                last_ok = self.rtt.last_rtt_ok_ns
                if last_ok:
                    self._next_probe_due_ns = max(
                        self._next_probe_due_ns, last_ok + self._rtt_timeout_ns
                    )
                if self._next_probe_due_ns and now >= self._next_probe_due_ns:
                    self._send_ping()
                    self._next_probe_due_ns = now + self._rtt_timeout_ns
                await asyncio.sleep(self._idle_check_s)
        except asyncio.CancelledError:
            return
