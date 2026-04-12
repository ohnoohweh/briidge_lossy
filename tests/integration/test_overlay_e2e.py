#!/usr/bin/env python3
import atexit
import argparse
import asyncio
import base64
import contextlib
import errno
import heapq
import hashlib
import inspect
import http.cookiejar
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
BRIDGE = ROOT / 'ObstacleBridge.py'
PAYLOAD_IN = b'\x01\x30'
PAYLOAD_OUT = b'\x02\x30'

from tests.fixtures.secure_link_cert import materialize_secure_link_cert_fixture_set
from tests.fixtures.localhost_tls import materialize_localhost_tls_fixture_set

_SECURE_LINK_CERT_FIXTURE_TMPDIR = tempfile.TemporaryDirectory()
atexit.register(_SECURE_LINK_CERT_FIXTURE_TMPDIR.cleanup)
SECURE_LINK_CERT_FIXTURES = materialize_secure_link_cert_fixture_set(Path(_SECURE_LINK_CERT_FIXTURE_TMPDIR.name))

_LOCALHOST_TLS_FIXTURE_TMPDIR = tempfile.TemporaryDirectory()
atexit.register(_LOCALHOST_TLS_FIXTURE_TMPDIR.cleanup)
LOCALHOST_TLS_FIXTURES = materialize_localhost_tls_fixture_set(Path(_LOCALHOST_TLS_FIXTURE_TMPDIR.name))

from obstacle_bridge.bridge import (
    CONTROL_MAX_MISSED,
    DataPacket,
    PROTO,
    PTYPE_CONTROL,
    PTYPE_DATA,
    SecureLinkPskSession,
)

log = logging.getLogger()

try:
    import fcntl
except Exception:  # pragma: no cover - non-POSIX fallback
    fcntl = None


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen
    log_path: Path
    admin_port: Optional[int] = None
    cmd: Optional[List[str]] = None
    env_extra: Dict[str, str] = field(default_factory=dict)

@dataclass
class Case:
    name: str
    bounce_proto: str
    bounce_bind: str
    bounce_port: int
    probe_proto: str
    probe_host: str
    probe_port: int
    probe_bind: Optional[str]
    bridge_server_args: List[str]
    bridge_client_args: List[str]
    settle_seconds: float = 2.0
    server_env: Dict[str, str] = field(default_factory=dict)
    client_env: Dict[str, str] = field(default_factory=dict)
    expected: bytes = PAYLOAD_OUT


@dataclass(frozen=True)
class MyudpDelayLossCase:
    name: str
    direction: str = 'client_to_server'
    payload: bytes = PAYLOAD_IN
    delay_ms: int = 300
    drop_client_to_server_data: tuple[int, ...] = ()
    drop_client_to_server_control: tuple[int, ...] = ()
    drop_server_to_client_data: tuple[int, ...] = ()
    drop_server_to_client_control: tuple[int, ...] = ()


@contextlib.contextmanager
def secure_link_test_lock():
    if fcntl is None:
        yield
        return
    lock_path = Path(tempfile.gettempdir()) / "quic_br_secure_link_integration.lock"
    with lock_path.open("w", encoding="utf-8") as fp:
        while True:
            try:
                fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
                break
            except OSError as exc:
                if exc.errno != errno.EINTR:
                    raise
        try:
            yield
        finally:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)


CASES: Dict[str, Case] = {
    'case01_udp_over_own_udp_ipv4': Case(
        name='case01_udp_over_own_udp_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--udp-bind', '0.0.0.0', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_ipv4.txt'],
        bridge_client_args=['--udp-bind', '0.0.0.0', '--udp-peer', '127.0.0.1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv4.txt'],
    ),
    'case02_udp_over_own_udp_overlay_ipv6_clients_ipv4': Case(
        name='case02_udp_over_own_udp_overlay_ipv6_clients_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--udp-bind', '::', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_ipv6.txt'],
        bridge_client_args=['--udp-bind', '::', '--udp-peer', '::1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case03_udp_over_own_udp_overlay_ipv6_clients_ipv6': Case(
        name='case03_udp_over_own_udp_overlay_ipv6_clients_ipv6',
        bounce_proto='udp', bounce_bind='::', bounce_port=26666,
        probe_proto='udp', probe_host='::1', probe_port=26667, probe_bind='::',
        bridge_server_args=['--udp-bind', '::', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_ipv6.txt'],
        bridge_client_args=['--udp-bind', '::', '--udp-peer', '::1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'udp,26667,::,udp,::1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case04_tcp_over_own_udp_clients_ipv4': Case(
        name='case04_tcp_over_own_udp_clients_ipv4',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=43128,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=43129, probe_bind='0.0.0.0',
        bridge_server_args=['--udp-bind', '0.0.0.0', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--udp-bind', '0.0.0.0', '--udp-peer', '127.0.0.1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'tcp,43129,0.0.0.0,tcp,127.0.0.1,43128', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client.txt'],
    ),
    'case05_tcp_over_own_udp_clients_ipv6': Case(
        name='case05_tcp_over_own_udp_clients_ipv6',
        bounce_proto='tcp', bounce_bind='::', bounce_port=43128,
        probe_proto='tcp', probe_host='::1', probe_port=43129, probe_bind='::',
        bridge_server_args=['--udp-bind', '0.0.0.0', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--udp-bind', '0.0.0.0', '--udp-peer', '127.0.0.1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'tcp,43129,::,tcp,::1,43128', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client.txt'],
    ),
    'case06_overlay_tcp_ipv4': Case(
        name='case06_overlay_tcp_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'tcp', '--tcp-bind', '0.0.0.0', '--tcp-own-port', '12345', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'tcp', '--tcp-peer', '127.0.0.1', '--tcp-peer-port', '12345', '--tcp-bind', '0.0.0.0', '--tcp-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case07_overlay_tcp_ipv6': Case(
        name='case07_overlay_tcp_ipv6',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'tcp', '--tcp-bind', '::', '--tcp-own-port', '12345', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'tcp', '--tcp-peer', '::1', '--tcp-peer-port', '12345', '--tcp-bind', '::', '--tcp-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case08_overlay_ws_ipv4': Case(
        name='case08_overlay_ws_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'ws', '--ws-bind', '0.0.0.0', '--ws-own-port', '54321', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'ws', '--ws-peer', '127.0.0.1', '--ws-peer-port', '54321', '--ws-bind', '0.0.0.0', '--ws-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
        server_env={'NO_PROXY': '127.0.0.1'},
        client_env={'NO_PROXY': '127.0.0.1'},
    ),
    'case09_overlay_ws_ipv6': Case(
        name='case09_overlay_ws_ipv6',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'ws', '--ws-bind', '::', '--ws-own-port', '54321', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'ws', '--ws-peer', '::1', '--ws-peer-port', '54321', '--ws-bind', '::', '--ws-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
        server_env={'NO_PROXY': '::1'},
        client_env={'NO_PROXY': '::1'},
    ),
    'case10_overlay_quic_ipv4': Case(
        name='case10_overlay_quic_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '0.0.0.0', '--quic-own-port', '4443', '--quic-cert', str(LOCALHOST_TLS_FIXTURES / 'cert.pem'), '--quic-key', str(LOCALHOST_TLS_FIXTURES / 'key.pem'), '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--quic-peer', '127.0.0.1', '--quic-peer-port', '4443', '--quic-bind', '0.0.0.0', '--quic-own-port', '0', '--quic-insecure', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case11_overlay_quic_ipv6': Case(
        name='case11_overlay_quic_ipv6',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '::', '--quic-own-port', '4443', '--quic-cert', str(LOCALHOST_TLS_FIXTURES / 'cert.pem'), '--quic-key', str(LOCALHOST_TLS_FIXTURES / 'key.pem'), '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--quic-peer', '::1', '--quic-peer-port', '4443', '--quic-bind', '::', '--quic-own-port', '0', '--quic-insecure', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case12_overlay_ws_ipv4_listener_two_clients': Case(
        name='case12_overlay_ws_ipv4_listener_two_clients',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'ws', '--ws-bind', '0.0.0.0', '--ws-own-port', '54331', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_two_clients.txt'],
        bridge_client_args=['--overlay-transport', 'ws', '--ws-peer', '127.0.0.1', '--ws-peer-port', '54331', '--ws-bind', '0.0.0.0', '--ws-own-port', '0', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_two_clients.txt'],
        server_env={'NO_PROXY': '127.0.0.1'},
        client_env={'NO_PROXY': '127.0.0.1'},
    ),
    'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels': Case(
        name='case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3138,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3139, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'ws', '--ws-bind', '0.0.0.0', '--ws-own-port', '54341', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_concurrent_tcp.txt'],
        bridge_client_args=[
            '--overlay-transport', 'ws', '--ws-peer', '127.0.0.1', '--ws-peer-port', '54341', '--ws-bind', '0.0.0.0', '--ws-own-port', '0',
            '--own-servers',
            'tcp,3139,0.0.0.0,tcp,127.0.0.1,3138',
            'udp,3140,0.0.0.0,udp,127.0.0.1,3141',
            'udp,3142,0.0.0.0,udp,127.0.0.1,3143',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_concurrent_tcp.txt',
        ],
        server_env={'NO_PROXY': '127.0.0.1'},
        client_env={'NO_PROXY': '127.0.0.1'},
    ),
    'case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp': Case(
        name='case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3248,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3249, probe_bind='0.0.0.0',
        bridge_server_args=[
            '--overlay-transport', 'ws,myudp',
            '--ws-bind', '0.0.0.0', '--ws-own-port', '54351',
            '--udp-bind', '0.0.0.0', '--udp-own-port', '14551',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', 'br_server_listener_ws_myudp.txt',
        ],
        bridge_client_args=['--overlay-transport', 'ws'],
        server_env={'NO_PROXY': '127.0.0.1'},
        client_env={'NO_PROXY': '127.0.0.1'},
    ),
    'case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp': Case(
        name='case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3348,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3349, probe_bind='0.0.0.0',
        bridge_server_args=[
            '--overlay-transport', 'myudp',
            '--udp-bind', '0.0.0.0', '--udp-own-port', '14561',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', 'br_server_listener_myudp_two_clients.txt',
        ],
        bridge_client_args=['--overlay-transport', 'myudp'],
        server_env={},
        client_env={},
    ),
    'case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp': Case(
        name='case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3448,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3449, probe_bind='0.0.0.0',
        bridge_server_args=[
            '--overlay-transport', 'tcp',
            '--tcp-bind', '0.0.0.0', '--tcp-own-port', '12355',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', 'br_server_listener_tcp_two_clients.txt',
        ],
        bridge_client_args=['--overlay-transport', 'tcp'],
        server_env={},
        client_env={},
    ),
    'case17_overlay_listener_quic_two_clients_concurrent_udp_tcp': Case(
        name='case17_overlay_listener_quic_two_clients_concurrent_udp_tcp',
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3548,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3549, probe_bind='0.0.0.0',
        bridge_server_args=[
            '--overlay-transport', 'quic',
            '--quic-bind', '0.0.0.0', '--quic-own-port', '14543',
            '--quic-cert', str(LOCALHOST_TLS_FIXTURES / 'cert.pem'), '--quic-key', str(LOCALHOST_TLS_FIXTURES / 'key.pem'),
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', 'br_server_listener_quic_two_clients.txt',
        ],
        bridge_client_args=['--overlay-transport', 'quic'],
        server_env={},
        client_env={},
    ),
}


def _replace_arg(args: List[str], option: str, value: str) -> List[str]:
    out = list(args)
    idx = out.index(option)
    out[idx + 1] = value
    return out


def _replace_last_arg(args: List[str], option: str, value: str) -> List[str]:
    out = list(args)
    for idx in range(len(out) - 2, -1, -1):
        if out[idx] == option:
            out[idx + 1] = value
            return out
    raise ValueError(f'missing option {option!r}')


def _append_args(args: List[str], extra: List[str]) -> List[str]:
    return list(args) + list(extra)


LOOPBACK_IPV4_SECOND_OCTET = 123
LOOPBACK_IPV6_MAPPED_SECOND_OCTET = 124
SECURE_LINK_LOOPBACK_KEY_BASE = 10000
SECURE_LINK_LOOPBACK_KEYS_PER_WORKER = 512
ADMIN_PORT_LOOPBACKS: Dict[int, Tuple[str, str]] = {}
ALLOCATED_CASE_PORT_OFFSETS: Dict[int, int] = {}
ALLOCATED_MYUDP_DELAY_LOSS_BASE_PORTS: Dict[int, int] = {}


def _loopback_host_octets(case_key: int, *, second_octet: int) -> Tuple[int, int, int, int]:
    slot = max(0, int(case_key))
    third_octet = (slot // 254) % 256
    fourth_octet = (slot % 254) + 1
    return 127, int(second_octet), third_octet, fourth_octet


def _loopback_ipv4_host(case_key: int, *, second_octet: int = LOOPBACK_IPV4_SECOND_OCTET) -> str:
    return '.'.join(str(part) for part in _loopback_host_octets(case_key, second_octet=second_octet))


def _loopback_ipv6_mapped_host(case_key: int) -> str:
    return f'::ffff:{_loopback_ipv4_host(case_key, second_octet=LOOPBACK_IPV6_MAPPED_SECOND_OCTET)}'


def _loopback_hosts_for_case(case_key: int) -> Tuple[str, str]:
    return _loopback_ipv4_host(case_key), _loopback_ipv6_mapped_host(case_key)


def _secure_link_loopback_key(secure_slot: int) -> int:
    return (
        SECURE_LINK_LOOPBACK_KEY_BASE
        + (_xdist_worker_index() * SECURE_LINK_LOOPBACK_KEYS_PER_WORKER)
        + int(secure_slot)
    )


def _rewrite_loopback_literal(value: Optional[str], *, ipv4_host: str, ipv6_host: str) -> Optional[str]:
    if value is None:
        return None
    rendered = str(value)
    stripped = rendered.strip()
    if stripped == '127.0.0.1':
        return ipv4_host
    return rendered


def _rewrite_bind_literal(value: Optional[str], *, ipv4_host: str, ipv6_host: str) -> Optional[str]:
    if value is None:
        return None
    rendered = str(value)
    stripped = rendered.strip()
    if stripped == '0.0.0.0':
        return ipv4_host
    if stripped in ('::', '::1'):
        return rendered
    return _rewrite_loopback_literal(rendered, ipv4_host=ipv4_host, ipv6_host=ipv6_host)


def _rewrite_loopback_service_specs(raw_specs: List[str], *, ipv4_host: str, ipv6_host: str) -> List[str]:
    rewritten: List[str] = []
    for raw in raw_specs:
        parts = [p.strip() for p in str(raw).split(',')]
        if len(parts) >= 6:
            parts[2] = str(_rewrite_bind_literal(parts[2], ipv4_host=ipv4_host, ipv6_host=ipv6_host))
            parts[4] = str(_rewrite_loopback_literal(parts[4], ipv4_host=ipv4_host, ipv6_host=ipv6_host))
            rewritten.append(','.join(parts))
            continue
        rewritten.append(str(raw))
    return rewritten


def _rewrite_loopback_args(args: List[str], *, ipv4_host: str, ipv6_host: str) -> List[str]:
    bind_options = {
        '--admin-web-bind',
        '--udp-bind',
        '--quic-bind',
        '--tcp-bind',
        '--ws-bind',
    }
    host_options = {
        '--peer',
        '--quic-peer',
        '--tcp-peer',
        '--udp-peer',
        '--ws-peer',
        '--ws-proxy-host',
    }
    service_options = {'--own-servers', '--remote-servers'}
    out: List[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg in bind_options and i + 1 < len(args):
            out.extend([
                arg,
                str(_rewrite_bind_literal(args[i + 1], ipv4_host=ipv4_host, ipv6_host=ipv6_host)),
            ])
            i += 2
            continue
        if arg in host_options and i + 1 < len(args):
            out.extend([
                arg,
                str(_rewrite_loopback_literal(args[i + 1], ipv4_host=ipv4_host, ipv6_host=ipv6_host)),
            ])
            i += 2
            continue
        if arg in service_options:
            out.append(arg)
            i += 1
            raw_specs: List[str] = []
            while i < len(args) and not str(args[i]).startswith('--'):
                raw_specs.append(str(args[i]))
                i += 1
            out.extend(_rewrite_loopback_service_specs(raw_specs, ipv4_host=ipv4_host, ipv6_host=ipv6_host))
            continue
        out.append(str(args[i]))
        i += 1
    return out


def _rewrite_loopback_env(env: Dict[str, str], *, ipv4_host: str, ipv6_host: str) -> Dict[str, str]:
    rewritten: Dict[str, str] = {}
    for key, value in dict(env).items():
        rendered = str(value)
        rendered = rendered.replace('127.0.0.1', ipv4_host)
        rewritten[str(key)] = rendered
    return rewritten


def _case_uses_localhost(case: Case) -> bool:
    values = list(case.bridge_server_args) + list(case.bridge_client_args)
    return any(str(value).strip().lower() == 'localhost' for value in values)


def _localhost_alias_name(case_index: int) -> str:
    return f'obhostalias{int(case_index)}'


def _case_prefers_ipv6_localhost(case: Case) -> bool:
    args = list(case.bridge_client_args)
    if '--peer-resolve-family' not in args:
        return False
    idx = args.index('--peer-resolve-family')
    return idx + 1 < len(args) and str(args[idx + 1]).strip().lower() == 'ipv6'


def _rewrite_localhost_alias_args(args: List[str], alias_name: str) -> List[str]:
    return [alias_name if str(value).strip().lower() == 'localhost' else str(value) for value in args]


def _append_csv_token(value: str, token: str) -> str:
    entries = [item.strip() for item in str(value).split(',') if item.strip()]
    if token not in entries:
        entries.insert(0, token)
    return ','.join(entries)


def _with_hostaliases(
    case: Case,
    log_dir: Path,
    case_index: int,
    server_cmd: List[str],
    client_cmd: List[str],
    server_env: Dict[str, str],
    client_env: Dict[str, str],
) -> tuple[List[str], List[str], Dict[str, str], Dict[str, str]]:
    if not _case_uses_localhost(case) or _case_prefers_ipv6_localhost(case):
        return server_cmd, client_cmd, server_env, client_env

    alias_name = _localhost_alias_name(case_index)
    alias_target = _loopback_ipv4_host(case_index)
    alias_path = log_dir / f'{case.name}_hostaliases.txt'
    alias_path.write_text(f'{alias_name} {alias_target}\n', encoding='utf-8')

    server_cmd = _rewrite_localhost_alias_args(server_cmd, alias_name)
    client_cmd = _rewrite_localhost_alias_args(client_cmd, alias_name)

    server_env = dict(server_env)
    client_env = dict(client_env)
    server_env['HOSTALIASES'] = str(alias_path)
    client_env['HOSTALIASES'] = str(alias_path)
    if 'NO_PROXY' in server_env:
        server_env['NO_PROXY'] = _append_csv_token(server_env['NO_PROXY'], alias_name)
    if 'no_proxy' in server_env:
        server_env['no_proxy'] = _append_csv_token(server_env['no_proxy'], alias_name)
    if 'NO_PROXY' in client_env:
        client_env['NO_PROXY'] = _append_csv_token(client_env['NO_PROXY'], alias_name)
    if 'no_proxy' in client_env:
        client_env['no_proxy'] = _append_csv_token(client_env['no_proxy'], alias_name)
    return server_cmd, client_cmd, server_env, client_env


def _materialize_case_loopback_hosts(case: Case, case_key: int) -> Case:
    ipv4_host, ipv6_host = _loopback_hosts_for_case(case_key)
    return replace(
        case,
        bounce_bind=str(_rewrite_bind_literal(case.bounce_bind, ipv4_host=ipv4_host, ipv6_host=ipv6_host)),
        probe_host=str(_rewrite_loopback_literal(case.probe_host, ipv4_host=ipv4_host, ipv6_host=ipv6_host)),
        probe_bind=_rewrite_bind_literal(case.probe_bind, ipv4_host=ipv4_host, ipv6_host=ipv6_host),
        bridge_server_args=_rewrite_loopback_args(case.bridge_server_args, ipv4_host=ipv4_host, ipv6_host=ipv6_host),
        bridge_client_args=_rewrite_loopback_args(case.bridge_client_args, ipv4_host=ipv4_host, ipv6_host=ipv6_host),
        server_env=_rewrite_loopback_env(case.server_env, ipv4_host=ipv4_host, ipv6_host=ipv6_host),
        client_env=_rewrite_loopback_env(case.client_env, ipv4_host=ipv4_host, ipv6_host=ipv6_host),
    )


def _xdist_worker_index() -> int:
    worker = str(os.environ.get('PYTEST_XDIST_WORKER') or '').strip()
    if worker.startswith('gw'):
        suffix = worker[2:]
        if suffix.isdigit():
            return int(suffix)
    return 0


def _xdist_worker_count() -> int:
    raw = str(os.environ.get('PYTEST_XDIST_WORKER_COUNT') or '').strip()
    if raw.isdigit():
        return max(1, int(raw))
    return max(1, _xdist_worker_index() + 1)


def _shift_port(port: int, offset: int) -> int:
    if int(port) == 0:
        return 0
    shifted = int(port) + int(offset)
    if shifted >= 65535:
        raise ValueError(f'port overflow while shifting {port} by {offset}')
    return shifted


def _case_port_offset(case_index: int, stride: int = 64, highest_static_port: int = 55000) -> int:
    worker_index = _xdist_worker_index()
    worker_count = _xdist_worker_count()
    max_offset = SERVICE_PORT_CEILING - int(highest_static_port) - 1
    if max_offset < stride:
        raise ValueError(
            f'port allocation window too small: highest_static_port={highest_static_port} stride={stride}'
        )
    per_worker_budget = max(1, max_offset // worker_count)
    if per_worker_budget < stride:
        raise ValueError(
            f'too many xdist workers for safe port allocation: '
            f'workers={worker_count} highest_static_port={highest_static_port} stride={stride}'
        )
    case_slots = max(1, per_worker_budget // stride)
    case_slot = (int(case_index) % case_slots) * stride
    return worker_index * per_worker_budget + case_slot


def _case_port_offset_candidates(case_index: int, stride: int = 64, highest_static_port: int = 55000) -> List[int]:
    worker_index = _xdist_worker_index()
    worker_count = _xdist_worker_count()
    max_offset = SERVICE_PORT_CEILING - int(highest_static_port) - 1
    if max_offset < stride:
        raise ValueError(
            f'port allocation window too small: highest_static_port={highest_static_port} stride={stride}'
        )
    per_worker_budget = max(1, max_offset // worker_count)
    if per_worker_budget < stride:
        raise ValueError(
            f'too many xdist workers for safe port allocation: '
            f'workers={worker_count} highest_static_port={highest_static_port} stride={stride}'
        )
    case_slots = max(1, per_worker_budget // stride)
    requested_slot = int(case_index) % case_slots
    base_offset = worker_index * per_worker_budget
    candidates: List[int] = []
    for slot_index in range(requested_slot, case_slots):
        candidates.append(base_offset + (slot_index * stride))
    for slot_index in range(0, requested_slot):
        candidates.append(base_offset + (slot_index * stride))
    return candidates


def _shift_service_specs(raw_specs: List[str], offset: int) -> List[str]:
    shifted: List[str] = []
    for raw in raw_specs:
        parts = [p.strip() for p in raw.split(',')]
        if len(parts) < 6:
            shifted.append(raw)
            continue
        parts[1] = str(_shift_port(int(parts[1]), offset))
        parts[5] = str(_shift_port(int(parts[5]), offset))
        shifted.append(','.join(parts))
    return shifted


def _shift_port_options(args: List[str], offset: int) -> List[str]:
    port_options = {
        '--udp-own-port',
        '--udp-peer-port',
        '--tcp-own-port',
        '--tcp-peer-port',
        '--ws-own-port',
        '--ws-peer-port',
        '--quic-own-port',
        '--quic-peer-port',
        '--admin-web-port',
    }
    service_options = {'--own-servers', '--remote-servers'}
    out: List[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in port_options and i + 1 < len(args):
            out.extend([arg, str(_shift_port(int(args[i + 1]), offset))])
            i += 2
            continue
        if arg in service_options:
            out.append(arg)
            i += 1
            specs: List[str] = []
            while i < len(args) and not str(args[i]).startswith('--'):
                specs.append(str(args[i]))
                i += 1
            out.extend(_shift_service_specs(specs, offset))
            continue
        out.append(arg)
        i += 1
    return out


def materialize_case_ports(case: Case, case_index: int) -> Case:
    case = _materialize_case_loopback_hosts(case, case_index)
    cached_offset = ALLOCATED_CASE_PORT_OFFSETS.get(int(case_index))
    if cached_offset is not None:
        if cached_offset == 0:
            return case
        return replace(
            case,
            bounce_port=_shift_port(case.bounce_port, cached_offset),
            probe_port=_shift_port(case.probe_port, cached_offset),
            bridge_server_args=_shift_port_options(case.bridge_server_args, cached_offset),
            bridge_client_args=_shift_port_options(case.bridge_client_args, cached_offset),
        )
    highest = _max_case_static_port(case)
    selected_offset: Optional[int] = None
    for candidate_offset in _case_port_offset_candidates(case_index, highest_static_port=highest):
        candidate = replace(
            case,
            bounce_port=_shift_port(case.bounce_port, candidate_offset),
            probe_port=_shift_port(case.probe_port, candidate_offset),
            bridge_server_args=_shift_port_options(case.bridge_server_args, candidate_offset),
            bridge_client_args=_shift_port_options(case.bridge_client_args, candidate_offset),
        )
        if all(_can_bind_local_endpoint(proto, host, port) for proto, host, port in _iter_case_local_bind_endpoints(candidate)):
            selected_offset = candidate_offset
            break
    if selected_offset is None:
        raise RuntimeError(f'no generic integration port slot available: case={case.name} case_index={case_index}')
    offset = selected_offset
    ALLOCATED_CASE_PORT_OFFSETS[int(case_index)] = offset
    if offset == 0:
        return case
    return replace(
        case,
        bounce_port=_shift_port(case.bounce_port, offset),
        probe_port=_shift_port(case.probe_port, offset),
        bridge_server_args=_shift_port_options(case.bridge_server_args, offset),
        bridge_client_args=_shift_port_options(case.bridge_client_args, offset),
    )


def _max_port_in_shiftable_args(args: List[str]) -> int:
    port_options = {
        '--udp-own-port',
        '--udp-peer-port',
        '--tcp-own-port',
        '--tcp-peer-port',
        '--ws-own-port',
        '--ws-peer-port',
        '--quic-own-port',
        '--quic-peer-port',
        '--admin-web-port',
    }
    service_options = {'--own-servers', '--remote-servers'}
    highest = 0
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in port_options and i + 1 < len(args):
            with contextlib.suppress(Exception):
                highest = max(highest, int(args[i + 1]))
            i += 2
            continue
        if arg in service_options:
            i += 1
            while i < len(args) and not str(args[i]).startswith('--'):
                parts = [p.strip() for p in str(args[i]).split(',')]
                if len(parts) >= 6:
                    with contextlib.suppress(Exception):
                        highest = max(highest, int(parts[1]), int(parts[5]))
                i += 1
            continue
        i += 1
    return highest


def _max_case_static_port(case: Case) -> int:
    return max(
        int(case.bounce_port),
        int(case.probe_port),
        _max_port_in_shiftable_args(case.bridge_server_args),
        _max_port_in_shiftable_args(case.bridge_client_args),
    )


def _bind_proto_socket_kind(proto: str) -> int:
    rendered = str(proto).strip().lower()
    if rendered in ('udp', 'myudp', 'quic'):
        return socket.SOCK_DGRAM
    return socket.SOCK_STREAM


def _can_bind_local_endpoint(proto: str, host: str, port: int) -> bool:
    if int(port) <= 0:
        return True
    family = socket.AF_INET6 if ':' in str(host) else socket.AF_INET
    sock_type = _bind_proto_socket_kind(proto)
    try:
        with contextlib.closing(socket.socket(family, sock_type)) as s:
            if sock_type == socket.SOCK_STREAM:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((str(host), int(port)))
        return True
    except OSError:
        return False


def _iter_case_local_bind_endpoints(case: Case) -> List[Tuple[str, str, int]]:
    endpoints: List[Tuple[str, str, int]] = [
        (str(case.bounce_proto), str(case.bounce_bind), int(case.bounce_port)),
    ]

    def collect(args: List[str]) -> None:
        bind_map = {
            '--udp-own-port': ('udp', '--udp-bind'),
            '--tcp-own-port': ('tcp', '--tcp-bind'),
            '--ws-own-port': ('ws', '--ws-bind'),
            '--quic-own-port': ('quic', '--quic-bind'),
        }
        bind_hosts = {
            '--udp-bind': '0.0.0.0',
            '--tcp-bind': '0.0.0.0',
            '--ws-bind': '0.0.0.0',
            '--quic-bind': '0.0.0.0',
        }
        service_options = {'--own-servers', '--remote-servers'}
        i = 0
        while i < len(args):
            arg = str(args[i])
            if arg in bind_hosts and i + 1 < len(args):
                bind_hosts[arg] = str(args[i + 1])
                i += 2
                continue
            if arg in bind_map and i + 1 < len(args):
                proto, bind_opt = bind_map[arg]
                port = int(args[i + 1])
                if port > 0:
                    endpoints.append((proto, str(bind_hosts[bind_opt]), port))
                i += 2
                continue
            if arg in service_options:
                i += 1
                while i < len(args) and not str(args[i]).startswith('--'):
                    parts = [p.strip() for p in str(args[i]).split(',')]
                    if len(parts) >= 6:
                        with contextlib.suppress(Exception):
                            local_proto = str(parts[0])
                            local_port = int(parts[1])
                            local_bind = str(parts[2])
                            if local_port > 0:
                                endpoints.append((local_proto, local_bind, local_port))
                    i += 1
                continue
            i += 1

    collect(case.bridge_server_args)
    collect(case.bridge_client_args)
    return endpoints


def _secure_link_slot_is_available(case: Case, slot: int) -> bool:
    candidate = _materialize_case_loopback_hosts(case, _secure_link_loopback_key(slot))
    offset = SECURE_LINK_PORT_OFFSET_BASE + (int(slot) * SECURE_LINK_PORT_STRIDE)
    candidate = replace(
        candidate,
        bounce_port=_shift_port(candidate.bounce_port, offset),
        probe_port=_shift_port(candidate.probe_port, offset),
        bridge_server_args=_shift_port_options(candidate.bridge_server_args, offset),
        bridge_client_args=_shift_port_options(candidate.bridge_client_args, offset),
    )
    return all(_can_bind_local_endpoint(proto, host, port) for proto, host, port in _iter_case_local_bind_endpoints(candidate))


def materialize_secure_link_case_ports(case: Case, secure_slot: int) -> Case:
    highest = _max_case_static_port(case)
    max_slots = _secure_link_port_slots_per_worker(highest)
    slot = int(secure_slot)
    if slot < 0 or slot >= max_slots:
        raise ValueError(
            f'secure-link slot out of range: slot={slot} max_slots={max_slots} '
            f'highest={highest} base={SECURE_LINK_PORT_OFFSET_BASE}'
        )
    selected_slot: Optional[int] = None
    for candidate_slot in range(slot, max_slots):
        if _secure_link_slot_is_available(case, candidate_slot):
            selected_slot = candidate_slot
            break
    if selected_slot is None:
        raise RuntimeError(
            f'no secure-link slot available: requested_slot={slot} max_slots={max_slots} highest={highest}'
        )
    case = _materialize_case_loopback_hosts(case, _secure_link_loopback_key(selected_slot))
    offset = SECURE_LINK_PORT_OFFSET_BASE + (selected_slot * SECURE_LINK_PORT_STRIDE)
    if highest + offset >= SERVICE_PORT_CEILING:
        raise ValueError(
            f'secure-link test port offset out of range: highest={highest} offset={offset} ceiling={SERVICE_PORT_CEILING}'
        )
    return replace(
        case,
        bounce_port=_shift_port(case.bounce_port, offset),
        probe_port=_shift_port(case.probe_port, offset),
        bridge_server_args=_shift_port_options(case.bridge_server_args, offset),
        bridge_client_args=_shift_port_options(case.bridge_client_args, offset),
    )


def _replace_own_servers_local_port(args: List[str], local_port: int) -> List[str]:
    out = list(args)
    if '--own-servers' not in out:
        raise ValueError('missing --own-servers option')
    idx = out.index('--own-servers')
    if idx + 1 >= len(out):
        raise ValueError('missing --own-servers value')
    raw = out[idx + 1]
    parts = [p.strip() for p in raw.split(',')]
    if len(parts) < 6:
        raise ValueError(f'unsupported --own-servers format: {raw!r}')
    parts[1] = str(local_port)
    out[idx + 1] = ','.join(parts)
    return out


def _replace_option_values(args: List[str], option: str, values: List[str]) -> List[str]:
    out: List[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg == option:
            i += 1
            while i < len(args) and not str(args[i]).startswith('--'):
                i += 1
            continue
        out.append(arg)
        i += 1
    if values:
        out.extend([str(option), *[str(v) for v in values]])
    return out


def _with_localhost_peer(case: Case, name: str, bind_host: str, resolve_family: str) -> Case:
    transport = 'myudp'
    if '--overlay-transport' in case.bridge_client_args:
        t_idx = case.bridge_client_args.index('--overlay-transport')
        if t_idx + 1 < len(case.bridge_client_args):
            transport = str(case.bridge_client_args[t_idx + 1]).strip().lower()

    bind_opt = '--udp-bind'
    peer_opt = '--udp-peer'
    if transport in ('tcp', 'quic', 'ws'):
        bind_opt = f'--{transport}-bind'
        peer_opt = f'--{transport}-peer'

    server_args = _replace_arg(case.bridge_server_args, bind_opt, bind_host)
    client_args = _replace_arg(case.bridge_client_args, peer_opt, 'localhost')
    client_args = _replace_arg(client_args, bind_opt, bind_host)
    client_args = _append_args(client_args, ['--peer-resolve-family', resolve_family])

    server_env = dict(case.server_env)
    client_env = dict(case.client_env)
    if '--overlay-transport' in case.bridge_client_args and case.bridge_client_args[case.bridge_client_args.index('--overlay-transport') + 1] == 'ws':
        server_env['NO_PROXY'] = 'localhost,127.0.0.1'
        client_env['NO_PROXY'] = 'localhost,127.0.0.1'

    return replace(
        case,
        name=name,
        bridge_server_args=server_args,
        bridge_client_args=client_args,
        server_env=server_env,
        client_env=client_env,
    )


BASE_CASES = [
    'case01_udp_over_own_udp_ipv4',
    'case02_udp_over_own_udp_overlay_ipv6_clients_ipv4',
    'case03_udp_over_own_udp_overlay_ipv6_clients_ipv6',
    'case04_tcp_over_own_udp_clients_ipv4',
    'case05_tcp_over_own_udp_clients_ipv6',
    'case06_overlay_tcp_ipv4',
    'case07_overlay_tcp_ipv6',
    'case08_overlay_ws_ipv4',
    'case09_overlay_ws_ipv6',
    'case10_overlay_quic_ipv4',
    'case11_overlay_quic_ipv6',
]

LOCALHOST_CASES = [
    'case01_udp_over_own_udp_localhost_ipv4',
    'case01_udp_over_own_udp_localhost_ipv6',
    'case06_overlay_tcp_localhost_ipv4',
    'case06_overlay_tcp_localhost_ipv6',
    'case08_overlay_ws_localhost_ipv4',
    'case08_overlay_ws_localhost_ipv6',
    'case10_overlay_quic_localhost_ipv4',
    'case10_overlay_quic_localhost_ipv6',
]

LISTENER_CASES = [
    'case12_overlay_ws_ipv4_listener_two_clients',
]

CONCURRENT_TCP_CHANNEL_CASES = [
    'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels',
    'case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp',
    'case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp',
    'case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp',
    'case17_overlay_listener_quic_two_clients_concurrent_udp_tcp',
]

MYUDP_DELAY_LOSS_CASES: Dict[str, MyudpDelayLossCase] = {
    'tc0_idle_connectivity': MyudpDelayLossCase(name='tc0_idle_connectivity'),
    'tc1_small_client_to_server': MyudpDelayLossCase(name='tc1_small_client_to_server', direction='client_to_server', payload=b'Hello from A1 -> via A2 -> to B2 (expect at B1)'),
    'tc1a_drop_first_data_client_to_server': MyudpDelayLossCase(
        name='tc1a_drop_first_data_client_to_server',
        direction='client_to_server',
        payload=b'Hello from A1 -> via A2 -> to B2 (expect at B1)',
        drop_client_to_server_data=(1,),
    ),
    'tc1b_drop_first_control_server_to_client': MyudpDelayLossCase(
        name='tc1b_drop_first_control_server_to_client',
        direction='client_to_server',
        payload=b'Hello from A1 -> via A2 -> to B2 (expect at B1)',
        drop_server_to_client_control=(1,),
    ),
    'tc2_small_server_to_client': MyudpDelayLossCase(name='tc2_small_server_to_client', direction='server_to_client', payload=b'Hello from B2 -> to B1 (loop) -> over to A1'),
    'tc3_2000_client_to_server': MyudpDelayLossCase(name='tc3_2000_client_to_server', direction='client_to_server', payload=b'A' * 2000),
    'tc4_2000_server_to_client': MyudpDelayLossCase(name='tc4_2000_server_to_client', direction='server_to_client', payload=b'B' * 2000),
    'tc5_concurrent_bidir': MyudpDelayLossCase(name='tc5_concurrent_bidir'),
    'tc6_20k_drop_2_3': MyudpDelayLossCase(name='tc6_20k_drop_2_3', direction='client_to_server', payload=b'X' * (20 * 1024), drop_client_to_server_data=(2, 3)),
    'tc7_20k_drop_2_3_20': MyudpDelayLossCase(name='tc7_20k_drop_2_3_20', direction='client_to_server', payload=b'X' * (20 * 1024), drop_client_to_server_data=(2, 3, 20)),
    'tc8_20k_drop_2_3_21': MyudpDelayLossCase(name='tc8_20k_drop_2_3_21', direction='client_to_server', payload=b'X' * (20 * 1024), drop_client_to_server_data=(2, 3, 21)),
    'tc9_20k_drop_2_3_20_21': MyudpDelayLossCase(name='tc9_20k_drop_2_3_20_21', direction='client_to_server', payload=b'X' * (20 * 1024), drop_client_to_server_data=(2, 3, 20, 21)),
    'tc10_full_missed_list_pressure': MyudpDelayLossCase(
        name='tc10_full_missed_list_pressure',
        direction='client_to_server',
        drop_client_to_server_data=tuple(range(1, CONTROL_MAX_MISSED + 3)),
    ),
}

CASES.update({
    'case01_udp_over_own_udp_localhost_ipv4': _with_localhost_peer(
        CASES['case01_udp_over_own_udp_ipv4'],
        'case01_udp_over_own_udp_localhost_ipv4',
        '0.0.0.0',
        'ipv4',
    ),
    'case01_udp_over_own_udp_localhost_ipv6': _with_localhost_peer(
        CASES['case01_udp_over_own_udp_ipv4'],
        'case01_udp_over_own_udp_localhost_ipv6',
        '::',
        'ipv6',
    ),
    'case06_overlay_tcp_localhost_ipv4': _with_localhost_peer(
        CASES['case06_overlay_tcp_ipv4'],
        'case06_overlay_tcp_localhost_ipv4',
        '0.0.0.0',
        'ipv4',
    ),
    'case06_overlay_tcp_localhost_ipv6': _with_localhost_peer(
        CASES['case06_overlay_tcp_ipv4'],
        'case06_overlay_tcp_localhost_ipv6',
        '::',
        'ipv6',
    ),
    'case08_overlay_ws_localhost_ipv4': _with_localhost_peer(
        CASES['case08_overlay_ws_ipv4'],
        'case08_overlay_ws_localhost_ipv4',
        '0.0.0.0',
        'ipv4',
    ),
    'case08_overlay_ws_localhost_ipv6': _with_localhost_peer(
        CASES['case08_overlay_ws_ipv4'],
        'case08_overlay_ws_localhost_ipv6',
        '::',
        'ipv6',
    ),
    'case10_overlay_quic_localhost_ipv4': _with_localhost_peer(
        CASES['case10_overlay_quic_ipv4'],
        'case10_overlay_quic_localhost_ipv4',
        '0.0.0.0',
        'ipv4',
    ),
    'case10_overlay_quic_localhost_ipv6': _with_localhost_peer(
        CASES['case10_overlay_quic_ipv4'],
        'case10_overlay_quic_localhost_ipv6',
        '::',
        'ipv6',
    ),
})

BASIC_CASES = list(BASE_CASES)
RECONNECT_CASES = list(BASE_CASES) + list(LOCALHOST_CASES)
ALL_CASES = list(CASES.keys())

DEFAULT_CASES = {
    'basic': BASIC_CASES,
    'reconnect': RECONNECT_CASES,
    'listener-two-clients': LISTENER_CASES,
    'concurrent-tcp-channels': CONCURRENT_TCP_CHANNEL_CASES,
}

CASE_INDEX_BASE_BASIC = 0
CASE_INDEX_BASE_RECONNECT = 100
CASE_INDEX_BASE_LISTENER = 200
CASE_INDEX_BASE_CONCURRENT = 300
CASE_INDEX_BASE_RESTART = 400
CASE_INDEX_BASE_MYUDP_DELAY_LOSS = 500
CASE_INDEX_BASE_MYUDP_STALE = 580

SERVICE_PORT_CEILING = 61000
ADMIN_PORT_BASE = 61000
ADMIN_PORTS_PER_WORKER = 256
ADMIN_PORTS_PER_CASE = 4
SECURE_LINK_ADMIN_BASE = 62000
SECURE_LINK_PORT_OFFSET_BASE = 6000
SECURE_LINK_PORT_STRIDE = 64


def _secure_link_port_slots_per_worker(highest_static_port: int) -> int:
    max_offset = SERVICE_PORT_CEILING - int(highest_static_port) - 1
    remaining = max_offset - SECURE_LINK_PORT_OFFSET_BASE
    if remaining < 0:
        raise ValueError(
            f'secure-link test port base out of range: highest={highest_static_port} '
            f'base={SECURE_LINK_PORT_OFFSET_BASE} ceiling={SERVICE_PORT_CEILING}'
        )
    return max(1, (remaining // SECURE_LINK_PORT_STRIDE) + 1)

EXACT_BYTES_CASES = {
    'case01_udp_over_own_udp_ipv4',
    'case04_tcp_over_own_udp_clients_ipv4',
}


def _validate_case_catalog() -> None:
    missing_from_cases = [name for name in ALL_CASES if name not in CASES]
    if missing_from_cases:
        raise RuntimeError(f'Case catalog mismatch; missing case specs: {missing_from_cases}')

    required_by_cases = set(BASE_CASES) | set(LOCALHOST_CASES) | set(LISTENER_CASES) | set(CONCURRENT_TCP_CHANNEL_CASES)
    missing_choice_names = sorted(name for name in required_by_cases if name not in ALL_CASES)
    if missing_choice_names:
        raise RuntimeError(f'--cases choices missing required names: {missing_choice_names}')


_validate_case_catalog()


def response_payload(data: bytes) -> bytes:
    if not data:
        return data
    return bytes([0x02]) + data[1:]


class BounceBackServer:
    def __init__(self, name: str, proto: str, bind_host: str, port: int, log_path: Path):
        self.name = name
        self.proto = proto
        self.bind_host = bind_host
        self.port = port
        self.log_path = log_path
        self.family = socket.AF_INET6 if ':' in bind_host else socket.AF_INET
        self.thread: Optional[threading.Thread] = None
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()
        self.sock: Optional[socket.socket] = None

    def _log(self, msg: str) -> None:
        with self.log_path.open('a', encoding='utf-8', errors='replace') as fp:
            fp.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {msg}\n')
    

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(5.0):
            raise RuntimeError(f'BounceBackServer {self.name} failed to start')

    def stop(self) -> None:
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        if self.thread:
            self.thread.join(timeout=2.0)

    def _run(self) -> None:
        if self.proto == 'udp':
            self._run_udp()
        elif self.proto == 'tcp':
            self._run_tcp()
        else:
            raise RuntimeError(f'Unsupported bounce proto: {self.proto}')

    def _run_udp(self) -> None:
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_host, self.port))
        self.sock.settimeout(0.5)
        self._log(f'UDP bounce-back listening on {self.bind_host}:{self.port}')
        self.ready_event.set()
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            reply = response_payload(data)
            self._log(f'RX {data.hex(" ")} from {addr!r} -> TX {reply.hex(" ")}')
            try:
                self.sock.sendto(reply, addr)
            except OSError as e:
                self._log(f'sendto failed: {e!r}')

    def _run_tcp(self) -> None:
        self.sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_host, self.port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)
        self._log(f'TCP bounce-back listening on {self.bind_host}:{self.port}')
        self.ready_event.set()
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_tcp_conn, args=(conn, addr), daemon=True)
            t.start()

    def _handle_tcp_conn(self, conn: socket.socket, addr) -> None:
        with conn:
            conn.settimeout(0.5)
            self._log(f'TCP accepted {addr!r}')
            while not self.stop_event.is_set():
                try:
                    data = conn.recv(65535)
                except socket.timeout:
                    continue
                except OSError as e:
                    self._log(f'TCP recv failed from {addr!r}: {e!r}')
                    return
                if not data:
                    return
                reply = response_payload(data)
                self._log(f'RX {data.hex(" ")} from {addr!r} -> TX {reply.hex(" ")}')
                try:
                    conn.sendall(reply)
                except OSError as e:
                    self._log(f'TCP send failed to {addr!r}: {e!r}')
                    return


class UdpDelayLossProxy:
    def __init__(
        self,
        *,
        name: str,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        forward_bind_host: str,
        forward_bind_port: int,
        delay_ms: int,
        log_path: Path,
        drop_client_to_server_data: tuple[int, ...] = (),
        drop_client_to_server_control: tuple[int, ...] = (),
        drop_server_to_client_data: tuple[int, ...] = (),
        drop_server_to_client_control: tuple[int, ...] = (),
        delay_server_to_client_secure_link_types_ms: Optional[Dict[int, int]] = None,
    ):
        self.name = name
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self.forward_bind_host = forward_bind_host
        self.forward_bind_port = int(forward_bind_port)
        self.delay_ms = max(0, int(delay_ms))
        self.log_path = log_path
        self.listen_sock: Optional[socket.socket] = None
        self.upstream_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()
        self.client_addr: Optional[tuple[str, int]] = None
        self._pending: list[tuple[float, int, socket.socket, tuple[str, int], bytes]] = []
        self._pending_seq = 0
        self._drop_rules = {
            'client_to_server': {
                'data': set(drop_client_to_server_data),
                'control': set(drop_client_to_server_control),
            },
            'server_to_client': {
                'data': set(drop_server_to_client_data),
                'control': set(drop_server_to_client_control),
            },
        }
        self._counters = {
            'client_to_server': {'data': 0, 'control': 0},
            'server_to_client': {'data': 0, 'control': 0},
        }
        self._secure_link_delay_rules_ms = {
            'server_to_client': {
                int(sl_type): max(0, int(delay_override_ms))
                for sl_type, delay_override_ms in dict(delay_server_to_client_secure_link_types_ms or {}).items()
            },
        }

    def _log(self, msg: str) -> None:
        with self.log_path.open('a', encoding='utf-8', errors='replace') as fp:
            fp.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {msg}\n')

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(5.0):
            raise RuntimeError(f'UDP proxy {self.name} failed to start')

    def stop(self) -> None:
        self.stop_event.set()
        for sock in (self.listen_sock, self.upstream_sock):
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def _classify(self, data: bytes) -> Optional[str]:
        parsed = PROTO.parse_frame_with_times(data)
        if not parsed:
            return None
        ptype, payload, _tx_ns, _echo_ns = parsed
        if ptype == PTYPE_DATA:
            payload_bytes = bytes(payload)
            ctr = struct.unpack('>H', payload_bytes[:2])[0] if len(payload_bytes) >= 2 else 0
            if ctr == 0:
                return None
            return 'data'
        if ptype == PTYPE_CONTROL:
            return 'control'
        return None

    def _should_drop(self, direction: str, data: bytes) -> tuple[bool, Optional[str], Optional[int]]:
        frame_kind = self._classify(data)
        if frame_kind is None:
            return False, None, None
        self._counters[direction][frame_kind] += 1
        frame_idx = self._counters[direction][frame_kind]
        should_drop = frame_idx in self._drop_rules[direction][frame_kind]
        return should_drop, frame_kind, frame_idx

    def _secure_link_type(self, data: bytes) -> Optional[int]:
        pkt = DataPacket.parse_full(data)
        if pkt is None or int(pkt.frame_type) != 0x01:
            return None
        parsed = SecureLinkPskSession._parse_frame(pkt.data)
        if parsed is None:
            return None
        sl_type, _session_id, _counter, _body = parsed
        return int(sl_type)

    def _extra_delay_ms(self, direction: str, data: bytes) -> int:
        rules = self._secure_link_delay_rules_ms.get(direction) or {}
        if not rules:
            return 0
        sl_type = self._secure_link_type(data)
        if sl_type is None:
            return 0
        return int(rules.get(int(sl_type), 0) or 0)

    def _schedule(self, sock: socket.socket, dest: tuple[str, int], data: bytes, *, direction: str) -> None:
        total_delay_ms = max(0, int(self.delay_ms) + int(self._extra_delay_ms(direction, data) or 0))
        if total_delay_ms <= 0:
            sock.sendto(data, dest)
            return
        self._pending_seq += 1
        due = time.monotonic() + (total_delay_ms / 1000.0)
        heapq.heappush(self._pending, (due, self._pending_seq, sock, dest, data))

    def _flush_pending(self) -> None:
        now = time.monotonic()
        while self._pending and self._pending[0][0] <= now:
            _due, _seq, sock, dest, data = heapq.heappop(self._pending)
            try:
                sock.sendto(data, dest)
            except OSError as e:
                self._log(f'sendto failed dest={dest!r}: {e!r}')

    def _run(self) -> None:
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.bind((self.listen_host, self.listen_port))
        self.listen_sock.setblocking(False)
        self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream_sock.bind((self.forward_bind_host, self.forward_bind_port))
        self.upstream_sock.setblocking(False)
        self._log(
            f'proxy listening {self.listen_host}:{self.listen_port} '
            f'-> {self.upstream_host}:{self.upstream_port} via {self.forward_bind_host}:{self.forward_bind_port} '
            f'delay_ms={self.delay_ms}'
        )
        self.ready_event.set()
        while not self.stop_event.is_set():
            self._flush_pending()
            timeout = 0.05
            if self._pending:
                timeout = max(0.0, min(timeout, self._pending[0][0] - time.monotonic()))
            try:
                readable, _, _ = select.select([self.listen_sock, self.upstream_sock], [], [], timeout)
            except (OSError, ValueError):
                break
            for sock in readable:
                try:
                    data, addr = sock.recvfrom(65535)
                except BlockingIOError:
                    continue
                except OSError:
                    continue
                if sock is self.listen_sock:
                    self.client_addr = (str(addr[0]), int(addr[1]))
                    should_drop, frame_kind, frame_idx = self._should_drop('client_to_server', data)
                    if should_drop:
                        self._log(f'drop c2s kind={frame_kind} idx={frame_idx} from={addr!r}')
                        continue
                    self._schedule(
                        self.upstream_sock,
                        (self.upstream_host, self.upstream_port),
                        data,
                        direction='client_to_server',
                    )
                else:
                    if self.client_addr is None:
                        self._log(f'ignore s2c packet before client discovery from={addr!r}')
                        continue
                    should_drop, frame_kind, frame_idx = self._should_drop('server_to_client', data)
                    if should_drop:
                        self._log(f'drop s2c kind={frame_kind} idx={frame_idx} from={addr!r}')
                        continue
                    self._schedule(self.listen_sock, self.client_addr, data, direction='server_to_client')
        self._flush_pending()


class HttpConnectProxy:
    def __init__(
        self,
        *,
        name: str,
        listen_host: str,
        listen_port: int,
        log_path: Path,
        require_negotiate: bool = False,
    ):
        self.name = name
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.log_path = log_path
        self.require_negotiate = bool(require_negotiate)
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self.connect_requests: list[str] = []
        self.proxy_authorizations: list[str] = []
        self.first_tunnel_request_line: Optional[str] = None

    def _log(self, msg: str) -> None:
        with self.log_path.open('a', encoding='utf-8', errors='replace') as fp:
            fp.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {msg}\n')

    @property
    def connect_count(self) -> int:
        with self._lock:
            return len(self.connect_requests)

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(5.0):
            raise RuntimeError(f'HTTP proxy {self.name} failed to start')

    def stop(self) -> None:
        self.stop_event.set()
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def _recv_headers(self, conn: socket.socket) -> bytes:
        buf = b''
        while b'\r\n\r\n' not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf

    def _record_connect(self, authority: str) -> None:
        with self._lock:
            self.connect_requests.append(authority)

    def _record_proxy_authorization(self, value: str) -> None:
        with self._lock:
            self.proxy_authorizations.append(value)

    def _record_first_tunnel_request_line(self, value: str) -> None:
        with self._lock:
            if self.first_tunnel_request_line is None:
                self.first_tunnel_request_line = value

    def _extract_proxy_authorization(self, head: bytes) -> Optional[str]:
        for raw_line in head.splitlines()[1:]:
            try:
                line = raw_line.decode('ascii', 'replace')
            except Exception:
                continue
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            if key.strip().lower() == 'proxy-authorization':
                return value.strip()
        return None

    def _relay(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while not self.stop_event.is_set():
                data = src.recv(65535)
                if not data:
                    return
                dst.sendall(data)
        except Exception:
            return
        finally:
            with contextlib.suppress(Exception):
                dst.shutdown(socket.SHUT_WR)

    def _handle_conn(self, conn: socket.socket, addr) -> None:
        upstream = None
        try:
            conn.settimeout(5.0)
            raw = self._recv_headers(conn)
            head, _, _rest = raw.partition(b'\r\n\r\n')
            line = head.splitlines()[0].decode('ascii', 'replace') if head else ''
            parts = line.split()
            if len(parts) < 3 or parts[0].upper() != 'CONNECT':
                self._log(f'reject non-CONNECT from {addr!r}: {line!r}')
                conn.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n')
                return
            authority = parts[1].strip()
            host = authority
            port = 80
            if authority.startswith('['):
                end = authority.find(']')
                if end != -1:
                    host = authority[1:end]
                    rest = authority[end + 1:]
                    if rest.startswith(':') and rest[1:].isdigit():
                        port = int(rest[1:])
            elif ':' in authority:
                base, maybe_port = authority.rsplit(':', 1)
                if maybe_port.isdigit():
                    host = base
                    port = int(maybe_port)
            auth_header = self._extract_proxy_authorization(head)
            self._record_connect(authority)
            if auth_header:
                self._record_proxy_authorization(auth_header)
            self._log(f'CONNECT {authority} from={addr!r}')
            if self.require_negotiate and not (auth_header or '').lower().startswith('negotiate '):
                conn.sendall(
                    b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    b'Proxy-Authenticate: Negotiate\r\n'
                    b'Connection: close\r\n\r\n'
                )
                return
            upstream = socket.create_connection((str(host).strip('[]'), int(port)), timeout=5.0)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n')
            first_upstream = self._recv_headers(conn)
            if first_upstream:
                first_head, _, first_rest = first_upstream.partition(b'\r\n\r\n')
                first_line = first_head.splitlines()[0].decode('ascii', 'replace') if first_head else ''
                if first_line:
                    self._record_first_tunnel_request_line(first_line)
                upstream.sendall(first_upstream)
            conn.settimeout(None)
            upstream.settimeout(None)
            t1 = threading.Thread(target=self._relay, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=self._relay, args=(upstream, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            self._log(f'handler error from={addr!r}: {e!r}')
        finally:
            with contextlib.suppress(Exception):
                conn.close()
            if upstream is not None:
                with contextlib.suppress(Exception):
                    upstream.close()

    def _run(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_host, self.listen_port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)
        self._log(f'HTTP CONNECT proxy listening on {self.listen_host}:{self.listen_port}')
        self.ready_event.set()
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
            t.start()


def merge_env(extra: Dict[str, str]) -> Dict[str, str]:
    env = os.environ.copy()
    for k, v in extra.items():
        if k == 'NO_PROXY' and env.get('NO_PROXY'):
            if v not in env['NO_PROXY']:
                env['NO_PROXY'] = f'{v},{env["NO_PROXY"]}'
        else:
            env[k] = v
    return env


def _legacy_service_spec_to_structured(spec: str) -> Optional[Dict[str, Any]]:
    parts = [p.strip() for p in str(spec).split(',')]
    if len(parts) != 6:
        return None
    listen_proto = parts[0].lower()
    target_proto = parts[3].lower()
    listen_port: int
    target_port: int
    try:
        listen_port = int(parts[1])
        target_port = int(parts[5])
    except Exception:
        return None
    listen_obj: Dict[str, Any] = {
        'protocol': listen_proto,
    }
    target_obj: Dict[str, Any] = {
        'protocol': target_proto,
    }
    if listen_proto == 'tun':
        listen_obj['ifname'] = parts[2]
        listen_obj['mtu'] = listen_port
    else:
        listen_obj['bind'] = parts[2]
        listen_obj['port'] = listen_port
    if target_proto == 'tun':
        target_obj['ifname'] = parts[4]
        target_obj['mtu'] = target_port
    else:
        target_obj['host'] = parts[4]
        target_obj['port'] = target_port
    return {
        'listen': listen_obj,
        'target': target_obj,
    }


def _normalize_service_arg_item(item: str) -> str:
    raw = str(item).strip()
    if not raw:
        return raw
    with contextlib.suppress(Exception):
        decoded = json.loads(raw)
        if isinstance(decoded, dict):
            return json.dumps(decoded, separators=(',', ':'))
        if isinstance(decoded, list) and all(isinstance(entry, dict) for entry in decoded):
            return json.dumps(decoded, separators=(',', ':'))
    structured = _legacy_service_spec_to_structured(raw)
    if structured is None:
        return str(item)
    return json.dumps(structured, separators=(',', ':'))


def _normalize_service_specs_cli_args(args: List[str]) -> List[str]:
    service_options = {'--own-servers', '--remote-servers'}
    out: List[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i])
        out.append(arg)
        i += 1
        if arg not in service_options:
            continue
        while i < len(args) and not str(args[i]).startswith('--'):
            out.append(_normalize_service_arg_item(str(args[i])))
            i += 1
    return out


def start_proc(name: str, cmd: List[str], log_dir: Path, env_extra: Optional[Dict[str, str]] = None, admin_port: Optional[int] = None) -> Proc:
    normalized_cmd = _normalize_service_specs_cli_args([str(part) for part in cmd])
    log_path = log_dir / f'{name}.log'
    fp = open(log_path, 'wb')
    kwargs = {
        'stdin': subprocess.PIPE,
        'stdout': fp,
        'stderr': subprocess.STDOUT,
        'cwd': str(ROOT),
        'env': merge_env(env_extra or {}),
    }
    if os.name != 'nt':
        kwargs['start_new_session'] = True
    p = subprocess.Popen(normalized_cmd, **kwargs)
    return Proc(
        name=name,
        popen=p,
        log_path=log_path,
        admin_port=admin_port,
        cmd=list(normalized_cmd),
        env_extra=dict(env_extra or {}),
    )


def bridge_entrypoint(*, with_failure_injection: bool = False) -> List[str]:
    py = sys.executable
    if with_failure_injection:
        return [py, '-m', 'obstacle_bridge.bridge_FI']
    return [py, str(BRIDGE)]

RESTART_EXIT_CODES = {75, 77}


def _is_restart_exit_code(rc: Optional[int]) -> bool:
    return rc is not None and int(rc) in RESTART_EXIT_CODES

def proc_exited_for_restart(proc: Proc) -> bool:
    rc = proc.popen.poll()
    return _is_restart_exit_code(rc)


def restart_proc(proc: Proc, log_dir: Path) -> Proc:
    
    if not proc.cmd:
        raise RuntimeError(f'{proc.name} cannot be restarted: missing cmd')
    rc = proc.popen.poll()
    log.info(f'[PROC] self-restart detected for {proc.name} rc={rc}; relaunching')
    cmd = list(proc.cmd)
    admin_port = proc.admin_port
    if admin_port:
        admin_port = alloc_admin_port({int(admin_port)}, host_pair=_admin_loopback_hosts(admin_port))
        cmd = _replace_last_arg(cmd, '--admin-web-port', str(admin_port))
    return start_proc(
        proc.name,
        cmd,
        log_dir,
        env_extra=proc.env_extra,
        admin_port=admin_port,
    )

def stop_proc(proc: Proc) -> None:
    
    log.info(f'[PROC] stopping {proc.name} pid={proc.popen.pid}')

    if proc.popen.poll() is not None:
        return

    # First choice: graceful admin shutdown
    if proc.admin_port:
        try:
            code, body = post_json(f'http://127.0.0.1:{proc.admin_port}/api/shutdown', timeout=2.0)
            log.info(f'[PROC] admin shutdown on {proc.admin_port}: code={code} body={body!r}')
        except Exception as e:
            log.info(f'[PROC] admin shutdown failed on {proc.admin_port}: {e!r}')

    deadline = time.time() + 8.0
    while time.time() < deadline:
        if proc.popen.poll() is not None:
            return
        time.sleep(0.1)

    # Fallback only if graceful shutdown failed
    try:
        if os.name == 'nt':
            proc.popen.terminate()
        else:
            os.killpg(proc.popen.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.popen.terminate()
        except Exception:
            pass

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if proc.popen.poll() is not None:
            return
        time.sleep(0.1)

    try:
        if os.name == 'nt':
            proc.popen.kill()
        else:
            os.killpg(proc.popen.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.popen.kill()
        except Exception:
            pass


def assert_running(proc: Proc) -> None:
    
    rc = proc.popen.poll()
    if rc is None:
        return
    
    log.info(f'[RUN]{proc.name} exited with rc={rc}\n')
    if _is_restart_exit_code(rc):
        raise RuntimeError(f'{proc.name} exited for self-restart rc={rc}')
    tail = proc.log_path.read_text(errors='replace')[-4000:] if proc.log_path.exists() else ''
    raise RuntimeError(f'{proc.name} exited early with rc={rc}\n--- {proc.log_path.name} ---\n{tail}')

def ensure_proc_up(proc: Proc, log_dir: Path, admin_timeout: float = 10.0) -> Proc:
    
    rc = proc.popen.poll()
    if rc is None:
        return proc

    log.info(f'[RUN]{proc.name} exited with rc={rc}\n')
    if not _is_restart_exit_code(rc):
        tail = proc.log_path.read_text(errors='replace')[-4000:] if proc.log_path.exists() else ''
        raise RuntimeError(f'{proc.name} exited early with rc={rc}\n--- {proc.log_path.name} ---\n{tail}')

    new_proc = restart_proc(proc, log_dir)
    time.sleep(0.5)
    rc2 = new_proc.popen.poll()
    if rc2 is not None:
        tail = new_proc.log_path.read_text(errors='replace')[-4000:] if new_proc.log_path.exists() else ''
        raise RuntimeError(f'{new_proc.name} exited immediately after self-restart with rc={rc2}\n--- {new_proc.log_path.name} ---\n{tail}')

    if new_proc.admin_port:
        wait_admin_up(new_proc.admin_port, timeout=admin_timeout)

    return new_proc

def wait_tcp_listen(host: str, port: int, timeout: float = 5.0) -> None:
    candidates = [host]
    if str(host).startswith('::ffff:127.124.'):
        candidates.append('::1')
    end = time.time() + timeout
    last_exc = None
    while time.time() < end:
        for candidate in candidates:
            family = socket.AF_INET6 if ':' in candidate else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect((candidate, port))
                s.close()
                return
            except Exception as e:
                last_exc = e
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(0.1)
    raise RuntimeError(f'TCP port {host}:{port} not ready: {last_exc}')


def probe_udp(host: str, port: int, bind_host: Optional[str], payload: bytes, timeout: float = 1.0) -> bytes:
    candidates = [host]
    if str(host).startswith('::ffff:127.124.'):
        candidates.append('::1')
    last_exc = None
    for candidate in candidates:
        family = socket.AF_INET6 if ':' in candidate else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            try:
                if bind_host is not None:
                    s.bind((bind_host, 0))
                s.settimeout(timeout)
                s.sendto(payload, (candidate, port))
                data, _ = s.recvfrom(65535)
                return data
            except Exception as e:
                last_exc = e
    raise last_exc or RuntimeError(f'UDP probe failed for {host}:{port}')


def probe_tcp(
    host: str,
    port: int,
    bind_host: Optional[str],
    payload: bytes,
    timeout: float = 1.0,
    before_close: Optional[Callable[[], None]] = None,
) -> bytes:
    candidates = [host]
    if str(host).startswith('::ffff:127.124.'):
        candidates.append('::1')
    last_exc = None
    for candidate in candidates:
        family = socket.AF_INET6 if ':' in candidate else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            try:
                if bind_host is not None:
                    s.bind((bind_host, 0))
                s.settimeout(timeout)
                s.connect((candidate, port))
                s.sendall(payload)
                data = s.recv(4096)
                if before_close is not None:
                    before_close()
                return data
            except Exception as e:
                last_exc = e
    raise last_exc or RuntimeError(f'TCP probe failed for {host}:{port}')


def _row_source_port(row: dict) -> Optional[int]:
    source = row.get('source')
    if isinstance(source, (list, tuple)) and len(source) >= 2:
        try:
            return int(source[1])
        except Exception:
            return None
    return None


def _matching_connection_rows(
    doc: dict,
    protocol: str,
    *,
    local_port: Optional[int] = None,
    state: Optional[str] = None,
    source_port: Optional[int] = None,
) -> list[dict]:
    rows = []
    for row in doc.get(protocol, []) or []:
        if local_port is not None and int(row.get('local_port') or -1) != int(local_port):
            continue
        if state is not None and str(row.get('state') or '').strip().lower() != str(state).strip().lower():
            continue
        if source_port is not None and _row_source_port(row) != int(source_port):
            continue
        rows.append(row)
    return rows


def wait_probe(
    case: Case,
    payload: bytes = PAYLOAD_IN,
    expected: Optional[bytes] = None,
    timeout: float = 8.0,
    before_tcp_close: Optional[Callable[[], None]] = None,
) -> None:
    if expected is None:
        expected = response_payload(payload)
    end = time.time() + timeout
    last_exc = None
    while time.time() < end:
        try:
            if case.probe_proto == 'udp':
                data = probe_udp(case.probe_host, case.probe_port, case.probe_bind, payload, timeout=1.0)
            else:
                data = probe_tcp(
                    case.probe_host,
                    case.probe_port,
                    case.probe_bind,
                    payload,
                    timeout=1.0,
                    before_close=before_tcp_close,
                )
            if data == expected:
                return
            last_exc = RuntimeError(f'unexpected response: {data!r}')
        except Exception as e:
            last_exc = e
            time.sleep(0.25)
    raise RuntimeError(f'Probe failed for {case.name}: {last_exc}')


def _wait_jsonl_events(path: Path, predicate: Callable[[List[Dict[str, str]]], bool], *, timeout: float = 12.0) -> List[Dict[str, str]]:
    end = time.time() + timeout
    last_rows: List[Dict[str, str]] = []
    while time.time() < end:
        if path.exists():
            rows: List[Dict[str, str]] = []
            for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
                line = str(raw).strip()
                if not line:
                    continue
                with contextlib.suppress(Exception):
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        rows.append({str(k): '' if v is None else str(v) for k, v in parsed.items()})
            last_rows = rows
            if predicate(rows):
                return rows
        time.sleep(0.1)
    raise RuntimeError(f'event predicate not satisfied for {path.name}; rows={last_rows!r}')


def expect_probe_failure(case: Case, payload: bytes, timeout: float = 5.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if case.probe_proto == 'udp':
                probe_udp(case.probe_host, case.probe_port, case.probe_bind, payload, timeout=0.75)
            else:
                probe_tcp(case.probe_host, case.probe_port, case.probe_bind, payload, timeout=0.75)
        except Exception:
            return
        time.sleep(0.25)
    raise RuntimeError(f'Probe unexpectedly still succeeds for {case.name}')


def materialize_args(args: List[str], log_dir: Path, case_name: str, side: str) -> List[str]:
    out: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--log-file' and i + 1 < len(args):
            filename = args[i + 1]
            out.extend([a, str(log_dir / f'{case_name}_{side}_{Path(filename).name}')])
            i += 2
            continue
        out.append(a)
        i += 1
    return out


def _arg_value(args: List[str], name: str, default: str) -> str:
    if name in args:
        idx = args.index(name)
        if idx + 1 < len(args):
            return str(args[idx + 1])
    return default


def _listener_overlay_port(case: Case, transport: str) -> int:
    listen_opt = {'myudp': '--udp-own-port', 'tcp': '--tcp-own-port', 'quic': '--quic-own-port', 'ws': '--ws-own-port'}[transport]
    base_default = {'myudp': 4433, 'tcp': 8081, 'quic': 443, 'ws': 8080}[transport]
    return int(_arg_value(case.bridge_server_args, listen_opt, str(base_default)))


def _listener_overlay_bind_host(case: Case, transport: str) -> str:
    bind_opt = {'myudp': '--udp-bind', 'tcp': '--tcp-bind', 'quic': '--quic-bind', 'ws': '--ws-bind'}[transport]
    default = '0.0.0.0'
    return _arg_value(case.bridge_server_args, bind_opt, default)


def _connect_host_for_bind(bind_host: str, case_key: int) -> str:
    ipv4_host, ipv6_host = _loopback_hosts_for_case(case_key)
    host = str(bind_host or '').strip()
    if host in ('', '0.0.0.0'):
        return ipv4_host
    if host == '::':
        return ipv6_host
    rewritten = _rewrite_loopback_literal(host, ipv4_host=ipv4_host, ipv6_host=ipv6_host)
    return str(rewritten or host)


def _admin_loopback_hosts(admin_port: int) -> Tuple[str, str]:
    return ADMIN_PORT_LOOPBACKS.get(int(admin_port), ('127.0.0.1', '::1'))


def _admin_host_for_port(admin_port: int) -> str:
    return _admin_loopback_hosts(admin_port)[0]


def _rewrite_registered_admin_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url))
    except Exception:
        return str(url)
    host = parsed.hostname
    port = parsed.port
    if host not in ('127.0.0.1', '::1') or port is None:
        return str(url)
    if int(port) not in ADMIN_PORT_LOOPBACKS:
        return str(url)
    target_host = _admin_host_for_port(port) if host == '127.0.0.1' else _admin_loopback_hosts(port)[1]
    netloc = f'[{target_host}]:{port}' if ':' in target_host else f'{target_host}:{port}'
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def alloc_admin_ports(case_index: int, base: int = ADMIN_PORT_BASE) -> Tuple[int, int]:
    server = alloc_admin_port(case_index=case_index, base=base)
    client = alloc_admin_port(case_index=case_index + 1, exclude={server}, base=base)
    return server, client


def alloc_admin_port(
    exclude: Optional[Set[int]] = None,
    *,
    case_index: int = 0,
    base: int = ADMIN_PORT_BASE,
    host_pair: Optional[Tuple[str, str]] = None,
) -> int:
    blocked = set(exclude or ())
    worker_index = _xdist_worker_index()
    worker_count = _xdist_worker_count()
    base_i = max(int(base), SERVICE_PORT_CEILING)
    upper_bound = 65535
    if base_i < SECURE_LINK_ADMIN_BASE:
        upper_bound = min(upper_bound, SECURE_LINK_ADMIN_BASE)
    available = upper_bound - base_i
    if available <= worker_count:
        raise RuntimeError(f'admin port allocation window too small: base={base_i} workers={worker_count}')
    per_worker_budget = max(8, available // worker_count)
    start = base_i + (worker_index * per_worker_budget)
    stop = min(upper_bound, start + per_worker_budget)
    span = max(1, stop - start)
    first = start + (int(case_index) % span)
    candidates = list(range(first, stop)) + list(range(start, first))
    admin_host, admin_ipv6_host = host_pair or (_loopback_ipv4_host(case_index), _loopback_ipv6_mapped_host(case_index))
    for port in candidates:
        if port in blocked:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((admin_host, port))
            except OSError:
                continue
        ADMIN_PORT_LOOPBACKS[int(port)] = (admin_host, admin_ipv6_host)
        return port
    raise RuntimeError('failed to allocate a free admin web port')


def admin_args(port: int) -> List[str]:
    return ['--admin-web', '--admin-web-bind', _admin_host_for_port(port), '--admin-web-port', str(port)]


def build_commands(case: Case, log_dir: Path, case_index: int, enable_admin: bool = False) -> List[tuple[str, List[str], Dict[str, str], Optional[int]]]:
    py = sys.executable
    server_admin, client_admin = alloc_admin_ports(case_index)
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    client_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_client_args, log_dir, case.name, 'bridge_client')
    server_env = dict(case.server_env)
    client_env = dict(case.client_env)
    server_cmd, client_cmd, server_env, client_env = _with_hostaliases(
        case,
        log_dir,
        case_index,
        server_cmd,
        client_cmd,
        server_env,
        client_env,
    )
    # Force default startup values from CLI/test case and avoid loading local ObstacleBridge.cfg.
    # ConfigAwareCLI treats a missing explicitly-requested config as non-fatal and continues with defaults.
    server_cmd += ['--config', missing_cfg]
    client_cmd += ['--config', missing_cfg]
    # Prevent accidental fixed-port collisions from external config defaults.
    server_cmd += ['--admin-web-port', '0']
    client_cmd += ['--admin-web-port', '0']
    client_cmd += ['--client-restart-if-disconnected', '10']
    if enable_admin:
        server_cmd += admin_args(server_admin)
        client_cmd += admin_args(client_admin)
    return [
        ('bridge_server', server_cmd, server_env, server_admin if enable_admin else None),
        ('bridge_client', client_cmd, client_env, client_admin if enable_admin else None),
    ]


def post_json(url: str, timeout: float = 2.0) -> tuple[int, dict]:
    url = _rewrite_registered_admin_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        url,
        data=b'{}',
        method='POST',
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Connection': 'close',
        },
    )
    with opener.open(req, timeout=timeout) as resp:
        code = getattr(resp, 'status', 200)
        body = json.loads(resp.read().decode('utf-8', 'replace'))
        return code, body


def make_json_opener(with_cookies: bool = False) -> urllib.request.OpenerDirector:
    handlers: list = [urllib.request.ProxyHandler({})]
    if with_cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    return urllib.request.build_opener(*handlers)


def request_json(
    url: str,
    *,
    method: str = 'GET',
    payload: Optional[dict] = None,
    timeout: float = 1.5,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> tuple[int, dict]:
    url = _rewrite_registered_admin_url(url)
    headers = {
        'Accept': 'application/json',
        'Connection': 'close',
    }
    req_data = None
    if payload is not None:
        req_data = json.dumps(payload).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=req_data, method=method, headers=headers)
    op = opener or make_json_opener(with_cookies=False)
    try:
        with op.open(req, timeout=timeout) as resp:
            code = getattr(resp, 'status', 200)
            body = json.loads(resp.read().decode('utf-8', 'replace'))
            return code, body
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', 'replace')
        body = json.loads(raw) if raw else {}
        return e.code, body


def fetch_json(url: str, timeout: float = 1.5) -> tuple[int, dict]:
    url = _rewrite_registered_admin_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        url,
        headers={
            'Accept': 'application/json',
            'Connection': 'close',
        },
    )
    with opener.open(req, timeout=timeout) as resp:
        code = getattr(resp, 'status', 200)
        body = json.loads(resp.read().decode('utf-8', 'replace'))
        return code, body


def fetch_json_auth(url: str, *, timeout: float = 1.5, opener: Optional[urllib.request.OpenerDirector] = None) -> tuple[int, dict]:
    return request_json(url, timeout=timeout, opener=opener)


def fetch_http_bytes(
    url: str,
    *,
    timeout: float = 1.5,
    headers: Optional[Dict[str, str]] = None,
) -> tuple[int, Dict[str, str], bytes]:
    url = _rewrite_registered_admin_url(url)
    req_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection': 'keep-alive',
    }
    req_headers.update(headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers=req_headers)
    with opener.open(req, timeout=timeout) as resp:
        code = getattr(resp, 'status', 200)
        body = resp.read()
        response_headers = {str(key).strip().lower(): str(value).strip() for key, value in resp.headers.items()}
        return code, response_headers, body


def fetch_http_text(
    url: str,
    *,
    timeout: float = 1.5,
    headers: Optional[Dict[str, str]] = None,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> tuple[int, Dict[str, str], str]:
    url = _rewrite_registered_admin_url(url)
    req_headers = {
        'Accept': 'text/html,application/javascript,text/javascript,text/css,*/*;q=0.8',
        'Connection': 'close',
    }
    req_headers.update(headers or {})
    req = urllib.request.Request(url, headers=req_headers)
    op = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(req, timeout=timeout) as resp:
        code = getattr(resp, 'status', 200)
        body = resp.read().decode('utf-8', 'replace')
        response_headers = {str(key).strip().lower(): str(value).strip() for key, value in resp.headers.items()}
        return code, response_headers, body


def _read_http_response_from_socket(sock: socket.socket, *, timeout: float = 1.5) -> tuple[int, Dict[str, str], bytes]:
    sock.settimeout(timeout)
    raw = bytearray()
    while b'\r\n\r\n' not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f'connection closed before HTTP headers completed: {bytes(raw)!r}')
        raw.extend(chunk)

    header_block, body = raw.split(b'\r\n\r\n', 1)
    lines = header_block.decode('iso-8859-1', 'replace').split('\r\n')
    if not lines:
        raise RuntimeError('missing HTTP status line')
    status_parts = lines[0].split()
    if len(status_parts) < 2:
        raise RuntimeError(f'invalid HTTP status line: {lines[0]!r}')
    status_code = int(status_parts[1])
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ':' not in line:
            continue
        key, value = line.split(':', 1)
        headers[key.strip().lower()] = value.strip()

    content_length = int(headers.get('content-length', '0') or '0')
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(
                f'connection closed before HTTP body completed: expected={content_length} got={len(body)}'
            )
        body += chunk
    return status_code, headers, bytes(body[:content_length])


def fetch_http_keepalive_sequence(
    host: str,
    port: int,
    *,
    path: str = '/',
    attempts: int = 2,
    timeout: float = 1.5,
) -> list[tuple[int, Dict[str, str], bytes]]:
    responses: list[tuple[int, Dict[str, str], bytes]] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        for _ in range(max(1, int(attempts))):
            request = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {host}:{port}\r\n'
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
                'Connection: keep-alive\r\n'
                '\r\n'
            ).encode('ascii')
            sock.sendall(request)
            responses.append(_read_http_response_from_socket(sock, timeout=timeout))
    return responses


def assert_static_http_root_serves_repeatedly(url: str, *, attempts: int = 6, timeout: float = 1.5) -> bytes:
    last_body = b''
    for _ in range(max(1, int(attempts))):
        code, headers, body = fetch_http_bytes(url, timeout=timeout)
        assert code == 200
        assert headers.get('content-type', '').startswith('text/html')
        assert b'Hello! Welcome!' in body
        last_body = body
    return last_body


def get_health(admin_port: int) -> dict:
    _code, body = fetch_json(f'http://127.0.0.1:{admin_port}/api/health', timeout=1.5)
    return body


def try_get_status(admin_port: int) -> Optional[dict]:
    try:
        _code, body = fetch_json(f'http://127.0.0.1:{admin_port}/api/status', timeout=1.5)
        return body
    except urllib.error.HTTPError as e:
        if e.code == 503:
            return None
        raise


def get_status(admin_port: int) -> dict:
    doc = try_get_status(admin_port)
    if doc is None:
        raise RuntimeError(f'/api/status on port {admin_port} returned 503')
    return doc

def wait_admin_up(admin_port: int, timeout: float = 10.0) -> dict:
    
    end = time.time() + timeout
    last_exc = None
    url = f'http://127.0.0.1:{admin_port}/api/health'
    log.info(f'[HARNESS] wait_admin_up using {url}')
    while time.time() < end:
        try:
            body = get_health(admin_port)
            log.info(f'[HARNESS] health ok on {admin_port}: {body!r}')
            if body.get('ok') is True:
                return body
        except Exception as e:
            last_exc = e
            log.info(f'[HARNESS] health poll failed on {admin_port}: {e!r}')
        time.sleep(0.25)
    raise RuntimeError(f'Admin endpoint not ready on port {admin_port}: {last_exc}')


def wait_admin_auth_up(admin_port: int, timeout: float = 10.0) -> dict:
    end = time.time() + timeout
    last_exc = None
    url = f'http://127.0.0.1:{admin_port}/api/auth/state'
    log.info(f'[HARNESS] wait_admin_auth_up using {url}')
    while time.time() < end:
        try:
            code, body = request_json(url, timeout=1.5)
            if code == 200 and body.get('ok') is True:
                log.info(f'[HARNESS] auth state ok on {admin_port}: {body!r}')
                return body
            last_exc = RuntimeError(f'unexpected auth state response code={code} body={body!r}')
        except Exception as e:
            last_exc = e
            log.info(f'[HARNESS] auth state poll failed on {admin_port}: {e!r}')
        time.sleep(0.25)
    raise RuntimeError(f'Admin auth endpoint not ready on port {admin_port}: {last_exc}')


def wait_status_connected_auth(
    admin_port: int,
    *,
    opener: urllib.request.OpenerDirector,
    timeout: float = 20.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last = None
    while time.time() < end:
        code, body = fetch_json_auth(
            f'http://127.0.0.1:{admin_port}/api/status',
            timeout=1.5,
            opener=opener,
        )
        if code == 200:
            last = body
            if status_state(body) == 'CONNECTED':
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} CONNECTED reached via authenticated admin session')
                return body
        time.sleep(0.25)
    raise RuntimeError(f'Authenticated /api/status did not reach CONNECTED on port {admin_port}; last={last!r}')


def admin_authenticate(
    admin_port: int,
    username: str,
    password: str,
    *,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> tuple[int, dict, urllib.request.OpenerDirector]:
    op = opener or make_json_opener(with_cookies=True)
    code, challenge = request_json(
        f'http://127.0.0.1:{admin_port}/api/auth/challenge',
        timeout=1.5,
        opener=op,
    )
    if code != 200:
        raise RuntimeError(f'challenge failed code={code} body={challenge!r}')
    if not challenge.get('auth_required', False):
        return code, challenge, op
    seed = str(challenge.get('seed') or '')
    challenge_id = str(challenge.get('challenge_id') or '')
    proof = hashlib.sha256(f'{seed}:{username}:{password}'.encode('utf-8')).hexdigest()
    login_code, login_doc = request_json(
        f'http://127.0.0.1:{admin_port}/api/auth/login',
        method='POST',
        payload={'challenge_id': challenge_id, 'proof': proof},
        timeout=1.5,
        opener=op,
    )
    return login_code, login_doc, op


def config_change_proof(seed: str, username: str, password: str, updates_digest: str) -> str:
    return hashlib.sha256(f'{seed}:{username}:{password}:{updates_digest}'.encode('utf-8')).hexdigest()


def proc_config_path(proc: Proc) -> Path:
    cmd = list(proc.cmd or [])
    for idx, item in enumerate(cmd):
        if item == '--config' and idx + 1 < len(cmd):
            return Path(cmd[idx + 1])
    raise RuntimeError(f'process command does not include --config: {cmd!r}')


async def _admin_ws_collect_messages(
    admin_port: int,
    *,
    opener: Optional[urllib.request.OpenerDirector] = None,
    subscribe: Optional[list[str]] = None,
    want_types: Optional[set[str]] = None,
    timeout: float = 5.0,
) -> list[dict]:
    import websockets

    headers = {}
    if opener is not None:
        cookiejar = None
        for handler in getattr(opener, "handlers", []):
            if isinstance(handler, urllib.request.HTTPCookieProcessor):
                cookiejar = getattr(handler, "cookiejar", None)
                break
        if cookiejar is not None:
            cookies = []
            for cookie in cookiejar:
                cookies.append(f"{cookie.name}={cookie.value}")
            if cookies:
                headers["Cookie"] = "; ".join(cookies)

    connect_sig = inspect.signature(websockets.connect)
    connect_kwargs = {}
    header_key = "additional_headers" if "additional_headers" in connect_sig.parameters else "extra_headers"
    if headers:
        connect_kwargs[header_key] = headers

    url = _rewrite_registered_admin_url(f'ws://127.0.0.1:{admin_port}/api/live')
    seen: list[dict] = []
    targets = set(want_types or set())
    async with websockets.connect(url, **connect_kwargs) as ws:
        if subscribe:
            await ws.send(json.dumps({"subscribe": subscribe, "request": subscribe}))
        end = time.time() + timeout
        while time.time() < end:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, end - time.time()))
            msg = json.loads(raw)
            seen.append(msg)
            if targets and targets.issubset({str(item.get("type") or "") for item in seen}):
                return seen
    return seen


def _conn_rows_with_traffic(doc: dict) -> list[dict]:
    rows = []
    for key in ('udp', 'tcp'):
        for row in doc.get(key, []) or []:
            stats = row.get('stats') or {}
            if (
                int(stats.get('rx_msgs', 0)) > 0
                and int(stats.get('tx_msgs', 0)) > 0
                and int(stats.get('rx_bytes', 0)) > 0
                and int(stats.get('tx_bytes', 0)) > 0
            ):
                rows.append(row)
    return rows


def _connections_totals(doc: dict) -> tuple[int, int]:
    rx_total = 0
    tx_total = 0
    for key in ('udp', 'tcp'):
        for row in doc.get(key, []) or []:
            stats = row.get('stats') or {}
            rx_total += int(stats.get('rx_bytes', 0) or 0)
            tx_total += int(stats.get('tx_bytes', 0) or 0)
    return rx_total, tx_total


def _tcp_connections_totals(doc: dict) -> tuple[int, int]:
    rx_total = 0
    tx_total = 0
    for row in doc.get('tcp', []) or []:
        stats = row.get('stats') or {}
        rx_total += int(stats.get('rx_bytes', 0) or 0)
        tx_total += int(stats.get('tx_bytes', 0) or 0)
    return rx_total, tx_total


def _connected_tcp_rows(doc: dict) -> list[dict]:
    rows: list[dict] = []
    for row in doc.get('tcp', []) or []:
        if str(row.get('state', '')).strip().lower() == 'connected':
            rows.append(row)
    return rows


def wait_tcp_connections_exact_transferred_bytes(
    admin_port: int,
    expected_bytes: int,
    timeout: float = 3.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_conn = None
    while time.time() < end:
        _code, conn_doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        last_conn = conn_doc
        tcp_rx, tcp_tx = _tcp_connections_totals(conn_doc)
        if tcp_rx == expected_bytes and tcp_tx == expected_bytes:
            who = f' {label}' if label else ''
            log.info(
                '[METRICS]%s port=%s exact /api/connections TCP bytes rx=%s tx=%s',
                who,
                admin_port,
                tcp_rx,
                tcp_tx,
            )
            return conn_doc
        time.sleep(0.1)
    raise RuntimeError(
        f'Exact TCP /api/connections byte counters not reached on port {admin_port}; '
        f'expected={expected_bytes}; last_connections={last_conn!r}'
    )


def wait_exact_transferred_bytes(
    admin_port: int,
    expected_bytes: int,
    timeout: float = 8.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_conn = None
    last_status = None
    while time.time() < end:
        _code, conn_doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        last_conn = conn_doc
        conn_rx, conn_tx = _connections_totals(conn_doc)
        if conn_rx >= expected_bytes and conn_tx >= expected_bytes:
            who = f' {label}' if label else ''
            log.info(
                '[METRICS]%s port=%s /api/connections bytes reached rx=%s tx=%s',
                who,
                admin_port,
                conn_rx,
                conn_tx,
            )
            return conn_doc

        # TCP probes can disconnect too quickly for /api/connections polling to
        # observe a live row. Validate exact byte totals via aggregate counters.
        _status_code, status_doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/status', timeout=1.5)
        last_status = status_doc
        app_traffic = (status_doc.get('traffic') or {}).get('app') or {}
        app_rx = int(app_traffic.get('rx_total_bytes', 0) or 0)
        app_tx = int(app_traffic.get('tx_total_bytes', 0) or 0)
        if app_rx >= expected_bytes and app_tx >= expected_bytes:
            who = f' {label}' if label else ''
            log.info(
                '[METRICS]%s port=%s aggregate bytes reached rx=%s tx=%s',
                who,
                admin_port,
                app_rx,
                app_tx,
            )
            return conn_doc
        time.sleep(0.25)
    raise RuntimeError(
        f'Exact byte counters not reached on port {admin_port}; expected={expected_bytes}; '
        f'last_connections={last_conn!r}; last_status={last_status!r}'
    )


def wait_connections_metrics_updated(admin_port: int, timeout: float = 8.0, label: str = '') -> dict:
    end = time.time() + timeout
    last_doc = None
    last_status = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        last_doc = doc
        rows = _conn_rows_with_traffic(doc)
        if rows:
            who = f' {label}' if label else ''
            log.info(f'[METRICS]{who} port={admin_port} traffic rows={len(rows)}')
            return doc

        # TCP probes can be very short-lived, so a connection may complete and tear
        # down before /api/connections polling observes a live row. In that case,
        # accept aggregate app counters from /api/status as proof of traffic.
        _status_code, status_doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/status', timeout=1.5)
        last_status = status_doc
        app_traffic = (status_doc.get('traffic') or {}).get('app') or {}
        if int(app_traffic.get('rx_total_bytes', 0) or 0) > 0 and int(app_traffic.get('tx_total_bytes', 0) or 0) > 0:
            who = f' {label}' if label else ''
            log.info(
                '[METRICS]%s port=%s aggregate traffic rx=%s tx=%s',
                who,
                admin_port,
                int(app_traffic.get('rx_total_bytes', 0) or 0),
                int(app_traffic.get('tx_total_bytes', 0) or 0),
            )
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/connections metrics not updated on port {admin_port}; '
        f'last_connections={last_doc!r}; last_status={last_status!r}'
    )


def wait_connection_rows(
    admin_port: int,
    protocol: str,
    *,
    local_port: Optional[int] = None,
    state: Optional[str] = None,
    source_port: Optional[int] = None,
    minimum_count: int = 1,
    timeout: float = 8.0,
    label: str = '',
) -> list[dict]:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        last_doc = doc
        rows = _matching_connection_rows(
            doc,
            protocol,
            local_port=local_port,
            state=state,
            source_port=source_port,
        )
        if len(rows) >= minimum_count:
            who = f' {label}' if label else ''
            log.info(f'[CONN]{who} port={admin_port} protocol={protocol} matched_rows={len(rows)}')
            return rows
        time.sleep(0.1)
    raise RuntimeError(
        f'/api/connections did not expose {minimum_count} matching {protocol} rows on port {admin_port}; '
        f'local_port={local_port} state={state} source_port={source_port} last={last_doc!r}'
    )


def wait_connection_rows_gone(
    admin_port: int,
    protocol: str,
    *,
    local_port: Optional[int] = None,
    state: Optional[str] = None,
    source_port: Optional[int] = None,
    timeout: float = 8.0,
    label: str = '',
) -> None:
    end = time.time() + timeout
    last_doc = None
    last_exc = None
    while time.time() < end:
        try:
            _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        except Exception as e:
            last_exc = e
            who = f' {label}' if label else ''
            log.info(f'[CONN]{who} port={admin_port} protocol={protocol} query failed while waiting for rows gone: {e!r}')
            return
        last_doc = doc
        rows = _matching_connection_rows(
            doc,
            protocol,
            local_port=local_port,
            state=state,
            source_port=source_port,
        )
        if not rows:
            who = f' {label}' if label else ''
            log.info(f'[CONN]{who} port={admin_port} protocol={protocol} rows gone')
            return
        time.sleep(0.1)
    raise RuntimeError(
        f'/api/connections kept matching {protocol} rows on port {admin_port}; '
        f'local_port={local_port} state={state} source_port={source_port} last={last_doc!r} last_exc={last_exc!r}'
    )


def wait_peers_count(admin_port: int, minimum_count: int, timeout: float = 12.0, label: str = '') -> dict:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        rows = list(doc.get('peers') or [])
        if len(rows) >= minimum_count:
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} count={len(rows)}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(f'/api/peers did not reach {minimum_count} rows on port {admin_port}; last={last_doc!r}')


def wait_listener_peer_rows_zeroed(admin_port: int, timeout: float = 12.0, label: str = '') -> dict:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        rows = list(doc.get('peers') or [])
        listening_rows = [row for row in rows if str(row.get('state', '')).strip().lower() == 'listening']
        if not listening_rows:
            time.sleep(0.25)
            continue

        valid = True
        for row in listening_rows:
            if row.get('connected'):
                valid = False
                break
            rtt = row.get('rtt_est_ms')
            if rtt not in (None, '', 'n/a', 'N/A'):
                valid = False
                break
            open_connections = row.get('open_connections') or {}
            traffic = row.get('traffic') or {}
            myudp = row.get('myudp') or {}
            if int(open_connections.get('udp', -1) or 0) != 0:
                valid = False
                break
            if int(open_connections.get('tcp', -1) or 0) != 0:
                valid = False
                break
            if int(traffic.get('rx_bytes', -1) or 0) != 0:
                valid = False
                break
            if int(traffic.get('tx_bytes', -1) or 0) != 0:
                valid = False
                break
            if int(row.get('decode_errors', -1) or 0) != 0:
                valid = False
                break
            if int(row.get('inflight', -1) or 0) != 0:
                valid = False
                break
            if int(myudp.get('buffered_frames', -1) or 0) != 0:
                valid = False
                break
            if int(myudp.get('confirmed_total', -1) or 0) != 0:
                valid = False
                break
            if int(myudp.get('first_pass', -1) or 0) != 0:
                valid = False
                break
            if int(myudp.get('repeated_once', -1) or 0) != 0:
                valid = False
                break
            if int(myudp.get('repeated_multiple', -1) or 0) != 0:
                valid = False
                break
        if valid:
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} listening_rows_zeroed={len(listening_rows)}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers listening rows were not fully zeroed on port {admin_port}; last={last_doc!r}'
    )


def wait_http_proxy_connects(proxy: HttpConnectProxy, minimum_count: int = 1, timeout: float = 8.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if proxy.connect_count >= minimum_count:
            return
        time.sleep(0.1)
    raise RuntimeError(
        f'HTTP proxy did not observe {minimum_count} CONNECT request(s); '
        f'observed={proxy.connect_count} requests={proxy.connect_requests!r}'
    )


def wait_peer_endpoint_visible(admin_port: int, timeout: float = 12.0, label: str = '', transport: str = 'myudp') -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        rows = list(doc.get('peers') or [])
        for row in rows:
            if str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            peer = str(row.get('peer') or '').strip()
            if peer and peer.lower() != 'n/a':
                who = f' {label}' if label else ''
                log.info(f'[PEERS]{who} port={admin_port} transport={normalized_transport} peer={peer}')
                return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose a non-empty peer endpoint for transport={normalized_transport} '
        f'on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_row_visible(
    admin_port: int,
    *,
    transport: str,
    peer: Optional[str] = None,
    state: Optional[str] = None,
    timeout: float = 12.0,
    label: str = '',
) -> tuple[dict, dict]:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    expected_peer = str(peer or '').strip()
    expected_state = str(state or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if expected_peer and str(row.get('peer') or '').strip() != expected_peer:
                continue
            if expected_state and str(row.get('state', '')).strip().lower() != expected_state:
                continue
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} matched_row={row!r}')
            return doc, row
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose a matching peer row for transport={normalized_transport} '
        f'peer={expected_peer or "*"} state={expected_state or "*"} on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_row_absent(
    admin_port: int,
    *,
    transport: str,
    peer: Optional[str] = None,
    state: Optional[str] = None,
    timeout: float = 25.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_doc = None
    last_match = None
    normalized_transport = str(transport or '').strip().lower()
    expected_peer = str(peer or '').strip()
    expected_state = str(state or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        matched = None
        for row in list(doc.get('peers') or []):
            if str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if expected_peer and str(row.get('peer') or '').strip() != expected_peer:
                continue
            if expected_state and str(row.get('state', '')).strip().lower() != expected_state:
                continue
            matched = row
            break
        if matched is None:
            who = f' {label}' if label else ''
            log.info(
                f'[PEERS]{who} port={admin_port} matched_row_absent transport={normalized_transport} '
                f'peer={expected_peer or "*"} state={expected_state or "*"}'
            )
            return doc
        last_match = matched
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers kept a stale matching peer row for transport={normalized_transport} '
        f'peer={expected_peer or "*"} state={expected_state or "*"} on port {admin_port}; '
        f'last_match={last_match!r} last={last_doc!r}'
    )


def wait_distinct_peer_endpoints(
    admin_port: int,
    *,
    transport: str,
    minimum_count: int = 2,
    timeout: float = 12.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        peers = set()
        for row in list(doc.get('peers') or []):
            if str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            peer = str(row.get('peer') or '').strip()
            if peer and peer.lower() != 'n/a':
                peers.add(peer)
        if len(peers) >= minimum_count:
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} transport={normalized_transport} distinct_peers={sorted(peers)!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose {minimum_count} distinct peer endpoints for transport={normalized_transport} '
        f'on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_secure_link_state(
    admin_port: int,
    *,
    expected_state: str,
    timeout: float = 12.0,
    label: str = '',
    transport: Optional[str] = None,
    failure_reason: Optional[str] = None,
    failure_code: Optional[int] = None,
    failure_detail_substr: Optional[str] = None,
    authenticated: Optional[bool] = None,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    expected_state_norm = str(expected_state or '').strip().lower()
    expected_reason = None if failure_reason is None else str(failure_reason).strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            if str(secure_link.get('state', '')).strip().lower() != expected_state_norm:
                continue
            if expected_reason is not None and str(secure_link.get('failure_reason', '')).strip().lower() != expected_reason:
                continue
            if failure_code is not None and int(secure_link.get('failure_code') or 0) != int(failure_code):
                continue
            if failure_detail_substr is not None and failure_detail_substr not in str(secure_link.get('failure_detail') or ''):
                continue
            if authenticated is not None and bool(secure_link.get('authenticated')) != bool(authenticated):
                continue
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} secure_link_state={secure_link!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose secure_link state={expected_state_norm} on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_secure_link_state_auth(
    admin_port: int,
    *,
    opener: urllib.request.OpenerDirector,
    expected_state: str,
    timeout: float = 12.0,
    label: str = '',
    transport: Optional[str] = None,
    failure_reason: Optional[str] = None,
    failure_code: Optional[int] = None,
    failure_detail_substr: Optional[str] = None,
    authenticated: Optional[bool] = None,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    expected_state_norm = str(expected_state or '').strip().lower()
    expected_reason = None if failure_reason is None else str(failure_reason).strip().lower()
    while time.time() < end:
        code, doc = fetch_json_auth(
            f'http://127.0.0.1:{admin_port}/api/peers',
            timeout=1.5,
            opener=opener,
        )
        if code != 200:
            time.sleep(0.25)
            continue
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            if str(secure_link.get('state', '')).strip().lower() != expected_state_norm:
                continue
            if expected_reason is not None and str(secure_link.get('failure_reason', '')).strip().lower() != expected_reason:
                continue
            if failure_code is not None and int(secure_link.get('failure_code') or 0) != int(failure_code):
                continue
            if failure_detail_substr is not None and failure_detail_substr not in str(secure_link.get('failure_detail') or ''):
                continue
            if authenticated is not None and bool(secure_link.get('authenticated')) != bool(authenticated):
                continue
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} secure_link_state_auth={secure_link!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'Authenticated /api/peers did not expose secure_link state={expected_state_norm} '
        f'on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_myudp_transmit_stats(
    admin_port: int,
    *,
    minimum_count: int = 1,
    timeout: float = 12.0,
    label: str = '',
    transport: str = 'myudp',
    minimum_confirmed_total: int = 1,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    minimum_confirmed = max(1, int(minimum_confirmed_total))
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        qualified_rows = 0
        for row in list(doc.get('peers') or []):
            if str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            myudp = row.get('myudp') or {}
            confirmed_total = int(myudp.get('confirmed_total') or 0)
            attempts_total = (
                int(myudp.get('first_pass') or 0)
                + int(myudp.get('repeated_once') or 0)
                + int(myudp.get('repeated_multiple') or 0)
            )
            if confirmed_total >= minimum_confirmed and attempts_total >= minimum_confirmed:
                qualified_rows += 1
        if qualified_rows >= int(minimum_count):
            who = f' {label}' if label else ''
            log.info(
                f'[PEERS]{who} port={admin_port} transport={normalized_transport} '
                f'myudp_transmit_stats_rows={qualified_rows}'
            )
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose myudp transmit stats for transport={normalized_transport} '
        f'on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_compress_layer_stats(
    admin_port: int,
    *,
    timeout: float = 12.0,
    label: str = '',
    transport: Optional[str] = None,
    enabled: Optional[bool] = None,
    minimum_applied_total: Optional[int] = None,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            comp = row.get('compress_layer') or {}
            if enabled is not None and bool(comp.get('enabled')) != bool(enabled):
                continue
            if minimum_applied_total is not None and int(comp.get('compress_applied_total') or 0) < int(minimum_applied_total):
                continue
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} compress_layer={comp!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose matching compress_layer stats on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_secure_link_session_change(
    admin_port: int,
    *,
    previous_session_id: int,
    timeout: float = 12.0,
    label: str = '',
    transport: Optional[str] = None,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            session_id = int(secure_link.get('session_id') or 0)
            if session_id > 0 and session_id != int(previous_session_id):
                who = f' {label}' if label else ''
                log.info(f'[PEERS]{who} port={admin_port} secure_link_session_changed={secure_link!r}')
                return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose secure_link session change from {previous_session_id} on port {admin_port}; last={last_doc!r}'
    )


def wait_peer_secure_link_rekeys_completed(
    admin_port: int,
    *,
    minimum_count: int,
    timeout: float = 12.0,
    label: str = '',
    transport: Optional[str] = None,
    authenticated: Optional[bool] = None,
) -> dict:
    end = time.time() + timeout
    last_doc = None
    normalized_transport = str(transport or '').strip().lower()
    minimum_rekeys = max(1, int(minimum_count))
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        for row in list(doc.get('peers') or []):
            if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
                continue
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            if authenticated is not None and bool(secure_link.get('authenticated')) != bool(authenticated):
                continue
            if int(secure_link.get('rekeys_completed_total') or 0) < minimum_rekeys:
                continue
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} secure_link_rekeys_completed={secure_link!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose secure_link rekeys_completed_total>={minimum_rekeys} '
        f'on port {admin_port}; last={last_doc!r}'
    )


def first_active_secure_link_row(doc: dict, *, transport: Optional[str] = None) -> dict:
    normalized_transport = str(transport or '').strip().lower()
    for row in list(doc.get('peers') or []):
        if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
            continue
        if str(row.get('state', '')).strip().lower() == 'listening':
            continue
        return row
    raise RuntimeError(f'Could not determine active secure-link peer row from peers doc: {doc!r}')


def first_active_peer_row(doc: dict, *, transport: Optional[str] = None) -> dict:
    normalized_transport = str(transport or '').strip().lower()
    for row in list(doc.get('peers') or []):
        if normalized_transport and str(row.get('transport', '')).strip().lower() != normalized_transport:
            continue
        if str(row.get('state', '')).strip().lower() == 'listening':
            continue
        if bool(row.get('connected')):
            return row
    raise RuntimeError(f'Could not determine active peer row from peers doc: {doc!r}')


def wait_status_secure_link_state(
    admin_port: int,
    *,
    expected_state: str,
    timeout: float = 12.0,
    label: str = '',
    failure_reason: Optional[str] = None,
    failure_code: Optional[int] = None,
    failure_detail_substr: Optional[str] = None,
    authenticated: Optional[bool] = None,
) -> dict:
    return wait_peer_secure_link_state(
        admin_port,
        expected_state=expected_state,
        timeout=timeout,
        label=label,
        failure_reason=failure_reason,
        failure_code=failure_code,
        failure_detail_substr=failure_detail_substr,
        authenticated=authenticated,
    )


def wait_status_secure_link_authenticated_peers(
    admin_port: int,
    *,
    minimum_count: int,
    timeout: float = 12.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        authenticated_count = 0
        for row in list(doc.get('peers') or []):
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            if bool(secure_link.get('authenticated')):
                authenticated_count += 1
        if authenticated_count >= int(minimum_count):
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} secure_link_authenticated_peers={authenticated_count!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose secure_link authenticated peers>={minimum_count} on port {admin_port}; last={last_doc!r}'
    )


def wait_status_secure_link_consecutive_failures(
    admin_port: int,
    *,
    minimum_count: int,
    timeout: float = 12.0,
    label: str = '',
) -> dict:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/peers', timeout=1.5)
        last_doc = doc
        max_failures = 0
        for row in list(doc.get('peers') or []):
            if str(row.get('state', '')).strip().lower() == 'listening':
                continue
            secure_link = row.get('secure_link') or {}
            max_failures = max(max_failures, int(secure_link.get('consecutive_failures') or 0))
        if max_failures >= int(minimum_count):
            who = f' {label}' if label else ''
            log.info(f'[PEERS]{who} port={admin_port} secure_link_consecutive_failures={max_failures!r}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(
        f'/api/peers did not expose secure_link consecutive_failures>={minimum_count} on port {admin_port}; last={last_doc!r}'
    )


def status_state(doc: dict) -> str:
    return str(doc.get('peer_state', '')).strip().upper()

def phase(msg: str) -> None:
    
    log.info(f'[PHASE] {msg}')

def fmt_state_doc(doc: Optional[dict]) -> str:
    if doc is None:
        return 'STATUS_503'
    state = str(doc.get('peer_state', 'UNKNOWN')).strip().upper() or 'UNKNOWN'
    overlay = doc.get('overlay') or {}
    peer = overlay.get('peer')
    bind = overlay.get('bind')
    rtt = (doc.get('transport') or {}).get('rtt_est_ms')
    if isinstance(rtt, (int, float)):
        return f'{state} peer={peer} bind={bind} rtt_est_ms={rtt:.1f}'
    return f'{state} peer={peer} bind={bind}'


def wait_status_connected(admin_port: int, timeout: float = 30.0, label: str = '') -> dict:
    
    end = time.time() + timeout
    last = None
    last_rendered = None

    while time.time() < end:
        try:
            last = try_get_status(admin_port)
            rendered = fmt_state_doc(last)
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
            if last is not None and status_state(last) == 'CONNECTED':
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} CONNECTED reached')
                return last
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
        time.sleep(0.5)

    raise RuntimeError(f'Port {admin_port} did not reach CONNECTED; last={last!r}')

def wait_status_connected_proc(proc: Proc, log_dir: Path, timeout: float = 30.0, label: str = '') -> Proc:
    
    end = time.time() + timeout
    last = None
    last_rendered = None

    while time.time() < end:
        proc = ensure_proc_up(proc, log_dir)

        try:
            last = try_get_status(proc.admin_port or 0)
            rendered = fmt_state_doc(last)
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={proc.admin_port} {rendered}')
                last_rendered = rendered
            if last is not None and status_state(last) == 'CONNECTED':
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={proc.admin_port} CONNECTED reached')
                return proc
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={proc.admin_port} {rendered}')
                last_rendered = rendered
        time.sleep(0.5)

    raise RuntimeError(f'Proc {proc.name} did not reach CONNECTED; last={last!r}')


def wait_status_not_connected(admin_port: int, timeout: float = 30.0, label: str = '') -> dict:
    
    end = time.time() + timeout
    last = None
    last_rendered = None

    while time.time() < end:
        try:
            last = try_get_status(admin_port)
            rendered = fmt_state_doc(last)
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
            if last is None:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} NOT_CONNECTED reached via STATUS_503')
                return {"peer_state": "STATUS_503"}
            if status_state(last) != 'CONNECTED':
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} NOT_CONNECTED reached')
                return last
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
        time.sleep(0.5)

    raise RuntimeError(f'Port {admin_port} stayed CONNECTED for {timeout}s; last={last!r}')


def wait_status_failed(
    admin_port: int,
    *,
    timeout: float = 30.0,
    label: str = '',
    reason: Optional[str] = None,
) -> dict:
    end = time.time() + timeout
    last = None
    last_rendered = None

    while time.time() < end:
        try:
            last = try_get_status(admin_port)
            rendered = fmt_state_doc(last)
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
            if last is not None and status_state(last) == 'FAILED':
                if reason is None or str(last.get('connection_failure_reason') or '') == reason:
                    who = f' {label}' if label else ''
                    log.info(f'[STATUS]{who} port={admin_port} FAILED reached')
                    return last
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_rendered:
                who = f' {label}' if label else ''
                log.info(f'[STATUS]{who} port={admin_port} {rendered}')
                last_rendered = rendered
        time.sleep(0.5)

    raise RuntimeError(f'Port {admin_port} did not reach FAILED; last={last!r}')


def wait_any_status_failed(
    admin_ports: list[int],
    *,
    timeout: float = 30.0,
    reason: Optional[str] = None,
) -> tuple[int, dict]:
    end = time.time() + timeout
    last_by_port: dict[int, Optional[dict]] = {port: None for port in admin_ports}

    while time.time() < end:
        for port in admin_ports:
            try:
                doc = try_get_status(port)
            except Exception:
                doc = None
            last_by_port[port] = doc
            if doc is None or status_state(doc) != 'FAILED':
                continue
            if reason is None or str(doc.get('connection_failure_reason') or '') == reason:
                log.info(f'[STATUS] port={port} FAILED reached via any-port wait')
                return port, doc
        time.sleep(0.5)

    raise RuntimeError(f'Ports {admin_ports!r} did not reach FAILED; last={last_by_port!r}')


def wait_log_contains(log_path: Path, needle: str, timeout: float = 10.0) -> str:
    end = time.time() + timeout
    last = ''
    while time.time() < end:
        text = log_path.read_text(errors='replace') if log_path.exists() else ''
        if needle in text:
            return text
        last = text[-4000:]
        time.sleep(0.2)
    raise RuntimeError(f'Log {log_path.name} did not contain {needle!r}\n--- tail ---\n{last}')

def run_case(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
    case = materialize_case_ports(case, case_index)
    procs: List[Proc] = []
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    try:
        bounce.start()
        check_exact_bytes = case.name in EXACT_BYTES_CASES
        for name, cmd, env, admin_port in build_commands(case, log_dir, case_index, enable_admin=check_exact_bytes):
            proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
            procs.append(proc)
            time.sleep(0.5)
            assert_running(proc)
            if check_exact_bytes:
                wait_admin_up(proc.admin_port or 0, timeout=10.0)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        for proc in procs:
            assert_running(proc)

        if case.name.startswith('case01_'):
            for proc in procs:
                wait_peer_endpoint_visible(proc.admin_port or 0, timeout=10.0, label=proc.name, transport='myudp')

        if case.probe_proto == 'tcp':
            wait_tcp_listen(case.probe_host, case.probe_port, timeout=5.0)
        before_tcp_close = None
        if check_exact_bytes and case.probe_proto == 'tcp':
            expected_bytes = len(PAYLOAD_IN)
            admin_ports_with_name = [(proc.admin_port or 0, proc.name) for proc in procs]

            def _request_connections_before_close() -> None:
                for admin_port, proc_name in admin_ports_with_name:
                    wait_tcp_connections_exact_transferred_bytes(
                        admin_port,
                        expected_bytes=expected_bytes,
                        timeout=3.0,
                        label=f'{proc_name} before-close',
                    )

            before_tcp_close = _request_connections_before_close
        probe_timeout = 12.0 if case.name == 'case09_overlay_ws_ipv6' else 8.0
        wait_probe(case, timeout=probe_timeout, before_tcp_close=before_tcp_close)
        if check_exact_bytes:
            expected_bytes = len(PAYLOAD_IN)
            for proc in procs:
                wait_exact_transferred_bytes(
                    proc.admin_port or 0,
                    expected_bytes=expected_bytes,
                    timeout=8.0,
                    label=proc.name,
                )
    finally:
        for proc in reversed(procs):            
            stop_proc(proc)
        bounce.stop()


def _myudp_delay_loss_base_port(case_index: int) -> int:
    cached = ALLOCATED_MYUDP_DELAY_LOSS_BASE_PORTS.get(int(case_index))
    if cached is not None:
        return cached
    loopback_v4 = _loopback_ipv4_host(case_index)
    for offset in _case_port_offset_candidates(case_index, highest_static_port=40013):
        base_port = 36000 + offset
        ports = [
            base_port,
            base_port + 1,
            base_port + 2,
            base_port + 10,
            base_port + 11,
            base_port + 12,
            base_port + 13,
        ]
        if all(_can_bind_local_endpoint('udp', loopback_v4, port) for port in ports):
            ALLOCATED_MYUDP_DELAY_LOSS_BASE_PORTS[int(case_index)] = base_port
            return base_port
    raise RuntimeError(f'no myudp delay/loss port block available: case_index={case_index}')


def _wait_udp_probe_result(host: str, port: int, payload: bytes, *, bind_host: str = '127.0.0.1', timeout: float = 20.0) -> bytes:
    end = time.time() + timeout
    last_exc = None
    expected = response_payload(payload)
    while time.time() < end:
        try:
            got = probe_udp(host, port, bind_host, payload, timeout=min(2.5, max(0.5, end - time.time())))
            if got == expected:
                return got
            last_exc = RuntimeError(f'unexpected UDP reply: {got!r} != {expected!r}')
        except Exception as e:
            last_exc = e
        time.sleep(0.2)
    raise RuntimeError(f'UDP probe to {host}:{port} failed for payload len={len(payload)}: {last_exc!r}')


def run_case_myudp_delay_loss(loss_case: MyudpDelayLossCase, log_dir: Path, case_index: int) -> None:
    base_port = _myudp_delay_loss_base_port(case_index)
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(case_index)
    server_overlay_port = base_port
    proxy_listen_port = base_port + 1
    proxy_forward_port = base_port + 2
    client_probe_port = base_port + 10
    server_probe_port = base_port + 11
    server_target_port = base_port + 12
    client_target_port = base_port + 13
    server_admin, client_admin = alloc_admin_ports(case_index)

    bounce_server = BounceBackServer(
        name=f'{loss_case.name}_server_bounce',
        proto='udp',
        bind_host=loopback_v4,
        port=server_target_port,
        log_path=log_dir / f'{loss_case.name}_server_bounce.log',
    )
    bounce_client = BounceBackServer(
        name=f'{loss_case.name}_client_bounce',
        proto='udp',
        bind_host=loopback_v4,
        port=client_target_port,
        log_path=log_dir / f'{loss_case.name}_client_bounce.log',
    )
    proxy = UdpDelayLossProxy(
        name=loss_case.name,
        listen_host=loopback_v4,
        listen_port=proxy_listen_port,
        upstream_host=loopback_v4,
        upstream_port=server_overlay_port,
        forward_bind_host=loopback_v4,
        forward_bind_port=proxy_forward_port,
        delay_ms=loss_case.delay_ms,
        log_path=log_dir / f'{loss_case.name}_proxy.log',
        drop_client_to_server_data=loss_case.drop_client_to_server_data,
        drop_client_to_server_control=loss_case.drop_client_to_server_control,
        drop_server_to_client_data=loss_case.drop_server_to_client_data,
        drop_server_to_client_control=loss_case.drop_server_to_client_control,
    )

    py = sys.executable
    missing_cfg = str(log_dir / f'{loss_case.name}_missing.cfg')
    server_cmd = [
        py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-bind', loopback_v4, '--udp-own-port', str(server_overlay_port),
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{loss_case.name}_bridge_server.txt'),
        '--config', missing_cfg, '--admin-web-port', '0',
    ] + admin_args(server_admin)
    client_cmd = [
        py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', loopback_v4, '--udp-peer-port', str(proxy_listen_port),
        '--udp-bind', loopback_v4, '--udp-own-port', '0',
        '--own-servers', f'udp,{client_probe_port},{loopback_v4},udp,{loopback_v4},{server_target_port}',
        '--remote-servers', f'udp,{server_probe_port},{loopback_v4},udp,{loopback_v4},{client_target_port}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{loss_case.name}_bridge_client.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ] + admin_args(client_admin)

    server_proc: Optional[Proc] = None
    client_proc: Optional[Proc] = None
    try:
        phase('1. Start bidirectional UDP bounce services and delay/loss proxy')
        bounce_server.start()
        bounce_client.start()
        proxy.start()

        phase('2. Start myudp bridge server and client through proxy')
        server_proc = start_proc(f'{loss_case.name}_bridge_server', server_cmd, log_dir, admin_port=server_admin)
        client_proc = start_proc(f'{loss_case.name}_bridge_client', client_cmd, log_dir, admin_port=client_admin)
        wait_admin_up(server_admin, timeout=10.0)
        wait_admin_up(client_admin, timeout=10.0)

        phase('3. Wait for both peers to become CONNECTED')
        server_proc, client_proc = wait_both_connected(server_proc, client_proc, log_dir, timeout=30.0)
        wait_peer_endpoint_visible(server_admin, timeout=12.0, label='server', transport='myudp')
        wait_peer_endpoint_visible(client_admin, timeout=12.0, label='client', transport='myudp')

        if loss_case.name == 'tc0_idle_connectivity':
            time.sleep(1.5)
            return

        phase('4. Execute bidirectional app probes across the delayed/lossy myudp overlay')
        if loss_case.name == 'tc5_concurrent_bidir':
            results: dict[str, bytes] = {}
            errors: list[tuple[str, Exception]] = []

            def _worker(label: str, port: int, payload: bytes, timeout: float) -> None:
                try:
                    results[label] = _wait_udp_probe_result(loopback_v4, port, payload, timeout=timeout)
                except Exception as e:
                    errors.append((label, e))

            threads = [
                threading.Thread(target=_worker, args=('client_to_server', client_probe_port, b'A' * 2000, 20.0), daemon=True),
                threading.Thread(target=_worker, args=('server_to_client', server_probe_port, b'C' * 1900, 20.0), daemon=True),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=25.0)
            if errors:
                raise RuntimeError(f'Concurrent myudp delay/loss probes failed: {errors!r}')
            if results.get('client_to_server') != response_payload(b'A' * 2000):
                raise RuntimeError(f'Unexpected concurrent client_to_server reply: {results.get("client_to_server")!r}')
            if results.get('server_to_client') != response_payload(b'C' * 1900):
                raise RuntimeError(f'Unexpected concurrent server_to_client reply: {results.get("server_to_client")!r}')
            return

        if loss_case.name == 'tc10_full_missed_list_pressure':
            payloads = [
                (f'Z{i:03d}-'.encode('ascii') + b'Z' * (32768 - 5))
                for i in range(16)
            ]
            results: list[Optional[bytes]] = [None] * len(payloads)
            errors: list[tuple[int, Exception]] = []

            def _bulk_worker(idx: int, payload: bytes) -> None:
                try:
                    results[idx] = _wait_udp_probe_result(loopback_v4, client_probe_port, payload, timeout=45.0)
                except Exception as e:
                    errors.append((idx, e))

            threads = [threading.Thread(target=_bulk_worker, args=(idx, payload), daemon=True) for idx, payload in enumerate(payloads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=50.0)
            if errors:
                raise RuntimeError(f'Bulk myudp delay/loss probes failed: {errors!r}')
            for idx, payload in enumerate(payloads):
                expected = response_payload(payload)
                if results[idx] != expected:
                    raise RuntimeError(
                        f'Bulk myudp delay/loss reply mismatch idx={idx}: '
                        f'got={results[idx]!r} expected={expected!r}'
                    )
            return

        target_port = client_probe_port if loss_case.direction == 'client_to_server' else server_probe_port
        timeout = 30.0 if len(loss_case.payload) >= 20 * 1024 or loss_case.drop_client_to_server_data else 15.0
        got = _wait_udp_probe_result(loopback_v4, target_port, loss_case.payload, timeout=timeout)
        expected = response_payload(loss_case.payload)
        if got != expected:
            raise RuntimeError(f'myudp delay/loss probe mismatch: got={got!r} expected={expected!r}')
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        proxy.stop()
        bounce_client.stop()
        bounce_server.stop()


def run_case_reconnect(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None, reconnect_timeout: float = 30.0) -> None:
    case = materialize_case_ports(case, case_index)
    reconnect_probe_timeout = 12.0
    
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    server_proc: Optional[Proc] = None
    client_proc: Optional[Proc] = None
    server_spec, client_spec = build_commands(case, log_dir, case_index, enable_admin=True)

    def start_server() -> Proc:
        nonlocal server_proc
        
        name, cmd, env, admin_port = server_spec
        server_proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        log.info(f'[PROC] started server pid={server_proc.popen.pid} admin_port={server_proc.admin_port}')
        return server_proc

    def start_client() -> Proc:
        nonlocal client_proc
        
        name, cmd, env, admin_port = client_spec
        client_proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)        
        time.sleep(0.5)
        assert_running(client_proc)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        log.info(f'[PROC] started client pid={client_proc.popen.pid} admin_port={client_proc.admin_port}')
        return client_proc

    try:
        phase('1. Start bounce-back server')
        bounce.start()
        phase('2. Start incoming bridge server')
        start_server()
        phase('3. Start outgoing bridge client')
        start_client()

        phase('Wait for both bridges to become CONNECTED')
        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(server_proc)
        assert_running(client_proc)
        server_proc, client_proc = wait_both_connected(
                server_proc,
                client_proc,
                log_dir,
                timeout=reconnect_timeout,
            )

        phase('4. Send probe 01 30 and expect 02 30')
        log.info('[PROBE] send=0130 expect=0230')
        if case.probe_proto == 'tcp':
            wait_tcp_listen(case.probe_host, case.probe_port, timeout=5.0)
        wait_probe(case, payload=b'\x01\x30', timeout=8.0)

        phase('5. Kill outgoing bridge client')
        stop_proc(client_proc)

        phase('6. Wait for incoming bridge server to become NOT_CONNECTED')
        wait_status_not_connected(server_proc.admin_port or 0, timeout=reconnect_timeout, label='server')
        
        phase('Disconnected window: probe 01 31 should fail')
        log.info('[PROBE] send=0131 expect=FAIL')
        expect_probe_failure(case, payload=b'\x01\x31', timeout=4.0)

        phase('7. Restart outgoing bridge client')
        start_client()
        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(client_proc)

        phase('Wait for both bridges to become CONNECTED again after client restart')
        assert server_proc is not None
        assert client_proc is not None
        server_proc, client_proc = wait_both_connected(
                server_proc,
                client_proc,
                log_dir,
                timeout=reconnect_timeout,
            )

        phase('8. Send probe 01 32 and expect 02 32')
        log.info('[PROBE] send=0132 expect=0232')
        wait_probe(case, payload=b'\x01\x32', timeout=reconnect_probe_timeout)

        phase('9. Kill incoming bridge server')
        stop_proc(server_proc)
        phase('10. Wait for outgoing bridge client to become NOT_CONNECTED')
        wait_status_not_connected(client_proc.admin_port or 0, timeout=reconnect_timeout, label='client')
        phase('Disconnected window: probe 01 33 should fail')
        log.info('[PROBE] send=0133 expect=FAIL')
        expect_probe_failure(case, payload=b'\x01\x33', timeout=4.0)

        phase('11. Restart incoming bridge server')
        start_server()
        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(server_proc)
        
        phase('Wait for both bridges to become CONNECTED again after server restart')
        assert server_proc is not None
        assert client_proc is not None
        server_proc, client_proc = wait_both_connected(
                server_proc,
                client_proc,
                log_dir,
                timeout=reconnect_timeout,
            )

        phase('12. Send probe 01 34 and expect 02 34')
        log.info('[PROBE] send=0134 expect=0234')
        def assert_case12_tcp_bytes_before_close() -> None:
            if case.probe_proto != 'tcp':
                return
            wait_tcp_connections_exact_transferred_bytes(
                server_proc.admin_port or 0,
                expected_bytes=2,
                timeout=4.0,
                label='server',
            )
            wait_tcp_connections_exact_transferred_bytes(
                client_proc.admin_port or 0,
                expected_bytes=2,
                timeout=4.0,
                label='client',
            )

        wait_probe(
            case,
            payload=b'\x01\x34',
            timeout=reconnect_probe_timeout,
            before_tcp_close=assert_case12_tcp_bytes_before_close,
        )

        phase('13. Verify per-connection metrics updated after 01 34 / 02 34 exchange')
        wait_connections_metrics_updated(server_proc.admin_port or 0, timeout=8.0, label='server')
        wait_connections_metrics_updated(client_proc.admin_port or 0, timeout=8.0, label='client')
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()


def run_case_two_peer_clients_listener(
    case: Case,
    log_dir: Path,
    case_index: int,
    settle_s: Optional[float] = None,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[List[str]] = None,
    client1_extra_args: Optional[List[str]] = None,
    client2_extra_args: Optional[List[str]] = None,
) -> None:
    case = materialize_secure_link_case_ports(case, secure_slot) if secure_slot is not None else materialize_case_ports(case, case_index)
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    server_proc: Optional[Proc] = None
    client1_proc: Optional[Proc] = None
    client2_proc: Optional[Proc] = None
    server_spec, client_spec = build_commands(case, log_dir, case_index, enable_admin=True)
    client2_admin_port = alloc_admin_port(
        {
            int(server_spec[3] or 0),
            int(client_spec[3] or 0),
        },
        case_index=case_index + 2,
        base=SECURE_LINK_ADMIN_BASE if secure_slot is not None else ADMIN_PORT_BASE,
    ) if secure_slot is not None else None

    try:
        phase('1. Start bounce-back server')
        bounce.start()

        phase('2. Start listener/server bridge')
        name, cmd, env, admin_port = server_spec
        if server_extra_args:
            cmd = list(cmd) + list(server_extra_args)
        server_proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)

        phase('3. Start client #1 bridge')
        c_name, c_cmd, c_env, c_admin_port = client_spec
        client_base_cmd = list(c_cmd)
        if client1_extra_args:
            c_cmd = client_base_cmd + list(client1_extra_args)
        client1_proc = start_proc(f'{case.name}_{c_name}_1', c_cmd, log_dir, env_extra=c_env, admin_port=c_admin_port)
        time.sleep(0.5)
        assert_running(client1_proc)
        wait_admin_up(client1_proc.admin_port or 0, timeout=10.0)

        phase('4. Start client #2 bridge with a different local UDP service port')
        second_client_local_port = case.probe_port + 1
        client2_cmd = _replace_own_servers_local_port(client_base_cmd, second_client_local_port)
        if client2_extra_args:
            client2_cmd += list(client2_extra_args)
        client2_cmd += ['--admin-web-port', '0']
        if client2_admin_port is not None:
            client2_cmd += admin_args(client2_admin_port)
        client2_proc = start_proc(f'{case.name}_{c_name}_2', client2_cmd, log_dir, env_extra=c_env, admin_port=client2_admin_port)
        time.sleep(0.5)
        assert_running(client2_proc)
        if client2_admin_port is not None:
            wait_admin_up(client2_proc.admin_port or 0, timeout=10.0)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(server_proc)
        assert_running(client1_proc)
        assert_running(client2_proc)

        phase('5. Verify both client-side UDP service ports are reachable through the listener')
        wait_probe(case, payload=b'\x01\x41', timeout=8.0)
        second_reply = probe_udp(case.probe_host, second_client_local_port, case.probe_bind, b'\x01\x42', timeout=2.0)
        if second_reply != b'\x02\x42':
            raise RuntimeError(f'Unexpected second client probe response: {second_reply!r}')

        phase('6. Verify listener admin status keeps Overlay Peer as n/a')
        status_doc = wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
        overlay_peer = str((status_doc.get('overlay') or {}).get('peer') or '').strip().lower()
        if overlay_peer != 'n/a':
            raise RuntimeError(f'Expected server overlay.peer to be n/a with two clients, got {overlay_peer!r}')

        phase('7. Verify listener admin peers API shows two peer sessions')
        peers_doc = wait_peers_count(server_proc.admin_port or 0, minimum_count=2, timeout=12.0, label='server')
        wait_listener_peer_rows_zeroed(server_proc.admin_port or 0, timeout=12.0, label='server')
        rows = list(peers_doc.get('peers') or [])
        with_ip = [row for row in rows if row.get('peer') not in (None, '', 'n/a')]
        if len(with_ip) < 2:
            raise RuntimeError(f'Expected >=2 peer rows with endpoint labels, got rows={rows!r}')

        if secure_slot is not None:
            transport = 'unknown'
            for argv in (case.bridge_client_args, case.bridge_server_args):
                try:
                    idx = argv.index('--overlay-transport')
                    transport = str(argv[idx + 1]).split(',')[0].strip().lower()
                    if transport:
                        break
                except Exception:
                    continue
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_status_secure_link_authenticated_peers(server_proc.admin_port or 0, minimum_count=2, timeout=12.0, label='server')
            wait_status_secure_link_state(client1_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client1', authenticated=True)
            wait_status_secure_link_state(client2_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client2', authenticated=True)
            wait_peer_secure_link_state(client1_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client1', transport=transport, authenticated=True)
            wait_peer_secure_link_state(client2_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client2', transport=transport, authenticated=True)
            wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport=transport, authenticated=True)
    finally:
        if client2_proc is not None:
            stop_proc(client2_proc)
        if client1_proc is not None:
            stop_proc(client1_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()



def run_case_concurrent_tcp_channels(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
    case = materialize_case_ports(case, case_index)
    if case.name == 'case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp':
        run_case_mixed_overlay_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
        return
    if case.name == 'case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp':
        run_case_myudp_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
        return
    if case.name == 'case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp':
        run_case_tcp_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
        return
    if case.name == 'case17_overlay_listener_quic_two_clients_concurrent_udp_tcp':
        run_case_quic_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
        return

    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    udp_bounces = [
        BounceBackServer(
            name=f'{case.name}_udp_bounce_1',
            proto='udp',
            bind_host=case.bounce_bind,
            port=case.bounce_port + 3,
            log_path=log_dir / f'{case.name}_udp_bounce_1.log',
        ),
        BounceBackServer(
            name=f'{case.name}_udp_bounce_2',
            proto='udp',
            bind_host=case.bounce_bind,
            port=case.bounce_port + 5,
            log_path=log_dir / f'{case.name}_udp_bounce_2.log',
        ),
    ] if case.name == 'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels' else []
    server_proc: Optional[Proc] = None
    client_proc: Optional[Proc] = None
    server_spec, client_spec = build_commands(case, log_dir, case_index, enable_admin=True)

    payloads = [
        b'\x01alpha',
        b'\x01bravo-bravo',
        b'\x01charlie' * 8,
        b'\x01delta' * 32,
        b'\x01echo' * 96,
    ]

    try:
        phase('1. Start bounce-back server')
        bounce.start()
        for udp_bounce in udp_bounces:
            udp_bounce.start()

        phase('2. Start incoming bridge server')
        s_name, s_cmd, s_env, s_admin_port = server_spec
        server_proc = start_proc(f'{case.name}_{s_name}', s_cmd, log_dir, env_extra=s_env, admin_port=s_admin_port)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)

        phase('3. Start outgoing bridge client')
        c_name, c_cmd, c_env, c_admin_port = client_spec
        client_proc = start_proc(f'{case.name}_{c_name}', c_cmd, log_dir, env_extra=c_env, admin_port=c_admin_port)
        time.sleep(0.5)
        assert_running(client_proc)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(server_proc)
        assert_running(client_proc)
        server_proc, client_proc = wait_both_connected(server_proc, client_proc, log_dir, timeout=30.0)

        phase('4. Establish 5 concurrent TCP channels and transfer different payloads')
        wait_tcp_listen(case.probe_host, case.probe_port, timeout=5.0)

        start_evt = threading.Event()
        release_close_evt = threading.Event()
        ready_for_poll_evt = threading.Event()
        ready_lock = threading.Lock()
        ready_count = 0
        results: list[Optional[bytes]] = [None] * len(payloads)
        errors: list[tuple[int, Exception]] = []

        def _before_close() -> None:
            nonlocal ready_count
            with ready_lock:
                ready_count += 1
                if ready_count == len(payloads):
                    ready_for_poll_evt.set()
            if not release_close_evt.wait(timeout=8.0):
                raise TimeoutError('Timed out waiting to release TCP channel close')

        def _worker(i: int, payload: bytes) -> None:
            try:
                start_evt.wait(timeout=5.0)
                reply = probe_tcp(
                    case.probe_host,
                    case.probe_port,
                    case.probe_bind,
                    payload,
                    timeout=4.0,
                    before_close=_before_close,
                )
                results[i] = reply
            except Exception as e:
                errors.append((i, e))

        threads = [threading.Thread(target=_worker, args=(idx, payload), daemon=True) for idx, payload in enumerate(payloads)]
        for t in threads:
            t.start()
        start_evt.set()

        try:
            if not ready_for_poll_evt.wait(timeout=8.0):
                raise RuntimeError('Timed out waiting for concurrent TCP channels before /api/connections polling')

            expected_lens = sorted(len(p) for p in payloads)
            rows_observed = False
            poll_end = time.time() + 3.0
            last_conn_docs: dict[str, dict] = {}
            while time.time() < poll_end:
                for proc in (server_proc, client_proc):
                    _code, conn_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/connections', timeout=1.5)
                    last_conn_docs[proc.name] = conn_doc
                    connected_rows = _connected_tcp_rows(conn_doc)
                    if len(connected_rows) != len(payloads):
                        continue
                    rx_lens = sorted(int(((row.get('stats') or {}).get('rx_bytes', 0) or 0)) for row in connected_rows)
                    tx_lens = sorted(int(((row.get('stats') or {}).get('tx_bytes', 0) or 0)) for row in connected_rows)
                    if rx_lens != expected_lens or tx_lens != expected_lens:
                        raise RuntimeError(
                            f'/api/connections per-connection byte mismatch for {proc.name}: '
                            f'rx={rx_lens} tx={tx_lens} expected={expected_lens}; doc={conn_doc!r}'
                        )
                    rows_observed = True
                    break
                if rows_observed:
                    break
                time.sleep(0.1)
            if not rows_observed:
                raise RuntimeError(
                    f'/api/connections did not expose {len(payloads)} active TCP rows before teardown; '
                    f'last_docs={last_conn_docs!r}'
                )
        finally:
            release_close_evt.set()
        for t in threads:
            t.join(timeout=8.0)

        if errors:
            state_dump: dict[str, object] = {}
            for proc in (server_proc, client_proc):
                if proc is None or not proc.admin_port:
                    continue
                try:
                    _code, conn_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/connections', timeout=1.5)
                    _sc, status_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/status', timeout=1.5)
                    state_dump[proc.name] = {
                        'connections': conn_doc,
                        'status': status_doc,
                    }
                except Exception as e:
                    state_dump[proc.name] = {'error': repr(e)}
            raise RuntimeError(
                f'Concurrent TCP channel probe errors: {errors!r}; '
                f'partial_results={results!r}; per_channel_state={state_dump!r}'
            )

        for idx, payload in enumerate(payloads):
            expected = response_payload(payload)
            got = results[idx]
            if got != expected:
                state_dump: dict[str, object] = {}
                for proc in (server_proc, client_proc):
                    if proc is None or not proc.admin_port:
                        continue
                    try:
                        _code, conn_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/connections', timeout=1.5)
                        _sc, status_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/status', timeout=1.5)
                        state_dump[proc.name] = {
                            'connections': conn_doc,
                            'status': status_doc,
                        }
                    except Exception as e:
                        state_dump[proc.name] = {'error': repr(e)}
                raise RuntimeError(
                    f'Channel {idx} data mismatch: sent_len={len(payload)} expected_len={len(expected)} '
                    f'got_len={(len(got) if got is not None else None)} got={got!r} expected={expected!r}; '
                    f'per_channel_state={state_dump!r}'
                )

        if sum(1 for item in results if item is not None) != len(payloads):
            raise RuntimeError(f'Expected {len(payloads)} successful TCP replies, got results={results!r}')

        phase('5. Probe additional UDP channels routed through the same overlay peer')
        if udp_bounces:
            udp_probe_1_port = case.bounce_port + 2
            udp_probe_2_port = case.bounce_port + 4
            udp_probe_1 = probe_udp(case.probe_host, udp_probe_1_port, case.probe_bind, b'\x01udp-one', timeout=2.0)
            udp_probe_2 = probe_udp(case.probe_host, udp_probe_2_port, case.probe_bind, b'\x01udp-two', timeout=2.0)
            if udp_probe_1 != b'\x02udp-one':
                raise RuntimeError(f'Unexpected UDP probe response on {udp_probe_1_port}: {udp_probe_1!r}')
            if udp_probe_2 != b'\x02udp-two':
                raise RuntimeError(f'Unexpected UDP probe response on {udp_probe_2_port}: {udp_probe_2!r}')

        phase('6. Validate /api/connections and /api/status traffic counters')
        expected_bytes = sum(len(p) for p in payloads)
        for proc in (server_proc, client_proc):
            end = time.time() + 8.0
            while time.time() < end:
                _status_code, status_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/status', timeout=1.5)
                app_traffic = (status_doc.get('traffic') or {}).get('app') or {}
                app_rx = int(app_traffic.get('rx_total_bytes', 0) or 0)
                app_tx = int(app_traffic.get('tx_total_bytes', 0) or 0)
                if app_rx >= expected_bytes and app_tx >= expected_bytes:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError(
                    f'/api/status app totals too small for {proc.name}: '
                    f'rx={app_rx} tx={app_tx} expected_at_least={expected_bytes}'
                )

            _code, conn_doc = fetch_json(f'http://127.0.0.1:{proc.admin_port}/api/connections', timeout=1.5)
            tcp_rx, tcp_tx = _tcp_connections_totals(conn_doc)
            if (tcp_rx != 0 or tcp_tx != 0) and (tcp_rx < expected_bytes or tcp_tx < expected_bytes):
                raise RuntimeError(
                    f'/api/connections tcp totals too small for {proc.name}: '
                    f'rx={tcp_rx} tx={tcp_tx} expected_at_least={expected_bytes}'
                )
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for udp_bounce in udp_bounces:
            udp_bounce.stop()
        bounce.stop()


def wait_tcp_socket_closed(sock: socket.socket, timeout: float = 8.0) -> None:
    end = time.time() + timeout
    last_error: Optional[Exception] = None
    while time.time() < end:
        try:
            sock.settimeout(0.5)
            data = sock.recv(1)
            if data == b'':
                return
        except socket.timeout as e:
            last_error = e
        except OSError:
            return
        try:
            sock.sendall(b'\x01close-check')
        except OSError:
            return
        time.sleep(0.2)
    raise RuntimeError(f'TCP socket stayed open after peer server restart; last_error={last_error!r}')


def run_case_server_restart_closes_tcp_preserves_udp(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
    case = materialize_case_ports(case, case_index)
    if case.name != 'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels':
        raise RuntimeError(f'Unsupported restart-behavior case: {case.name}')

    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    udp_bounces = [
        BounceBackServer(
            name=f'{case.name}_udp_bounce_1',
            proto='udp',
            bind_host=case.bounce_bind,
            port=case.bounce_port + 3,
            log_path=log_dir / f'{case.name}_udp_bounce_1.log',
        ),
        BounceBackServer(
            name=f'{case.name}_udp_bounce_2',
            proto='udp',
            bind_host=case.bounce_bind,
            port=case.bounce_port + 5,
            log_path=log_dir / f'{case.name}_udp_bounce_2.log',
        ),
    ]
    server_proc: Optional[Proc] = None
    client_proc: Optional[Proc] = None
    tcp_sock: Optional[socket.socket] = None
    udp_sock: Optional[socket.socket] = None
    server_spec, client_spec = build_commands(case, log_dir, case_index, enable_admin=True)

    def start_server() -> Proc:
        nonlocal server_proc
        name, cmd, env, admin_port = server_spec
        server_proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        return server_proc

    try:
        phase('1. Start TCP and UDP bounce-back services')
        bounce.start()
        for udp_bounce in udp_bounces:
            udp_bounce.start()

        phase('2. Start bridge server and peer client')
        start_server()
        c_name, c_cmd, c_env, c_admin_port = client_spec
        client_proc = start_proc(f'{case.name}_{c_name}', c_cmd, log_dir, env_extra=c_env, admin_port=c_admin_port)
        time.sleep(0.5)
        assert_running(client_proc)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert server_proc is not None
        assert client_proc is not None
        server_proc, client_proc = wait_both_connected(server_proc, client_proc, log_dir, timeout=30.0)

        phase('3. Open one TCP channel and one UDP mapping through the peer client')
        wait_tcp_listen(case.probe_host, case.probe_port, timeout=5.0)
        tcp_family = socket.AF_INET6 if ':' in case.probe_host else socket.AF_INET
        tcp_sock = socket.socket(tcp_family, socket.SOCK_STREAM)
        if case.probe_bind is not None:
            tcp_sock.bind((case.probe_bind, 0))
        tcp_sock.settimeout(2.0)
        tcp_sock.connect((case.probe_host, case.probe_port))
        tcp_sock.sendall(b'\x01tcp-before-restart')
        tcp_reply = tcp_sock.recv(4096)
        if tcp_reply != b'\x02tcp-before-restart':
            raise RuntimeError(f'Unexpected TCP reply before restart: {tcp_reply!r}')

        udp_family = socket.AF_INET6 if ':' in case.probe_host else socket.AF_INET
        udp_sock = socket.socket(udp_family, socket.SOCK_DGRAM)
        if case.probe_bind is not None:
            udp_sock.bind((case.probe_bind, 0))
        udp_sock.settimeout(2.0)
        udp_local_port = case.bounce_port + 2
        udp_sock.sendto(b'\x01udp-before-restart', (case.probe_host, udp_local_port))
        udp_reply, _addr = udp_sock.recvfrom(4096)
        if udp_reply != b'\x02udp-before-restart':
            raise RuntimeError(f'Unexpected UDP reply before restart: {udp_reply!r}')
        udp_source_port = int(udp_sock.getsockname()[1])

        wait_connection_rows(
            client_proc.admin_port or 0,
            'tcp',
            local_port=case.probe_port,
            state='connected',
            minimum_count=1,
            timeout=8.0,
            label='client',
        )
        initial_udp_rows = wait_connection_rows(
            client_proc.admin_port or 0,
            'udp',
            local_port=udp_local_port,
            state='connected',
            source_port=udp_source_port,
            minimum_count=1,
            timeout=8.0,
            label='client',
        )
        initial_udp_row = initial_udp_rows[0]

        phase('4. Restart the peer server and observe peer client connection state')
        stop_proc(server_proc)
        wait_status_not_connected(client_proc.admin_port or 0, timeout=30.0, label='client')
        wait_connection_rows_gone(
            client_proc.admin_port or 0,
            'tcp',
            local_port=case.probe_port,
            state='connected',
            timeout=20.0,
            label='client',
        )
        wait_tcp_socket_closed(tcp_sock, timeout=8.0)

        phase('5. Restart the peer server and wait for reconnect')
        start_server()
        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert server_proc is not None
        assert client_proc is not None
        server_proc, client_proc = wait_both_connected(server_proc, client_proc, log_dir, timeout=30.0)

        phase('6. Verify UDP resumes on the peer client with the same local source port')
        udp_sock.sendto(b'\x01udp-after-restart', (case.probe_host, udp_local_port))
        udp_reply_after, _addr = udp_sock.recvfrom(4096)
        if udp_reply_after != b'\x02udp-after-restart':
            raise RuntimeError(f'Unexpected UDP reply after restart: {udp_reply_after!r}')
        resumed_udp_rows = wait_connection_rows(
            client_proc.admin_port or 0,
            'udp',
            local_port=udp_local_port,
            state='connected',
            source_port=udp_source_port,
            minimum_count=1,
            timeout=8.0,
            label='client',
        )
        resumed_udp_row = resumed_udp_rows[0]
        if int(resumed_udp_row.get('local_port') or -1) != int(initial_udp_row.get('local_port') or -1):
            raise RuntimeError(
                f'UDP local port changed across peer server restart: '
                f'before={initial_udp_row!r} after={resumed_udp_row!r}'
            )
        if _row_source_port(resumed_udp_row) != _row_source_port(initial_udp_row):
            raise RuntimeError(
                f'UDP source port changed across peer server restart: '
                f'before={initial_udp_row!r} after={resumed_udp_row!r}'
            )

        phase('7. Verify the test harness can open a new TCP client socket after reconnect')
        # This is a brand-new application-side TCP connect from the test harness.
        # The pre-restart TCP socket is expected to stay closed and is not resumed.
        wait_probe(case, payload=b'\x01tcp-after-restart', timeout=8.0)
    finally:
        if udp_sock is not None:
            try:
                udp_sock.close()
            except Exception:
                pass
        if tcp_sock is not None:
            try:
                tcp_sock.close()
            except Exception:
                pass
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for udp_bounce in udp_bounces:
            udp_bounce.stop()
        bounce.stop()


def run_case_mixed_overlay_two_clients_concurrent_udp_tcp(
    case: Case,
    log_dir: Path,
    case_index: int,
    settle_s: Optional[float] = None,
) -> None:
    base_tcp_port = case.bounce_port
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(case_index)
    ws_peer_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), case_index)
    udp_peer_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'myudp'), case_index)
    own_udp_bounces = [
        BounceBackServer(name=f'{case.name}_own_udp_1', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 20, log_path=log_dir / f'{case.name}_own_udp_1.log'),
        BounceBackServer(name=f'{case.name}_own_udp_2', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 21, log_path=log_dir / f'{case.name}_own_udp_2.log'),
        BounceBackServer(name=f'{case.name}_own_udp_3', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 22, log_path=log_dir / f'{case.name}_own_udp_3.log'),
        BounceBackServer(name=f'{case.name}_own_udp_4', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 23, log_path=log_dir / f'{case.name}_own_udp_4.log'),
    ]
    tcp_bounces = [
        BounceBackServer(name=f'{case.name}_tcp_{idx + 1}', proto='tcp', bind_host=case.bounce_bind, port=base_tcp_port + idx, log_path=log_dir / f'{case.name}_tcp_{idx + 1}.log')
        for idx in range(8)
    ]

    server_proc: Optional[Proc] = None
    ws_client_proc: Optional[Proc] = None
    udp_client_proc: Optional[Proc] = None
    server_admin, ws_client_admin = alloc_admin_ports(case_index)
    udp_client_admin = alloc_admin_port({server_admin, ws_client_admin})
    ws_peer_port = _listener_overlay_port(case, 'ws')
    udp_peer_port = _listener_overlay_port(case, 'myudp')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += admin_args(server_admin)

    ws_client_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'ws',
        '--ws-peer', ws_peer_host, '--ws-peer-port', str(ws_peer_port), '--ws-bind', loopback_v4, '--ws-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 30},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_ws.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    ws_client_cmd += admin_args(ws_client_admin)

    udp_client_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', udp_peer_host, '--udp-peer-port', str(udp_peer_port), '--udp-bind', loopback_v4, '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 34},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 7}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_myudp.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    udp_client_cmd += admin_args(udp_client_admin)

    tcp_specs = [
        ('ws-own-tcp-1', base_tcp_port + 32, b'\x01ws-own-tcp-1'),
        ('ws-own-tcp-2', base_tcp_port + 33, b'\x01ws-own-tcp-2' * 2),
        ('ws-remote-tcp-1', base_tcp_port + 40, b'\x01ws-remote-tcp-1' * 3),
        ('ws-remote-tcp-2', base_tcp_port + 41, b'\x01ws-remote-tcp-2' * 4),
        ('udp-own-tcp-1', base_tcp_port + 36, b'\x01udp-own-tcp-1' * 5),
        ('udp-own-tcp-2', base_tcp_port + 37, b'\x01udp-own-tcp-2' * 6),
        ('udp-remote-tcp-1', base_tcp_port + 44, b'\x01udp-remote-tcp-1' * 7),
        ('udp-remote-tcp-2', base_tcp_port + 45, b'\x01udp-remote-tcp-2' * 8),
    ]
    udp_specs = [
        (base_tcp_port + 30, b'\x01ws-own-udp-1'),
        (base_tcp_port + 31, b'\x01ws-own-udp-2' * 2),
        (base_tcp_port + 34, b'\x01udp-own-udp-1' * 3),
        (base_tcp_port + 35, b'\x01udp-own-udp-2' * 4),
    ]

    try:
        phase('1. Start UDP/TCP bounce-back services')
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.start()

        phase('2. Start bridge listener with ws+myudp overlay transports')
        server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, log_dir, env_extra=case.server_env, admin_port=server_admin)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_admin, timeout=10.0)

        phase('3. Start websocket and myudp peer clients')
        ws_client_proc = start_proc(f'{case.name}_bridge_client_ws', ws_client_cmd, log_dir, env_extra=case.client_env, admin_port=ws_client_admin)
        udp_client_proc = start_proc(f'{case.name}_bridge_client_myudp', udp_client_cmd, log_dir, env_extra=case.client_env, admin_port=udp_client_admin)
        time.sleep(0.8)
        assert_running(ws_client_proc)
        assert_running(udp_client_proc)
        wait_admin_up(ws_client_admin, timeout=10.0)
        wait_admin_up(udp_client_admin, timeout=10.0)
        ws_client_proc = ensure_proc_up(ws_client_proc, log_dir)
        udp_client_proc = ensure_proc_up(udp_client_proc, log_dir)
        server_proc = ensure_proc_up(server_proc, log_dir)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)

        phase('4. Open 8 concurrent TCP channels and hold them during /api/connections polling')
        start_evt = threading.Event()
        release_close_evt = threading.Event()
        ready_for_poll_evt = threading.Event()
        ready_lock = threading.Lock()
        ready_count = 0
        tcp_results: list[Optional[bytes]] = [None] * len(tcp_specs)
        tcp_errors: list[tuple[int, Exception]] = []

        def _before_close() -> None:
            nonlocal ready_count
            with ready_lock:
                ready_count += 1
                if ready_count == len(tcp_specs):
                    ready_for_poll_evt.set()
            if not release_close_evt.wait(timeout=8.0):
                raise TimeoutError('Timed out waiting to release TCP channel close')

        def _tcp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                start_evt.wait(timeout=5.0)
                tcp_results[idx] = probe_tcp(case.probe_host, target_port, case.probe_bind, payload, timeout=4.0, before_close=_before_close)
            except Exception as e:
                tcp_errors.append((idx, e))

        tcp_threads = [threading.Thread(target=_tcp_worker, args=(idx, port, payload), daemon=True) for idx, (_name, port, payload) in enumerate(tcp_specs)]
        for t in tcp_threads:
            t.start()
        start_evt.set()

        try:
            poll_end = time.time() + 8.0
            observed = False
            last_docs: dict[str, dict] = {}
            while time.time() < poll_end:
                _code, conn_doc = fetch_json(f'http://127.0.0.1:{server_admin}/api/connections', timeout=1.5)
                last_docs['server'] = conn_doc
                connected_rows = _connected_tcp_rows(conn_doc)
                if len(connected_rows) == 8:
                    observed = True
                    break
                time.sleep(0.1)
            if not observed:
                raise RuntimeError(
                    f'/api/connections on server did not expose 8 active TCP rows; '
                    f'ready_count={ready_count}/{len(tcp_specs)} last_docs={last_docs!r}'
                )
        finally:
            release_close_evt.set()
        for t in tcp_threads:
            t.join(timeout=8.0)
        if tcp_errors:
            raise RuntimeError(f'Concurrent TCP probes failed: {tcp_errors!r}')

        phase('5. Verify all TCP replies and 4 concurrent UDP probes with unique payload lengths')
        for idx, (_name, _port, payload) in enumerate(tcp_specs):
            expected = response_payload(payload)
            if tcp_results[idx] != expected:
                raise RuntimeError(f'TCP channel {idx} mismatch: got={tcp_results[idx]!r} expected={expected!r}')

        udp_results: list[Optional[bytes]] = [None] * len(udp_specs)
        udp_errors: list[tuple[int, Exception]] = []

        def _udp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                udp_results[idx] = probe_udp(case.probe_host, target_port, case.probe_bind, payload, timeout=2.0)
            except Exception as e:
                udp_errors.append((idx, e))

        udp_threads = [threading.Thread(target=_udp_worker, args=(idx, port, payload), daemon=True) for idx, (port, payload) in enumerate(udp_specs)]
        for t in udp_threads:
            t.start()
        for t in udp_threads:
            t.join(timeout=4.0)
        if udp_errors:
            raise RuntimeError(f'Concurrent UDP probes failed: {udp_errors!r}')
        for idx, (_port, payload) in enumerate(udp_specs):
            expected = response_payload(payload)
            if udp_results[idx] != expected:
                raise RuntimeError(f'UDP channel {idx} mismatch: got={udp_results[idx]!r} expected={expected!r}')

    finally:
        if udp_client_proc is not None:
            stop_proc(udp_client_proc)
        if ws_client_proc is not None:
            stop_proc(ws_client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.stop()


def run_case_myudp_two_clients_concurrent_udp_tcp(
    case: Case,
    log_dir: Path,
    case_index: int,
    settle_s: Optional[float] = None,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[List[str]] = None,
    client1_extra_args: Optional[List[str]] = None,
    client2_extra_args: Optional[List[str]] = None,
) -> None:
    base_tcp_port = case.bounce_port
    loopback_key = _secure_link_loopback_key(secure_slot) if secure_slot is not None else case_index
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(loopback_key)
    udp_peer_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'myudp'), loopback_key)
    own_udp_bounces = [
        BounceBackServer(name=f'{case.name}_own_udp_1', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 20, log_path=log_dir / f'{case.name}_own_udp_1.log'),
        BounceBackServer(name=f'{case.name}_own_udp_2', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 21, log_path=log_dir / f'{case.name}_own_udp_2.log'),
        BounceBackServer(name=f'{case.name}_own_udp_3', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 22, log_path=log_dir / f'{case.name}_own_udp_3.log'),
        BounceBackServer(name=f'{case.name}_own_udp_4', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 23, log_path=log_dir / f'{case.name}_own_udp_4.log'),
    ]
    tcp_bounces = [
        BounceBackServer(name=f'{case.name}_tcp_{idx + 1}', proto='tcp', bind_host=case.bounce_bind, port=base_tcp_port + idx, log_path=log_dir / f'{case.name}_tcp_{idx + 1}.log')
        for idx in range(8)
    ]

    server_proc: Optional[Proc] = None
    client1_proc: Optional[Proc] = None
    client2_proc: Optional[Proc] = None
    admin_base = SECURE_LINK_ADMIN_BASE if secure_slot is not None else ADMIN_PORT_BASE
    server_admin, client1_admin = alloc_admin_ports(case_index, base=admin_base)
    client2_admin = alloc_admin_port({server_admin, client1_admin}, case_index=case_index + 2, base=admin_base)
    udp_peer_port = _listener_overlay_port(case, 'myudp')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += list(server_extra_args or [])
    server_cmd += admin_args(server_admin)

    client1_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', udp_peer_host, '--udp-peer-port', str(udp_peer_port), '--udp-bind', loopback_v4, '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 30},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_1.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client1_cmd += list(client1_extra_args or [])
    client1_cmd += admin_args(client1_admin)

    client2_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', udp_peer_host, '--udp-peer-port', str(udp_peer_port), '--udp-bind', loopback_v4, '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 34},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 7}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_2.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client2_cmd += list(client2_extra_args or [])
    client2_cmd += admin_args(client2_admin)

    tcp_specs = [
        ('client1-own-tcp-1', base_tcp_port + 32, b'\x01client1-own-tcp-1'),
        ('client1-own-tcp-2', base_tcp_port + 33, b'\x01client1-own-tcp-2' * 2),
        ('client1-remote-tcp-1', base_tcp_port + 40, b'\x01client1-remote-tcp-1' * 3),
        ('client1-remote-tcp-2', base_tcp_port + 41, b'\x01client1-remote-tcp-2' * 4),
        ('client2-own-tcp-1', base_tcp_port + 36, b'\x01client2-own-tcp-1' * 5),
        ('client2-own-tcp-2', base_tcp_port + 37, b'\x01client2-own-tcp-2' * 6),
        ('client2-remote-tcp-1', base_tcp_port + 44, b'\x01client2-remote-tcp-1' * 7),
        ('client2-remote-tcp-2', base_tcp_port + 45, b'\x01client2-remote-tcp-2' * 8),
    ]
    udp_specs = [
        (base_tcp_port + 30, b'\x01client1-own-udp-1'),
        (base_tcp_port + 31, b'\x01client1-own-udp-2' * 2),
        (base_tcp_port + 34, b'\x01client2-own-udp-1' * 3),
        (base_tcp_port + 35, b'\x01client2-own-udp-2' * 4),
    ]

    try:
        phase('1. Start UDP/TCP bounce-back services')
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.start()

        phase('2. Start bridge listener with myudp overlay transport')
        server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, log_dir, env_extra=case.server_env, admin_port=server_admin)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_admin, timeout=10.0)

        phase('3. Start two myudp peer clients')
        client1_proc = start_proc(f'{case.name}_bridge_client_1', client1_cmd, log_dir, env_extra=case.client_env, admin_port=client1_admin)
        client2_proc = start_proc(f'{case.name}_bridge_client_2', client2_cmd, log_dir, env_extra=case.client_env, admin_port=client2_admin)
        time.sleep(0.8)
        assert_running(client1_proc)
        assert_running(client2_proc)
        wait_admin_up(client1_admin, timeout=10.0)
        wait_admin_up(client2_admin, timeout=10.0)
        client1_proc = ensure_proc_up(client1_proc, log_dir)
        client2_proc = ensure_proc_up(client2_proc, log_dir)
        server_proc = ensure_proc_up(server_proc, log_dir)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)

        phase('4. Verify both myudp peer clients connect to the same listener')
        wait_peers_count(server_admin, minimum_count=2, timeout=12.0, label='server')
        wait_listener_peer_rows_zeroed(server_admin, timeout=12.0, label='server')
        wait_distinct_peer_endpoints(server_admin, transport='myudp', minimum_count=2, timeout=12.0, label='server')
        if secure_slot is not None:
            wait_status_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=2, timeout=12.0, label='server')
            wait_status_secure_link_state(client1_admin, expected_state='authenticated', timeout=12.0, label='client1', authenticated=True)
            wait_status_secure_link_state(client2_admin, expected_state='authenticated', timeout=12.0, label='client2', authenticated=True)
            wait_peer_secure_link_state(client1_admin, expected_state='authenticated', timeout=12.0, label='client1', transport='myudp', authenticated=True)
            wait_peer_secure_link_state(client2_admin, expected_state='authenticated', timeout=12.0, label='client2', transport='myudp', authenticated=True)
            wait_peer_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', transport='myudp', authenticated=True)

        phase('5. Open 8 concurrent TCP channels and hold them during /api/connections polling')
        start_evt = threading.Event()
        release_close_evt = threading.Event()
        ready_for_poll_evt = threading.Event()
        ready_lock = threading.Lock()
        ready_count = 0
        tcp_results: list[Optional[bytes]] = [None] * len(tcp_specs)
        tcp_errors: list[tuple[int, Exception]] = []

        def _before_close() -> None:
            nonlocal ready_count
            with ready_lock:
                ready_count += 1
                if ready_count == len(tcp_specs):
                    ready_for_poll_evt.set()
            if not release_close_evt.wait(timeout=8.0):
                raise TimeoutError('Timed out waiting to release TCP channel close')

        def _tcp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                start_evt.wait(timeout=5.0)
                tcp_results[idx] = probe_tcp(case.probe_host, target_port, case.probe_bind, payload, timeout=4.0, before_close=_before_close)
            except Exception as e:
                tcp_errors.append((idx, e))

        tcp_threads = [threading.Thread(target=_tcp_worker, args=(idx, port, payload), daemon=True) for idx, (_name, port, payload) in enumerate(tcp_specs)]
        for t in tcp_threads:
            t.start()
        start_evt.set()

        try:
            poll_end = time.time() + 8.0
            observed = False
            last_docs: dict[str, dict] = {}
            while time.time() < poll_end:
                _code, conn_doc = fetch_json(f'http://127.0.0.1:{server_admin}/api/connections', timeout=1.5)
                last_docs['server'] = conn_doc
                connected_rows = _connected_tcp_rows(conn_doc)
                if len(connected_rows) == 8:
                    observed = True
                    break
                time.sleep(0.1)
            if not observed:
                raise RuntimeError(
                    f'/api/connections on server did not expose 8 active TCP rows; '
                    f'ready_count={ready_count}/{len(tcp_specs)} last_docs={last_docs!r}'
                )
        finally:
            release_close_evt.set()

        for t in tcp_threads:
            t.join(timeout=8.0)
        if tcp_errors:
            raise RuntimeError(f'Concurrent TCP probes failed: {tcp_errors!r}')

        phase('6. Verify all TCP replies and 4 concurrent UDP probes with unique payload lengths')
        for idx, (_name, _port, payload) in enumerate(tcp_specs):
            expected = response_payload(payload)
            if tcp_results[idx] != expected:
                raise RuntimeError(f'TCP channel {idx} mismatch: got={tcp_results[idx]!r} expected={expected!r}')

        udp_results: list[Optional[bytes]] = [None] * len(udp_specs)
        udp_errors: list[tuple[int, Exception]] = []

        def _udp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                udp_results[idx] = probe_udp(case.probe_host, target_port, case.probe_bind, payload, timeout=2.0)
            except Exception as e:
                udp_errors.append((idx, e))

        udp_threads = [threading.Thread(target=_udp_worker, args=(idx, port, payload), daemon=True) for idx, (port, payload) in enumerate(udp_specs)]
        for t in udp_threads:
            t.start()
        for t in udp_threads:
            t.join(timeout=4.0)
        if udp_errors:
            raise RuntimeError(f'Concurrent UDP probes failed: {udp_errors!r}')
        for idx, (_port, payload) in enumerate(udp_specs):
            expected = response_payload(payload)
            if udp_results[idx] != expected:
                raise RuntimeError(f'UDP channel {idx} mismatch: got={udp_results[idx]!r} expected={expected!r}')
        if secure_slot is not None:
            wait_peer_myudp_transmit_stats(server_admin, minimum_count=2, timeout=12.0, label='server', transport='myudp')
            wait_peer_myudp_transmit_stats(client1_admin, minimum_count=1, timeout=12.0, label='client1', transport='myudp')
            wait_peer_myudp_transmit_stats(client2_admin, minimum_count=1, timeout=12.0, label='client2', transport='myudp')
    finally:
        if client2_proc is not None:
            stop_proc(client2_proc)
        if client1_proc is not None:
            stop_proc(client1_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.stop()


def run_case_tcp_two_clients_concurrent_udp_tcp(
    case: Case,
    log_dir: Path,
    case_index: int,
    settle_s: Optional[float] = None,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[List[str]] = None,
    client1_extra_args: Optional[List[str]] = None,
    client2_extra_args: Optional[List[str]] = None,
) -> None:
    base_tcp_port = case.bounce_port
    loopback_key = _secure_link_loopback_key(secure_slot) if secure_slot is not None else case_index
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(loopback_key)
    tcp_peer_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'tcp'), loopback_key)
    own_udp_bounces = [
        BounceBackServer(name=f'{case.name}_own_udp_1', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 20, log_path=log_dir / f'{case.name}_own_udp_1.log'),
        BounceBackServer(name=f'{case.name}_own_udp_2', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 21, log_path=log_dir / f'{case.name}_own_udp_2.log'),
        BounceBackServer(name=f'{case.name}_own_udp_3', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 22, log_path=log_dir / f'{case.name}_own_udp_3.log'),
        BounceBackServer(name=f'{case.name}_own_udp_4', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 23, log_path=log_dir / f'{case.name}_own_udp_4.log'),
    ]
    tcp_bounces = [
        BounceBackServer(name=f'{case.name}_tcp_{idx + 1}', proto='tcp', bind_host=case.bounce_bind, port=base_tcp_port + idx, log_path=log_dir / f'{case.name}_tcp_{idx + 1}.log')
        for idx in range(8)
    ]

    server_proc: Optional[Proc] = None
    client1_proc: Optional[Proc] = None
    client2_proc: Optional[Proc] = None
    admin_base = SECURE_LINK_ADMIN_BASE if secure_slot is not None else ADMIN_PORT_BASE
    server_admin, client1_admin = alloc_admin_ports(case_index, base=admin_base)
    client2_admin = alloc_admin_port({server_admin, client1_admin}, case_index=case_index + 2, base=admin_base)
    tcp_peer_port = _listener_overlay_port(case, 'tcp')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += list(server_extra_args or [])
    server_cmd += admin_args(server_admin)

    client1_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'tcp',
        '--tcp-peer', tcp_peer_host, '--tcp-peer-port', str(tcp_peer_port), '--tcp-bind', loopback_v4, '--tcp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 30},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_1.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client1_cmd += list(client1_extra_args or [])
    client1_cmd += admin_args(client1_admin)

    client2_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'tcp',
        '--tcp-peer', tcp_peer_host, '--tcp-peer-port', str(tcp_peer_port), '--tcp-bind', loopback_v4, '--tcp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 34},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 7}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_2.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client2_cmd += list(client2_extra_args or [])
    client2_cmd += admin_args(client2_admin)

    tcp_specs = [
        ('client1-own-tcp-1', base_tcp_port + 32, b'\x01client1-own-tcp-1'),
        ('client1-own-tcp-2', base_tcp_port + 33, b'\x01client1-own-tcp-2' * 2),
        ('client1-remote-tcp-1', base_tcp_port + 40, b'\x01client1-remote-tcp-1' * 3),
        ('client1-remote-tcp-2', base_tcp_port + 41, b'\x01client1-remote-tcp-2' * 4),
        ('client2-own-tcp-1', base_tcp_port + 36, b'\x01client2-own-tcp-1' * 5),
        ('client2-own-tcp-2', base_tcp_port + 37, b'\x01client2-own-tcp-2' * 6),
        ('client2-remote-tcp-1', base_tcp_port + 44, b'\x01client2-remote-tcp-1' * 7),
        ('client2-remote-tcp-2', base_tcp_port + 45, b'\x01client2-remote-tcp-2' * 8),
    ]
    udp_specs = [
        (base_tcp_port + 30, b'\x01client1-own-udp-1'),
        (base_tcp_port + 31, b'\x01client1-own-udp-2' * 2),
        (base_tcp_port + 34, b'\x01client2-own-udp-1' * 3),
        (base_tcp_port + 35, b'\x01client2-own-udp-2' * 4),
    ]

    try:
        phase('1. Start UDP/TCP bounce-back services')
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.start()

        phase('2. Start bridge listener with tcp overlay transport')
        server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, log_dir, env_extra=case.server_env, admin_port=server_admin)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_admin, timeout=10.0)

        phase('3. Start two tcp peer clients')
        client1_proc = start_proc(f'{case.name}_bridge_client_1', client1_cmd, log_dir, env_extra=case.client_env, admin_port=client1_admin)
        client2_proc = start_proc(f'{case.name}_bridge_client_2', client2_cmd, log_dir, env_extra=case.client_env, admin_port=client2_admin)
        time.sleep(0.8)
        assert_running(client1_proc)
        assert_running(client2_proc)
        wait_admin_up(client1_admin, timeout=10.0)
        wait_admin_up(client2_admin, timeout=10.0)
        client1_proc = ensure_proc_up(client1_proc, log_dir)
        client2_proc = ensure_proc_up(client2_proc, log_dir)
        server_proc = ensure_proc_up(server_proc, log_dir)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)

        phase('4. Verify both tcp peer clients connect to the same listener')
        wait_peers_count(server_admin, minimum_count=2, timeout=12.0, label='server')
        wait_listener_peer_rows_zeroed(server_admin, timeout=12.0, label='server')
        wait_distinct_peer_endpoints(server_admin, transport='tcp', minimum_count=2, timeout=12.0, label='server')

        phase('5. Open 8 concurrent TCP channels and hold them during /api/connections polling')
        start_evt = threading.Event()
        release_close_evt = threading.Event()
        ready_lock = threading.Lock()
        ready_count = 0
        tcp_results: list[Optional[bytes]] = [None] * len(tcp_specs)
        tcp_errors: list[tuple[int, Exception]] = []

        def _before_close() -> None:
            nonlocal ready_count
            with ready_lock:
                ready_count += 1
            if not release_close_evt.wait(timeout=8.0):
                raise TimeoutError('Timed out waiting to release TCP channel close')

        def _tcp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                start_evt.wait(timeout=5.0)
                tcp_results[idx] = probe_tcp(case.probe_host, target_port, case.probe_bind, payload, timeout=4.0, before_close=_before_close)
            except Exception as e:
                tcp_errors.append((idx, e))

        tcp_threads = [threading.Thread(target=_tcp_worker, args=(idx, port, payload), daemon=True) for idx, (_name, port, payload) in enumerate(tcp_specs)]
        for t in tcp_threads:
            t.start()
        start_evt.set()

        try:
            poll_end = time.time() + 8.0
            observed = False
            last_docs: dict[str, dict] = {}
            while time.time() < poll_end:
                _code, conn_doc = fetch_json(f'http://127.0.0.1:{server_admin}/api/connections', timeout=1.5)
                last_docs['server'] = conn_doc
                connected_rows = _connected_tcp_rows(conn_doc)
                if len(connected_rows) == 8:
                    observed = True
                    break
                time.sleep(0.1)
            if not observed:
                raise RuntimeError(
                    f'/api/connections on server did not expose 8 active TCP rows; '
                    f'ready_count={ready_count}/{len(tcp_specs)} last_docs={last_docs!r}'
                )
        finally:
            release_close_evt.set()

        for t in tcp_threads:
            t.join(timeout=8.0)
        if tcp_errors:
            raise RuntimeError(f'Concurrent TCP probes failed: {tcp_errors!r}')

        phase('6. Verify all TCP replies and 4 concurrent UDP probes with unique payload lengths')
        for idx, (_name, _port, payload) in enumerate(tcp_specs):
            expected = response_payload(payload)
            if tcp_results[idx] != expected:
                raise RuntimeError(f'TCP channel {idx} mismatch: got={tcp_results[idx]!r} expected={expected!r}')

        udp_results: list[Optional[bytes]] = [None] * len(udp_specs)
        udp_errors: list[tuple[int, Exception]] = []

        def _udp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                udp_results[idx] = probe_udp(case.probe_host, target_port, case.probe_bind, payload, timeout=2.0)
            except Exception as e:
                udp_errors.append((idx, e))

        udp_threads = [threading.Thread(target=_udp_worker, args=(idx, port, payload), daemon=True) for idx, (port, payload) in enumerate(udp_specs)]
        for t in udp_threads:
            t.start()
        for t in udp_threads:
            t.join(timeout=4.0)
        if udp_errors:
            raise RuntimeError(f'Concurrent UDP probes failed: {udp_errors!r}')
        for idx, (_port, payload) in enumerate(udp_specs):
            expected = response_payload(payload)
            if udp_results[idx] != expected:
                raise RuntimeError(f'UDP channel {idx} mismatch: got={udp_results[idx]!r} expected={expected!r}')
    finally:
        if client2_proc is not None:
            stop_proc(client2_proc)
        if client1_proc is not None:
            stop_proc(client1_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.stop()


def run_case_quic_two_clients_concurrent_udp_tcp(
    case: Case,
    log_dir: Path,
    case_index: int,
    settle_s: Optional[float] = None,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[List[str]] = None,
    client1_extra_args: Optional[List[str]] = None,
    client2_extra_args: Optional[List[str]] = None,
) -> None:
    base_tcp_port = case.bounce_port
    loopback_key = _secure_link_loopback_key(secure_slot) if secure_slot is not None else case_index
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(loopback_key)
    quic_peer_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'quic'), loopback_key)
    own_udp_bounces = [
        BounceBackServer(name=f'{case.name}_own_udp_1', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 20, log_path=log_dir / f'{case.name}_own_udp_1.log'),
        BounceBackServer(name=f'{case.name}_own_udp_2', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 21, log_path=log_dir / f'{case.name}_own_udp_2.log'),
        BounceBackServer(name=f'{case.name}_own_udp_3', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 22, log_path=log_dir / f'{case.name}_own_udp_3.log'),
        BounceBackServer(name=f'{case.name}_own_udp_4', proto='udp', bind_host=case.bounce_bind, port=base_tcp_port + 23, log_path=log_dir / f'{case.name}_own_udp_4.log'),
    ]
    tcp_bounces = [
        BounceBackServer(name=f'{case.name}_tcp_{idx + 1}', proto='tcp', bind_host=case.bounce_bind, port=base_tcp_port + idx, log_path=log_dir / f'{case.name}_tcp_{idx + 1}.log')
        for idx in range(8)
    ]

    server_proc: Optional[Proc] = None
    client1_proc: Optional[Proc] = None
    client2_proc: Optional[Proc] = None
    admin_base = SECURE_LINK_ADMIN_BASE if secure_slot is not None else ADMIN_PORT_BASE
    server_admin, client1_admin = alloc_admin_ports(case_index, base=admin_base)
    client2_admin = alloc_admin_port({server_admin, client1_admin}, case_index=case_index + 2, base=admin_base)
    quic_peer_port = _listener_overlay_port(case, 'quic')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += list(server_extra_args or [])
    server_cmd += admin_args(server_admin)

    client1_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'quic',
        '--quic-peer', quic_peer_host, '--quic-peer-port', str(quic_peer_port), '--quic-bind', loopback_v4, '--quic-own-port', '0', '--quic-insecure',
        '--own-servers',
        f'udp,{base_tcp_port + 30},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_1.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client1_cmd += list(client1_extra_args or [])
    client1_cmd += admin_args(client1_admin)

    client2_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'quic',
        '--quic-peer', quic_peer_host, '--quic-peer-port', str(quic_peer_port), '--quic-bind', loopback_v4, '--quic-own-port', '0', '--quic-insecure',
        '--own-servers',
        f'udp,{base_tcp_port + 34},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},{loopback_v4},udp,{case.bounce_bind},{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},{loopback_v4},tcp,{case.bounce_bind},{base_tcp_port + 7}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_2.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client2_cmd += list(client2_extra_args or [])
    client2_cmd += admin_args(client2_admin)

    tcp_specs = [
        ('client1-own-tcp-1', base_tcp_port + 32, b'\x01client1-own-tcp-1'),
        ('client1-own-tcp-2', base_tcp_port + 33, b'\x01client1-own-tcp-2' * 2),
        ('client1-remote-tcp-1', base_tcp_port + 40, b'\x01client1-remote-tcp-1' * 3),
        ('client1-remote-tcp-2', base_tcp_port + 41, b'\x01client1-remote-tcp-2' * 4),
        ('client2-own-tcp-1', base_tcp_port + 36, b'\x01client2-own-tcp-1' * 5),
        ('client2-own-tcp-2', base_tcp_port + 37, b'\x01client2-own-tcp-2' * 6),
        ('client2-remote-tcp-1', base_tcp_port + 44, b'\x01client2-remote-tcp-1' * 7),
        ('client2-remote-tcp-2', base_tcp_port + 45, b'\x01client2-remote-tcp-2' * 8),
    ]
    udp_specs = [
        (base_tcp_port + 30, b'\x01client1-own-udp-1'),
        (base_tcp_port + 31, b'\x01client1-own-udp-2' * 2),
        (base_tcp_port + 34, b'\x01client2-own-udp-1' * 3),
        (base_tcp_port + 35, b'\x01client2-own-udp-2' * 4),
    ]

    try:
        phase('1. Start UDP/TCP bounce-back services')
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.start()

        phase('2. Start bridge listener with quic overlay transport')
        server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, log_dir, env_extra=case.server_env, admin_port=server_admin)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_admin, timeout=10.0)

        phase('3. Start two quic peer clients')
        client1_proc = start_proc(f'{case.name}_bridge_client_1', client1_cmd, log_dir, env_extra=case.client_env, admin_port=client1_admin)
        client2_proc = start_proc(f'{case.name}_bridge_client_2', client2_cmd, log_dir, env_extra=case.client_env, admin_port=client2_admin)
        time.sleep(0.8)
        assert_running(client1_proc)
        assert_running(client2_proc)
        wait_admin_up(client1_admin, timeout=10.0)
        wait_admin_up(client2_admin, timeout=10.0)
        client1_proc = ensure_proc_up(client1_proc, log_dir)
        client2_proc = ensure_proc_up(client2_proc, log_dir)
        server_proc = ensure_proc_up(server_proc, log_dir)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)

        phase('4. Verify both quic peer clients connect to the same listener')
        wait_peers_count(server_admin, minimum_count=2, timeout=12.0, label='server')
        wait_listener_peer_rows_zeroed(server_admin, timeout=12.0, label='server')
        wait_distinct_peer_endpoints(server_admin, transport='quic', minimum_count=2, timeout=12.0, label='server')
        if secure_slot is not None:
            wait_status_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=2, timeout=12.0, label='server')
            wait_status_secure_link_state(client1_admin, expected_state='authenticated', timeout=12.0, label='client1', authenticated=True)
            wait_status_secure_link_state(client2_admin, expected_state='authenticated', timeout=12.0, label='client2', authenticated=True)
            wait_peer_secure_link_state(client1_admin, expected_state='authenticated', timeout=12.0, label='client1', transport='quic', authenticated=True)
            wait_peer_secure_link_state(client2_admin, expected_state='authenticated', timeout=12.0, label='client2', transport='quic', authenticated=True)
            wait_peer_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', transport='quic', authenticated=True)

        phase('5. Open 8 concurrent TCP channels and hold them during /api/connections polling')
        start_evt = threading.Event()
        release_close_evt = threading.Event()
        ready_lock = threading.Lock()
        ready_count = 0
        tcp_results: list[Optional[bytes]] = [None] * len(tcp_specs)
        tcp_errors: list[tuple[int, Exception]] = []

        def _before_close() -> None:
            nonlocal ready_count
            with ready_lock:
                ready_count += 1
            if not release_close_evt.wait(timeout=8.0):
                raise TimeoutError('Timed out waiting to release TCP channel close')

        def _tcp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                start_evt.wait(timeout=5.0)
                tcp_results[idx] = probe_tcp(case.probe_host, target_port, case.probe_bind, payload, timeout=4.0, before_close=_before_close)
            except Exception as e:
                tcp_errors.append((idx, e))

        tcp_threads = [threading.Thread(target=_tcp_worker, args=(idx, port, payload), daemon=True) for idx, (_name, port, payload) in enumerate(tcp_specs)]
        for t in tcp_threads:
            t.start()
        start_evt.set()

        try:
            poll_end = time.time() + 8.0
            observed = False
            last_docs: dict[str, dict] = {}
            while time.time() < poll_end:
                _code, conn_doc = fetch_json(f'http://127.0.0.1:{server_admin}/api/connections', timeout=1.5)
                last_docs['server'] = conn_doc
                connected_rows = _connected_tcp_rows(conn_doc)
                if len(connected_rows) == 8:
                    observed = True
                    break
                time.sleep(0.1)
            if not observed:
                raise RuntimeError(
                    f'/api/connections on server did not expose 8 active TCP rows; '
                    f'ready_count={ready_count}/{len(tcp_specs)} last_docs={last_docs!r}'
                )
        finally:
            release_close_evt.set()
            for t in tcp_threads:
                t.join(timeout=6.0)

        if tcp_errors:
            raise RuntimeError(f'Concurrent TCP probes failed: {tcp_errors!r}')
        for idx, (_name, _port, payload) in enumerate(tcp_specs):
            expected = response_payload(payload)
            if tcp_results[idx] != expected:
                raise RuntimeError(f'TCP channel {idx} mismatch: got={tcp_results[idx]!r} expected={expected!r}')

        phase('6. Probe all 4 UDP services')
        udp_results: list[Optional[bytes]] = [None] * len(udp_specs)
        udp_errors: list[tuple[int, Exception]] = []

        def _udp_worker(idx: int, target_port: int, payload: bytes) -> None:
            try:
                udp_results[idx] = probe_udp(case.probe_host, target_port, case.probe_bind, payload, timeout=3.0)
            except Exception as e:
                udp_errors.append((idx, e))

        udp_threads = [threading.Thread(target=_udp_worker, args=(idx, port, payload), daemon=True) for idx, (port, payload) in enumerate(udp_specs)]
        for t in udp_threads:
            t.start()
        for t in udp_threads:
            t.join(timeout=5.0)

        if udp_errors:
            raise RuntimeError(f'Concurrent UDP probes failed: {udp_errors!r}')
        for idx, (_port, payload) in enumerate(udp_specs):
            expected = response_payload(payload)
            if udp_results[idx] != expected:
                raise RuntimeError(f'UDP channel {idx} mismatch: got={udp_results[idx]!r} expected={expected!r}')
    finally:
        if client2_proc is not None:
            stop_proc(client2_proc)
        if client1_proc is not None:
            stop_proc(client1_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        for bounce in own_udp_bounces + tcp_bounces:
            bounce.stop()

def wait_both_connected(
    server_proc: Proc,
    client_proc: Proc,
    log_dir: Path,
    timeout: float = 30.0,
) -> tuple[Proc, Proc]:
    end = time.time() + timeout

    last_server_rendered = None
    last_client_rendered = None
    last_server = None
    last_client = None

    while time.time() < end:
        server_proc = ensure_proc_up(server_proc, log_dir)
        client_proc = ensure_proc_up(client_proc, log_dir)

        try:
            last_server = try_get_status(server_proc.admin_port or 0)
            rendered = fmt_state_doc(last_server)
            if rendered != last_server_rendered:
                log.info(f'[STATUS] server port={server_proc.admin_port} {rendered}')
                last_server_rendered = rendered
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_server_rendered:
                log.info(f'[STATUS] server port={server_proc.admin_port} {rendered}')
                last_server_rendered = rendered

        try:
            last_client = try_get_status(client_proc.admin_port or 0)
            rendered = fmt_state_doc(last_client)
            if rendered != last_client_rendered:
                log.info(f'[STATUS] client port={client_proc.admin_port} {rendered}')
                last_client_rendered = rendered
        except Exception as e:
            rendered = f'QUERY_FAILED {e!r}'
            if rendered != last_client_rendered:
                log.info(f'[STATUS] client port={client_proc.admin_port} {rendered}')
                last_client_rendered = rendered

        server_ok = last_server is not None and status_state(last_server) == 'CONNECTED'
        client_ok = last_client is not None and status_state(last_client) == 'CONNECTED'

        if server_ok and client_ok:
            log.info(f'[STATUS] server port={server_proc.admin_port} CONNECTED reached')
            log.info(f'[STATUS] client port={client_proc.admin_port} CONNECTED reached')
            return server_proc, client_proc

        time.sleep(0.5)

    raise RuntimeError(
        f'Both not CONNECTED before timeout; '
        f'server_last={last_server!r} client_last={last_client!r}'
    )

def _start_case_with_client_admin_auth(
    case: Case,
    log_dir: Path,
    *,
    case_index: int,
    client_auth_args: Optional[List[str]] = None,
    require_probe: bool = True,
) -> tuple[BounceBackServer, Proc, Proc]:
    case = materialize_case_ports(case, case_index)
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    bounce.start()
    specs = build_commands(case, log_dir, case_index, enable_admin=True)
    server_name, server_cmd, server_env, server_admin = specs[0]
    client_name, client_cmd, client_env, client_admin = specs[1]
    client_cmd = list(client_cmd) + list(client_auth_args or [])

    client_proc: Optional[Proc] = None
    server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, log_dir, env_extra=server_env, admin_port=server_admin)
    try:
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        overlay_transport = str(_arg_value(case.bridge_server_args, '--overlay-transport', '')).strip().lower()
        if overlay_transport in ('tcp', 'ws'):
            listen_host = _connect_host_for_bind(_listener_overlay_bind_host(case, overlay_transport), case_index)
            wait_tcp_listen(listen_host, _listener_overlay_port(case, overlay_transport), timeout=10.0)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, log_dir, env_extra=client_env, admin_port=client_admin)
        if client_auth_args:
            wait_admin_auth_up(client_proc.admin_port or 0, timeout=10.0)
        else:
            wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        if require_probe:
            time.sleep(case.settle_seconds)
            wait_probe(case, timeout=20.0)
        return bounce, server_proc, client_proc
    except Exception:
        if client_proc is not None:
            stop_proc(client_proc)
        stop_proc(server_proc)
        bounce.stop()
        raise


def _stop_proc_without_admin(proc: Proc) -> None:
    saved = proc.admin_port
    proc.admin_port = None
    try:
        stop_proc(proc)
    finally:
        proc.admin_port = saved


def _proxy_env(proxy_port: int, *, no_proxy: Optional[str], include_system_override: bool = False) -> Dict[str, str]:
    env = {
        'HTTP_PROXY': f'http://127.0.0.1:{int(proxy_port)}',
        'http_proxy': f'http://127.0.0.1:{int(proxy_port)}',
        'HTTPS_PROXY': '',
        'https_proxy': '',
        'ALL_PROXY': '',
        'all_proxy': '',
    }
    if no_proxy is not None:
        env['NO_PROXY'] = no_proxy
        env['no_proxy'] = no_proxy
    if include_system_override:
        env['OBSTACLEBRIDGE_TEST_SYSTEM_PROXY'] = f'http=127.0.0.1:{int(proxy_port)};https=127.0.0.1:{int(proxy_port)}'
    return env


def _start_ws_case_with_client_env(
    case: Case,
    log_dir: Path,
    *,
    case_index: int,
    client_env_extra: Dict[str, str],
    client_extra_args: Optional[List[str]] = None,
    server_extra_args: Optional[List[str]] = None,
    server_env_extra: Optional[Dict[str, str]] = None,
    require_probe: bool = True,
) -> tuple[BounceBackServer, Proc, Proc]:
    case = materialize_case_ports(case, case_index)
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    bounce.start()
    specs = build_commands(case, log_dir, case_index, enable_admin=True)
    server_name, server_cmd, server_env, server_admin = specs[0]
    client_name, client_cmd, client_env, client_admin = specs[1]
    server_env = dict(server_env)
    server_env.update(server_env_extra or {})
    client_env = dict(client_env)
    client_env.update(client_env_extra)
    server_cmd = list(server_cmd) + list(server_extra_args or [])
    client_cmd = list(client_cmd) + list(client_extra_args or [])

    server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, log_dir, env_extra=server_env, admin_port=server_admin)
    listen_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), case_index)
    wait_tcp_listen(listen_host, _listener_overlay_port(case, 'ws'), timeout=10.0)
    client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, log_dir, env_extra=client_env, admin_port=client_admin)
    try:
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_proc = wait_status_connected_proc(client_proc, log_dir, timeout=20.0, label='client')
        if require_probe:
            time.sleep(case.settle_seconds)
            wait_probe(case, timeout=20.0)
        return bounce, server_proc, client_proc
    except Exception:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()
        raise


def _start_case_with_secure_link_args(
    case: Case,
    log_dir: Path,
    *,
    case_index: int,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[List[str]] = None,
    client_extra_args: Optional[List[str]] = None,
    client_restart_if_disconnected: float = 5.0,
    use_failure_injection_entrypoint: bool = False,
    wait_client_admin: bool = True,
) -> tuple[Case, BounceBackServer, Proc, Proc]:
    case = materialize_secure_link_case_ports(case, secure_slot) if secure_slot is not None else materialize_case_ports(case, case_index)
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=log_dir / f'{case.name}_bounce.log',
    )
    bounce.start()
    server_admin, client_admin = alloc_admin_ports(case_index, base=SECURE_LINK_ADMIN_BASE if secure_slot is not None else ADMIN_PORT_BASE)
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_name = 'bridge_server'
    client_name = 'bridge_client'
    server_cmd = bridge_entrypoint(with_failure_injection=use_failure_injection_entrypoint) + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    client_cmd = bridge_entrypoint(with_failure_injection=use_failure_injection_entrypoint) + materialize_args(case.bridge_client_args, log_dir, case.name, 'bridge_client')
    server_env = dict(case.server_env)
    client_env = dict(case.client_env)
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    client_cmd += ['--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', str(float(client_restart_if_disconnected))]
    server_cmd += admin_args(server_admin)
    client_cmd += admin_args(client_admin)
    server_cmd = list(server_cmd) + list(server_extra_args or [])
    client_cmd = list(client_cmd) + list(client_extra_args or [])

    server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, log_dir, env_extra=server_env, admin_port=server_admin)
    overlay_transport = str(_arg_value(case.bridge_server_args, '--overlay-transport', '')).strip().lower()
    if overlay_transport in ('tcp', 'ws'):
        listen_port = _listener_overlay_port(case, overlay_transport)
        connect_case_key = _secure_link_loopback_key(secure_slot) if secure_slot is not None else case_index
        listen_host = _connect_host_for_bind(_listener_overlay_bind_host(case, overlay_transport), connect_case_key)
        wait_tcp_listen(listen_host, listen_port, timeout=10.0)
    client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, log_dir, env_extra=client_env, admin_port=client_admin)
    try:
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        if wait_client_admin:
            wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        return case, bounce, server_proc, client_proc
    except Exception:
        stop_proc(client_proc)
        stop_proc(server_proc)
        bounce.stop()
        raise


def _cert_secure_args(
    *,
    root_pub: str,
    cert_body: str,
    cert_sig: str,
    private_key: str,
    revoked_serials: Optional[str] = None,
    extra: Optional[List[str]] = None,
) -> List[str]:
    return _cert_secure_args_paths(
        root_pub=str(SECURE_LINK_CERT_FIXTURES / root_pub),
        cert_body=str(SECURE_LINK_CERT_FIXTURES / cert_body),
        cert_sig=str(SECURE_LINK_CERT_FIXTURES / cert_sig),
        private_key=str(SECURE_LINK_CERT_FIXTURES / private_key),
        revoked_serials=str(SECURE_LINK_CERT_FIXTURES / revoked_serials) if revoked_serials else None,
        extra=extra,
    )


def _cert_secure_args_paths(
    *,
    root_pub: str,
    cert_body: str,
    cert_sig: str,
    private_key: str,
    revoked_serials: Optional[str] = None,
    extra: Optional[List[str]] = None,
) -> List[str]:
    args = [
        '--secure-link',
        '--secure-link-mode', 'cert',
        '--secure-link-root-pub', str(root_pub),
        '--secure-link-cert-body', str(cert_body),
        '--secure-link-cert-sig', str(cert_sig),
        '--secure-link-private-key', str(private_key),
    ]
    if revoked_serials:
        args += ['--secure-link-revoked-serials', str(revoked_serials)]
    args += list(extra or [])
    return args


def _copy_secure_link_cert_fixture_set(target_dir: Path) -> Path:
    return materialize_secure_link_cert_fixture_set(target_dir)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", BASIC_CASES)
def test_overlay_e2e_basic(case_name: str, tmp_path: Path) -> None:
    run_case(CASES[case_name], tmp_path, CASE_INDEX_BASE_BASIC + ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", RECONNECT_CASES)
def test_overlay_e2e_reconnect(case_name: str, tmp_path: Path) -> None:
    run_case_reconnect(CASES[case_name], tmp_path, CASE_INDEX_BASE_RECONNECT + ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_structured_own_servers_lifecycle_hooks_execute(tmp_path: Path) -> None:
    case_index = 206
    case = materialize_case_ports(CASES['case01_udp_over_own_udp_ipv4'], case_index)
    hook_log = tmp_path / 'own_server_hook_events.jsonl'
    hook_writer = (
        "import json,os,pathlib;"
        "p=pathlib.Path(os.environ['OB_HOOK_OUT']);"
        "p.parent.mkdir(parents=True, exist_ok=True);"
        "evt=dict("
        "event=os.environ.get('OB_EVENT',''),"
        "role=os.environ.get('OB_ROLE',''),"
        "catalog=os.environ.get('OB_CATALOG',''),"
        "protocol=os.environ.get('OB_PROTOCOL',''),"
        "service_name=os.environ.get('OB_SERVICE_NAME',''),"
        "service_id=os.environ.get('OB_SERVICE_ID',''),"
        "channel_id=os.environ.get('OB_CHANNEL_ID','')"
        ");"
        "fp=p.open('a', encoding='utf-8');"
        "fp.write(json.dumps(evt,separators=(',',':'))+'\\n');"
        "fp.close()"
    )
    hook_cmd = {
        'argv': [sys.executable, '-c', hook_writer],
        'timeout_ms': 2000,
        'env': {
            'OB_HOOK_OUT': str(hook_log),
            'OB_EVENT': '{event}',
            'OB_ROLE': '{role}',
            'OB_CATALOG': '{catalog}',
            'OB_PROTOCOL': '{protocol}',
            'OB_SERVICE_NAME': '{service_name}',
            'OB_SERVICE_ID': '{service_id}',
            'OB_CHANNEL_ID': '{channel_id}',
        },
    }
    structured_own = json.dumps(
        {
            'name': 'hooked-own-udp',
            'listen': {'protocol': 'udp', 'bind': str(case.probe_bind or '0.0.0.0'), 'port': int(case.probe_port)},
            'target': {'protocol': 'udp', 'host': str(case.bounce_bind), 'port': int(case.bounce_port)},
            'lifecycle_hooks': {
                'listener': {
                    'on_created': hook_cmd,
                    'on_channel_connected': hook_cmd,
                }
            },
        },
        separators=(',', ':'),
    )

    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=tmp_path / f'{case.name}_bounce.log',
    )
    bounce.start()
    specs = build_commands(case, tmp_path, case_index, enable_admin=True)
    server_name, server_cmd, server_env, server_admin = specs[0]
    client_name, client_cmd, client_env, client_admin = specs[1]
    client_cmd = _replace_option_values(client_cmd, '--own-servers', [structured_own])

    server_proc = client_proc = None
    try:
        server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, tmp_path, env_extra=server_env, admin_port=server_admin)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, tmp_path, env_extra=client_env, admin_port=client_admin)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
        wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
        wait_probe(case, payload=b'\x01hook-own', timeout=12.0)

        rows = _wait_jsonl_events(
            hook_log,
            lambda entries: (
                {'on_created', 'on_channel_connected'}.issubset({str(e.get('event') or '') for e in entries})
            ),
            timeout=12.0,
        )
        created_rows = [row for row in rows if row.get('event') == 'on_created']
        connected_rows = [row for row in rows if row.get('event') == 'on_channel_connected']
        assert created_rows and connected_rows
        assert all(row.get('role') == 'listener' for row in created_rows + connected_rows)
        assert all(row.get('catalog') == 'own_servers' for row in created_rows + connected_rows)
        assert all(row.get('protocol') == 'udp' for row in created_rows + connected_rows)
        assert all(row.get('service_name') == 'hooked-own-udp' for row in created_rows + connected_rows)
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_structured_remote_servers_udp_forwarding(tmp_path: Path) -> None:
    case_index = 207
    case = materialize_case_ports(CASES['case01_udp_over_own_udp_ipv4'], case_index)
    structured_remote = json.dumps(
        {
            'name': 'remote-udp-json',
            'listen': {'protocol': 'udp', 'bind': str(case.probe_bind or '0.0.0.0'), 'port': int(case.probe_port)},
            'target': {'protocol': 'udp', 'host': str(case.bounce_bind), 'port': int(case.bounce_port)},
        },
        separators=(',', ':'),
    )

    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=tmp_path / f'{case.name}_bounce.log',
    )
    bounce.start()
    specs = build_commands(case, tmp_path, case_index, enable_admin=True)
    server_name, server_cmd, server_env, server_admin = specs[0]
    client_name, client_cmd, client_env, client_admin = specs[1]
    client_cmd = _replace_option_values(client_cmd, '--own-servers', [])
    client_cmd = _replace_option_values(client_cmd, '--remote-servers', [structured_remote])

    server_proc = client_proc = None
    try:
        server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, tmp_path, env_extra=server_env, admin_port=server_admin)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, tmp_path, env_extra=client_env, admin_port=client_admin)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
        wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
        wait_probe(case, payload=b'\x01remote-json', timeout=12.0)
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", LISTENER_CASES)
def test_overlay_e2e_listener_two_clients(case_name: str, tmp_path: Path) -> None:
    run_case_two_peer_clients_listener(CASES[case_name], tmp_path, CASE_INDEX_BASE_LISTENER + ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", CONCURRENT_TCP_CHANNEL_CASES)
def test_overlay_e2e_concurrent_tcp_channels(case_name: str, tmp_path: Path) -> None:
    run_case_concurrent_tcp_channels(CASES[case_name], tmp_path, CASE_INDEX_BASE_CONCURRENT + ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", list(MYUDP_DELAY_LOSS_CASES.keys()))
def test_overlay_e2e_myudp_delay_loss(case_name: str, tmp_path: Path) -> None:
    run_case_myudp_delay_loss(
        MYUDP_DELAY_LOSS_CASES[case_name],
        tmp_path,
        CASE_INDEX_BASE_MYUDP_DELAY_LOSS + list(MYUDP_DELAY_LOSS_CASES.keys()).index(case_name),
    )


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_listener_invalid_sender_expires_before_stale_window(tmp_path: Path) -> None:
    case_index = CASE_INDEX_BASE_MYUDP_STALE
    base_port = _myudp_delay_loss_base_port(case_index)
    overlay_port = base_port
    admin_port = alloc_admin_port(case_index=case_index)
    loopback_v4, _loopback_v6 = _loopback_hosts_for_case(case_index)
    missing_cfg = str(tmp_path / 'myudp_listener_invalid_sender_missing.cfg')
    server_proc = None
    try:
        phase('1. Start myudp listener with admin API enabled')
        server_cmd = [
            *bridge_entrypoint(),
            '--overlay-transport', 'myudp',
            '--udp-bind', loopback_v4,
            '--udp-own-port', str(overlay_port),
            '--log', 'INFO',
            '--log-channel-mux', 'DEBUG',
            '--log-udp-session', 'DEBUG',
            '--log-file', str(tmp_path / 'myudp_listener_invalid_sender_server.txt'),
            '--admin-web-auth-disable',
            '--config', missing_cfg,
            '--admin-web-port', '0',
            *admin_args(admin_port),
        ]
        server_proc = start_proc(
            'myudp_listener_invalid_sender_server',
            server_cmd,
            tmp_path,
            admin_port=admin_port,
        )
        wait_admin_up(admin_port, timeout=10.0)
        wait_listener_peer_rows_zeroed(admin_port, timeout=10.0, label='listener')

        phase('2. Send one invalid UDP datagram from a fresh source port')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
            attacker.bind((loopback_v4, 0))
            attacker.sendto(b'port-scan-junk', (loopback_v4, overlay_port))
            attacker_peer = f'{loopback_v4}:{attacker.getsockname()[1]}'

        phase('3. Verify /api/peers exposes the connecting junk sender with age and decode data')
        _doc, row = wait_peer_row_visible(
            admin_port,
            transport='myudp',
            peer=attacker_peer,
            state='connecting',
            timeout=8.0,
            label='listener',
        )
        assert int(row.get('decode_errors') or 0) >= 1
        age = row.get('last_incoming_age_seconds')
        assert isinstance(age, (int, float))
        assert 0 <= float(age) < 5.0

        phase('4. Fail if the junk sender survives into the stale window; expect it to be reaped')
        wait_peer_row_absent(
            admin_port,
            transport='myudp',
            peer=attacker_peer,
            state='connecting',
            timeout=25.0,
            label='listener',
        )
        wait_listener_peer_rows_zeroed(admin_port, timeout=5.0, label='listener')
    finally:
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", ['case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels'])
def test_overlay_e2e_server_restart_closes_tcp_preserves_udp(case_name: str, tmp_path: Path) -> None:
    run_case_server_restart_closes_tcp_preserves_udp(
        CASES[case_name],
        tmp_path,
        CASE_INDEX_BASE_RESTART + ALL_CASES.index(case_name),
    )


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_api_available_when_auth_disabled(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    auth_args = [
        '--admin-web-auth-disable',
        '--admin-web-username', 'admin',
        '--admin-web-password', 'secret-pass',
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=200, client_auth_args=auth_args)
        code, body = fetch_json_auth(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
        assert code == 200
        assert isinstance(body, dict)
        assert 'peer_state' in body
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_api_unavailable_without_correct_auth(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    auth_args = [
        '--admin-web-username', 'admin',
        '--admin-web-password', 'secret-pass',
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=201, client_auth_args=auth_args)
        code, body = fetch_json_auth(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
        assert code == 401
        assert body.get('authenticated') is False
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_api_available_after_correct_auth(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    username = 'admin'
    password = 'secret-pass'
    auth_args = [
        '--admin-web-username', username,
        '--admin-web-password', password,
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=202, client_auth_args=auth_args)
        login_code, login_doc, opener = admin_authenticate(client_proc.admin_port or 0, username, password)
        assert login_code == 200
        assert login_doc.get('authenticated') is True
        code, body = fetch_json_auth(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5, opener=opener)
        assert code == 200
        assert 'peer_state' in body
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_api_auth_isolated_per_concurrent_http_client(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    username = 'admin'
    password = 'secret-pass'
    auth_args = [
        '--admin-web-username', username,
        '--admin-web-password', password,
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=203, client_auth_args=auth_args)
        opener1 = make_json_opener(with_cookies=True)
        opener2 = make_json_opener(with_cookies=True)

        login_code, login_doc, opener1 = admin_authenticate(client_proc.admin_port or 0, username, password, opener=opener1)
        assert login_code == 200
        assert login_doc.get('authenticated') is True

        code1, body1 = fetch_json_auth(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5, opener=opener1)
        code2, body2 = fetch_json_auth(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5, opener=opener2)

        assert code1 == 200
        assert 'peer_state' in body1
        assert code2 == 401
        assert body2.get('authenticated') is False
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_config_challenge_masks_and_saves_secrets_encrypted(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    username = 'admin'
    password = 'secret-pass'
    auth_args = [
        '--admin-web-username', username,
        '--admin-web-password', password,
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=204, client_auth_args=auth_args)
        login_code, login_doc, opener = admin_authenticate(client_proc.admin_port or 0, username, password)
        assert login_code == 200
        assert login_doc.get('authenticated') is True

        code, config_doc = request_json(f'http://127.0.0.1:{client_proc.admin_port}/api/config', opener=opener)
        assert code == 200
        assert config_doc.get('ok') is True
        config = dict(config_doc.get('config') or {})
        schema = dict(config_doc.get('schema') or {})
        schema_by_key = {
            str(item.get('key')): dict(item)
            for items in schema.values()
            for item in list(items or [])
            if isinstance(item, dict)
        }
        assert config.get('admin_web_password') == ''
        assert config.get('secure_link_psk') == ''
        assert (schema_by_key.get('admin_web_password') or {}).get('secret') is True
        assert (schema_by_key.get('secure_link_psk') or {}).get('secret') is True

        updates = {
            'console_level': 'DEBUG',
            'admin_web_password': 'rotated-pass',
            'secure_link_psk': 'runtime-psk-secret',
        }
        no_challenge_code, no_challenge_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/config',
            method='POST',
            payload={'updates': updates},
            opener=opener,
        )
        assert no_challenge_code == 428
        assert 'confirmation required' in str(no_challenge_doc.get('error') or '')

        challenge_code, challenge_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/config/challenge',
            method='POST',
            payload={'updates': updates},
            opener=opener,
        )
        assert challenge_code == 200
        proof = config_change_proof(
            str(challenge_doc.get('seed') or ''),
            username,
            password,
            str(challenge_doc.get('updates_digest') or ''),
        )
        save_code, save_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/config',
            method='POST',
            payload={'updates': updates, 'challenge_id': challenge_doc.get('challenge_id'), 'proof': proof},
            opener=opener,
        )
        assert save_code == 200
        assert save_doc.get('ok') is True
        saved_config = dict(save_doc.get('config') or {})
        assert saved_config.get('admin_web_password') == ''
        assert saved_config.get('secure_link_psk') == ''

        cfg_text = proc_config_path(client_proc).read_text(encoding='utf-8')
        assert 'rotated-pass' not in cfg_text
        assert 'runtime-psk-secret' not in cfg_text
        assert 'enc:v1:' in cfg_text
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_onboarding_invite_api_masks_psk_and_returns_apply_updates(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    auth_args = [
        '--admin-web-auth-disable',
        '--secure-link-mode', 'psk',
        '--secure-link-psk', 'invite-psk-secret',
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=205, client_auth_args=auth_args)
        code, profiles_doc = request_json(f'http://127.0.0.1:{client_proc.admin_port}/api/onboarding/connection-profiles')
        assert code == 200
        profiles = list(profiles_doc.get('profiles') or [])
        assert profiles
        connection_id = str(profiles[0].get('id') or '')

        generate_code, generate_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/onboarding/invite/generate',
            method='POST',
            payload={'connection_id': connection_id},
        )
        assert generate_code == 200
        assert generate_doc.get('ok') is True
        token = str(generate_doc.get('invite_token') or '')
        assert token

        preview_code, preview_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/onboarding/invite/preview',
            method='POST',
            payload={'invite_token': token},
        )
        assert preview_code == 200
        assert preview_doc.get('ok') is True
        preview = dict(preview_doc.get('preview') or {})
        updates = dict(preview_doc.get('suggested_updates') or {})
        assert preview.get('secure_link_psk') == '***hidden***'
        assert preview.get('secure_link_psk_present') is True
        assert updates.get('secure_link_psk') == 'invite-psk-secret'
        assert updates.get('overlay_transport')
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_reconnect_targets_selected_peer_id(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    auth_args = ['--admin-web-auth-disable']
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=206, client_auth_args=auth_args)
        client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
        code, peers_doc = request_json(f'http://127.0.0.1:{client_proc.admin_port}/api/peers')
        assert code == 200
        row = first_active_peer_row(peers_doc, transport='ws')
        peer_id = str(row.get('id'))
        missing_code, missing_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/reconnect',
            method='POST',
            payload={'peer_id': f'{peer_id}-missing'},
        )
        assert missing_code == 404
        assert missing_doc.get('reason') == 'unknown_peer_id'

        reconnect_code, reconnect_doc = request_json(
            f'http://127.0.0.1:{client_proc.admin_port}/api/reconnect',
            method='POST',
            payload={'peer_id': peer_id},
        )
        assert reconnect_code == 200
        assert reconnect_doc.get('ok') is True
        assert reconnect_doc.get('target_peer_id') == peer_id
        assert int(reconnect_doc.get('requested') or 0) == 1
        assert reconnect_doc.get('transports') == ['ws']
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_default_entrypoint_config_bootstrap_and_webadmin_notice(tmp_path: Path) -> None:
    case_index = 207
    admin_port = alloc_admin_port(case_index=case_index, host_pair=('127.0.0.1', '::1'))
    missing_cfg = tmp_path / 'missing-entrypoint.cfg'
    env = dict(os.environ)
    env['PYTHONPATH'] = f'{SRC}{os.pathsep}{env.get("PYTHONPATH", "")}'
    cmd = [
        sys.executable,
        '-m',
        'obstacle_bridge',
        '--no-redirect',
        '--config',
        str(missing_cfg),
        '--admin-web',
        '--admin-web-auth-disable',
        '--admin-web-bind',
        '127.0.0.1',
        '--admin-web-port',
        str(admin_port),
        '--no-dashboard',
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines: list[str] = []
    try:
        deadline = time.time() + 12.0
        while time.time() < deadline:
            assert proc.stdout is not None
            ready, _, _ = select.select([proc.stdout], [], [], 0.25)
            if ready:
                line = proc.stdout.readline()
                if line:
                    lines.append(line.rstrip())
                    if f'http://127.0.0.1:{admin_port}/' in line:
                        break
            if proc.poll() is not None:
                break
        assert any(f'Open WebAdmin interface http://127.0.0.1:{admin_port}/' in line for line in lines), lines
        wait_admin_up(admin_port, timeout=10.0)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5.0)

    invalid_cfg = tmp_path / 'invalid-entrypoint.cfg'
    invalid_cfg.write_text('{not-json', encoding='utf-8')
    bad = subprocess.run(
        [
            sys.executable,
            str(BRIDGE),
            '--config',
            str(invalid_cfg),
            '--admin-web-port',
            '0',
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10.0,
    )
    assert bad.returncode != 0
    assert 'Invalid JSON config' in (bad.stdout or '')


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_live_ws_available_when_auth_disabled(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    auth_args = [
        '--admin-web-auth-disable',
        '--admin-web-username', 'admin',
        '--admin-web-password', 'secret-pass',
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=260, client_auth_args=auth_args)
        docs = asyncio.run(
            _admin_ws_collect_messages(
                client_proc.admin_port or 0,
                subscribe=['status', 'connections', 'peers', 'meta'],
                want_types={'status', 'connections', 'peers', 'meta'},
                timeout=5.0,
            )
        )
        by_type = {str(item.get('type') or ''): item.get('data') for item in docs if item.get('type') != 'hello'}
        assert 'peer_state' in (by_type.get('status') or {})
        assert 'udp' in (by_type.get('connections') or {})
        assert 'peers' in (by_type.get('peers') or {})
        assert 'admin_web_name' in (by_type.get('meta') or {})
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_live_ws_unavailable_without_correct_auth(tmp_path: Path) -> None:
    import websockets

    case = CASES['case01_udp_over_own_udp_ipv4']
    auth_args = [
        '--admin-web-username', 'admin',
        '--admin-web-password', 'secret-pass',
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(case, tmp_path, case_index=261, client_auth_args=auth_args)

        async def _attempt() -> None:
            await _admin_ws_collect_messages(
                client_proc.admin_port or 0,
                subscribe=['status'],
                want_types={'status'},
                timeout=2.0,
            )

        with pytest.raises(Exception, match='401|Unauthorized|server rejected WebSocket connection'):
            asyncio.run(_attempt())
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_live_ws_available_after_correct_auth(tmp_path: Path) -> None:
    case = CASES['case01_udp_over_own_udp_ipv4']
    username = 'admin'
    password = 'secret-pass'
    auth_args = [
        '--admin-web-username', username,
        '--admin-web-password', password,
    ]
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_case_with_client_admin_auth(
            case,
            tmp_path,
            case_index=262,
            client_auth_args=auth_args,
            require_probe=False,
        )
        login_code, login_doc, opener = admin_authenticate(client_proc.admin_port or 0, username, password)
        assert login_code == 200
        assert login_doc.get('authenticated') is True
        docs = asyncio.run(
            _admin_ws_collect_messages(
                client_proc.admin_port or 0,
                opener=opener,
                subscribe=['status', 'connections', 'peers', 'meta'],
                want_types={'status', 'connections', 'peers', 'meta'},
                timeout=5.0,
            )
        )
        by_type = {str(item.get('type') or ''): item.get('data') for item in docs if item.get('type') != 'hello'}
        assert 'peer_state' in (by_type.get('status') or {})
        assert 'udp' in (by_type.get('connections') or {})
        assert 'peers' in (by_type.get('peers') or {})
        assert 'admin_web_name' in (by_type.get('meta') or {})
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            _stop_proc_without_admin(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_listener_adopts_client_payload_mode_from_upgrade_request(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    bounce = None
    server_proc = client_proc = None
    try:
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=293,
            client_env_extra={},
            server_extra_args=['--ws-payload-mode', 'binary', '--log-ws-session', 'DEBUG'],
            client_extra_args=['--ws-payload-mode', 'semi-text-shape', '--log-ws-session', 'DEBUG'],
        )
        wait_probe(materialize_case_ports(case, 293), timeout=8.0)
        assert status_state(get_status(client_proc.admin_port or 0)) == 'CONNECTED'
        assert status_state(get_status(server_proc.admin_port or 0)) == 'CONNECTED'
        server_log = wait_log_contains(server_proc.log_path, 'payload_mode=semi-text-shape', timeout=10.0)
        assert 'accept: peer_id=' in server_log
    finally:
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_secure_link_psk_udp_fragmentation_survives_text_mode(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case08_overlay_ws_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=294,
                secure_slot=9,
                server_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--ws-payload-mode', 'semi-text-shape',
                    '--ws-max-size', '160',
                    '--log-channel-mux', 'DEBUG',
                    '--log-ws-session', 'DEBUG',
                    '--log-secure-link', 'DEBUG',
                ],
                client_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--ws-payload-mode', 'semi-text-shape',
                    '--ws-max-size', '160',
                    '--log-channel-mux', 'DEBUG',
                    '--log-ws-session', 'DEBUG',
                    '--log-secure-link', 'DEBUG',
                ],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)

            payload = b'\x01' + (b'F' * 1400)
            wait_probe(case, payload=payload, expected=response_payload(payload), timeout=15.0)
            wait_exact_transferred_bytes(client_proc.admin_port or 0, expected_bytes=len(payload), timeout=12.0, label='client')
            wait_exact_transferred_bytes(server_proc.admin_port or 0, expected_bytes=len(payload), timeout=12.0, label='server')

            client_log = wait_log_contains(client_proc.log_path, 'fragment UDP datagram', timeout=10.0)
            assert 'frag_payload_limit=' in client_log
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_overlay_uses_http_proxy_env(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_http_proxy_env',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_http_proxy_env.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=263,
            client_env_extra=_proxy_env(proxy_port, no_proxy=''),
        )
        wait_http_proxy_connects(proxy, minimum_count=1, timeout=8.0)
        wait_probe(materialize_case_ports(case, 263), timeout=12.0)
        assert proxy.connect_count >= 1
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_overlay_honors_no_proxy_env(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    no_proxy_host = _loopback_ipv4_host(264)
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_no_proxy_env',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_no_proxy_env.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=264,
            client_env_extra=_proxy_env(proxy_port, no_proxy=f'127.0.0.1,{no_proxy_host}'),
        )
        time.sleep(1.0)
        wait_probe(materialize_case_ports(case, 264), timeout=8.0)
        assert proxy.connect_count == 0
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_proxy_is_scoped_to_peer_client_only(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    no_proxy_host = _loopback_ipv4_host(265)
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_listener_scope_proxy',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_listener_scope_proxy.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=265,
            client_env_extra={'NO_PROXY': f'127.0.0.1,{no_proxy_host}', 'no_proxy': f'127.0.0.1,{no_proxy_host}'},
            server_env_extra=_proxy_env(proxy_port, no_proxy=''),
        )
        wait_probe(materialize_case_ports(case, 265), timeout=8.0)
        time.sleep(1.0)
        assert proxy.connect_count == 0
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("case_name", "case_index"),
    [
        ('case01_udp_over_own_udp_ipv4', 266),
        ('case06_overlay_tcp_ipv4', 267),
        ('case10_overlay_quic_ipv4', 268),
    ],
)
def test_overlay_e2e_http_proxy_env_does_not_apply_to_non_ws_transports(case_name: str, case_index: int, tmp_path: Path) -> None:
    case = CASES[case_name]
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name=f'{case_name}_non_ws_proxy',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / f'{case_name}_non_ws_proxy.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        case = materialize_case_ports(case, case_index)
        bounce = BounceBackServer(
            name=f'{case.name}_bounce',
            proto=case.bounce_proto,
            bind_host=case.bounce_bind,
            port=case.bounce_port,
            log_path=tmp_path / f'{case.name}_bounce.log',
        )
        bounce.start()
        specs = build_commands(case, tmp_path, case_index, enable_admin=True)
        server_name, server_cmd, server_env, server_admin = specs[0]
        client_name, client_cmd, client_env, client_admin = specs[1]
        client_env = dict(client_env)
        client_env.update(_proxy_env(proxy_port, no_proxy=''))
        server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, tmp_path, env_extra=server_env, admin_port=server_admin)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        overlay_transport = str(_arg_value(case.bridge_server_args, '--overlay-transport', '')).strip().lower()
        if overlay_transport in ('tcp', 'ws'):
            listen_host = _connect_host_for_bind(_listener_overlay_bind_host(case, overlay_transport), case_index)
            wait_tcp_listen(listen_host, _listener_overlay_port(case, overlay_transport), timeout=10.0)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, tmp_path, env_extra=client_env, admin_port=client_admin)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
        time.sleep(case.settle_seconds)
        wait_probe(case, timeout=20.0)
        time.sleep(1.0)
        assert proxy.connect_count == 0
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_proxy_tunnel_precedes_websocket_handshake(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_proxy_handshake_order',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_proxy_handshake_order.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=269,
            client_env_extra=_proxy_env(proxy_port, no_proxy=''),
        )
        wait_http_proxy_connects(proxy, minimum_count=1, timeout=8.0)
        assert proxy.first_tunnel_request_line is not None
        assert proxy.first_tunnel_request_line.startswith('GET ')
        wait_probe(materialize_case_ports(case, 269), timeout=8.0)
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_proxy_failure_keeps_overlay_state_machine_healthy(tmp_path: Path) -> None:
    case = materialize_case_ports(CASES['case08_overlay_ws_ipv4'], 270)
    bad_proxy_port = alloc_admin_port()
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=tmp_path / f'{case.name}_bounce.log',
    )
    server_proc = client_proc = None
    try:
        bounce.start()
        specs = build_commands(case, tmp_path, 270, enable_admin=True)
        server_name, server_cmd, server_env, server_admin = specs[0]
        client_name, client_cmd, client_env, client_admin = specs[1]
        client_cmd = _replace_last_arg(client_cmd, '--client-restart-if-disconnected', '0')
        client_env = dict(client_env)
        client_env.update(_proxy_env(bad_proxy_port, no_proxy=''))
        server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, tmp_path, env_extra=server_env, admin_port=server_admin)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, tmp_path, env_extra=client_env, admin_port=client_admin)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        assert_running(server_proc)
        assert_running(client_proc)
        time.sleep(2.0)
        client_status = get_status(client_proc.admin_port or 0)
        server_status = get_status(server_proc.admin_port or 0)
        assert status_state(client_status) != 'CONNECTED'
        assert status_state(server_status) != 'CONNECTED'
        expect_probe_failure(case, PAYLOAD_IN, timeout=3.0)
    finally:
        bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_direct_preflight_requires_http_200_before_upgrade(tmp_path: Path) -> None:
    case_index = 271
    case = materialize_case_ports(CASES['case08_overlay_ws_ipv4'], case_index)
    bounce = BounceBackServer(
        name=f'{case.name}_bounce',
        proto=case.bounce_proto,
        bind_host=case.bounce_bind,
        port=case.bounce_port,
        log_path=tmp_path / f'{case.name}_bounce.log',
    )
    server_proc = client_proc = None
    try:
        bounce.start()
        specs = build_commands(case, tmp_path, case_index, enable_admin=True)
        server_name, server_cmd, server_env, server_admin = specs[0]
        client_name, client_cmd, client_env, client_admin = specs[1]
        client_cmd = _replace_last_arg(client_cmd, '--client-restart-if-disconnected', '0')
        server_cmd = _replace_last_arg(server_cmd, '--log', 'DEBUG')
        client_cmd = _replace_last_arg(client_cmd, '--log', 'DEBUG')
        server_cmd = _append_args(
            server_cmd,
            [
                '--log-ws-session', 'DEBUG',
                '--ws-static-dir', str(tmp_path / 'missing_ws_static_root'),
            ],
        )
        client_cmd = _append_args(client_cmd, ['--log-ws-session', 'DEBUG'])
        server_runtime_log = Path(_arg_value(server_cmd, '--log-file', ''))
        client_runtime_log = Path(_arg_value(client_cmd, '--log-file', ''))

        server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, tmp_path, env_extra=server_env, admin_port=server_admin)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        wait_log_contains(server_runtime_log, 'server listening on', timeout=10.0)
        client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, tmp_path, env_extra=client_env, admin_port=client_admin)

        wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_status = wait_status_failed(
            client_proc.admin_port or 0,
            timeout=15.0,
            label='client',
            reason='http_preflight_failed',
        )
        server_status = wait_status_not_connected(server_proc.admin_port or 0, timeout=10.0, label='server')
        assert status_state(client_status) == 'FAILED'
        assert client_status.get('connection_failure_reason') == 'http_preflight_failed'
        assert client_status.get('connection_failure_transport') == 'ws'
        assert client_status.get('connection_last_event') == 'connect_failed'
        assert 'HTTP status 426' in str(client_status.get('connection_failure_detail') or '')
        assert status_state(server_status) != 'CONNECTED'
        assert_running(server_proc)
        assert_running(client_proc)
        expect_probe_failure(case, PAYLOAD_IN, timeout=3.0)

        client_log = wait_log_contains(client_runtime_log, 'HTTP preflight GET / response status=426', timeout=10.0)
        assert 'refusing websocket upgrade because HTTP preflight returned status=426' in client_log
        assert 'body_bytes=' in client_log

        server_log = wait_log_contains(server_runtime_log, 'note=upgrade-required-static-disabled', timeout=10.0)
        assert 'status=426' in server_log
        assert 'websocket upgrade requested' not in server_log
    finally:
        bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_proxy_manual_override_uses_explicit_proxy(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_manual_proxy_override',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_manual_proxy_override.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=271,
            client_env_extra={'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'},
            client_extra_args=[
                '--ws-proxy-mode', 'manual',
                '--ws-proxy-host', '127.0.0.1',
                '--ws-proxy-port', str(proxy_port),
            ],
        )
        wait_http_proxy_connects(proxy, minimum_count=1, timeout=8.0)
        wait_probe(materialize_case_ports(case, 271), timeout=8.0)
        assert proxy.connect_count >= 1
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_proxy_off_override_disables_platform_default_proxy(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_proxy_off_override',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_proxy_off_override.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=272,
            client_env_extra=_proxy_env(proxy_port, no_proxy=''),
            client_extra_args=['--ws-proxy-mode', 'off'],
            require_probe=False,
        )
        wait_probe(materialize_case_ports(case, 272), timeout=20.0)
        time.sleep(1.0)
        assert proxy.connect_count == 0
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.windows_only
@pytest.mark.skipif(sys.platform != 'win32', reason='Windows-only system proxy default behavior')
def test_overlay_e2e_ws_proxy_system_default_on_windows_uses_system_proxy(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_system_default_windows',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_system_default_windows.log',
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=273,
            client_env_extra=_proxy_env(proxy_port, no_proxy='', include_system_override=True),
        )
        wait_http_proxy_connects(proxy, minimum_count=1, timeout=8.0)
        wait_probe(materialize_case_ports(case, 273), timeout=8.0)
        assert proxy.connect_count >= 1
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.windows_only
@pytest.mark.skipif(sys.platform != 'win32', reason='Windows-only Negotiate proxy behavior')
def test_overlay_e2e_ws_proxy_negotiate_auth_on_windows(tmp_path: Path) -> None:
    case = CASES['case08_overlay_ws_ipv4']
    proxy_port = alloc_admin_port()
    proxy = HttpConnectProxy(
        name='ws_negotiate_windows',
        listen_host='127.0.0.1',
        listen_port=proxy_port,
        log_path=tmp_path / 'ws_negotiate_windows.log',
        require_negotiate=True,
    )
    bounce = None
    server_proc = client_proc = None
    try:
        proxy.start()
        bounce, server_proc, client_proc = _start_ws_case_with_client_env(
            case,
            tmp_path,
            case_index=274,
            client_env_extra=_proxy_env(proxy_port, no_proxy='', include_system_override=True),
            client_extra_args=['--ws-proxy-auth', 'negotiate'],
        )
        wait_http_proxy_connects(proxy, minimum_count=2, timeout=8.0)
        wait_probe(materialize_case_ports(case, 274), timeout=8.0)
        assert any(value.lower().startswith('negotiate ') for value in proxy.proxy_authorizations)
    finally:
        proxy.stop()
        if bounce is not None:
            bounce.stop()
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_happy_path(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=275,
                secure_slot=0,
                server_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret'],
                client_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret'],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport='tcp', authenticated=True)
            wait_peer_compress_layer_stats(client_proc.admin_port or 0, timeout=12.0, label='client', transport='tcp', enabled=True)
            wait_peer_compress_layer_stats(server_proc.admin_port or 0, timeout=12.0, label='server', transport='tcp', enabled=True)
            req = urllib.request.Request(
                _rewrite_registered_admin_url(f'http://127.0.0.1:{server_proc.admin_port}/api/secure-link/debug'),
                data=b'{}',
                method='POST',
                headers={'Connection': 'close'},
            )
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=1.5)
            assert excinfo.value.code == 404
            _code, client_doc = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/peers', timeout=1.5)
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'authenticated'
            assert int(client_secure.get('handshake_attempts_total') or 0) >= 1
            assert int(client_secure.get('authenticated_sessions_total') or 0) >= 1
            assert client_secure.get('last_authenticated_unix_ts') is not None
            _status_code, client_status = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
            assert bool((client_status.get('compress_layer') or {}).get('enabled'))
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_compress_layer_disabled(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=986,
                secure_slot=2,
                server_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--no-compress-layer',
                ],
                client_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--no-compress-layer',
                ],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport='tcp', authenticated=True)
            wait_peer_compress_layer_stats(client_proc.admin_port or 0, timeout=12.0, label='client', transport='tcp', enabled=False)
            wait_peer_compress_layer_stats(server_proc.admin_port or 0, timeout=12.0, label='server', transport='tcp', enabled=False)
            _status_code, client_status = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
            _status_code, server_status = fetch_json(f'http://127.0.0.1:{server_proc.admin_port}/api/status', timeout=1.5)
            assert not bool((client_status.get('compress_layer') or {}).get('enabled'))
            assert not bool((server_status.get('compress_layer') or {}).get('enabled'))
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_compress_layer_mismatched_peer_settings(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=987,
                secure_slot=33,
                server_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--no-compress-layer',
                    '--compress-layer-min-bytes', '4096',
                    '--compress-layer-level', '1',
                    '--compress-layer-types', 'data',
                ],
                client_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--compress-layer-min-bytes', '32',
                    '--compress-layer-level', '9',
                    '--compress-layer-types', 'data,data_frag',
                ],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport='tcp', authenticated=True)

            payload = b'\x21' + (b'C' * 1400)
            wait_probe(case, payload=payload, expected=response_payload(payload), timeout=15.0)

            wait_peer_compress_layer_stats(
                client_proc.admin_port or 0,
                timeout=12.0,
                label='client',
                transport='tcp',
                enabled=True,
                minimum_applied_total=1,
            )
            wait_peer_compress_layer_stats(
                server_proc.admin_port or 0,
                timeout=12.0,
                label='server',
                transport='tcp',
                enabled=True,
            )

            _status_code, client_peers = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/peers', timeout=1.5)
            _status_code, server_peers = fetch_json(f'http://127.0.0.1:{server_proc.admin_port}/api/peers', timeout=1.5)
            client_row = first_active_secure_link_row(client_peers, transport='tcp')
            server_row = first_active_secure_link_row(server_peers, transport='tcp')
            client_comp = dict(client_row.get('compress_layer') or {})
            server_comp = dict(server_row.get('compress_layer') or {})

            assert bool(client_comp.get('enabled'))
            assert bool(server_comp.get('enabled'))
            assert int(client_comp.get('compress_applied_total') or 0) >= 1
            assert int(server_comp.get('decompress_ok_total') or 0) >= 1
            # Server-side local compression config is passive for peer-client-driven compression:
            # once the client proves compression is active, the server compresses replies for that peer too.
            assert int(server_comp.get('compress_applied_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_time_rekey_rearms_after_completion(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=276,
                secure_slot=1,
                server_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret'],
                client_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
                    '--secure-link-rekey-after-seconds', '1.0',
                ],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport='tcp', authenticated=True)

            wait_probe(case, payload=b'\x01prime-time-threshold-rekey', timeout=12.0)
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            first_secure = dict((first_active_secure_link_row(first_doc, transport='tcp').get('secure_link') or {}))
            first_session_id = int(first_secure.get('session_id') or 0)
            assert first_session_id > 0

            seen_session_ids = {first_session_id}

            first_rekey_doc = wait_peer_secure_link_rekeys_completed(
                client_proc.admin_port or 0,
                minimum_count=1,
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            first_rekey_secure = dict((first_active_secure_link_row(first_rekey_doc, transport='tcp').get('secure_link') or {}))
            first_rekey_session_id = int(first_rekey_secure.get('session_id') or 0)
            seen_session_ids.add(first_rekey_session_id)
            assert first_rekey_session_id > 0
            assert first_rekey_session_id != first_session_id
            assert first_rekey_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(first_rekey_secure.get('rekeys_completed_total') or 0) >= 1

            wait_probe(case, payload=b'\x01after-first-time-threshold-rekey', timeout=12.0)

            second_rekey_doc = wait_peer_secure_link_rekeys_completed(
                client_proc.admin_port or 0,
                minimum_count=2,
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            second_rekey_secure = dict((first_active_secure_link_row(second_rekey_doc, transport='tcp').get('secure_link') or {}))
            second_rekey_session_id = int(second_rekey_secure.get('session_id') or 0)
            seen_session_ids.add(second_rekey_session_id)
            assert second_rekey_session_id > 0
            assert second_rekey_session_id != first_rekey_session_id
            assert second_rekey_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(second_rekey_secure.get('rekeys_completed_total') or 0) >= 2
            assert len({sid for sid in seen_session_ids if sid > 0}) >= 3

            wait_probe(case, payload=b'\x01after-second-time-threshold-rekey', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("case_name", "case_index", "secure_slot", "transport"),
    [
        ('case06_overlay_tcp_ipv4', 290, 21, 'tcp'),
        ('case01_udp_over_own_udp_ipv4', 291, 5, 'myudp'),
        ('case08_overlay_ws_ipv4', 292, 6, 'ws'),
        ('case10_overlay_quic_ipv4', 293, 7, 'quic'),
    ],
)
def test_overlay_e2e_secure_link_cert_happy_path_transports(
    case_name: str,
    case_index: int,
    secure_slot: int,
    transport: str,
    tmp_path: Path,
) -> None:
    with secure_link_test_lock():
        case = CASES[case_name]
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=case_index,
                secure_slot=secure_slot,
                server_extra_args=_cert_secure_args(
                    root_pub='root_a_pub.pem',
                    cert_body='server_valid_cert_body.json',
                    cert_sig='server_valid_cert.sig',
                    private_key='server_valid_key.pem',
                ),
                client_extra_args=_cert_secure_args(
                    root_pub='root_a_pub.pem',
                    cert_body='client_valid_cert_body.json',
                    cert_sig='client_valid_cert.sig',
                    private_key='client_valid_key.pem',
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport=transport, authenticated=True)
            server_doc = wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport=transport, authenticated=True)
            client_secure = dict((first_active_secure_link_row(client_doc, transport=transport).get('secure_link') or {}))
            server_secure = dict((first_active_secure_link_row(server_doc, transport=transport).get('secure_link') or {}))
            assert client_secure.get('mode') == 'cert'
            assert client_secure.get('peer_subject_id') == 'bridge-server-01'
            assert client_secure.get('peer_subject_name') == 'Bridge Server 01'
            assert client_secure.get('peer_roles') == ['server']
            assert client_secure.get('peer_deployment_id') == 'lab-a'
            assert client_secure.get('peer_serial') == 'server_valid'
            assert client_secure.get('issuer_id') == 'deployment-admin-a'
            assert client_secure.get('trust_validation_state') == 'trusted'
            assert client_secure.get('trust_anchor_id')
            assert server_secure.get('peer_subject_id') == 'bridge-client-01'
            assert server_secure.get('peer_roles') == ['client']
            assert server_secure.get('trust_validation_state') == 'trusted'
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("expected_reason", "client_root", "client_body", "client_sig", "client_key", "server_revoked"),
    [
        ('unknown_root', 'root_b_pub.pem', 'client_root_b_cert_body.json', 'client_root_b_cert.sig', 'client_root_b_key.pem', None),
        ('wrong_role', 'root_a_pub.pem', 'client_wrong_role_cert_body.json', 'client_wrong_role_cert.sig', 'client_wrong_role_key.pem', None),
        ('expired', 'root_a_pub.pem', 'client_expired_cert_body.json', 'client_expired_cert.sig', 'client_expired_key.pem', None),
        ('not_yet_valid', 'root_a_pub.pem', 'client_future_cert_body.json', 'client_future_cert.sig', 'client_future_key.pem', None),
        ('deployment_mismatch', 'root_a_pub.pem', 'client_other_deploy_cert_body.json', 'client_other_deploy_cert.sig', 'client_other_deploy_key.pem', None),
        ('revoked_serial', 'root_a_pub.pem', 'client_valid_cert_body.json', 'client_valid_cert.sig', 'client_valid_key.pem', 'revoked_serials.json'),
    ],
)
def test_overlay_e2e_tcp_secure_link_cert_rejection_matrix(
    expected_reason: str,
    client_root: str,
    client_body: str,
    client_sig: str,
    client_key: str,
    server_revoked: Optional[str],
    tmp_path: Path,
    ) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            wait_client_admin = expected_reason not in ('expired', 'not_yet_valid')
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=294,
                secure_slot=25,
                server_extra_args=_cert_secure_args(
                    root_pub='root_a_pub.pem',
                    cert_body='server_valid_cert_body.json',
                    cert_sig='server_valid_cert.sig',
                    private_key='server_valid_key.pem',
                    revoked_serials=server_revoked,
                ),
                client_extra_args=_cert_secure_args(
                    root_pub=client_root,
                    cert_body=client_body,
                    cert_sig=client_sig,
                    private_key=client_key,
                ),
                client_restart_if_disconnected=30,
                wait_client_admin=wait_client_admin,
            )
            wait_status_not_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            if expected_reason in ('expired', 'not_yet_valid'):
                deadline = time.time() + 10.0
                while time.time() < deadline and client_proc.popen.poll() is None:
                    time.sleep(0.1)
                rc = client_proc.popen.poll()
                assert rc not in (None, 0)
                tail = client_proc.log_path.read_text(errors='replace')[-4000:] if client_proc.log_path.exists() else ''
                if expected_reason == 'expired':
                    assert 'local certificate has expired' in tail
                else:
                    assert 'local certificate is not valid yet' in tail
            else:
                wait_status_not_connected(client_proc.admin_port or 0, timeout=20.0, label='client')
                failed_doc = wait_peer_secure_link_state(
                    client_proc.admin_port or 0,
                    expected_state='failed',
                    timeout=12.0,
                    label='client',
                    transport='tcp',
                    authenticated=False,
                    failure_reason=expected_reason,
                )
                secure = dict((first_active_secure_link_row(failed_doc, transport='tcp').get('secure_link') or {}))
                assert secure.get('mode') == 'cert'
                assert secure.get('trust_validation_state') == 'failed'
                assert secure.get('trust_failure_reason') == expected_reason
                assert secure.get('trust_failure_detail')
            with pytest.raises(Exception):
                wait_probe(case, timeout=3.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_operator_forced_rekey(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=295,
                secure_slot=26,
                server_extra_args=_cert_secure_args(
                    root_pub='root_a_pub.pem',
                    cert_body='server_valid_cert_body.json',
                    cert_sig='server_valid_cert.sig',
                    private_key='server_valid_key.pem',
                ),
                client_extra_args=_cert_secure_args(
                    root_pub='root_a_pub.pem',
                    cert_body='client_valid_cert_body.json',
                    cert_sig='client_valid_cert.sig',
                    private_key='client_valid_key.pem',
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            target_peer_id = ""
            first_session_id = 0
            for row in list(first_doc.get('peers') or []):
                if str(row.get('transport', '')).strip().lower() != 'tcp':
                    continue
                if str(row.get('state', '')).strip().lower() == 'listening':
                    continue
                target_peer_id = str(row.get('id') or "")
                first_session_id = int(((row.get('secure_link') or {}).get('session_id') or 0))
                if first_session_id:
                    break
            if first_session_id <= 0 or not target_peer_id:
                raise RuntimeError(f'Could not determine cert-mode peer/session from peers doc: {first_doc!r}')
            wait_probe(case, payload=b'\x01prime-cert-operator-rekey', timeout=12.0)
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/rekey',
                method='POST',
                payload={"peer_id": target_peer_id},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=12.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01after-cert-operator-rekey', timeout=12.0)
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('mode') == 'cert'
            assert client_secure.get('last_event') == 'rekey_completed'
            assert client_secure.get('last_rekey_trigger') == 'operator'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("scope", "button_id", "button_label", "expect_drop"),
    [
        ('revocation', 'secureLinkReloadRevocationBtn', 'Reload Revocation', False),
        ('local_identity', 'secureLinkReloadIdentityBtn', 'Reload Local Identity', True),
        ('all', 'secureLinkReloadAllBtn', 'Reload All', True),
    ],
)
def test_overlay_e2e_webadmin_cert_reload_buttons_drive_authenticated_reload_flow(
    scope: str,
    button_id: str,
    button_label: str,
    expect_drop: bool,
    tmp_path: Path,
) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / f"runtime-certs-webadmin-{scope}")
        revoked_path = runtime_certs / "revoked_runtime.json"
        revoked_path.write_text("[]\n", encoding="utf-8")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        username = 'admin'
        password = 'secret-pass'
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=301,
                secure_slot=32,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                    extra=['--admin-web-username', username, '--admin-web-password', password],
                ),
                wait_client_admin=False,
            )
            wait_admin_auth_up(client_proc.admin_port or 0, timeout=10.0)
            login_code, login_doc, opener = admin_authenticate(client_proc.admin_port or 0, username, password)
            assert login_code == 200
            assert login_doc.get('authenticated') is True
            wait_probe(case, payload=f'\x01webadmin-reload-prime-{scope}'.encode('ascii'), timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_connected_auth(client_proc.admin_port or 0, timeout=20.0, label='client', opener=opener)

            index_code, index_headers, index_html = fetch_http_text(
                f'http://127.0.0.1:{client_proc.admin_port}/',
                timeout=2.0,
                opener=opener,
            )
            assert index_code == 200
            assert 'text/html' in str(index_headers.get('content-type') or '').lower()
            assert f'id="{button_id}"' in index_html
            assert button_label in index_html

            app_code, app_headers, app_js = fetch_http_text(
                f'http://127.0.0.1:{client_proc.admin_port}/app.js',
                timeout=2.0,
                opener=opener,
            )
            assert app_code == 200
            app_content_type = str(app_headers.get('content-type') or '').lower()
            assert 'javascript' in app_content_type or 'text/plain' in app_content_type
            assert f"document.getElementById('{button_id}')" in app_js
            assert f"requestSecureLinkReload('{scope}')" in app_js

            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": scope},
                timeout=2.0,
                opener=opener,
            )
            assert code == 200
            assert body.get('ok') is True
            assert body.get('scope') == scope
            if expect_drop:
                assert int(body.get('dropped') or 0) >= 1
            else:
                assert int(body.get('dropped') or 0) == 0

            client_doc = wait_peer_secure_link_state_auth(
                client_proc.admin_port or 0,
                opener=opener,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('mode') == 'cert'
            assert secure.get('last_material_reload_scope') == scope
            assert secure.get('last_material_reload_result') == 'applied'

            _status_code, status_doc = fetch_json_auth(
                f'http://127.0.0.1:{client_proc.admin_port}/api/status',
                timeout=1.5,
                opener=opener,
            )
            assert status_doc.get('secure_link_last_reload_scope') == scope
            assert status_doc.get('secure_link_last_reload_result') == 'applied'
            if expect_drop:
                assert int(status_doc.get('secure_link_peers_dropped_total') or 0) >= 1

            wait_probe(case, payload=f'\x01webadmin-reload-after-{scope}'.encode('ascii'), timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_revocation_reload_happy_path(tmp_path: Path) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / "runtime-certs-revoke")
        revoked_path = runtime_certs / "revoked_runtime.json"
        revoked_path.write_text("[]\n", encoding="utf-8")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=296,
                secure_slot=27,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01prime-cert-revocation-reload', timeout=12.0)
            revoked_path.write_text(json.dumps(["server_valid"]), encoding="utf-8")
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": "revocation"},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            assert body.get('scope') == 'revocation'
            assert int(body.get('dropped') or 0) >= 1
            failed_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='failed',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=False,
                failure_reason='revoked_serial',
            )
            secure = dict((first_active_secure_link_row(failed_doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('disconnect_reason') == 'revocation_applied'
            assert secure.get('last_material_reload_scope') == 'revocation'
            assert secure.get('last_material_reload_result') == 'applied'
            _status_code, status_doc = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
            assert status_doc.get('secure_link_last_reload_scope') == 'revocation'
            assert status_doc.get('secure_link_last_reload_result') == 'applied'
            assert int(status_doc.get('secure_link_peers_dropped_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_revocation_reload_noop(tmp_path: Path) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / "runtime-certs-revoke-noop")
        revoked_path = runtime_certs / "revoked_runtime.json"
        revoked_path.write_text("[]\n", encoding="utf-8")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=297,
                secure_slot=28,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": "revocation"},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            assert int(body.get('dropped') or 0) == 0
            wait_probe(case, payload=b'\x01cert-revocation-noop', timeout=12.0)
            doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            secure = dict((first_active_secure_link_row(doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('last_material_reload_scope') == 'revocation'
            assert secure.get('last_material_reload_result') == 'applied'
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_happy_path(tmp_path: Path) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / "runtime-certs-local-reload")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=298,
                secure_slot=29,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            first_secure = dict((first_active_secure_link_row(first_doc, transport='tcp').get('secure_link') or {}))
            first_generation = int(first_secure.get('active_material_generation') or 0)
            wait_probe(case, payload=b'\x01prime-cert-local-identity-reload', timeout=12.0)
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": "local_identity"},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            assert body.get('scope') == 'local_identity'
            assert int(body.get('dropped') or 0) >= 1
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('last_material_reload_scope') == 'local_identity'
            assert secure.get('last_material_reload_result') == 'applied'
            assert int(secure.get('active_material_generation') or 0) > first_generation
            assert int(secure.get('handshake_attempts_total') or 0) >= 2
            wait_probe(case, payload=b'\x01after-cert-local-identity-reload', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_rejected(tmp_path: Path) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / "runtime-certs-local-reload-fail")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=299,
                secure_slot=30,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01prime-cert-local-identity-reload-fail', timeout=12.0)
            (runtime_certs / 'client_valid_cert_body.json').write_text('{bad json', encoding='utf-8')
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": "local_identity"},
                timeout=2.0,
            )
            assert code == 409
            assert body.get('ok') is False
            doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            secure = dict((first_active_secure_link_row(doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('last_material_reload_result') == 'failed'
            wait_probe(case, payload=b'\x01after-cert-local-identity-reload-fail', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_cert_full_reload_applies_atomically(tmp_path: Path) -> None:
    with secure_link_test_lock():
        runtime_certs = _copy_secure_link_cert_fixture_set(tmp_path / "runtime-certs-full-reload")
        revoked_path = runtime_certs / "revoked_runtime.txt"
        revoked_path.write_text("", encoding="utf-8")
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=300,
                secure_slot=31,
                server_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'server_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'server_valid_cert.sig'),
                    private_key=str(runtime_certs / 'server_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
                client_extra_args=_cert_secure_args_paths(
                    root_pub=str(runtime_certs / 'root_a_pub.pem'),
                    cert_body=str(runtime_certs / 'client_valid_cert_body.json'),
                    cert_sig=str(runtime_certs / 'client_valid_cert.sig'),
                    private_key=str(runtime_certs / 'client_valid_key.pem'),
                    revoked_serials=str(revoked_path),
                ),
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01prime-cert-full-reload', timeout=12.0)
            revoked_path.write_text("unused-serial\n", encoding="utf-8")
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/reload',
                method='POST',
                payload={"scope": "all"},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            assert body.get('scope') == 'all'
            assert int(body.get('dropped') or 0) >= 1
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert secure.get('last_material_reload_scope') == 'all'
            assert secure.get('last_material_reload_result') == 'applied'
            assert int(secure.get('active_material_generation') or 0) >= 2
            _status_code, status_doc = fetch_json(f'http://127.0.0.1:{client_proc.admin_port}/api/status', timeout=1.5)
            assert status_doc.get('secure_link_last_reload_scope') == 'all'
            assert status_doc.get('secure_link_last_reload_result') == 'applied'
            wait_probe(case, payload=b'\x01after-cert-full-reload', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=276,
                secure_slot=1,
                server_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'server-secret'],
                client_extra_args=[
                    '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'client-secret',
                    '--secure-link-retry-backoff-initial-ms', '250',
                    '--secure-link-retry-backoff-max-ms', '500',
                ],
                client_restart_if_disconnected=30,
            )
            wait_status_not_connected(client_proc.admin_port or 0, timeout=20.0, label='client')
            wait_status_not_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='failed',
                timeout=12.0,
                label='client',
                authenticated=False,
                failure_code=1,
                failure_reason='bad_psk',
                failure_detail_substr='pre-shared secret mismatch',
            )
            failed_doc = wait_status_secure_link_consecutive_failures(
                client_proc.admin_port or 0,
                minimum_count=2,
                timeout=12.0,
                label='client',
            )
            secure_link = dict((first_active_secure_link_row(failed_doc, transport='tcp').get('secure_link') or {}))
            assert float(secure_link.get('retry_backoff_sec') or 0.0) >= 0.0
            assert secure_link.get('next_retry_unix_ts') is not None
            assert secure_link.get('last_event') == 'retry_scheduled'
            assert secure_link.get('failure_session_id') is not None
            assert int(secure_link.get('handshake_attempts_total') or 0) >= 2
            with pytest.raises(Exception):
                wait_probe(case, timeout=3.0)
            assert_running(server_proc)
            assert_running(client_proc)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-frames', '1',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=284,
                secure_slot=9,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            first_session_id = 0
            for row in list(first_doc.get('peers') or []):
                if str(row.get('transport', '')).strip().lower() != 'tcp':
                    continue
                if str(row.get('state', '')).strip().lower() == 'listening':
                    continue
                first_session_id = int(((row.get('secure_link') or {}).get('session_id') or 0))
                if first_session_id:
                    break
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial secure-link session id from peers doc: {first_doc!r}')
            wait_probe(case, payload=b'\x01rekey-one', timeout=12.0)
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=12.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01rekey-two', timeout=12.0)
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            server_doc = wait_peer_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', transport='tcp', authenticated=True)
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            server_secure = dict((first_active_secure_link_row(server_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'rekey_completed'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
            assert int(client_secure.get('authenticated_sessions_total') or 0) >= 2
            assert server_secure.get('last_authenticated_unix_ts') is not None
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        server_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]
        client_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-seconds', '1.0',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=285,
                secure_slot=10,
                server_extra_args=server_args,
                client_extra_args=client_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            first_session_id = 0
            for row in list(first_doc.get('peers') or []):
                if str(row.get('transport', '')).strip().lower() != 'tcp':
                    continue
                if str(row.get('state', '')).strip().lower() == 'listening':
                    continue
                first_session_id = int(((row.get('secure_link') or {}).get('session_id') or 0))
                if first_session_id:
                    break
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial secure-link session id from peers doc: {first_doc!r}')
            wait_probe(case, payload=b'\x01prime-time-rekey', timeout=12.0)
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=12.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01time-rekey', timeout=12.0)
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'rekey_completed'
            assert client_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold_while_idle(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        server_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]
        client_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-seconds', '10.0',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=386,
                secure_slot=21,
                server_extra_args=server_args,
                client_extra_args=client_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            client_secure_initial = dict((first_active_secure_link_row(first_doc, transport='tcp').get('secure_link') or {}))
            first_session_id = int(client_secure_initial.get('session_id') or 0)
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial secure-link session id from peers doc: {first_doc!r}')
            due_unix_ts = client_secure_initial.get('rekey_due_unix_ts')
            if due_unix_ts is None:
                raise RuntimeError(
                    f'Client secure-link row did not publish a time-based rekey deadline after authentication: '
                    f'{client_secure_initial!r}'
                )
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=16.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01idle-time-rekey', timeout=12.0)
            client_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'rekey_completed'
            assert client_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_secure_link_psk_rekeys_after_time_threshold_under_live_traffic(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case01_udp_over_own_udp_ipv4']
        bounce = None
        server_proc = client_proc = None
        server_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        client_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-seconds', '3.0',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=391,
                secure_slot=23,
                server_extra_args=server_args,
                client_extra_args=client_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='myudp',
                authenticated=True,
            )
            first_secure = dict((first_active_secure_link_row(first_doc, transport='myudp').get('secure_link') or {}))
            first_session_id = int(first_secure.get('session_id') or 0)
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial myudp secure-link session id from peers doc: {first_doc!r}')
            if first_secure.get('rekey_due_unix_ts') is None:
                raise RuntimeError(
                    f'Client myudp secure-link row did not publish a time-based rekey deadline after authentication: '
                    f'{first_secure!r}'
                )

            rekey_doc = None
            last_secure = first_secure
            for attempt in range(8):
                wait_probe(case, payload=f'\x01myudp-live-time-{attempt}'.encode('ascii'), timeout=12.0)
                code, polled_doc = request_json(
                    f'http://127.0.0.1:{client_proc.admin_port}/api/peers',
                    timeout=2.0,
                )
                assert code == 200
                last_secure = dict((first_active_secure_link_row(polled_doc, transport='myudp').get('secure_link') or {}))
                if int(last_secure.get('session_id') or 0) != first_session_id:
                    rekey_doc = polled_doc
                    break
                time.sleep(0.5)

            if rekey_doc is None:
                raise RuntimeError(
                    'myudp secure-link session did not rotate while protected traffic was flowing across the '
                    f'time-threshold window; last secure-link row: {last_secure!r}'
                )

            client_secure = dict((first_active_secure_link_row(rekey_doc, transport='myudp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'rekey_completed'
            assert client_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
            wait_probe(case, payload=b'\x01myudp-live-time-after', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_secure_link_psk_rekey_done_delay_keeps_same_udp_channel_healthy(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case_index = 392
        base_port = _myudp_delay_loss_base_port(case_index)
        loopback_v4, _loopback_v6 = _loopback_hosts_for_case(case_index)
        server_overlay_port = base_port
        proxy_listen_port = base_port + 1
        proxy_forward_port = base_port + 2
        client_probe_port = base_port + 10
        server_target_port = base_port + 12
        server_admin, client_admin = alloc_admin_ports(case_index, base=SECURE_LINK_ADMIN_BASE)
        missing_cfg = str(tmp_path / 'myudp_secure_link_rekey_done_delay_missing.cfg')
        py = sys.executable

        proxy = UdpDelayLossProxy(
            name='myudp_secure_link_rekey_done_delay',
            listen_host=loopback_v4,
            listen_port=proxy_listen_port,
            upstream_host=loopback_v4,
            upstream_port=server_overlay_port,
            forward_bind_host=loopback_v4,
            forward_bind_port=proxy_forward_port,
            delay_ms=0,
            log_path=tmp_path / 'myudp_secure_link_rekey_done_delay.log',
            delay_server_to_client_secure_link_types_ms={
                SecureLinkPskSession._SL_TYPE_REKEY_DONE: 2500,
            },
        )
        bounce = BounceBackServer(
            name='myudp_secure_link_rekey_done_delay_bounce',
            proto='udp',
            bind_host=loopback_v4,
            port=server_target_port,
            log_path=tmp_path / 'myudp_secure_link_rekey_done_delay_bounce.log',
        )

        server_cmd = [
            py, str(BRIDGE),
            '--overlay-transport', 'myudp',
            '--udp-bind', loopback_v4, '--udp-own-port', str(server_overlay_port),
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', str(tmp_path / 'myudp_secure_link_rekey_done_delay_server.txt'),
            '--config', missing_cfg, '--admin-web-port', '0',
        ] + admin_args(server_admin) + [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]
        client_cmd = [
            py, str(BRIDGE),
            '--overlay-transport', 'myudp',
            '--udp-peer', loopback_v4, '--udp-peer-port', str(proxy_listen_port),
            '--udp-bind', loopback_v4, '--udp-own-port', '0',
            '--own-servers', f'udp,{client_probe_port},{loopback_v4},udp,{loopback_v4},{server_target_port}',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', str(tmp_path / 'myudp_secure_link_rekey_done_delay_client.txt'),
            '--config', missing_cfg, '--admin-web-port', '0',
        ] + admin_args(client_admin) + [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]

        server_proc: Optional[Proc] = None
        client_proc: Optional[Proc] = None
        udp_sock: Optional[socket.socket] = None
        try:
            bounce.start()
            proxy.start()
            server_proc = start_proc('myudp_secure_link_rekey_done_delay_server', server_cmd, tmp_path, admin_port=server_admin)
            client_proc = start_proc('myudp_secure_link_rekey_done_delay_client', client_cmd, tmp_path, admin_port=client_admin)
            wait_admin_up(server_admin, timeout=10.0)
            wait_admin_up(client_admin, timeout=10.0)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=30.0, label='client')

            client_doc = wait_peer_secure_link_state(
                client_admin,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='myudp',
                authenticated=True,
            )
            first_row = first_active_secure_link_row(client_doc, transport='myudp')
            first_secure = dict((first_row.get('secure_link') or {}))
            first_session_id = int(first_secure.get('session_id') or 0)
            target_peer_id = str(first_row.get('id') or '')
            if first_session_id <= 0 or not target_peer_id:
                raise RuntimeError(f'Could not determine initial myudp secure-link peer row: {client_doc!r}')

            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind((loopback_v4, 0))
            udp_sock.settimeout(1.5)
            udp_sock.sendto(b'\x01rekey-gap-prime', (loopback_v4, client_probe_port))
            prime_reply, _addr = udp_sock.recvfrom(4096)
            assert prime_reply == response_payload(b'\x01rekey-gap-prime')
            wait_peer_secure_link_state(
                server_admin,
                expected_state='authenticated',
                timeout=12.0,
                label='server',
                transport='myudp',
                authenticated=True,
            )

            code, body = request_json(
                f'http://127.0.0.1:{client_admin}/api/secure-link/rekey',
                method='POST',
                payload={'peer_id': target_peer_id},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True

            end = time.time() + 12.0
            gap_window_open = False
            while time.time() < end:
                _client_code, polled_client = fetch_json(f'http://127.0.0.1:{client_admin}/api/peers', timeout=1.5)
                _server_code, polled_server = fetch_json(f'http://127.0.0.1:{server_admin}/api/peers', timeout=1.5)
                client_secure = dict((first_active_secure_link_row(polled_client, transport='myudp').get('secure_link') or {}))
                server_secure = dict((first_active_secure_link_row(polled_server, transport='myudp').get('secure_link') or {}))
                if (
                    bool(client_secure.get('rekey_in_progress'))
                    and int(client_secure.get('session_id') or 0) == first_session_id
                    and int(server_secure.get('session_id') or 0) != first_session_id
                ):
                    gap_window_open = True
                    break
                time.sleep(0.05)
            if not gap_window_open:
                raise RuntimeError('Did not observe the rekey cutover gap where server switched before client received REKEY_DONE')

            udp_sock.settimeout(5.0)
            udp_sock.sendto(b'\x01rekey-gap-during', (loopback_v4, client_probe_port))
            during_reply, _addr = udp_sock.recvfrom(4096)
            assert during_reply == response_payload(b'\x01rekey-gap-during')

            wait_peer_secure_link_session_change(
                client_admin,
                previous_session_id=first_session_id,
                timeout=12.0,
                label='client',
                transport='myudp',
            )
            udp_sock.settimeout(2.0)
            udp_sock.sendto(b'\x01rekey-gap-after', (loopback_v4, client_probe_port))
            after_reply, _addr = udp_sock.recvfrom(4096)
            assert after_reply == response_payload(b'\x01rekey-gap-after')
        finally:
            if udp_sock is not None:
                udp_sock.close()
            proxy.stop()
            bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_operator_forced_rekey(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=286,
                secure_slot=10,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            first_session_id = 0
            target_peer_id = ""
            for row in list(first_doc.get('peers') or []):
                if str(row.get('transport', '')).strip().lower() != 'tcp':
                    continue
                if str(row.get('state', '')).strip().lower() == 'listening':
                    continue
                target_peer_id = str(row.get('id') or "")
                first_session_id = int(((row.get('secure_link') or {}).get('session_id') or 0))
                if first_session_id:
                    break
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial secure-link session id from peers doc: {first_doc!r}')
            if not target_peer_id:
                raise RuntimeError(f'Could not determine target peer id from peers doc: {first_doc!r}')
            wait_probe(case, payload=b'\x01prime-operator-rekey', timeout=12.0)
            code, body = request_json(
                f'http://127.0.0.1:{client_proc.admin_port}/api/secure-link/rekey',
                method='POST',
                payload={"peer_id": target_peer_id},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            assert body.get('target_peer_id') == target_peer_id
            assert int(body.get('requested') or 0) >= 1
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=12.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01forced-rekey', timeout=12.0)
            client_doc = wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='tcp', authenticated=True)
            client_secure = dict((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}))
            assert client_secure.get('last_event') == 'rekey_completed'
            assert client_secure.get('last_rekey_trigger') == 'operator'
            assert int(client_secure.get('rekeys_completed_total') or 0) >= 1
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_reconnects_with_fresh_session(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=287,
                secure_slot=12,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
                client_restart_if_disconnected=30,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            client_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            old_session_id = int(((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}).get('session_id') or 0))
            if old_session_id <= 0:
                raise RuntimeError(f'Could not determine initial secure-link session id from client peers doc: {client_doc!r}')
            wait_probe(case, payload=b'\x01reconnect-prime', timeout=12.0)
            server_doc = wait_peer_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='server',
                transport='tcp',
                authenticated=True,
            )

            old_client = client_proc
            stop_proc(client_proc)
            client_proc = None
            wait_status_not_connected(server_proc.admin_port or 0, timeout=20.0, label='server')

            client_proc = start_proc(
                old_client.name,
                list(old_client.cmd or []),
                tmp_path,
                env_extra=old_client.env_extra,
                admin_port=old_client.admin_port,
            )
            wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01reconnect-after-prime', timeout=12.0)
            server_doc = wait_peer_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=20.0,
                label='server',
                transport='tcp',
                authenticated=True,
            )
            new_session_id = int(((first_active_secure_link_row(server_doc, transport='tcp').get('secure_link') or {}).get('session_id') or 0))
            if new_session_id <= 0:
                raise RuntimeError(f'Could not determine reconnected secure-link session id from peers doc: {server_doc!r}')
            assert new_session_id != old_session_id
            wait_probe(case, payload=b'\x01reconnect-after', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_secure_link_psk_recovery_after_prior_time_threshold_rekey_reports_fresh_authentication(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case_index = 389
        base_port = _myudp_delay_loss_base_port(case_index)
        loopback_v4, _loopback_v6 = _loopback_hosts_for_case(case_index)
        server_overlay_port = base_port
        proxy_listen_port = base_port + 1
        proxy_forward_port = base_port + 2
        client_probe_port = base_port + 10
        server_probe_port = base_port + 11
        server_target_port = base_port + 12
        client_target_port = base_port + 13
        server_admin, client_admin = alloc_admin_ports(case_index, base=SECURE_LINK_ADMIN_BASE)
        missing_cfg = str(tmp_path / 'myudp_secure_link_recovery_elapsed_timer_missing.cfg')
        py = sys.executable

        bounce_server = BounceBackServer(
            name='myudp_secure_link_recovery_server_bounce',
            proto='udp',
            bind_host=loopback_v4,
            port=server_target_port,
            log_path=tmp_path / 'myudp_secure_link_recovery_server_bounce.log',
        )
        bounce_client = BounceBackServer(
            name='myudp_secure_link_recovery_client_bounce',
            proto='udp',
            bind_host=loopback_v4,
            port=client_target_port,
            log_path=tmp_path / 'myudp_secure_link_recovery_client_bounce.log',
        )

        def build_proxy() -> UdpDelayLossProxy:
            return UdpDelayLossProxy(
                name='myudp_secure_link_recovery_elapsed_timer',
                listen_host=loopback_v4,
                listen_port=proxy_listen_port,
                upstream_host=loopback_v4,
                upstream_port=server_overlay_port,
                forward_bind_host=loopback_v4,
                forward_bind_port=proxy_forward_port,
                delay_ms=300,
                log_path=tmp_path / 'myudp_secure_link_recovery_proxy.log',
            )

        server_cmd = [
            py, str(BRIDGE),
            '--overlay-transport', 'myudp',
            '--udp-bind', loopback_v4, '--udp-own-port', str(server_overlay_port),
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', str(tmp_path / 'myudp_secure_link_recovery_server.txt'),
            '--config', missing_cfg, '--admin-web-port', '0',
        ] + admin_args(server_admin) + [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
        ]
        client_cmd = [
            py, str(BRIDGE),
            '--overlay-transport', 'myudp',
            '--udp-peer', loopback_v4, '--udp-peer-port', str(proxy_listen_port),
            '--udp-bind', loopback_v4, '--udp-own-port', '0',
            '--own-servers', f'udp,{client_probe_port},{loopback_v4},udp,{loopback_v4},{server_target_port}',
            '--remote-servers', f'udp,{server_probe_port},{loopback_v4},udp,{loopback_v4},{client_target_port}',
            '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
            '--log-file', str(tmp_path / 'myudp_secure_link_recovery_client.txt'),
            '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
        ] + admin_args(client_admin) + [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-seconds', '10.0',
        ]

        server_proc: Optional[Proc] = None
        client_proc: Optional[Proc] = None
        proxy: Optional[UdpDelayLossProxy] = None
        try:
            bounce_server.start()
            bounce_client.start()
            proxy = build_proxy()
            proxy.start()

            server_proc = start_proc('myudp_secure_link_recovery_server', server_cmd, tmp_path, admin_port=server_admin)
            client_proc = start_proc('myudp_secure_link_recovery_client', client_cmd, tmp_path, admin_port=client_admin)
            wait_admin_up(server_admin, timeout=10.0)
            wait_admin_up(client_admin, timeout=10.0)

            server_proc, client_proc = wait_both_connected(server_proc, client_proc, tmp_path, timeout=30.0)
            wait_peer_endpoint_visible(server_admin, timeout=12.0, label='server', transport='myudp')
            wait_peer_endpoint_visible(client_proc.admin_port or 0, timeout=12.0, label='client', transport='myudp')

            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='myudp',
                authenticated=True,
            )
            first_secure = dict((first_active_secure_link_row(first_doc, transport='myudp').get('secure_link') or {}))
            first_session_id = int(first_secure.get('session_id') or 0)
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial myudp secure-link session id from peers doc: {first_doc!r}')
            if first_secure.get('rekey_due_unix_ts') is None:
                raise RuntimeError(
                    f'Client myudp secure-link row did not publish a time-based rekey deadline after authentication: '
                    f'{first_secure!r}'
                )
            got = _wait_udp_probe_result(loopback_v4, client_probe_port, b'\x01myudp-recovery-prime', timeout=12.0)
            if got != response_payload(b'\x01myudp-recovery-prime'):
                raise RuntimeError(f'Unexpected pre-outage myudp probe reply: {got!r}')

            rekey_doc = wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=18.0,
                label='client',
                transport='myudp',
            )
            rekey_secure = dict((first_active_secure_link_row(rekey_doc, transport='myudp').get('secure_link') or {}))
            pre_recovery_session_id = int(rekey_secure.get('session_id') or 0)
            if pre_recovery_session_id <= 0:
                raise RuntimeError(f'Could not determine post-rekey myudp secure-link session id from peers doc: {rekey_doc!r}')
            assert pre_recovery_session_id != first_session_id
            assert rekey_secure.get('last_event') == 'rekey_completed'
            assert rekey_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(rekey_secure.get('rekeys_completed_total') or 0) >= 1

            proxy.stop()
            proxy = None
            wait_status_not_connected(client_proc.admin_port or 0, timeout=30.0, label='client')
            wait_status_not_connected(server_admin, timeout=30.0, label='server')

            rebuilt_proxy = build_proxy()
            rebuilt_proxy.start()
            proxy = rebuilt_proxy

            server_proc, client_proc = wait_both_connected(server_proc, client_proc, tmp_path, timeout=30.0)
            recovered_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=20.0,
                label='client',
                transport='myudp',
                authenticated=True,
            )
            recovered_secure = dict((first_active_secure_link_row(recovered_doc, transport='myudp').get('secure_link') or {}))
            recovered_session_id = int(recovered_secure.get('session_id') or 0)
            if recovered_session_id <= 0:
                raise RuntimeError(f'Could not determine recovered myudp secure-link session id from peers doc: {recovered_doc!r}')
            assert recovered_session_id != pre_recovery_session_id
            assert recovered_secure.get('last_event') == 'authenticated'
            assert not str(recovered_secure.get('last_rekey_trigger') or '')
            assert int(recovered_secure.get('rekeys_completed_total') or 0) == 0

            got = _wait_udp_probe_result(loopback_v4, client_probe_port, b'\x01myudp-recovery-after', timeout=12.0)
            if got != response_payload(b'\x01myudp-recovery-after'):
                raise RuntimeError(f'Unexpected recovered myudp probe reply: {got!r}')
        finally:
            if proxy is not None:
                proxy.stop()
            bounce_client.stop()
            bounce_server.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_secure_link_psk_client_restart_after_prior_time_threshold_rekey_drops_stale_pre_restart_row(
    tmp_path: Path,
) -> None:
    with secure_link_test_lock():
        case = CASES['case01_udp_over_own_udp_ipv4']
        bounce = None
        server_proc = client_proc = None
        server_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        client_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-seconds', '3.0',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=390,
                secure_slot=22,
                server_extra_args=server_args,
                client_extra_args=client_args,
                client_restart_if_disconnected=30,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            first_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='myudp',
                authenticated=True,
            )
            first_secure = dict((first_active_secure_link_row(first_doc, transport='myudp').get('secure_link') or {}))
            first_session_id = int(first_secure.get('session_id') or 0)
            if first_session_id <= 0:
                raise RuntimeError(f'Could not determine initial myudp secure-link session id from peers doc: {first_doc!r}')
            wait_probe(case, payload=b'\x01myudp-restart-prime', timeout=12.0)
            rekey_doc = wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=first_session_id,
                timeout=18.0,
                label='client',
                transport='myudp',
            )
            rekey_secure = dict((first_active_secure_link_row(rekey_doc, transport='myudp').get('secure_link') or {}))
            pre_restart_session_id = int(rekey_secure.get('session_id') or 0)
            if pre_restart_session_id <= 0:
                raise RuntimeError(f'Could not determine pre-restart myudp secure-link session id from peers doc: {rekey_doc!r}')
            assert pre_restart_session_id != first_session_id
            assert rekey_secure.get('last_event') == 'rekey_completed'
            assert rekey_secure.get('last_rekey_trigger') == 'time_threshold'
            assert int(rekey_secure.get('rekeys_completed_total') or 0) >= 1

            survivor_proc = server_proc
            restarted_proc = client_proc
            survivor_admin = survivor_proc.admin_port or 0

            stop_proc(restarted_proc)
            client_proc = None
            time.sleep(1.0)

            restarted_proc = start_proc(
                restarted_proc.name,
                list(restarted_proc.cmd or []),
                tmp_path,
                env_extra=restarted_proc.env_extra,
                admin_port=restarted_proc.admin_port,
            )
            wait_admin_up(restarted_proc.admin_port or 0, timeout=10.0)
            client_proc = wait_status_connected_proc(restarted_proc, tmp_path, timeout=20.0, label='client')

            wait_probe(case, payload=b'\x01myudp-restart-recover', timeout=20.0)

            recovered_doc = wait_peer_secure_link_session_change(
                survivor_admin,
                previous_session_id=pre_restart_session_id,
                timeout=20.0,
                label='server',
                transport='myudp',
            )
            active_rows = [
                row
                for row in list(recovered_doc.get('peers') or [])
                if str(row.get('transport', '')).strip().lower() == 'myudp'
                and str(row.get('state', '')).strip().lower() != 'listening'
            ]
            stale_rows = [
                row
                for row in active_rows
                if int(((row.get('secure_link') or {}).get('session_id') or 0)) == pre_restart_session_id
            ]
            assert not stale_rows, recovered_doc
            recovered_rows = [
                row
                for row in active_rows
                if int(((row.get('secure_link') or {}).get('session_id') or 0)) > 0
            ]
            if not recovered_rows:
                raise RuntimeError(f'Could not determine recovered myudp secure-link row from peers doc: {recovered_doc!r}')
            recovered_secure = dict((recovered_rows[0].get('secure_link') or {}))
            assert recovered_secure.get('last_event') == 'authenticated'
            assert not str(recovered_secure.get('last_rekey_trigger') or '')
            assert int(recovered_secure.get('authenticated_sessions_total') or 0) == 1
            assert int(recovered_secure.get('rekeys_completed_total') or 0) == 0

            wait_probe(case, payload=b'\x01myudp-restart-after', timeout=12.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_replay_after_reconnect_is_rejected(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=288,
                secure_slot=13,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
                client_restart_if_disconnected=30,
                use_failure_injection_entrypoint=True,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            client_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            old_session_id = int(((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}).get('session_id') or 0))
            wait_probe(case, payload=b'\x01replay-reconnect-prime', timeout=12.0)

            old_client = client_proc
            stop_proc(client_proc)
            client_proc = None
            wait_status_not_connected(server_proc.admin_port or 0, timeout=20.0, label='server')

            client_proc = start_proc(
                old_client.name,
                list(old_client.cmd or []),
                tmp_path,
                env_extra=old_client.env_extra,
                admin_port=old_client.admin_port,
            )
            wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01replay-reconnect-new-prime', timeout=12.0)
            server_doc = wait_peer_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=20.0,
                label='server',
                transport='tcp',
                authenticated=True,
            )
            new_session_id = int(((first_active_secure_link_row(server_doc, transport='tcp').get('secure_link') or {}).get('session_id') or 0))
            assert new_session_id != old_session_id

            code, body = request_json(
                f'http://127.0.0.1:{server_proc.admin_port}/api/secure-link/debug',
                method='POST',
                payload={'action': 'replay_recent', 'session_id': old_session_id},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            wait_status_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='failed',
                timeout=12.0,
                label='server',
                authenticated=False,
                failure_code=4,
                failure_reason='decode',
            )
            expect_probe_failure(case, payload=b'\x01replay-reconnect-after', timeout=4.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_replay_after_rekey_is_rejected(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--secure-link-rekey-after-frames', '1',
        ]
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=289,
                secure_slot=14,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
                use_failure_injection_entrypoint=True,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            client_doc = wait_peer_secure_link_state(
                client_proc.admin_port or 0,
                expected_state='authenticated',
                timeout=12.0,
                label='client',
                transport='tcp',
                authenticated=True,
            )
            old_session_id = int(((first_active_secure_link_row(client_doc, transport='tcp').get('secure_link') or {}).get('session_id') or 0))
            wait_probe(case, payload=b'\x01replay-rekey-prime', timeout=12.0)
            wait_peer_secure_link_session_change(
                client_proc.admin_port or 0,
                previous_session_id=old_session_id,
                timeout=12.0,
                label='client',
                transport='tcp',
            )
            wait_probe(case, payload=b'\x01replay-rekey-after', timeout=12.0)

            code, body = request_json(
                f'http://127.0.0.1:{server_proc.admin_port}/api/secure-link/debug',
                method='POST',
                payload={'action': 'replay_recent', 'session_id': old_session_id},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            wait_status_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='failed',
                timeout=12.0,
                label='server',
                authenticated=False,
                failure_code=4,
                failure_reason='decode',
            )
            expect_probe_failure(case, payload=b'\x01replay-rekey-final', timeout=4.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_malformed_frame_fails_closed_subprocess(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case06_overlay_tcp_ipv4']
        bounce = None
        server_proc = client_proc = None
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=290,
                secure_slot=15,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
                use_failure_injection_entrypoint=True,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01malformed-prime', timeout=12.0)
            code, body = request_json(
                f'http://127.0.0.1:{server_proc.admin_port}/api/secure-link/debug',
                method='POST',
                payload={'action': 'inject_raw', 'payload_b64': base64.b64encode(b'\x01\x02\x03').decode('ascii')},
                timeout=2.0,
            )
            assert code == 200
            assert body.get('ok') is True
            wait_status_secure_link_state(
                server_proc.admin_port or 0,
                expected_state='failed',
                timeout=12.0,
                label='server',
                authenticated=False,
                failure_code=4,
                failure_reason='decode',
            )
            expect_probe_failure(case, payload=b'\x01malformed-after', timeout=4.0)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize(
    ("case_name", "case_index", "secure_slot"),
    [
        ('case01_udp_over_own_udp_ipv4', 278, 3),
        ('case08_overlay_ws_ipv4', 279, 4),
        ('case10_overlay_quic_ipv4', 280, 5),
    ],
)
def test_overlay_e2e_secure_link_psk_happy_path_other_transports(
    case_name: str,
    case_index: int,
    secure_slot: int,
    tmp_path: Path,
) -> None:
    with secure_link_test_lock():
        case = CASES[case_name]
        bounce = None
        server_proc = client_proc = None
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=case_index,
                secure_slot=secure_slot,
                server_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret'],
                client_extra_args=['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret'],
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_static_http_root_repeated_requests_with_secure_link_ws_peer(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case08_overlay_ws_ipv4']
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        bounce = None
        server_proc = client_proc = None
        ws_listener_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), _secure_link_loopback_key(9))
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=284,
                secure_slot=9,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01ws-static-http-before', timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_peer_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', transport='ws', authenticated=True)

            ws_http_url = f'http://{ws_listener_host}:{_listener_overlay_port(case, "ws")}/'
            body = assert_static_http_root_serves_repeatedly(ws_http_url, attempts=8, timeout=2.0)
            assert b'Hello! Welcome!' in body

            wait_probe(case, payload=b'\x01ws-static-http-after', timeout=12.0)
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_static_http_root_keepalive_same_connection_with_secure_link_ws_peer(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case08_overlay_ws_ipv4']
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        bounce = None
        server_proc = client_proc = None
        ws_listener_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), _secure_link_loopback_key(10))
        try:
            case, bounce, server_proc, client_proc = _start_case_with_secure_link_args(
                case,
                tmp_path,
                case_index=286,
                secure_slot=10,
                server_extra_args=secure_args,
                client_extra_args=secure_args,
            )
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01ws-static-http-keepalive-before', timeout=12.0)
            wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)

            responses = fetch_http_keepalive_sequence(
                ws_listener_host,
                _listener_overlay_port(case, 'ws'),
                attempts=2,
                timeout=2.0,
            )
            assert len(responses) == 2
            for code, headers, body in responses:
                assert code == 200
                assert headers.get('content-type', '').startswith('text/html')
                assert b'Hello! Welcome!' in body

            wait_probe(case, payload=b'\x01ws-static-http-keepalive-after', timeout=12.0)
            wait_status_secure_link_state(client_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_proc.admin_port or 0, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_static_http_root_repeated_requests_with_secure_link_ws_peer_on_mixed_listener(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp'], 10)
        loopback_v4, _loopback_v6 = _loopback_hosts_for_case(_secure_link_loopback_key(10))
        ws_listener_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), _secure_link_loopback_key(10))
        secure_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--log-secure-link', 'DEBUG',
        ]
        bounce = None
        server_proc = client_proc = None
        server_admin = client_admin = None
        try:
            bounce = BounceBackServer(
                name=f'{case.name}_ws_http_probe_bounce',
                proto=case.bounce_proto,
                bind_host=case.bounce_bind,
                port=case.bounce_port,
                log_path=tmp_path / f'{case.name}_ws_http_probe_bounce.log',
            )
            bounce.start()
            server_admin, client_admin = alloc_admin_ports(288, base=SECURE_LINK_ADMIN_BASE)
            missing_cfg = str(tmp_path / f'{case.name}_missing.cfg')

            server_cmd = bridge_entrypoint() + materialize_args(case.bridge_server_args, tmp_path, case.name, 'bridge_server')
            server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
            server_cmd += secure_args
            server_cmd += admin_args(server_admin)

            ws_client_cmd = bridge_entrypoint() + [
                '--overlay-transport', 'ws',
                '--ws-peer', ws_listener_host, '--ws-peer-port', str(_listener_overlay_port(case, 'ws')),
                '--ws-bind', loopback_v4, '--ws-own-port', '0',
                '--own-servers', f'tcp,{case.probe_port},{loopback_v4},tcp,{case.bounce_bind},{case.bounce_port}',
                '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
                '--log-file', str(tmp_path / f'{case.name}_bridge_client_ws_http_probe.txt'),
                '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
            ]
            ws_client_cmd += secure_args
            ws_client_cmd += admin_args(client_admin)

            server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, tmp_path, env_extra=case.server_env, admin_port=server_admin)
            time.sleep(0.5)
            assert_running(server_proc)
            wait_admin_up(server_admin, timeout=10.0)
            wait_tcp_listen(ws_listener_host, _listener_overlay_port(case, 'ws'), timeout=10.0)

            client_proc = start_proc(f'{case.name}_bridge_client_ws_http_probe', ws_client_cmd, tmp_path, env_extra=case.client_env, admin_port=client_admin)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_probe(case, payload=b'\x01ws-mixed-static-http-before', timeout=12.0)
            wait_status_connected(server_admin, timeout=20.0, label='server')
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
            wait_peer_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', transport='ws', authenticated=True)
            wait_peer_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', transport='ws', authenticated=True)

            ws_http_url = f'http://{ws_listener_host}:{_listener_overlay_port(case, "ws")}/'
            body = assert_static_http_root_serves_repeatedly(ws_http_url, attempts=8, timeout=2.0)
            assert b'Hello! Welcome!' in body

            wait_probe(case, payload=b'\x01ws-mixed-static-http-after', timeout=12.0)
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', authenticated=True)
        finally:
            if bounce is not None:
                bounce.stop()
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_static_http_root_repeated_requests_with_secure_link_myudp_peer_on_mixed_listener(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp'], 10)
        loopback_v4, _loopback_v6 = _loopback_hosts_for_case(_secure_link_loopback_key(10))
        ws_listener_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), _secure_link_loopback_key(10))
        secure_args = [
            '--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret',
            '--log-secure-link', 'DEBUG',
        ]
        bounce = BounceBackServer(
            name=f'{case.name}_myudp_http_probe_bounce',
            proto='udp',
            bind_host=loopback_v4,
            port=case.bounce_port + 20,
            log_path=tmp_path / f'{case.name}_myudp_http_probe_bounce.log',
        )
        server_proc = client_proc = None
        server_admin = client_admin = None
        try:
            bounce.start()
            server_admin, client_admin = alloc_admin_ports(285, base=SECURE_LINK_ADMIN_BASE)
            missing_cfg = str(tmp_path / f'{case.name}_missing.cfg')
            server_cmd = bridge_entrypoint() + materialize_args(case.bridge_server_args, tmp_path, case.name, 'bridge_server')
            server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
            server_cmd += secure_args
            server_cmd += admin_args(server_admin)

            myudp_service_port = case.bounce_port + 30
            myudp_client_cmd = bridge_entrypoint() + [
                '--overlay-transport', 'myudp',
                '--udp-peer', loopback_v4, '--udp-peer-port', str(_listener_overlay_port(case, 'myudp')),
                '--udp-bind', loopback_v4, '--udp-own-port', '0',
                '--own-servers', f'udp,{myudp_service_port},{loopback_v4},udp,{loopback_v4},{case.bounce_port + 20}',
                '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
                '--log-file', str(tmp_path / f'{case.name}_bridge_client_myudp_http_probe.txt'),
                '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
            ]
            myudp_client_cmd += secure_args
            myudp_client_cmd += admin_args(client_admin)

            server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, tmp_path, env_extra=case.server_env, admin_port=server_admin)
            time.sleep(0.5)
            assert_running(server_proc)
            wait_admin_up(server_admin, timeout=10.0)
            wait_tcp_listen(ws_listener_host, _listener_overlay_port(case, 'ws'), timeout=10.0)

            client_proc = start_proc(f'{case.name}_bridge_client_myudp_http_probe', myudp_client_cmd, tmp_path, env_extra=case.client_env, admin_port=client_admin)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_peers_count(server_admin, minimum_count=1, timeout=12.0, label='server')

            myudp_probe_case = replace(
                case,
                probe_proto='udp',
                probe_host=loopback_v4,
                probe_port=myudp_service_port,
                probe_bind=loopback_v4,
                expected=response_payload(b'\x01myudp-static-http-before'),
            )
            wait_probe(myudp_probe_case, payload=b'\x01myudp-static-http-before', timeout=12.0)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=1, timeout=12.0, label='server')
            wait_peer_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', transport='myudp', authenticated=True)
            wait_peer_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', transport='myudp', authenticated=True)

            ws_http_url = f'http://{ws_listener_host}:{_listener_overlay_port(case, "ws")}/'
            body = assert_static_http_root_serves_repeatedly(ws_http_url, attempts=8, timeout=2.0)
            assert b'Hello! Welcome!' in body

            myudp_probe_case = replace(myudp_probe_case, expected=response_payload(b'\x01myudp-static-http-after'))
            wait_probe(myudp_probe_case, payload=b'\x01myudp-static-http-after', timeout=12.0)
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=1, timeout=12.0, label='server')
        finally:
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)
            bounce.stop()


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_static_http_root_keepalive_same_connection_with_secure_link_myudp_peer_on_mixed_listener(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp'], 10)
        loopback_v4, _loopback_v6 = _loopback_hosts_for_case(_secure_link_loopback_key(10))
        ws_listener_host = _connect_host_for_bind(_listener_overlay_bind_host(case, 'ws'), _secure_link_loopback_key(10))
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        bounce = BounceBackServer(
            name=f'{case.name}_myudp_http_keepalive_probe_bounce',
            proto='udp',
            bind_host=loopback_v4,
            port=case.bounce_port + 20,
            log_path=tmp_path / f'{case.name}_myudp_http_keepalive_probe_bounce.log',
        )
        server_proc = client_proc = None
        server_admin = client_admin = None
        try:
            bounce.start()
            server_admin, client_admin = alloc_admin_ports(287, base=SECURE_LINK_ADMIN_BASE)
            missing_cfg = str(tmp_path / f'{case.name}_missing.cfg')
            server_cmd = bridge_entrypoint() + materialize_args(case.bridge_server_args, tmp_path, case.name, 'bridge_server')
            server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
            server_cmd += secure_args
            server_cmd += admin_args(server_admin)

            myudp_service_port = case.bounce_port + 30
            myudp_client_cmd = bridge_entrypoint() + [
                '--overlay-transport', 'myudp',
                '--udp-peer', loopback_v4, '--udp-peer-port', str(_listener_overlay_port(case, 'myudp')),
                '--udp-bind', loopback_v4, '--udp-own-port', '0',
                '--own-servers', f'udp,{myudp_service_port},{loopback_v4},udp,{loopback_v4},{case.bounce_port + 20}',
                '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
                '--log-file', str(tmp_path / f'{case.name}_bridge_client_myudp_http_keepalive_probe.txt'),
                '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
            ]
            myudp_client_cmd += secure_args
            myudp_client_cmd += admin_args(client_admin)

            server_proc = start_proc(f'{case.name}_bridge_server', server_cmd, tmp_path, env_extra=case.server_env, admin_port=server_admin)
            time.sleep(0.5)
            assert_running(server_proc)
            wait_admin_up(server_admin, timeout=10.0)
            wait_tcp_listen(ws_listener_host, _listener_overlay_port(case, 'ws'), timeout=10.0)

            client_proc = start_proc(f'{case.name}_bridge_client_myudp_http_keepalive_probe', myudp_client_cmd, tmp_path, env_extra=case.client_env, admin_port=client_admin)
            client_proc = wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label='client')
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_peers_count(server_admin, minimum_count=1, timeout=12.0, label='server')

            myudp_probe_case = replace(
                case,
                probe_proto='udp',
                probe_host=loopback_v4,
                probe_port=myudp_service_port,
                probe_bind=loopback_v4,
                expected=response_payload(b'\x01myudp-static-http-keepalive-before'),
            )
            wait_probe(myudp_probe_case, payload=b'\x01myudp-static-http-keepalive-before', timeout=12.0)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=1, timeout=12.0, label='server')
            wait_peer_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', transport='myudp', authenticated=True)
            wait_peer_secure_link_state(server_admin, expected_state='authenticated', timeout=12.0, label='server', transport='myudp', authenticated=True)

            responses = fetch_http_keepalive_sequence(
                ws_listener_host,
                _listener_overlay_port(case, 'ws'),
                attempts=2,
                timeout=2.0,
            )
            assert len(responses) == 2
            for code, headers, body in responses:
                assert code == 200
                assert headers.get('content-type', '').startswith('text/html')
                assert b'Hello! Welcome!' in body

            myudp_probe_case = replace(myudp_probe_case, expected=response_payload(b'\x01myudp-static-http-keepalive-after'))
            wait_probe(myudp_probe_case, payload=b'\x01myudp-static-http-keepalive-after', timeout=12.0)
            wait_status_secure_link_state(client_admin, expected_state='authenticated', timeout=12.0, label='client', authenticated=True)
            wait_status_secure_link_authenticated_peers(server_admin, minimum_count=1, timeout=12.0, label='server')
        finally:
            if client_proc is not None:
                stop_proc(client_proc)
            if server_proc is not None:
                stop_proc(server_proc)
            bounce.stop()


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_tcp_secure_link_psk_listener_two_clients_concurrent_udp_tcp(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp'], 2)
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        run_case_tcp_two_clients_concurrent_udp_tcp(
            case,
            tmp_path,
            case_index=277,
            secure_slot=2,
            server_extra_args=secure_args,
            client1_extra_args=secure_args,
            client2_extra_args=secure_args,
        )


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_ws_secure_link_psk_listener_two_clients(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = CASES['case12_overlay_ws_ipv4_listener_two_clients']
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        run_case_two_peer_clients_listener(
            case,
            tmp_path,
            case_index=281,
            secure_slot=6,
            server_extra_args=secure_args,
            client1_extra_args=secure_args,
            client2_extra_args=secure_args,
        )


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_myudp_secure_link_psk_listener_two_clients_concurrent_udp_tcp(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp'], 20)
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        run_case_myudp_two_clients_concurrent_udp_tcp(
            case,
            tmp_path,
            case_index=282,
            secure_slot=20,
            server_extra_args=secure_args,
            client1_extra_args=secure_args,
            client2_extra_args=secure_args,
        )


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_quic_secure_link_psk_listener_two_clients_concurrent_udp_tcp(tmp_path: Path) -> None:
    with secure_link_test_lock():
        case = materialize_secure_link_case_ports(CASES['case17_overlay_listener_quic_two_clients_concurrent_udp_tcp'], 8)
        secure_args = ['--secure-link', '--secure-link-mode', 'psk', '--secure-link-psk', 'lab-secret']
        run_case_quic_two_clients_concurrent_udp_tcp(
            case,
            tmp_path,
            case_index=283,
            secure_slot=8,
            server_extra_args=secure_args,
            client1_extra_args=secure_args,
            client2_extra_args=secure_args,
        )


def test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case13() -> None:
    args = parse_args(['--cases', 'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels'])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels']
    assert selected_mode == 'concurrent-tcp-channels'


def test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case14() -> None:
    args = parse_args(['--cases', 'case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp'])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp']
    assert selected_mode == 'concurrent-tcp-channels'


def test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case15() -> None:
    args = parse_args(['--cases', 'case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp'])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp']
    assert selected_mode == 'concurrent-tcp-channels'


def test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case16() -> None:
    args = parse_args(['--cases', 'case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp'])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp']
    assert selected_mode == 'concurrent-tcp-channels'


def test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case17() -> None:
    args = parse_args(['--cases', 'case17_overlay_listener_quic_two_clients_concurrent_udp_tcp'])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case17_overlay_listener_quic_two_clients_concurrent_udp_tcp']
    assert selected_mode == 'concurrent-tcp-channels'


def test_overlay_e2e_cli_routing_keeps_explicit_mode_override() -> None:
    args = parse_args([
        '--mode',
        'reconnect',
        '--cases',
        'case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels',
    ])
    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    assert selected_cases == ['case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels']
    assert selected_mode == 'reconnect'


def test_overlay_e2e_materialize_case_ports_shifts_overlay_and_service_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('PYTEST_XDIST_WORKER', raising=False)
    monkeypatch.delenv('PYTEST_XDIST_WORKER_COUNT', raising=False)
    ALLOCATED_CASE_PORT_OFFSETS.clear()
    baseline_offset = _case_port_offset(2)
    case = materialize_case_ports(CASES['case01_udp_over_own_udp_ipv4'], case_index=2)
    case_again = materialize_case_ports(CASES['case01_udp_over_own_udp_ipv4'], case_index=2)
    expected_ipv4_host = _loopback_ipv4_host(2)
    offset = case.bounce_port - 26666

    assert offset >= baseline_offset
    assert case_again.bounce_port == case.bounce_port
    assert case_again.probe_port == case.probe_port
    assert ALLOCATED_CASE_PORT_OFFSETS[2] == offset
    assert case.bounce_port == 26666 + offset
    assert case.probe_port == 26667 + offset
    assert case.probe_host == expected_ipv4_host
    assert case.bounce_bind == expected_ipv4_host
    assert _arg_value(case.bridge_server_args, '--udp-own-port', '0') == str(14443 + offset)
    assert _arg_value(case.bridge_client_args, '--udp-peer-port', '0') == str(14443 + offset)
    assert _arg_value(case.bridge_client_args, '--udp-peer', '') == expected_ipv4_host
    own_spec = case.bridge_client_args[case.bridge_client_args.index('--own-servers') + 1]
    assert own_spec == f'udp,{26667 + offset},{expected_ipv4_host},udp,{expected_ipv4_host},{26666 + offset}'


def test_overlay_e2e_normalize_service_specs_cli_args_migrates_legacy_tuples() -> None:
    args = [
        'python',
        str(BRIDGE),
        '--own-servers',
        'udp,26667,127.0.0.1,udp,127.0.0.1,26666',
        '--remote-servers',
        'tcp,43129,0.0.0.0,tcp,127.0.0.1,43128',
        '--log',
        'INFO',
    ]
    normalized = _normalize_service_specs_cli_args(args)

    own_spec = normalized[normalized.index('--own-servers') + 1]
    remote_spec = normalized[normalized.index('--remote-servers') + 1]
    assert own_spec.startswith('{"listen":')
    assert remote_spec.startswith('{"listen":')
    own_obj = json.loads(own_spec)
    remote_obj = json.loads(remote_spec)
    assert own_obj['listen']['protocol'] == 'udp'
    assert own_obj['listen']['port'] == 26667
    assert own_obj['target']['host'] == '127.0.0.1'
    assert remote_obj['listen']['protocol'] == 'tcp'
    assert remote_obj['target']['port'] == 43128


def test_overlay_e2e_normalize_service_specs_cli_args_preserves_structured_json() -> None:
    structured = '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'
    normalized = _normalize_service_specs_cli_args(['python', str(BRIDGE), '--own-servers', structured])

    own_spec = normalized[normalized.index('--own-servers') + 1]
    own_obj = json.loads(own_spec)
    assert own_obj['listen']['protocol'] == 'udp'
    assert own_obj['listen']['port'] == 16667
    assert own_obj['target']['port'] == 16666


def test_overlay_e2e_normalize_service_specs_cli_args_migrates_legacy_tun_tuples() -> None:
    args = [
        'python',
        str(BRIDGE),
        '--remote-servers',
        'tun,1400,oblt301s,tun,oblt301c,1400',
    ]
    normalized = _normalize_service_specs_cli_args(args)

    remote_spec = normalized[normalized.index('--remote-servers') + 1]
    remote_obj = json.loads(remote_spec)
    assert remote_obj['listen']['protocol'] == 'tun'
    assert remote_obj['listen']['ifname'] == 'oblt301s'
    assert remote_obj['listen']['mtu'] == 1400
    assert remote_obj['target']['protocol'] == 'tun'
    assert remote_obj['target']['ifname'] == 'oblt301c'
    assert remote_obj['target']['mtu'] == 1400


def test_overlay_e2e_alloc_admin_ports_isolates_xdist_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('PYTEST_XDIST_WORKER', 'gw3')
    monkeypatch.setenv('PYTEST_XDIST_WORKER_COUNT', '16')
    server_port, client_port = alloc_admin_ports(4)
    expected_admin_host = _loopback_ipv4_host(4)

    assert server_port != client_port
    assert server_port >= ADMIN_PORT_BASE
    assert client_port >= ADMIN_PORT_BASE
    assert server_port < 65535
    assert client_port < 65535
    assert admin_args(server_port) == ['--admin-web', '--admin-web-bind', expected_admin_host, '--admin-web-port', str(server_port)]


def test_overlay_e2e_case_port_offset_stays_in_range_for_many_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('PYTEST_XDIST_WORKER', 'gw15')
    monkeypatch.setenv('PYTEST_XDIST_WORKER_COUNT', '16')

    case = materialize_case_ports(CASES['case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp'], case_index=33)

    assert case.bounce_port < 65535
    assert case.probe_port < 65535
    assert int(_arg_value(case.bridge_server_args, '--ws-own-port', '0')) < 65535
    assert int(_arg_value(case.bridge_server_args, '--udp-own-port', '0')) < 65535
    assert case.bounce_port < SERVICE_PORT_CEILING
    assert case.probe_port < SERVICE_PORT_CEILING


def test_overlay_e2e_secure_link_port_slots_stay_above_regular_band() -> None:
    highest = _max_case_static_port(CASES['case08_overlay_ws_ipv4'])
    slots = _secure_link_port_slots_per_worker(highest)

    assert slots >= 7
    case = materialize_secure_link_case_ports(CASES['case08_overlay_ws_ipv4'], 6)
    assert case.bounce_port < 65535
    assert case.probe_port < 65535
    assert case.bounce_port >= CASES['case08_overlay_ws_ipv4'].bounce_port + SECURE_LINK_PORT_OFFSET_BASE


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Automated end-to-end overlay tests with built-in bounce-back server')
    p.add_argument('--cases', nargs='*', default=None, choices=ALL_CASES)
    p.add_argument(
        '--mode',
        choices=['basic', 'reconnect', 'listener-two-clients', 'concurrent-tcp-channels'],
        default=None,
        help='Execution path: basic smoke, reconnect workflow, two-peer listener workflow, or concurrent TCP channels over one peer',
    )
    p.add_argument('--list-cases', action='store_true')
    p.add_argument('--log-dir', default=None, help='Directory for child-process logs (default: temp dir)')
    p.add_argument('--settle-seconds', type=float, default=None, help='Override per-case settle time')
    p.add_argument('--require-aioquic', action='store_true', help='Fail fast if aioquic is not importable')
    p.add_argument('--reconnect-timeout', type=float, default=30.0, help='Timeout for connected/disconnected state transitions')
    return p.parse_args(argv)


def infer_mode_from_cases(selected_cases: List[str]) -> str:
    selected = set(selected_cases)
    if selected and selected.issubset(set(CONCURRENT_TCP_CHANNEL_CASES)):
        return 'concurrent-tcp-channels'
    if selected and selected.issubset(set(LOCALHOST_CASES)):
        return 'reconnect'
    return 'basic'


def resolve_selected_cases_and_mode(args: argparse.Namespace) -> Tuple[List[str], str]:
    if args.mode is not None:
        selected_cases = list(args.cases) if args.cases is not None else list(DEFAULT_CASES[args.mode])
        return selected_cases, args.mode

    if args.cases is None:
        return list(DEFAULT_CASES['basic']), 'basic'

    selected_cases = list(args.cases)
    return selected_cases, infer_mode_from_cases(selected_cases)


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )
    args = parse_args()

    if args.list_cases:
        for name in ALL_CASES:
            print(name)
        return 0

    selected_cases, selected_mode = resolve_selected_cases_and_mode(args)

    log_dir = Path(args.log_dir) if args.log_dir else Path(tempfile.mkdtemp(prefix='overlay_e2e_'))
    log_dir.mkdir(parents=True, exist_ok=True)

    log.info(f'Using log dir: {log_dir}')
    log.info(f'ObstacleBridge.py: {BRIDGE}')
    log.info('Bounce-back server: built into this harness')
    log.info(f'Mode: {selected_mode}')

    if args.require_aioquic:
        try:
            __import__('aioquic')
        except Exception as e:
            log.info(f'aioquic import check failed: {e}')
            return 2

    failures = []
    for idx, name in enumerate(selected_cases):
        case = CASES[name]
        log.info(f'=== RUN {case.name} ===')
        try:
            if selected_mode == 'basic':
                run_case(case, log_dir, idx, settle_s=args.settle_seconds)
            elif selected_mode == 'listener-two-clients':
                run_case_two_peer_clients_listener(case, log_dir, idx, settle_s=args.settle_seconds)
            elif selected_mode == 'concurrent-tcp-channels':
                run_case_concurrent_tcp_channels(case, log_dir, idx, settle_s=args.settle_seconds)
            else:
                run_case_reconnect(case, log_dir, idx, settle_s=args.settle_seconds, reconnect_timeout=args.reconnect_timeout)
            log.info(f'PASS {case.name}')
        except Exception as e:
            log.info(f'FAIL {case.name}: {e}')
            failures.append(case.name)
        log.info('')

    if failures:
        log.info('Failed cases: ' + ', '.join(failures))
        log.info(f'Logs kept in: {log_dir}')
        return 1

    log.info('All selected cases passed.')
    log.info(f'Logs kept in: {log_dir}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
