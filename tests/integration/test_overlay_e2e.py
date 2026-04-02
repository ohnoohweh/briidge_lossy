#!/usr/bin/env python3
import argparse
import hashlib
import http.cookiejar
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import logging
import time
import urllib.error
import urllib.request

import pytest
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / 'ObstacleBridge.py'
PAYLOAD_IN = b'\x01\x30'
PAYLOAD_OUT = b'\x02\x30'

log = logging.getLogger()


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
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '0.0.0.0', '--quic-own-port', '4443', '--quic-cert', 'Cert_localhost/cert.pem', '--quic-key', 'Cert_localhost/key.pem', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--quic-peer', '127.0.0.1', '--quic-peer-port', '4443', '--quic-bind', '0.0.0.0', '--quic-own-port', '0', '--quic-insecure', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case11_overlay_quic_ipv6': Case(
        name='case11_overlay_quic_ipv6',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '::', '--quic-own-port', '4443', '--quic-cert', 'Cert_localhost/cert.pem', '--quic-key', 'Cert_localhost/key.pem', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
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
}


def _replace_arg(args: List[str], option: str, value: str) -> List[str]:
    out = list(args)
    idx = out.index(option)
    out[idx + 1] = value
    return out


def _append_args(args: List[str], extra: List[str]) -> List[str]:
    return list(args) + list(extra)


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
]

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


def merge_env(extra: Dict[str, str]) -> Dict[str, str]:
    env = os.environ.copy()
    for k, v in extra.items():
        if k == 'NO_PROXY' and env.get('NO_PROXY'):
            if v not in env['NO_PROXY']:
                env['NO_PROXY'] = f'{v},{env["NO_PROXY"]}'
        else:
            env[k] = v
    return env


def start_proc(name: str, cmd: List[str], log_dir: Path, env_extra: Optional[Dict[str, str]] = None, admin_port: Optional[int] = None) -> Proc:
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
    p = subprocess.Popen(cmd, **kwargs)
    return Proc(
        name=name,
        popen=p,
        log_path=log_path,
        admin_port=admin_port,
        cmd=list(cmd),
        env_extra=dict(env_extra or {}),
    )

RESTART_EXIT_CODE = 75

def proc_exited_for_restart(proc: Proc) -> bool:
    rc = proc.popen.poll()
    return rc == RESTART_EXIT_CODE


def restart_proc(proc: Proc, log_dir: Path) -> Proc:
    
    if not proc.cmd:
        raise RuntimeError(f'{proc.name} cannot be restarted: missing cmd')
    log.info(f'[PROC] self-restart detected for {proc.name} rc={RESTART_EXIT_CODE}; relaunching')
    return start_proc(
        proc.name,
        proc.cmd,
        log_dir,
        env_extra=proc.env_extra,
        admin_port=proc.admin_port,
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
    if rc == RESTART_EXIT_CODE:
        raise RuntimeError(f'{proc.name} exited for self-restart rc={rc}')
    tail = proc.log_path.read_text(errors='replace')[-4000:] if proc.log_path.exists() else ''
    raise RuntimeError(f'{proc.name} exited early with rc={rc}\n--- {proc.log_path.name} ---\n{tail}')

def ensure_proc_up(proc: Proc, log_dir: Path, admin_timeout: float = 10.0) -> Proc:
    
    rc = proc.popen.poll()
    if rc is None:
        return proc

    log.info(f'[RUN]{proc.name} exited with rc={rc}\n')
    if rc != RESTART_EXIT_CODE:
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
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    end = time.time() + timeout
    last_exc = None
    while time.time() < end:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            s.close()
            return
        except Exception as e:
            last_exc = e
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    raise RuntimeError(f'TCP port {host}:{port} not ready: {last_exc}')


def probe_udp(host: str, port: int, bind_host: Optional[str], payload: bytes, timeout: float = 1.0) -> bytes:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        if bind_host is not None:
            s.bind((bind_host, 0))
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(4096)
        return data


def probe_tcp(
    host: str,
    port: int,
    bind_host: Optional[str],
    payload: bytes,
    timeout: float = 1.0,
    before_close: Optional[Callable[[], None]] = None,
) -> bytes:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        if bind_host is not None:
            s.bind((bind_host, 0))
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(payload)
        data = s.recv(4096)
        if before_close is not None:
            before_close()
        return data


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


def alloc_admin_ports(case_index: int, base: int = 18180) -> Tuple[int, int]:
    server = base + case_index * 20
    client = server + 10
    return server, client


def admin_args(port: int) -> List[str]:
    return ['--admin-web', '--admin-web-bind', '127.0.0.1', '--admin-web-port', str(port)]


def build_commands(case: Case, log_dir: Path, case_index: int, enable_admin: bool = False) -> List[tuple[str, List[str], Dict[str, str], Optional[int]]]:
    py = sys.executable
    server_admin, client_admin = alloc_admin_ports(case_index)
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    client_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_client_args, log_dir, case.name, 'bridge_client')
    # Force default startup values from CLI/test case and avoid loading local ObstacleBridge.cfg.
    # ConfigAwareCLI treats a missing explicitly-requested config as non-fatal and continues with defaults.
    server_cmd += ['--config', missing_cfg]
    client_cmd += ['--config', missing_cfg]
    # Prevent accidental fixed-port collisions from external config defaults.
    server_cmd += ['--admin-web-port', '0']
    client_cmd += ['--admin-web-port', '0']
    client_cmd += ['--client-restart-if-disconnected', '5']
    if enable_admin:
        server_cmd += admin_args(server_admin)
        client_cmd += admin_args(client_admin)
    return [
        ('bridge_server', server_cmd, case.server_env, server_admin if enable_admin else None),
        ('bridge_client', client_cmd, case.client_env, client_admin if enable_admin else None),
    ]


def post_json(url: str, timeout: float = 2.0) -> tuple[int, dict]:
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

def run_case(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
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
        wait_probe(case, timeout=8.0, before_tcp_close=before_tcp_close)
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


def run_case_reconnect(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None, reconnect_timeout: float = 30.0) -> None:
    
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
        wait_probe(case, payload=b'\x01\x32', timeout=8.0)

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
            timeout=8.0,
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


def run_case_two_peer_clients_listener(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
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

    try:
        phase('1. Start bounce-back server')
        bounce.start()

        phase('2. Start listener/server bridge')
        name, cmd, env, admin_port = server_spec
        server_proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
        time.sleep(0.5)
        assert_running(server_proc)
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)

        phase('3. Start client #1 bridge')
        c_name, c_cmd, c_env, c_admin_port = client_spec
        client1_proc = start_proc(f'{case.name}_{c_name}_1', c_cmd, log_dir, env_extra=c_env, admin_port=c_admin_port)
        time.sleep(0.5)
        assert_running(client1_proc)
        wait_admin_up(client1_proc.admin_port or 0, timeout=10.0)

        phase('4. Start client #2 bridge with a different local UDP service port')
        client2_cmd = _replace_own_servers_local_port(c_cmd, 16668)
        client2_cmd += ['--admin-web-port', '0']
        client2_proc = start_proc(f'{case.name}_{c_name}_2', client2_cmd, log_dir, env_extra=c_env, admin_port=None)
        time.sleep(0.5)
        assert_running(client2_proc)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        assert_running(server_proc)
        assert_running(client1_proc)
        assert_running(client2_proc)

        phase('5. Verify both client-side UDP service ports are reachable through the listener')
        wait_probe(case, payload=b'\x01\x41', timeout=8.0)
        second_reply = probe_udp(case.probe_host, 16668, case.probe_bind, b'\x01\x42', timeout=2.0)
        if second_reply != b'\x02\x42':
            raise RuntimeError(f'Unexpected second client probe response: {second_reply!r}')

        phase('6. Verify listener admin status keeps Overlay Peer as n/a')
        status_doc = wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label='server')
        overlay_peer = str((status_doc.get('overlay') or {}).get('peer') or '').strip().lower()
        if overlay_peer != 'n/a':
            raise RuntimeError(f'Expected server overlay.peer to be n/a with two clients, got {overlay_peer!r}')

        phase('7. Verify listener admin peers API shows two peer sessions')
        peers_doc = wait_peers_count(server_proc.admin_port or 0, minimum_count=2, timeout=12.0, label='server')
        rows = list(peers_doc.get('peers') or [])
        with_ip = [row for row in rows if row.get('peer') not in (None, '', 'n/a')]
        if len(with_ip) < 2:
            raise RuntimeError(f'Expected >=2 peer rows with endpoint labels, got rows={rows!r}')
    finally:
        if client2_proc is not None:
            stop_proc(client2_proc)
        if client1_proc is not None:
            stop_proc(client1_proc)
        if server_proc is not None:
            stop_proc(server_proc)
        bounce.stop()



def run_case_concurrent_tcp_channels(case: Case, log_dir: Path, case_index: int, settle_s: Optional[float] = None) -> None:
    if case.name == 'case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp':
        run_case_mixed_overlay_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
        return
    if case.name == 'case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp':
        run_case_myudp_two_clients_concurrent_udp_tcp(case, log_dir, case_index, settle_s=settle_s)
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
            port=3141,
            log_path=log_dir / f'{case.name}_udp_bounce_1.log',
        ),
        BounceBackServer(
            name=f'{case.name}_udp_bounce_2',
            proto='udp',
            bind_host=case.bounce_bind,
            port=3143,
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
            udp_probe_1 = probe_udp(case.probe_host, 3140, case.probe_bind, b'\x01udp-one', timeout=2.0)
            udp_probe_2 = probe_udp(case.probe_host, 3142, case.probe_bind, b'\x01udp-two', timeout=2.0)
            if udp_probe_1 != b'\x02udp-one':
                raise RuntimeError(f'Unexpected UDP probe response on 3140: {udp_probe_1!r}')
            if udp_probe_2 != b'\x02udp-two':
                raise RuntimeError(f'Unexpected UDP probe response on 3142: {udp_probe_2!r}')

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
            port=3141,
            log_path=log_dir / f'{case.name}_udp_bounce_1.log',
        ),
        BounceBackServer(
            name=f'{case.name}_udp_bounce_2',
            proto='udp',
            bind_host=case.bounce_bind,
            port=3143,
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
        udp_sock.sendto(b'\x01udp-before-restart', (case.probe_host, 3140))
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
            local_port=3140,
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
            timeout=8.0,
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
        udp_sock.sendto(b'\x01udp-after-restart', (case.probe_host, 3140))
        udp_reply_after, _addr = udp_sock.recvfrom(4096)
        if udp_reply_after != b'\x02udp-after-restart':
            raise RuntimeError(f'Unexpected UDP reply after restart: {udp_reply_after!r}')
        resumed_udp_rows = wait_connection_rows(
            client_proc.admin_port or 0,
            'udp',
            local_port=3140,
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
    udp_client_admin = ws_client_admin + 1
    ws_peer_port = _listener_overlay_port(case, 'ws')
    udp_peer_port = _listener_overlay_port(case, 'myudp')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += admin_args(server_admin)

    ws_client_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'ws',
        '--ws-peer', '127.0.0.1', '--ws-peer-port', str(ws_peer_port), '--ws-bind', '0.0.0.0', '--ws-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 30},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_ws.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    ws_client_cmd += admin_args(ws_client_admin)

    udp_client_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', '127.0.0.1', '--udp-peer-port', str(udp_peer_port), '--udp-bind', '0.0.0.0', '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 34},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 7}',
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
) -> None:
    base_tcp_port = case.bounce_port
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
    server_admin, client1_admin = alloc_admin_ports(case_index)
    client2_admin = client1_admin + 1
    udp_peer_port = _listener_overlay_port(case, 'myudp')

    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    server_cmd += ['--config', missing_cfg, '--admin-web-port', '0']
    server_cmd += admin_args(server_admin)

    client1_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', '127.0.0.1', '--udp-peer-port', str(udp_peer_port), '--udp-bind', '0.0.0.0', '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 30},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 20}',
        f'udp,{base_tcp_port + 31},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 21}',
        f'tcp,{base_tcp_port + 32},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 0}',
        f'tcp,{base_tcp_port + 33},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 1}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 40},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 2}',
        f'tcp,{base_tcp_port + 41},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 3}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_1.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
    client1_cmd += admin_args(client1_admin)

    client2_cmd = [py, str(BRIDGE),
        '--overlay-transport', 'myudp',
        '--udp-peer', '127.0.0.1', '--udp-peer-port', str(udp_peer_port), '--udp-bind', '0.0.0.0', '--udp-own-port', '0',
        '--own-servers',
        f'udp,{base_tcp_port + 34},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 22}',
        f'udp,{base_tcp_port + 35},0.0.0.0,udp,127.0.0.1,{base_tcp_port + 23}',
        f'tcp,{base_tcp_port + 36},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 4}',
        f'tcp,{base_tcp_port + 37},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 5}',
        '--remote-servers',
        f'tcp,{base_tcp_port + 44},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 6}',
        f'tcp,{base_tcp_port + 45},0.0.0.0,tcp,127.0.0.1,{base_tcp_port + 7}',
        '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG',
        '--log-file', str(log_dir / f'{case.name}_bridge_client_2.txt'),
        '--config', missing_cfg, '--admin-web-port', '0', '--client-restart-if-disconnected', '5',
    ]
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


def _require_overlay_e2e_enabled() -> None:
    if os.environ.get("RUN_OVERLAY_E2E") != "1":
        pytest.skip("Set RUN_OVERLAY_E2E=1 to run overlay integration harness")


def _start_case_with_client_admin_auth(
    case: Case,
    log_dir: Path,
    *,
    case_index: int,
    client_auth_args: Optional[List[str]] = None,
) -> tuple[BounceBackServer, Proc, Proc]:
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

    server_proc = start_proc(f'{case.name}_{server_name}', server_cmd, log_dir, env_extra=server_env, admin_port=server_admin)
    client_proc = start_proc(f'{case.name}_{client_name}', client_cmd, log_dir, env_extra=client_env, admin_port=client_admin)
    try:
        wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        if client_auth_args:
            wait_admin_auth_up(client_proc.admin_port or 0, timeout=10.0)
        else:
            wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        wait_probe(case, timeout=12.0)
        return bounce, server_proc, client_proc
    except Exception:
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


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", BASIC_CASES)
def test_overlay_e2e_basic(case_name: str, tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
    run_case(CASES[case_name], tmp_path, ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", RECONNECT_CASES)
def test_overlay_e2e_reconnect(case_name: str, tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
    run_case_reconnect(CASES[case_name], tmp_path, ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", LISTENER_CASES)
def test_overlay_e2e_listener_two_clients(case_name: str, tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
    run_case_two_peer_clients_listener(CASES[case_name], tmp_path, ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", CONCURRENT_TCP_CHANNEL_CASES)
def test_overlay_e2e_concurrent_tcp_channels(case_name: str, tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
    run_case_concurrent_tcp_channels(CASES[case_name], tmp_path, ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("case_name", ['case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels'])
def test_overlay_e2e_server_restart_closes_tcp_preserves_udp(case_name: str, tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
    run_case_server_restart_closes_tcp_preserves_udp(CASES[case_name], tmp_path, ALL_CASES.index(case_name))


@pytest.mark.integration
@pytest.mark.slow
def test_overlay_e2e_admin_api_available_when_auth_disabled(tmp_path: Path) -> None:
    _require_overlay_e2e_enabled()
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
    _require_overlay_e2e_enabled()
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
    _require_overlay_e2e_enabled()
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
    _require_overlay_e2e_enabled()
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
