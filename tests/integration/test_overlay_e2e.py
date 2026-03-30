#!/usr/bin/env python3
import argparse
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / 'ObstacleBridge.py'
PAYLOAD_IN = b'\x01\x30'
PAYLOAD_OUT = b'\x02\x30'


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen
    log_path: Path


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
        bounce_proto='tcp', bounce_bind='0.0.0.0', bounce_port=3128,
        probe_proto='tcp', probe_host='127.0.0.1', probe_port=3129, probe_bind='0.0.0.0',
        bridge_server_args=['--udp-bind', '0.0.0.0', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--udp-bind', '0.0.0.0', '--udp-peer', '127.0.0.1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'tcp,3129,0.0.0.0,tcp,127.0.0.1,3128', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client.txt'],
    ),
    'case05_tcp_over_own_udp_clients_ipv6': Case(
        name='case05_tcp_over_own_udp_clients_ipv6',
        bounce_proto='tcp', bounce_bind='::', bounce_port=3128,
        probe_proto='tcp', probe_host='::1', probe_port=3129, probe_bind='::',
        bridge_server_args=['--udp-bind', '0.0.0.0', '--udp-own-port', '14443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--udp-bind', '0.0.0.0', '--udp-peer', '127.0.0.1', '--udp-peer-port', '14443', '--udp-own-port', '0', '--own-servers', 'tcp,3129,::,tcp,::1,3128', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client.txt'],
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
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '0.0.0.0', '--quic-own-port', '4443', '--quic-cert', 'cert.pem', '--quic-key', 'key.pem', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--quic-peer', '127.0.0.1', '--quic-peer-port', '4443', '--quic-bind', '0.0.0.0', '--quic-own-port', '0', '--quic-insecure', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case11_overlay_quic_ipv6': Case(
        name='case11_overlay_quic_ipv6',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=26666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=26667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'quic', '--quic-bind', '::', '--quic-own-port', '4443', '--quic-cert', 'cert.pem', '--quic-key', 'key.pem', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--quic-peer', '::1', '--quic-peer-port', '4443', '--quic-bind', '::', '--quic-own-port', '0', '--quic-insecure', '--own-servers', 'udp,26667,0.0.0.0,udp,127.0.0.1,26666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
}

DEFAULT_CASES = list(CASES.keys())


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
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.exc: Optional[BaseException] = None
        self._log_fp = None

    def _log(self, msg: str) -> None:
        line = f'[{time.strftime("%H:%M:%S")}] {msg}\n'
        if self._log_fp is not None:
            self._log_fp.write(line)
            self._log_fp.flush()

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_fp = open(self.log_path, 'w', encoding='utf-8', errors='replace')
        self.thread = threading.Thread(target=self._run, name=self.name, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(timeout=5.0):
            raise RuntimeError(f'{self.name} did not become ready')
        if self.exc is not None:
            raise RuntimeError(f'{self.name} failed to start: {self.exc}')

    def stop(self) -> None:
        self.stop_event.set()
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)
        if self._log_fp is not None:
            self._log_fp.close()
            self._log_fp = None

    def _run(self) -> None:
        try:
            if self.proto == 'udp':
                self._run_udp()
            else:
                self._run_tcp()
        except BaseException as e:
            self.exc = e
            self._log(f'FATAL: {e!r}')
            self.ready_event.set()

    def _run_udp(self) -> None:
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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


def start_proc(name: str, cmd: List[str], log_dir: Path, env_extra: Optional[Dict[str, str]] = None) -> Proc:
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
    return Proc(name=name, popen=p, log_path=log_path)


def stop_proc(proc: Proc) -> None:
    if proc.popen.poll() is not None:
        return
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
    if rc is not None:
        tail = proc.log_path.read_text(errors='replace')[-4000:] if proc.log_path.exists() else ''
        raise RuntimeError(f'{proc.name} exited early with rc={rc}\n--- {proc.log_path.name} ---\n{tail}')


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


def probe_udp(host: str, port: int, bind_host: Optional[str], timeout: float = 1.0) -> bytes:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        if bind_host is not None:
            s.bind((bind_host, 0))
        s.settimeout(timeout)
        s.sendto(PAYLOAD_IN, (host, port))
        data, _ = s.recvfrom(4096)
        return data


def probe_tcp(host: str, port: int, bind_host: Optional[str], timeout: float = 1.0) -> bytes:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        if bind_host is not None:
            s.bind((bind_host, 0))
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(PAYLOAD_IN)
        return s.recv(4096)


def wait_probe(case: Case, timeout: float = 8.0) -> None:
    end = time.time() + timeout
    last_exc = None
    while time.time() < end:
        try:
            if case.probe_proto == 'udp':
                data = probe_udp(case.probe_host, case.probe_port, case.probe_bind, timeout=1.0)
            else:
                data = probe_tcp(case.probe_host, case.probe_port, case.probe_bind, timeout=1.0)
            if data == case.expected:
                return
            last_exc = RuntimeError(f'unexpected response: {data!r}')
        except Exception as e:
            last_exc = e
            time.sleep(0.25)
    raise RuntimeError(f'Probe failed for {case.name}: {last_exc}')


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


def build_commands(case: Case, log_dir: Path) -> List[tuple[str, List[str], Dict[str, str]]]:
    py = sys.executable
    missing_cfg = str(log_dir / f'{case.name}_missing.cfg')
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    client_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_client_args, log_dir, case.name, 'bridge_client')

    # Force defaults from the test case/CLI and avoid loading a local ObstacleBridge.cfg.
    # ConfigAwareCLI treats an explicitly requested missing config as non-fatal.
    server_cmd += ['--config', missing_cfg]
    client_cmd += ['--config', missing_cfg]

    # Avoid collisions with local services when multiple bridge instances are launched.
    server_cmd += ['--admin-web-port', '0']
    client_cmd += ['--admin-web-port', '0']

    return [
        ('bridge_server', server_cmd, case.server_env),
        ('bridge_client', client_cmd, case.client_env),
    ]


def run_case(case: Case, log_dir: Path, settle_s: Optional[float] = None) -> None:
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
        for name, cmd, env in build_commands(case, log_dir):
            proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env)
            procs.append(proc)
            time.sleep(0.5)
            assert_running(proc)

        time.sleep(case.settle_seconds if settle_s is None else settle_s)
        for proc in procs:
            assert_running(proc)

        if case.probe_proto == 'tcp':
            wait_tcp_listen(case.probe_host, case.probe_port, timeout=5.0)
        wait_probe(case, timeout=8.0)
    finally:
        for proc in reversed(procs):
            stop_proc(proc)
        bounce.stop()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Automated end-to-end overlay tests with built-in bounce-back server')
    p.add_argument('--cases', nargs='*', default=DEFAULT_CASES, choices=DEFAULT_CASES)
    p.add_argument('--list-cases', action='store_true')
    p.add_argument('--log-dir', default=None, help='Directory for child-process logs (default: temp dir)')
    p.add_argument('--settle-seconds', type=float, default=None, help='Override per-case settle time')
    p.add_argument('--require-aioquic', action='store_true', help='Fail fast if aioquic is not importable')
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_cases:
        for name in DEFAULT_CASES:
            print(name)
        return 0

    log_dir = Path(args.log_dir) if args.log_dir else Path(tempfile.mkdtemp(prefix='overlay_e2e_'))
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f'Using log dir: {log_dir}')
    print(f'ObstacleBridge.py: {BRIDGE}')
    print('Bounce-back server: built into this harness')
    print()

    if args.require_aioquic:
        try:
            __import__('aioquic')
        except Exception as e:
            print(f'aioquic import check failed: {e}')
            return 2

    failures = []
    for name in args.cases:
        case = CASES[name]
        print(f'=== RUN {case.name} ===')
        try:
            run_case(case, log_dir, settle_s=args.settle_seconds)
            print(f'PASS {case.name}')
        except Exception as e:
            print(f'FAIL {case.name}: {e}')
            failures.append(case.name)
        print()

    if failures:
        print('Failed cases: ' + ', '.join(failures))
        print(f'Logs kept in: {log_dir}')
        return 1

    print('All selected cases passed.')
    print(f'Logs kept in: {log_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
