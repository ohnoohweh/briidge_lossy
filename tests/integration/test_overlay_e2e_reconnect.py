#!/usr/bin/env python3
import argparse
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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=16666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=16667, probe_bind='0.0.0.0',
        bridge_server_args=['--bind443', '0.0.0.0', '--port443', '443', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server_ipv4.txt'],
        bridge_client_args=['--bind443', '0.0.0.0', '--peer', '127.0.0.1', '--peer-port', '443', '--port443', '0', '--own-servers', 'udp,16667,0.0.0.0,udp,127.0.0.1,16666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv4.txt'],
    ),
    'case06_overlay_tcp_ipv4': Case(
        name='case06_overlay_tcp_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=16666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=16667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'tcp', '--bind443', '0.0.0.0', '--port443', '12345', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'tcp', '--peer', '127.0.0.1', '--peer-port', '12345', '--bind443', '0.0.0.0', '--port443', '0', '--own-servers', 'udp,16667,0.0.0.0,udp,127.0.0.1,16666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
    'case08_overlay_ws_ipv4': Case(
        name='case08_overlay_ws_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=16666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=16667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'ws', '--bind443', '0.0.0.0', '--port443', '54321', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'ws', '--peer', '127.0.0.1', '--peer-port', '54321', '--bind443', '0.0.0.0', '--port443', '0', '--own-servers', 'udp,16667,0.0.0.0,udp,127.0.0.1,16666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
        server_env={'NO_PROXY': '127.0.0.1'},
        client_env={'NO_PROXY': '127.0.0.1'},
    ),
    'case10_overlay_quic_ipv4': Case(
        name='case10_overlay_quic_ipv4',
        bounce_proto='udp', bounce_bind='0.0.0.0', bounce_port=16666,
        probe_proto='udp', probe_host='127.0.0.1', probe_port=16667, probe_bind='0.0.0.0',
        bridge_server_args=['--overlay-transport', 'quic', '--bind443', '0.0.0.0', '--port443', '4443', '--quic-cert', 'cert.pem', '--quic-key', 'key.pem', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_server.txt'],
        bridge_client_args=['--overlay-transport', 'quic', '--peer', '127.0.0.1', '--peer-port', '4443', '--bind443', '0.0.0.0', '--port443', '0', '--quic-insecure', '--own-servers', 'udp,16667,0.0.0.0,udp,127.0.0.1,16666', '--log', 'INFO', '--log-channel-mux', 'DEBUG', '--log-udp-session', 'DEBUG', '--log-file', 'br_client_ipv6.txt'],
    ),
}


def _replace_arg(args: List[str], option: str, value: str) -> List[str]:
    out = list(args)
    idx = out.index(option)
    out[idx + 1] = value
    return out


def _append_args(args: List[str], extra: List[str]) -> List[str]:
    return list(args) + list(extra)


def _with_localhost_peer(case: Case, name: str, bind_host: str, resolve_family: str) -> Case:
    server_args = _replace_arg(case.bridge_server_args, '--bind443', bind_host)
    client_args = _replace_arg(case.bridge_client_args, '--peer', 'localhost')
    client_args = _replace_arg(client_args, '--bind443', bind_host)
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


def probe_tcp(host: str, port: int, bind_host: Optional[str], payload: bytes, timeout: float = 1.0) -> bytes:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        if bind_host is not None:
            s.bind((bind_host, 0))
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(payload)
        return s.recv(4096)


def wait_probe(case: Case, payload: bytes = PAYLOAD_IN, expected: Optional[bytes] = None, timeout: float = 8.0) -> None:
    if expected is None:
        expected = response_payload(payload)
    end = time.time() + timeout
    last_exc = None
    while time.time() < end:
        try:
            if case.probe_proto == 'udp':
                data = probe_udp(case.probe_host, case.probe_port, case.probe_bind, payload, timeout=1.0)
            else:
                data = probe_tcp(case.probe_host, case.probe_port, case.probe_bind, payload, timeout=1.0)
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


def alloc_admin_ports(case_index: int, base: int = 18080) -> Tuple[int, int]:
    server = base + case_index * 20
    client = server + 10
    return server, client


def admin_args(port: int) -> List[str]:
    return ['--admin-web', '--admin-web-bind', '127.0.0.1', '--admin-web-port', str(port)]


def build_commands(case: Case, log_dir: Path, case_index: int, enable_admin: bool = False) -> List[tuple[str, List[str], Dict[str, str], Optional[int]]]:
    py = sys.executable
    server_admin, client_admin = alloc_admin_ports(case_index)
    server_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_server_args, log_dir, case.name, 'bridge_server')
    client_cmd = [py, str(BRIDGE)] + materialize_args(case.bridge_client_args, log_dir, case.name, 'bridge_client')
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


def wait_connections_metrics_updated(admin_port: int, timeout: float = 8.0, label: str = '') -> dict:
    end = time.time() + timeout
    last_doc = None
    while time.time() < end:
        _code, doc = fetch_json(f'http://127.0.0.1:{admin_port}/api/connections', timeout=1.5)
        last_doc = doc
        rows = _conn_rows_with_traffic(doc)
        if rows:
            who = f' {label}' if label else ''
            log.info(f'[METRICS]{who} port={admin_port} traffic rows={len(rows)}')
            return doc
        time.sleep(0.25)
    raise RuntimeError(f'/api/connections metrics not updated on port {admin_port}; last={last_doc!r}')


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
        for name, cmd, env, admin_port in build_commands(case, log_dir, case_index, enable_admin=False):
            proc = start_proc(f'{case.name}_{name}', cmd, log_dir, env_extra=env, admin_port=admin_port)
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
        wait_probe(case, payload=b'\x01\x34', timeout=8.0)

        phase('13. Verify per-connection metrics updated after 01 34 / 02 34 exchange')
        wait_connections_metrics_updated(server_proc.admin_port or 0, timeout=8.0, label='server')
        wait_connections_metrics_updated(client_proc.admin_port or 0, timeout=8.0, label='client')
    finally:
        if client_proc is not None:
            stop_proc(client_proc)
        if server_proc is not None:
            stop_proc(server_proc)
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

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Automated end-to-end overlay tests with built-in bounce-back server')
    p.add_argument('--cases', nargs='*', default=DEFAULT_CASES, choices=DEFAULT_CASES)
    p.add_argument('--list-cases', action='store_true')
    p.add_argument('--log-dir', default=None, help='Directory for child-process logs (default: temp dir)')
    p.add_argument('--settle-seconds', type=float, default=None, help='Override per-case settle time')
    p.add_argument('--require-aioquic', action='store_true', help='Fail fast if aioquic is not importable')
    p.add_argument('--reconnect', action='store_true', help='Run reconnect regression flow instead of single smoke probe')
    p.add_argument('--reconnect-timeout', type=float, default=30.0, help='Timeout for connected/disconnected state transitions')
    return p.parse_args()


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )
    args = parse_args()

    if args.list_cases:
        for name in DEFAULT_CASES:
            print(name)
        return 0

    log_dir = Path(args.log_dir) if args.log_dir else Path(tempfile.mkdtemp(prefix='overlay_e2e_'))
    log_dir.mkdir(parents=True, exist_ok=True)

    log.info(f'Using log dir: {log_dir}')
    log.info(f'ObstacleBridge.py: {BRIDGE}')
    log.info('Bounce-back server: built into this harness')
    log.info(f'Mode: {"reconnect" if args.reconnect else "smoke"}')

    if args.require_aioquic:
        try:
            __import__('aioquic')
        except Exception as e:
            log.info(f'aioquic import check failed: {e}')
            return 2

    failures = []
    for idx, name in enumerate(args.cases):
        case = CASES[name]
        log.info(f'=== RUN {case.name} ===')
        try:
            if args.reconnect:
                run_case_reconnect(case, log_dir, idx, settle_s=args.settle_seconds, reconnect_timeout=args.reconnect_timeout)
            else:
                run_case(case, log_dir, idx, settle_s=args.settle_seconds)
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
