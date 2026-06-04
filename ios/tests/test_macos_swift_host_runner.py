from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import contextlib
import textwrap
import urllib.error
import urllib.request
import zlib
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from obstacle_bridge.bridge import AdminWebUI, CONFIG_SECRET_PREFIX, _decrypt_config_secret, _encrypt_config_secret
from obstacle_bridge.core import ObstacleBridgeClient
from obstacle_bridge.onboarding import decode_invite_token, encode_invite_token
from tests.fixtures.localhost_tls import materialize_localhost_tls_fixture_set

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from swift_test_support import build_macos_swift_artifact


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
APP_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeApp"


class _AsyncBridgeClientThread:
    def __init__(self, config: dict) -> None:
        self.client = ObstacleBridgeClient(config)
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        loop.run_forever()
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._thread_main, name="macos-swift-hostrunner-peer", daemon=True)
            self._thread.start()
            self._ready.wait(timeout=5.0)
        self._submit(self.client.start()).result(timeout=20.0)

    def stop(self) -> None:
        if self._loop is None:
            return
        try:
            self._submit(self.client.stop()).result(timeout=10.0)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5.0)
            self._thread = None
            self._loop = None
            self._ready.clear()

    def snapshot(self) -> dict:
        return dict(self.client.snapshot() or {})

    def _submit(self, coro) -> Future:
        if self._loop is None:
            raise RuntimeError("bridge client loop not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _unused_udp_port() -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(("::1", 0))
        return int(sock.getsockname()[1])


def _mixed_overlay_python_peer_config(
    *,
    transport: str,
    overlay_port: int,
    admin_port: int,
    cert_dir: Path | None = None,
    wrapped: bool = True,
) -> dict:
    config: dict[str, object] = {
        "overlay_transport": transport,
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": admin_port,
        "admin_web_auth_disable": True,
        "status": False,
    }
    if wrapped:
        config.update({
            "secure_link": True,
            "secure_link_mode": "psk",
            "secure_link_psk": f"remote-admin-{transport}-burst-psk",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 64,
            "compress_layer_types": "data",
        })
    if transport == "tcp":
        config.update({
            "tcp_bind": "127.0.0.1",
            "tcp_own_port": overlay_port,
        })
    elif transport == "ws":
        config.update({
            "ws_bind": "127.0.0.1",
            "ws_own_port": overlay_port,
            "ws_path": "/",
            "ws_tls": False,
        })
    elif transport == "quic":
        assert cert_dir is not None
        config.update({
            "quic_bind": "127.0.0.1",
            "quic_own_port": overlay_port,
            "quic_cert": str(cert_dir / "cert.pem"),
            "quic_key": str(cert_dir / "key.pem"),
            "quic_alpn": "hq-29",
        })
    else:
        raise ValueError(f"unsupported transport {transport}")
    return config


def _mixed_overlay_hostrunner_runtime_config(
    *,
    transport: str,
    overlay_port: int,
    admin_port: int,
    remote_tcp_port: int | None = None,
    own_servers: list[dict[str, object]] | None = None,
    remote_servers: list[dict[str, object]] | None = None,
    wrapped: bool = True,
) -> dict:
    config: dict[str, object] = {
        "overlay_transport": transport,
        "overlay_reconnect_retry_delay_ms": 250,
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": admin_port,
        "admin_web_dir": str((ROOT / "admin_web").resolve()),
        "admin_web_auth_disable": True,
    }
    if wrapped:
        config.update({
            "secure_link": True,
            "secure_link_mode": "psk",
            "secure_link_psk": f"remote-admin-{transport}-burst-psk",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 64,
            "compress_layer_types": "data",
        })
    if own_servers is not None:
        config["own_servers"] = own_servers
    if remote_servers is not None:
        config["remote_servers"] = remote_servers
    elif remote_tcp_port is not None:
        config["remote_servers"] = [
            {
                "name": f"Remote Admin Burst {transport}",
                "listen": {
                    "protocol": "tcp",
                    "bind": "127.0.0.1",
                    "port": remote_tcp_port,
                },
                "target": {
                    "protocol": "tcp",
                    "host": "127.0.0.1",
                    "port": admin_port,
                },
            }
        ]
    if transport == "tcp":
        config.update({
            "tcp_peer": "127.0.0.1",
            "tcp_peer_port": overlay_port,
        })
    elif transport == "ws":
        config.update({
            "ws_peer": "127.0.0.1",
            "ws_peer_port": overlay_port,
            "ws_bind": "127.0.0.1",
            "ws_own_port": 0,
            "ws_tls": False,
            "ws_path": "/",
        })
    elif transport == "quic":
        config.update({
            "quic_peer": "127.0.0.1",
            "quic_peer_port": overlay_port,
            "quic_bind": "127.0.0.1",
            "quic_own_port": 0,
            "quic_alpn": "hq-29",
            "quic_insecure": True,
        })
    else:
        raise ValueError(f"unsupported transport {transport}")
    return config


def _start_python_bridge_process(
    *,
    name: str,
    config: dict,
    tmp_path: Path,
    env_extra: dict[str, str] | None = None,
) -> tuple[subprocess.Popen[str], Path, object]:
    config_path = tmp_path / f"{name}.json"
    config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    log_path = tmp_path / f"{name}.log"
    log_fp = log_path.open("w", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    if env_extra:
        env.update(env_extra)
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "ObstacleBridge.py"),
            "--config",
            str(config_path),
        ],
        cwd=str(ROOT),
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    return process, log_path, log_fp


def _compile_swift_runtime_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for shared Swift runtime config tests")
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")


def _compile_swift_udp_overlay_peer_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for shared Swift UDP overlay runtime tests")
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")


def _http_json(url: str, *, timeout_sec: float = 2.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def _http_request_json(url: str, *, method: str = "GET", payload: dict | None = None, timeout_sec: float = 2.0) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def _http_request(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout_sec: float = 2.0,
) -> tuple[int, dict[str, str], bytes]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if data is not None and "Content-Type" not in request_headers:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            return int(response.status), {str(key): str(value) for key, value in response.headers.items()}, response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), {str(key): str(value) for key, value in exc.headers.items()}, exc.read()


def _http_text(url: str, *, timeout_sec: float = 2.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
        return response.read().decode("utf-8")


def _wait_http_json(url: str, *, timeout_sec: float = 10.0) -> dict:
    deadline = time.time() + timeout_sec
    last_error = "unknown"
    while time.time() < deadline:
        try:
            return _http_json(url, timeout_sec=1.0)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {url}: {last_error}")


def _wait_snapshot_condition(snapshot_getter, predicate, *, timeout_sec: float = 12.0):
    deadline = time.time() + timeout_sec
    last_snapshot = None
    while time.time() < deadline:
        snapshot = snapshot_getter()
        last_snapshot = snapshot
        if predicate(snapshot):
            return snapshot
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for snapshot condition; last={last_snapshot!r}")


def _wait_process_exit(process: subprocess.Popen[str], *, timeout_sec: float = 5.0) -> int:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            return int(exit_code)
        time.sleep(0.05)
    raise AssertionError(f"process did not exit within {timeout_sec} seconds")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError(f"socket closed while waiting for {size} bytes")
        data.extend(chunk)
    return bytes(data)


def _websocket_connect(
    host: str,
    port: int,
    path: str = "/api/live",
    *,
    headers: dict[str, str] | None = None,
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=2.0)
    sock.settimeout(2.0)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for header_key, header_value in (headers or {}).items():
        request_lines.append(f"{header_key}: {header_value}")
    request = "\r\n".join(request_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("websocket handshake response closed early")
        response.extend(chunk)
    header_text = response.decode("utf-8", errors="replace")
    if "101 Switching Protocols" not in header_text:
        raise AssertionError(f"unexpected websocket handshake response: {header_text}")
    return sock


def _websocket_handshake_response(
    host: str,
    port: int,
    *,
    path: str = "/api/live",
    headers: dict[str, str] | None = None,
) -> tuple[str, socket.socket]:
    sock = socket.create_connection((host, port), timeout=2.0)
    sock.settimeout(2.0)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for header_key, header_value in (headers or {}).items():
        request_lines.append(f"{header_key}: {header_value}")
    request = "\r\n".join(request_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    return response.decode("utf-8", errors="replace"), sock


def _recv_ws_json(sock: socket.socket) -> dict:
    while True:
        header = _recv_exact(sock, 2)
        b1, b2 = header[0], header[1]
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            length = int.from_bytes(_recv_exact(sock, 2), "big")
        elif length == 127:
            length = int.from_bytes(_recv_exact(sock, 8), "big")
        mask = _recv_exact(sock, 4) if masked else b""
        payload = bytearray(_recv_exact(sock, length))
        if masked:
            for index in range(len(payload)):
                payload[index] ^= mask[index % 4]
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise AssertionError("websocket closed before expected message")
        if opcode != 0x1:
            raise AssertionError(f"unexpected websocket opcode: {opcode}")
        return json.loads(payload.decode("utf-8"))


def _send_ws_json(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    mask = os.urandom(4)
    frame = bytearray([0x81])
    if len(raw) < 126:
        frame.append(0x80 | len(raw))
    elif len(raw) <= 0xFFFF:
        frame.append(0x80 | 126)
        frame.extend(len(raw).to_bytes(2, "big"))
    else:
        frame.append(0x80 | 127)
        frame.extend(len(raw).to_bytes(8, "big"))
    frame.extend(mask)
    for index, byte in enumerate(raw):
        frame.append(byte ^ mask[index % 4])
    sock.sendall(frame)


def _wait_ws_message(sock: socket.socket, predicate, *, timeout_sec: float = 5.0) -> dict:
    deadline = time.time() + timeout_sec
    last_message = None
    while time.time() < deadline:
        last_message = _recv_ws_json(sock)
        if predicate(last_message):
            return last_message
    raise AssertionError(f"timed out waiting for websocket message: {last_message!r}")


class _PythonAdminWebRunnerStub:
    pass


def _python_admin_web_payloads(config: dict) -> tuple[dict, dict]:
    args = argparse.Namespace(
        admin_web=True,
        admin_web_bind="127.0.0.1",
        admin_web_port=18080,
        admin_web_path="/",
        admin_web_landing_page_disable=False,
        admin_web_security_advisor_disable=False,
        admin_web_security_advisor_startup_disable=False,
        admin_web_first_tab="home",
        admin_web_token="",
        admin_web_auth_disable=False,
        admin_web_username="",
        admin_web_password="",
        secure_link_mode="off",
        secure_link_psk="",
        _first_start_detected=False,
        _config_file_state="unknown",
    )
    for key, value in config.items():
        setattr(args, key, value)
    admin_ui = AdminWebUI(args, _PythonAdminWebRunnerStub())
    return admin_ui._build_admin_ui_payload(), admin_ui._build_security_advisor_payload()


def _build_open_payload(
    *,
    svc_id: int,
    l_proto: str,
    l_bind: str,
    l_port: int,
    r_proto: str,
    r_host: str,
    r_port: int,
    name: str | None = None,
) -> bytes:
    proto_code = {"udp": 0, "tcp": 1, "tun": 2}
    left = l_bind.encode("utf-8")
    right = r_host.encode("utf-8")
    meta = json.dumps(
        {"name": name, "lifecycle_hooks": None, "options": None},
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        b"O5"
        + struct.pack(">QIHBH", 0, 0, svc_id, proto_code[l_proto], len(left))
        + left
        + struct.pack(">HBH", l_port, proto_code[r_proto], len(right))
        + right
        + struct.pack(">HI", r_port, len(meta))
        + meta
    )


def _pack_mux_frame(chan_id: int, proto: int, counter: int, mtype: int, body: bytes) -> bytes:
    return struct.pack(">HBHBH", chan_id, proto, counter & 0xFFFF, mtype, len(body)) + body


def _pack_tcp_overlay_payload(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 1) + b"\x00" + payload


def _recv_tcp_overlay_payload(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    body = _recv_exact(sock, length)
    assert body[:1] == b"\x00"
    return body[1:]


def _recv_mux_frame(sock: socket.socket) -> tuple[int, int, int, int, bytes]:
    payload = _recv_tcp_overlay_payload(sock)
    chan_id, proto, counter, mtype, size = struct.unpack(">HBHBH", payload[:8])
    return chan_id, proto, counter, mtype, payload[8 : 8 + size]


class _TCPOverlayPeer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, port))
        self._server.listen(1)
        self._server.settimeout(0.2)
        self._accepted = threading.Event()
        self._stop = threading.Event()
        self._conn: socket.socket | None = None
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._echo_thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._conn is not None:
            with contextlib.suppress(OSError):
                self._conn.close()
        with contextlib.suppress(OSError):
            self._server.close()
        self._thread.join(timeout=2.0)

    def wait_connected(self, *, timeout_sec: float = 5.0) -> socket.socket:
        if not self._accepted.wait(timeout=timeout_sec):
            raise AssertionError("timed out waiting for TCP overlay peer connection")
        assert self._conn is not None
        return self._conn

    def send_mux(self, chan_id: int, proto: int, counter: int, mtype: int, body: bytes) -> None:
        conn = self.wait_connected()
        conn.sendall(_pack_tcp_overlay_payload(_pack_mux_frame(chan_id, proto, counter, mtype, body)))

    def recv_mux(self) -> tuple[int, int, int, int, bytes]:
        conn = self.wait_connected()
        return _recv_mux_frame(conn)

    def start_mux_echo_loop(self) -> None:
        if self._echo_thread is not None:
            return
        self.wait_connected()
        self._echo_thread = threading.Thread(target=self._echo_loop, daemon=True)
        self._echo_thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            conn.settimeout(2.0)
            self._conn = conn
            self._accepted.set()
            return

    def _echo_loop(self) -> None:
        conn = self.wait_connected()
        while not self._stop.is_set():
            try:
                chan_id, proto, _counter, mtype, body = _recv_mux_frame(conn)
            except (AssertionError, OSError, TimeoutError, socket.timeout):
                return
            if mtype == 0:
                try:
                    conn.sendall(_pack_tcp_overlay_payload(_pack_mux_frame(chan_id, proto, 1, 0, body)))
                except OSError:
                    return


class _WrappedTCPOverlayPeer(_TCPOverlayPeer):
    _SL_HDR = struct.Struct(">BBBBQQ")

    def __init__(self, host: str, port: int, *, psk: str, compress_level: int = 3, compress_min_bytes: int = 64) -> None:
        super().__init__(host, port)
        self._psk = psk.encode("utf-8")
        self._compress_level = compress_level
        self._compress_min_bytes = compress_min_bytes
        self._session_id = 0
        self._client_nonce = b""
        self._server_nonce = b""
        self._c2s_key = b""
        self._s2c_key = b""
        self._authenticated = False
        self._server_tx_counter = 1

    @classmethod
    def _sl_hdr(cls, sl_type: int, session_id: int, counter: int, flags: int = 0) -> bytes:
        return cls._SL_HDR.pack(1, int(sl_type), int(flags), 0, int(session_id), int(counter))

    @classmethod
    def _parse_sl_frame(cls, payload: bytes) -> tuple[int, int, int, bytes]:
        version, sl_type, _flags, _reserved, session_id, counter = cls._SL_HDR.unpack(payload[: cls._SL_HDR.size])
        assert version == 1
        return int(sl_type), int(session_id), int(counter), payload[cls._SL_HDR.size :]

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + int(counter).to_bytes(8, "big")

    def _derive_keys(self, session_id: int, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
        transcript = b"obstaclebridge-securelink-psk-v1|" + int(session_id).to_bytes(8, "big") + client_nonce + server_nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=hashlib.sha256(self._psk).digest(),
            info=transcript,
        )
        material = hkdf.derive(self._psk + client_nonce + server_nonce)
        return material[:32], material[32:]

    def _server_proof(self, session_id: int, client_nonce: bytes, server_nonce: bytes) -> bytes:
        return hmac.new(
            self._psk,
            b"obstaclebridge-securelink-server-proof-v1|" + int(session_id).to_bytes(8, "big") + client_nonce + server_nonce,
            hashlib.sha256,
        ).digest()

    def _open_secure(self, sl_type: int, session_id: int, counter: int, ciphertext: bytes, key: bytes) -> bytes:
        aad = self._sl_hdr(sl_type, session_id, counter)
        return ChaCha20Poly1305(key).decrypt(self._nonce(counter), ciphertext, aad)

    def _seal_secure(self, sl_type: int, session_id: int, counter: int, payload: bytes, key: bytes) -> bytes:
        aad = self._sl_hdr(sl_type, session_id, counter)
        ciphertext = ChaCha20Poly1305(key).encrypt(self._nonce(counter), payload, aad)
        return aad + ciphertext

    def _compress_mux_if_profitable(self, payload: bytes) -> bytes:
        chan_id, proto, counter, mtype, size = struct.unpack(">HBHBH", payload[:8])
        body = payload[8 : 8 + size]
        if mtype != 0 or len(body) < self._compress_min_bytes:
            return payload
        compressed = zlib.compress(body, self._compress_level)
        if len(compressed) >= len(body):
            return payload
        return _pack_mux_frame(chan_id, proto, counter, mtype | 0x80, compressed)

    def _decompress_mux_if_needed(self, payload: bytes) -> bytes:
        chan_id, proto, counter, mtype, size = struct.unpack(">HBHBH", payload[:8])
        body = payload[8 : 8 + size]
        if mtype < 0x80:
            return payload
        return _pack_mux_frame(chan_id, proto, counter, mtype - 0x80, zlib.decompress(body))

    def _send_server_data(self, conn: socket.socket, payload: bytes) -> None:
        wrapped = self._compress_mux_if_profitable(payload) if payload else b""
        frame = self._seal_secure(4, self._session_id, self._server_tx_counter, wrapped, self._s2c_key)
        self._server_tx_counter += 1
        conn.sendall(_pack_tcp_overlay_payload(frame))

    def recv_secure_mux(self) -> tuple[int, int, int, int, bytes]:
        conn = self.wait_connected()
        while not self._stop.is_set():
            payload = _recv_tcp_overlay_payload(conn)
            sl_type, session_id, counter, body = self._parse_sl_frame(payload)
            if sl_type == 1:
                if len(body) < 34 or body[32] != 1:
                    raise AssertionError("invalid client hello")
                self._session_id = session_id
                self._client_nonce = body[:32]
                self._server_nonce = bytes([0x22]) * 32
                self._c2s_key, self._s2c_key = self._derive_keys(self._session_id, self._client_nonce, self._server_nonce)
                proof = self._server_proof(self._session_id, self._client_nonce, self._server_nonce)
                conn.sendall(_pack_tcp_overlay_payload(self._sl_hdr(2, self._session_id, 0) + self._server_nonce + b"\x01" + proof))
                continue
            if sl_type != 4 or not self._c2s_key:
                raise AssertionError(f"unexpected secure-link frame type {sl_type}")
            plaintext = self._open_secure(4, session_id, counter, body, self._c2s_key)
            if not self._authenticated:
                self._authenticated = True
                if not plaintext:
                    self._send_server_data(conn, b"")
                    continue
            if not plaintext:
                continue
            mux_payload = self._decompress_mux_if_needed(plaintext)
            chan_id, proto, mux_counter, mtype, size = struct.unpack(">HBHBH", mux_payload[:8])
            return chan_id, proto, mux_counter, mtype, mux_payload[8 : 8 + size]
        raise AssertionError("stopped before secure mux frame arrived")

    def _echo_loop(self) -> None:
        conn = self.wait_connected()
        while not self._stop.is_set():
            try:
                payload = _recv_tcp_overlay_payload(conn)
                sl_type, session_id, counter, body = self._parse_sl_frame(payload)
            except (AssertionError, OSError, TimeoutError, socket.timeout, struct.error):
                return
            if sl_type == 1:
                if len(body) < 34 or body[32] != 1:
                    return
                self._session_id = session_id
                self._client_nonce = body[:32]
                self._server_nonce = bytes([0x22]) * 32
                self._c2s_key, self._s2c_key = self._derive_keys(self._session_id, self._client_nonce, self._server_nonce)
                proof = self._server_proof(self._session_id, self._client_nonce, self._server_nonce)
                try:
                    conn.sendall(_pack_tcp_overlay_payload(self._sl_hdr(2, self._session_id, 0) + self._server_nonce + b"\x01" + proof))
                except OSError:
                    return
                continue
            if sl_type != 4 or not self._c2s_key:
                return
            try:
                plaintext = self._open_secure(4, session_id, counter, body, self._c2s_key)
            except Exception:
                return
            if not self._authenticated:
                self._authenticated = True
                if not plaintext:
                    try:
                        self._send_server_data(conn, b"")
                    except OSError:
                        return
                    continue
            if not plaintext:
                continue
            mux_payload = self._decompress_mux_if_needed(plaintext)
            chan_id, proto, _mux_counter, mtype, size = struct.unpack(">HBHBH", mux_payload[:8])
            body = mux_payload[8 : 8 + size]
            if mtype == 0:
                try:
                    self._send_server_data(conn, _pack_mux_frame(chan_id, proto, 1, 0, body))
                except OSError:
                    return


def test_shared_runtime_config_parses_remote_tun_specs_and_preserves_metadata(tmp_path: Path) -> None:
    source_path = tmp_path / "RuntimeProbe.swift"
    binary_path = tmp_path / "runtime-probe"
    source_path.write_text(
        """
import Foundation

@main
struct RuntimeProbe {
    static func main() throws {
        let payload: [String: Any] = [
            "channel_mux": [
                "own_servers": [
                    [
                        "name": "tcp_echo",
                        "listen": ["protocol": "tcp", "bind": "127.0.0.1", "port": 7001],
                        "target": ["protocol": "tcp", "host": "127.0.0.1", "port": 7002],
                        "lifecycle_hooks": [
                            "listener": [
                                "on_created": [
                                    "env": ["HOOK_FLAG": "yes"]
                                ]
                            ]
                        ],
                        "options": ["mode": "fast"]
                    ],
                    [
                        "name": "ios_tun",
                        "listen": ["protocol": "tun", "ifname": "ios-utun", "mtu": 1400],
                        "target": ["protocol": "tun", "ifname": "obtun1", "mtu": 1400],
                        "lifecycle_hooks": [
                            "listener": [
                                "on_created": [
                                    "env": ["TUN_ADDR": "192.168.105.1/30"]
                                ]
                            ]
                        ]
                    ]
                ],
                "remote_servers": [
                    [
                        "name": "peer_tun",
                        "listen": ["protocol": "tun", "ifname": "obtun1", "mtu": 1280],
                        "target": ["protocol": "tun", "ifname": "ios-utun", "mtu": 1280],
                        "lifecycle_hooks": [
                            "listener": [
                                "on_created": [
                                    "env": ["PEER_ADDR": "192.168.105.1", "TUN_SUBNET": "192.168.105.0/30"]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]

        let own = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: payload, preserveInputIndices: true)
        let remote = ObstacleBridgeRuntimeConfig.remoteServerSpecs(from: payload, preserveInputIndices: true)
        let localTCP = ObstacleBridgeRuntimeConfig.localTCPServiceSpecs(from: payload)
        let localDerived = own.last?.derivedLocalTunnelSettings(
            defaultTunnelAddress6: "fd20:106::1",
            defaultTunnelPrefix6: 126,
            defaultIncludedRoutes: ["0.0.0.0/0"],
            defaultExcludedRoutes: ["127.0.0.0/8"],
            defaultIncludedRoutes6: ["::/0"],
            defaultExcludedRoutes6: ["::1/128"],
            defaultDNS: ["1.1.1.1"],
            fallbackMTU: 1600
        )
        let remoteDerived = remote.first?.derivedRemoteTunnelSettings(
            defaultTunnelPrefix: 30,
            defaultTunnelPrefix6: 126,
            defaultIncludedRoutes: ["0.0.0.0/0"],
            defaultExcludedRoutes: ["127.0.0.0/8"],
            defaultIncludedRoutes6: ["::/0"],
            defaultExcludedRoutes6: ["::1/128"],
            defaultDNS: ["1.1.1.1"],
            fallbackMTU: 1600
        )
        let overridden = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: [
            "TUN_routing": [
                "included_routes": ["198.18.0.254/32"],
                "excluded_routes": ["0.0.0.0/0"],
                "dns_servers": ["9.9.9.9"],
                "mtu": 1600,
            ]
        ]).map { localDerived?.applying($0) }
        let flattenedOverride = ObstacleBridgeRuntimeConfig.tunnelRoutingOverride(from: [
            "tunnel_address": "192.168.107.1",
            "tunnel_prefix": 30,
            "tunnel_gateway": "192.168.107.2",
            "dns_servers": ["8.8.8.8"],
            "mtu": 1400,
        ])
        let loopbackTun = ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: "ios-utun", mtu: 1400)
        let result: [String: Any] = [
            "own_count": own.count,
            "own_tun_ifname": own.last?.listenIfname ?? "",
            "own_tun_env_blocks": own.last?.listenerHookEnvBlocks().count ?? -1,
            "local_derived_addr": localDerived?.tunnelAddress ?? "",
            "local_derived_prefix6": localDerived?.tunnelPrefix6 ?? -1,
            "local_derived_mtu": localDerived?.mtu ?? -1,
            "remote_count": remote.count,
            "remote_target_ifname": remote.first?.targetIfname ?? "",
            "remote_mtu": remote.first?.mtu(fallback: 0) ?? -1,
            "remote_peer_addr": remote.first?.listenerHookEnvBlocks().first?["PEER_ADDR"] as? String ?? "",
            "remote_derived_addr": remoteDerived?.tunnelAddress ?? "",
            "remote_derived_prefix": remoteDerived?.tunnelPrefix ?? -1,
            "remote_derived_prefix6": remoteDerived?.tunnelPrefix6 ?? -1,
            "override_dns": overridden??.dnsServers ?? [],
            "override_mtu": overridden??.mtu ?? -1,
            "override_included_routes": overridden??.includedRoutes ?? [],
            "flattened_override_addr": flattenedOverride?.tunnelAddress ?? "",
            "flattened_override_gateway": flattenedOverride?.tunnelGateway ?? "",
            "flattened_override_dns": flattenedOverride?.dnsServers ?? [],
            "flattened_override_mtu": flattenedOverride?.mtu ?? -1,
            "loopback_tun_bind": loopbackTun.lBind,
            "loopback_tun_port": loopbackTun.lPort,
            "loopback_tun_proto": loopbackTun.lProto,
            "local_tcp_hooks_present": localTCP.first?.lifecycleHooks != nil,
            "local_tcp_options_present": localTCP.first?.options != nil
        ]
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
    }
}
""",
        encoding="utf-8",
    )
    _compile_swift_runtime_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"runtime probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
    payload = json.loads(completed.stdout)

    assert payload == {
        "local_tcp_hooks_present": True,
        "local_tcp_options_present": True,
        "local_derived_addr": "192.168.105.1",
        "local_derived_mtu": 1400,
        "local_derived_prefix6": 126,
        "own_count": 2,
        "own_tun_env_blocks": 1,
        "own_tun_ifname": "ios-utun",
        "loopback_tun_bind": "ios-utun",
        "loopback_tun_port": 1400,
        "loopback_tun_proto": "tun",
        "flattened_override_addr": "192.168.107.1",
        "flattened_override_dns": ["8.8.8.8"],
        "flattened_override_gateway": "192.168.107.2",
        "flattened_override_mtu": 1400,
        "override_dns": ["9.9.9.9"],
        "override_included_routes": ["198.18.0.254/32"],
        "override_mtu": 1600,
        "remote_count": 1,
        "remote_derived_addr": "192.168.105.1",
        "remote_derived_prefix": 30,
        "remote_derived_prefix6": 126,
        "remote_mtu": 1280,
        "remote_peer_addr": "192.168.105.1",
        "remote_target_ifname": "ios-utun",
    }


def test_shared_udp_overlay_peer_runtime_recent_inbound_keeps_connected_state(tmp_path: Path) -> None:
    source_path = tmp_path / "UdpOverlayPeerRuntimeProbe.swift"
    binary_path = tmp_path / "udp-overlay-peer-runtime-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            @main
            struct UdpOverlayPeerRuntimeProbeMain {
                static func main() throws {
                    let runtime = ObstacleBridgeUdpOverlayPeerRuntime()
                    let now = DispatchTime.now().uptimeNanoseconds
                    let txNS = now > 5_000_000 ? now - 5_000_000 : now
                    _ = try runtime.handleInboundIdleFrame(
                        nowNS: now,
                        txNS: txNS,
                        echoNS: 0,
                        sendPortPresent: false
                    )
                    let connected = runtime.isConnected(nowNS: now + 1_000_000_000)
                    let payload: [String: Any] = [
                        "connected": connected,
                        "last_rx_wall_ns": runtime.lastRxWallNS,
                        "last_rtt_ok_ns": runtime.lastRttOkNS,
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_udp_overlay_peer_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=True)
    payload = json.loads(completed.stdout)
    assert payload["connected"] is True
    assert int(payload["last_rx_wall_ns"]) > 0
    assert int(payload["last_rtt_ok_ns"]) == 0


class _TCPEchoServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.received: list[bytes] = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, port))
        self._server.listen()
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            thread = threading.Thread(target=self._handle_client, args=(conn, self.received), daemon=True)
            thread.start()

    @staticmethod
    def _handle_client(conn: socket.socket, received: list[bytes]) -> None:
        with conn:
            while True:
                try:
                    data = conn.recv(65535)
                except OSError:
                    return
                if not data:
                    return
                received.append(data)
                try:
                    conn.sendall(data)
                except OSError:
                    return


class _UDPEchoServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server.bind((host, port))
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._server.recvfrom(65535)
            except (TimeoutError, socket.timeout, OSError):
                continue
            try:
                self._server.sendto(data, addr)
            except OSError:
                continue


def _wait_http_condition(url: str, predicate, *, timeout_sec: float = 10.0) -> dict:
    deadline = time.time() + timeout_sec
    last_doc = None
    last_error = None
    while time.time() < deadline:
        try:
            last_doc = _http_json(url)
            if predicate(last_doc):
                return last_doc
        except Exception as exc:
            last_error = exc
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for condition on {url}: last_doc={last_doc!r} last_error={last_error!r}")


def _wait_tcp_port_ready(host: str, port: int, *, timeout_sec: float = 10.0) -> None:
    deadline = time.time() + timeout_sec
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1)
    raise AssertionError(f"timed out waiting for tcp port {host}:{port}: {last_error!r}")


def test_macos_swift_host_runner_reports_python_style_build_payload(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path
    build_info_payload = json.loads(artifact.build_info_path.read_text(encoding="utf-8"))

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "build.example.net",
                "ws_peer_port": 9443,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")

        expected_build = {
            "commit": build_info_payload["commit"],
            "source": build_info_payload["source"],
            "repo_root": build_info_payload["repo_root"],
            "tainted": build_info_payload["tainted"],
            "tracked_changes": build_info_payload["tracked_changes"],
            "untracked_changes": build_info_payload["untracked_changes"],
            "available": build_info_payload["available"],
            "diff_sha": build_info_payload["diff_sha"],
        }
        assert status["build"] == expected_build
        assert meta["build"] == expected_build
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_myudp_remote_tcp_admin_web_handles_multiple_connections(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    hostrunner_admin_port = _unused_tcp_port()
    python_peer_admin_port = _unused_tcp_port()
    remote_tcp_port = _unused_tcp_port()
    hostrunner_udp_port = _unused_tcp_port()

    python_peer = _AsyncBridgeClientThread(
        {
            "overlay_transport": "myudp",
            "udp_bind": "127.0.0.1",
            "udp_own_port": overlay_port,
            "secure_link": True,
            "secure_link_mode": "psk",
            "secure_link_psk": "remote-admin-myudp-burst-psk",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 64,
            "compress_layer_types": "data",
            "admin_web": True,
            "admin_web_bind": "127.0.0.1",
            "admin_web_port": python_peer_admin_port,
            "admin_web_auth_disable": True,
            "status": False,
        }
    )

    runtime_config_path = tmp_path / "runtime_remote_admin_myudp_burst.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "myudp",
                "udp_bind": "127.0.0.1",
                "udp_own_port": hostrunner_udp_port,
                "udp_peer": "127.0.0.1",
                "udp_peer_port": overlay_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "remote-admin-myudp-burst-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": hostrunner_admin_port,
                "admin_web_dir": str((ROOT / "admin_web").resolve()),
                "admin_web_auth_disable": True,
                "remote_servers": [
                    {
                        "name": "Remote Admin Burst myUDP",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "127.0.0.1",
                            "port": remote_tcp_port,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": hostrunner_admin_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_peer.start()
    _wait_http_json(f"http://127.0.0.1:{python_peer_admin_port}/api/status", timeout_sec=20.0)
    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/status", timeout_sec=20.0)
        _wait_http_condition(
            f"http://127.0.0.1:{hostrunner_admin_port}/api/peers",
            lambda doc: bool(doc.get("peers")) and bool(doc["peers"][0].get("secure_link", {}).get("authenticated")),
            timeout_sec=20.0,
        )
        _wait_http_json(f"http://127.0.0.1:{remote_tcp_port}/api/status", timeout_sec=20.0)

        def _fetch_path(path: str) -> tuple[str, object]:
            url = f"http://127.0.0.1:{remote_tcp_port}{path}"
            if path in {"/", "/app.js", "/style.css"}:
                deadline = time.time() + 10.0
                last_error = "unknown"
                while time.time() < deadline:
                    try:
                        return path, _http_text(url, timeout_sec=3.0)
                    except Exception as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                        time.sleep(0.1)
                raise AssertionError(f"timed out waiting for text response from {url}: {last_error}")
            return path, _wait_http_json(url, timeout_sec=10.0)

        paths = ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/", "/app.js", "/style.css", "/api/status"]
        with ThreadPoolExecutor(max_workers=min(4, len(paths))) as executor:
            results = list(executor.map(_fetch_path, paths))

        result_map = {path: payload for path, payload in results}
        status = result_map["/api/status"]
        meta = result_map["/api/meta"]
        connections = result_map["/api/connections"]
        peers = result_map["/api/peers"]
        root_html = result_map["/"]
        app_js = result_map["/app.js"]
        style_css = result_map["/style.css"]

        assert isinstance(status, dict) and ("admin_ui" in status or "build" in status)
        assert isinstance(meta, dict) and "transport_runtime" in meta
        assert isinstance(connections, dict) and "counts" in connections
        assert isinstance(peers, dict) and "peers" in peers
        peer_row = peers["peers"][0]
        assert peer_row["transport"] == "myudp"
        assert peer_row["runtime"]["kind"] == "myudp"
        assert peer_row["peer"]["host"] == "127.0.0.1"
        assert int(peer_row["open_connections"]["tcp"]) >= 1
        assert isinstance(root_html, str) and ("ObstacleBridge" in root_html or "Admin Web" in root_html)
        assert isinstance(app_js, str) and "async function loadStatus()" in app_js
        assert isinstance(style_css, str) and "--bg:" in style_css
    finally:
        python_peer.stop()
        if process.poll() is None:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5.0)
        else:
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )



def test_macos_swift_host_runner_bootstraps_ws_stack_and_serves_status(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "ws_payload_mode": "base64",
                "ws_send_timeout": 7.5,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "mac-host-runner-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 96,
                "compress_layer_types": "data,data_ack",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        html = _http_text(f"http://127.0.0.1:{status_port}/")
        app_js = _http_text(f"http://127.0.0.1:{status_port}/app.js")
        style_css = _http_text(f"http://127.0.0.1:{status_port}/style.css")
        auth_state = _http_json(f"http://127.0.0.1:{status_port}/api/auth/state")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")
        with contextlib.closing(_websocket_connect("127.0.0.1", status_port)) as live_socket:
            hello = _recv_ws_json(live_socket)
            _send_ws_json(live_socket, {"request": ["status", "connections"]})
            live_status = _wait_ws_message(live_socket, lambda message: message.get("type") == "status")
            live_connections = _wait_ws_message(live_socket, lambda message: message.get("type") == "connections")
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")
        config = _http_json(f"http://127.0.0.1:{status_port}/api/config")
        logs = _http_json(f"http://127.0.0.1:{status_port}/api/logs?limit=5")
        restart = _http_request_json(f"http://127.0.0.1:{status_port}/api/restart", method="POST")
        reconnect = _http_request_json(f"http://127.0.0.1:{status_port}/api/reconnect", method="POST")
        status_after_controls = _http_json(f"http://127.0.0.1:{status_port}/api/status")
        shutdown = _http_request_json(f"http://127.0.0.1:{status_port}/api/shutdown", method="POST")
        exit_code = _wait_process_exit(process)

        assert status["ok"] is True
        assert status["mode"] == "swift_host_runner"
        assert status["admin_port"] == status_port
        assert status["admin_url"] == f"http://127.0.0.1:{status_port}/"
        assert isinstance(status["uptime_sec"], int)
        assert status["transport_runtime"]["kind"] == "ws"
        assert status["transport_runtime"]["websocket"]["uri"] == "ws://bridge.example.net:8443/"
        assert status["transport_runtime"]["websocket"]["payload_mode"] == "base64"
        assert status["compress_layer"]["algorithm"] == "zlib"
        assert status["compress_layer"]["min_bytes"] == 96
        bootstrap = status["bootstrap_state"]
        assert bootstrap["status"] == "prepared"
        assert bootstrap["transport"] == "ws"
        assert bootstrap["secure_link_mode"] == "psk"
        assert bootstrap["compress_runtime"] == "ready"
        assert bootstrap["websocket_runtime"] == "ready"
        assert bootstrap["compress_layer_types"] == "data,data_ack"
        assert bootstrap["ws_payload_mode"] == "base64"
        assert "ObstacleBridge" in html
        assert "Network Appliance" in html
        assert "async function loadStatus()" in app_js
        assert ".shell" in style_css
        assert auth_state == {
            "ok": True,
            "auth_required": False,
            "authenticated": True,
            "username": "",
        }
        assert meta["transport_runtime"]["websocket"]["uri"] == "ws://bridge.example.net:8443/"
        assert meta["compress_layer"]["level"] == 5
        assert hello["type"] == "hello"
        assert sorted(hello["topics"]) == ["connections", "meta", "peers", "status"]
        assert live_status["data"]["mode"] == "swift_host_runner"
        assert live_connections["data"]["counts"]["tcp"] == 0
        assert peers["peers"][0]["transport"] == "ws"
        assert peers["peers"][0]["peer"] == {"host": "bridge.example.net", "port": 8443}
        assert peers["peers"][0]["runtime"]["websocket"]["proxy_mode"] == "off"
        assert peers["peers"][0]["compress_layer"]["enabled"] is False
        assert config["config"]["overlay_transport"] == "ws"
        assert "admin_web" in config["schema"]
        assert "runner" in config["schema"]
        assert "udp_session" in config["schema"]
        assert "tcp_session" in config["schema"]
        assert "channel_mux" in config["schema"]
        runner_keys = {str(item["key"]) for item in config["schema"]["runner"]}
        assert {"overlay_transport", "client_restart_if_disconnected", "overlay_reconnect_retry_delay_ms"}.issubset(runner_keys)
        udp_session_keys = {str(item["key"]) for item in config["schema"]["udp_session"]}
        assert {"udp_bind", "udp_own_port", "udp_peer", "udp_peer_port"}.issubset(udp_session_keys)
        tcp_session_keys = {str(item["key"]) for item in config["schema"]["tcp_session"]}
        assert {"tcp_bind", "tcp_own_port", "tcp_peer", "tcp_peer_port"}.issubset(tcp_session_keys)
        ws_session_keys = {str(item["key"]) for item in config["schema"]["ws_session"]}
        assert "overlay_transport" not in ws_session_keys
        channel_mux_keys = {str(item["key"]) for item in config["schema"]["channel_mux"]}
        assert channel_mux_keys == {"own_servers", "remote_servers"}
        assert config["config"]["udp_bind"] == "::"
        assert config["config"]["udp_own_port"] == 4433
        assert config["config"]["udp_peer"] is None
        assert config["config"]["udp_peer_port"] == 4433
        assert config["config"]["tcp_bind"] == "::"
        assert config["config"]["tcp_own_port"] == 8081
        assert config["config"]["tcp_peer"] is None
        assert config["config"]["tcp_peer_port"] == 8081
        assert isinstance(config["config"]["own_servers"], list)
        assert isinstance(config["config"]["remote_servers"], list)
        assert logs == {"lines": []}
        assert restart["ok"] is True
        assert restart["restart_requested"] is True
        assert restart["control_actions"]["restart_count"] == 1
        assert reconnect["ok"] is True
        assert reconnect["reconnect_requested"] is True
        assert reconnect["control_actions"]["reconnect_count"] == 1
        assert status_after_controls["control_actions"]["restart_count"] == 1
        assert status_after_controls["control_actions"]["reconnect_count"] == 1
        assert shutdown["ok"] is True
        assert shutdown["shutdown_requested"] is True
        assert shutdown["control_actions"]["shutdown_requested"] is True
        assert exit_code == 0
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_empty_config_serves_onboarding_without_peer(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime_empty_onboarding.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        profiles = _http_json(f"http://127.0.0.1:{status_port}/api/onboarding/connection-profiles")
        blueprints = _http_json(f"http://127.0.0.1:{status_port}/api/onboarding/blueprints")
        html = _http_text(f"http://127.0.0.1:{status_port}/")

        assert status["ok"] is True
        assert status["mode"] == "swift_host_runner"
        assert isinstance(status.get("admin_ui"), dict)
        assert status["admin_ui"]["home_tab_enabled"] is True
        assert status["admin_ui"]["first_start_detected"] is True
        assert status["admin_ui"]["config_file_state"] == "empty"
        assert profiles["ok"] is True
        assert isinstance(profiles["profiles"], list)
        assert blueprints["ok"] is True
        assert isinstance(blueprints["blueprints"], list)
        assert "Setup Assistant" in html or "Open Setup Assistant" in html
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_restart_reloads_runtime_config_from_disk(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": 9,
                "admin_web": True,
                "admin_web_auth_disable": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "status": False,
            }
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        initial = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        assert initial["transport_runtime"]["kind"] == "tcp"
        uptime_before = int(initial.get("uptime_sec") or 0)
        if uptime_before < 1:
            time.sleep(1.2)
            initial = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
            uptime_before = int(initial.get("uptime_sec") or 0)

        runtime_config_path.write_text(
            json.dumps(
                {
                    "overlay_transport": "ws",
                    "ws_peer": "bridge.example.net",
                    "ws_peer_port": 8443,
                    "admin_web": True,
                    "admin_web_auth_disable": True,
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": status_port,
                    "status": False,
                }
            ),
            encoding="utf-8",
        )

        restart = _http_request_json(f"http://127.0.0.1:{status_port}/api/restart", method="POST")
        assert restart["ok"] is True
        assert restart["restart_requested"] is True
        assert restart["restart_supported"] is True
        assert restart["restart_mode"] == "immediate"
        assert restart["restart_embedded"] is True

        reloaded = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/status",
            lambda doc: doc["transport_runtime"].get("kind") == "ws",
            timeout_sec=5.0,
        )
        assert reloaded["transport_runtime"]["kind"] == "ws"
        assert reloaded["transport_runtime"]["websocket"]["uri"] == "ws://bridge.example.net:8443/"
        assert reloaded["control_actions"]["restart_count"] >= 1
        assert int(reloaded.get("uptime_sec") or 0) <= uptime_before
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_requires_admin_auth_when_credentials_configured(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_username": "admin",
                "admin_web_password": "s3cr3t-passphrase",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/auth/state")

        auth_state = _http_json(f"http://127.0.0.1:{status_port}/api/auth/state")
        status_code, _status_headers, status_body = _http_request(f"http://127.0.0.1:{status_port}/api/status")
        challenge = _http_json(f"http://127.0.0.1:{status_port}/api/auth/challenge")
        proof = hashlib.sha256(f"{challenge['seed']}:admin:s3cr3t-passphrase".encode("utf-8")).hexdigest()
        login_code, login_headers, login_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/auth/login",
            method="POST",
            payload={"challenge_id": challenge["challenge_id"], "proof": proof},
        )
        cookie = login_headers.get("Set-Cookie", "")
        session_cookie = cookie.split(";", 1)[0]
        status_after_code, _status_after_headers, status_after_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/status",
            headers={"Cookie": session_cookie},
        )
        config_code, _config_headers, config_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config",
            headers={"Cookie": session_cookie},
        )
        config = json.loads(config_body.decode("utf-8"))

        assert auth_state["auth_required"] is True
        assert auth_state["authenticated"] is False
        assert auth_state["username"] == "admin"
        assert status_code == 401
        assert json.loads(status_body.decode("utf-8")) == {"ok": False, "authenticated": False, "error": "authentication required"}
        assert challenge["algorithm"] == "sha256(seed:username:password)"
        assert login_code == 200
        assert json.loads(login_body.decode("utf-8")) == {"authenticated": True, "ok": True}
        assert cookie.startswith("admin_web_session_")
        assert status_after_code == 200
        assert json.loads(status_after_body.decode("utf-8"))["mode"] == "swift_host_runner"
        assert config_code == 200
        assert config["config"]["admin_web_password"] == ""
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_matches_python_admin_web_payloads_and_token_controls(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config = {
        "overlay_transport": "ws",
        "ws_peer": "bridge.example.net",
        "ws_peer_port": 8443,
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": status_port,
        "admin_web_path": "/swift-admin",
        "admin_web_landing_page_disable": True,
        "admin_web_security_advisor_disable": False,
        "admin_web_security_advisor_startup_disable": True,
        "admin_web_first_tab": "logs",
        "admin_web_token": "swift-token",
        "admin_web_auth_disable": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "short-psk",
    }
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(json.dumps(runtime_config, sort_keys=True), encoding="utf-8")
    expected_admin_ui, expected_security_advisor = _python_admin_web_payloads(runtime_config)

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        config = _http_json(f"http://127.0.0.1:{status_port}/api/config")

        admin_schema_keys = {str(item["key"]) for item in config["schema"]["admin_web"]}
        assert {
            "admin_web_landing_page_disable",
            "admin_web_security_advisor_disable",
            "admin_web_security_advisor_startup_disable",
            "admin_web_first_tab",
            "admin_web_token",
        }.issubset(admin_schema_keys)

        for key in [
            "home_tab_enabled",
            "landing_page_enabled",
            "security_advisor_enabled",
            "security_advisor_startup_enabled",
            "first_tab",
            "first_start_detected",
            "config_file_state",
        ]:
            assert status["admin_ui"][key] == expected_admin_ui[key]
        assert status["security_advisor"] == expected_security_advisor

        restart_unauthorized_code, _restart_unauthorized_headers, restart_unauthorized_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/restart",
            method="POST",
        )
        reconnect_unauthorized_code, _reconnect_unauthorized_headers, reconnect_unauthorized_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/reconnect",
            method="POST",
        )
        shutdown_unauthorized_code, _shutdown_unauthorized_headers, shutdown_unauthorized_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/shutdown",
            method="POST",
        )
        assert restart_unauthorized_code == 403
        assert reconnect_unauthorized_code == 403
        assert shutdown_unauthorized_code == 403
        assert restart_unauthorized_body.decode("utf-8") == "Forbidden"
        assert reconnect_unauthorized_body.decode("utf-8") == "Forbidden"
        assert shutdown_unauthorized_body.decode("utf-8") == "Forbidden"

        token_headers = {"Authorization": "Bearer swift-token"}
        restart_code, _restart_headers, restart_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/restart",
            method="POST",
            headers=token_headers,
        )
        reconnect_code, _reconnect_headers, reconnect_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/reconnect",
            method="POST",
            headers=token_headers,
        )
        shutdown_code, _shutdown_headers, shutdown_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/shutdown",
            method="POST",
            headers=token_headers,
        )

        assert restart_code == 200
        assert json.loads(restart_body.decode("utf-8"))["ok"] is True
        assert reconnect_code == 200
        assert json.loads(reconnect_body.decode("utf-8"))["ok"] is True
        assert shutdown_code == 200
        assert json.loads(shutdown_body.decode("utf-8"))["ok"] is True
        assert _wait_process_exit(process) == 0
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_accepts_python_invite_tokens_without_app_path_leakage(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    udp_port = _unused_udp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "myudp",
                "udp_bind": "::",
                "udp_own_port": udp_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_dir": str(tmp_path / "admin_web"),
                "ws_static_dir": str(tmp_path / "web"),
                "log_file": str(tmp_path / "logs" / "obstaclebridge.log"),
                "secure_link_mode": "psk",
                "secure_link_psk": "swift-host-secret",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    invite_token = encode_invite_token(
        {
            "version": 1,
            "admin_web_name": "Imported Swift Node",
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": "python-side-secret",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 96,
            "compress_layer_types": "data,data_ack",
            "TUN_routing": {
                "dns_servers": ["9.9.9.9"],
                "included_routes": ["0.0.0.0/0"],
            },
            "own_servers": [
                {
                    "name": "HTTP bridge",
                    "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": 18010},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 8010},
                }
            ],
            "remote_servers": [],
        }
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        profiles_doc = _wait_http_json(f"http://127.0.0.1:{status_port}/api/onboarding/connection-profiles")
        blueprints_doc = _http_json(f"http://127.0.0.1:{status_port}/api/onboarding/blueprints")
        preview_doc = _http_request_json(
            f"http://127.0.0.1:{status_port}/api/onboarding/invite/preview",
            method="POST",
            payload={"invite_token": invite_token},
        )

        assert profiles_doc["ok"] is True
        assert isinstance(profiles_doc["profiles"], list)
        assert blueprints_doc == {"ok": True, "count": 0, "blueprints": []}

        assert preview_doc["ok"] is True
        assert preview_doc["preview"]["secure_link_psk"] == "***hidden***"
        assert preview_doc["preview"]["secure_link_psk_present"] is True
        assert preview_doc["suggested_updates"]["overlay_transport"] == "tcp"
        assert preview_doc["suggested_updates"]["tcp_peer"] == "bridge.example.net"
        assert preview_doc["suggested_updates"]["tcp_peer_port"] == 4433
        assert preview_doc["suggested_updates"]["secure_link_psk"] == "python-side-secret"
        assert preview_doc["suggested_updates"]["admin_web_name"] == "Imported Swift Node"
        assert preview_doc["suggested_updates"]["compress_layer"] is True
        assert preview_doc["suggested_updates"]["compress_layer_level"] == 5
        assert preview_doc["suggested_updates"]["compress_layer_types"] == "data,data_ack"
        assert preview_doc["suggested_updates"]["TUN_routing"]["dns_servers"] == ["9.9.9.9"]
        assert preview_doc["suggested_updates"]["own_servers"][0]["name"] == "HTTP bridge"
        assert "admin_web_dir" not in preview_doc["suggested_updates"]
        assert "ws_static_dir" not in preview_doc["suggested_updates"]
        assert "log_file" not in preview_doc["suggested_updates"]
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_applies_invite_updates_with_tun_routing_section(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": status_port,
                    "admin_web_dir": str(tmp_path / "admin_web"),
                    "admin_web_auth_disable": True,
                    "admin_web_security_advisor_startup_disable": True,
                },
                "ws_session": {
                    "ws_static_dir": str(tmp_path / "web"),
                },
                "debug_logging": {
                    "log_file": str(tmp_path / "logs" / "obstaclebridge.log"),
                },
                "TUN_routing": {
                    "tunnel_address": ["192.168.106.1"],
                    "tunnel_prefix": 30,
                    "tunnel_gateway": "192.168.106.2",
                    "included_routes": ["0.0.0.0/0"],
                    "excluded_routes": ["127.0.0.0/8"],
                    "tunnel_address6": ["fd20:106::1"],
                    "tunnel_prefix6": 126,
                    "tunnel_gateway6": "fd20:106::2",
                    "included_routes6": ["::/0"],
                    "excluded_routes6": ["::1/128"],
                    "dns_servers": ["1.1.1.1"],
                    "mtu": 1600,
                    "log_TUN_routing": "CRITICAL",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    invite_token = encode_invite_token(
        {
            "version": 1,
            "admin_web_name": "Imported Swift Node",
            "connection": {
                "transport": "udp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": "python-side-secret",
            "TUN_routing": {
                "dns_servers": ["9.9.9.9"],
                "included_routes": ["0.0.0.0/0"],
                "excluded_routes": ["127.0.0.0/8"],
            },
            "own_servers": [
                {
                    "name": "HTTP bridge",
                    "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": 18010},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 8010},
                }
            ],
            "remote_servers": [],
        }
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        config_before = _wait_http_json(f"http://127.0.0.1:{status_port}/api/config")
        assert config_before["config"]["tunnel_address"] == "192.168.106.1"
        assert config_before["config"]["tunnel_address6"] == "fd20:106::1"

        preview_doc = _http_request_json(
            f"http://127.0.0.1:{status_port}/api/onboarding/invite/preview",
            method="POST",
            payload={"invite_token": invite_token},
        )
        assert preview_doc["ok"] is True
        assert preview_doc["suggested_updates"]["TUN_routing"]["dns_servers"] == ["9.9.9.9"]

        save_doc = _http_request_json(
            f"http://127.0.0.1:{status_port}/api/config",
            method="POST",
            payload={"updates": preview_doc["suggested_updates"]},
        )
        assert save_doc["ok"] is True
        assert save_doc["config"]["udp_peer"] == "bridge.example.net"
        assert save_doc["config"]["udp_peer_port"] == 4433
        assert save_doc["config"]["dns_servers"] == ["9.9.9.9"]
        assert save_doc["config"]["included_routes"] == ["0.0.0.0/0"]
        assert save_doc["config"]["tunnel_address"] == "192.168.106.1"
        assert save_doc["config"]["tunnel_address6"] == "fd20:106::1"
        assert save_doc["config"]["own_servers"][0]["name"] == "HTTP bridge"

        persisted = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        assert persisted["runner"]["overlay_transport"] == "myudp"
        assert persisted["udp_session"]["udp_peer"] == "bridge.example.net"
        assert persisted["udp_session"]["udp_peer_port"] == 4433
        assert persisted["TUN_routing"]["dns_servers"] == ["9.9.9.9"]
        assert persisted["TUN_routing"]["tunnel_address"] == ["192.168.106.1"]
        assert persisted["TUN_routing"]["tunnel_address6"] == ["fd20:106::1"]
        assert persisted["channel_mux"]["own_servers"][0]["name"] == "HTTP bridge"
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_generates_invite_token_with_override_name_and_extended_fields(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_bind": "::",
                "tcp_own_port": 4433,
                "tcp_peer": "bridge.example.net",
                "tcp_peer_port": 4433,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_name": "Origin Node",
                "admin_web_dir": str(tmp_path / "admin_web"),
                "ws_static_dir": str(tmp_path / "web"),
                "log_file": str(tmp_path / "logs" / "obstaclebridge.log"),
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 4,
                "compress_layer_min_bytes": 80,
                "compress_layer_types": "data,data_ack",
                "TUN_routing": {
                    "dns_servers": ["1.1.1.1"],
                    "included_routes": ["0.0.0.0/0"],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        profiles_doc = _wait_http_json(f"http://127.0.0.1:{status_port}/api/onboarding/connection-profiles")
        profile_id = str((profiles_doc.get("profiles") or [{}])[0].get("id", "") or "")
        invite_doc = _http_request_json(
            f"http://127.0.0.1:{status_port}/api/onboarding/invite/generate",
            method="POST",
            payload={
                "connection_id": profile_id,
                "admin_web_name": "Invite Alias",
                "TUN_routing": {
                    "dns_servers": ["9.9.9.9"],
                    "tunnel_address": ["192.168.250.1"],
                    "tunnel_prefix": 30,
                    "tunnel_gateway": "192.168.250.2",
                },
            },
        )

        assert invite_doc["ok"] is True
        payload = decode_invite_token(invite_doc["invite_token"])
        assert payload["generated_by"] == "Invite Alias"
        assert payload["admin_web_name"] == "Invite Alias"
        assert payload["compress_layer"] is True
        assert payload["compress_layer_level"] == 4
        assert payload["compress_layer_types"] == "data,data_ack"
        assert payload["TUN_routing"]["dns_servers"] == ["9.9.9.9"]
        assert payload["TUN_routing"]["tunnel_address"] == "192.168.250.1"
        assert payload["TUN_routing"]["tunnel_gateway"] == "192.168.250.2"
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_rejects_legacy_encrypted_invite_psk(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    udp_port = _unused_udp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "myudp",
                "udp_bind": "::",
                "udp_own_port": udp_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_dir": str(tmp_path / "admin_web"),
                "ws_static_dir": str(tmp_path / "web"),
                "log_file": str(tmp_path / "logs" / "obstaclebridge.log"),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    invite_token = encode_invite_token(
        {
            "version": 1,
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": "enc:v1:not-portable-across-hosts",
        }
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        status_code, _, body = _http_request(
            f"http://127.0.0.1:{status_port}/api/onboarding/invite/preview",
            method="POST",
            payload={"invite_token": invite_token},
        )
        preview_doc = json.loads(body.decode("utf-8"))

        assert status_code == 400
        assert preview_doc["ok"] is False
        assert "legacy encrypted secure_link_psk" in preview_doc["error"]
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_saves_admin_credentials_via_admin_web(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_username": "admin",
                "admin_web_password": "old-passphrase",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/auth/state")

        login_challenge = _http_json(f"http://127.0.0.1:{status_port}/api/auth/challenge")
        login_proof = hashlib.sha256(
            f"{login_challenge['seed']}:admin:old-passphrase".encode("utf-8")
        ).hexdigest()
        login_code, login_headers, login_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/auth/login",
            method="POST",
            payload={"challenge_id": login_challenge["challenge_id"], "proof": login_proof},
        )
        session_cookie = login_headers["Set-Cookie"].split(";", 1)[0]
        assert login_code == 200
        assert json.loads(login_body.decode("utf-8")) == {"authenticated": True, "ok": True}

        updates = {
            "admin_web_username": "operator",
            "admin_web_password": "new-passphrase",
        }
        challenge_code, _challenge_headers, challenge_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config/challenge",
            method="POST",
            headers={"Cookie": session_cookie},
            payload={"updates": updates},
        )
        challenge_doc = json.loads(challenge_body.decode("utf-8"))
        assert challenge_code == 200
        assert challenge_doc["auth_required"] is True
        proof = hashlib.sha256(
            f"{challenge_doc['seed']}:admin:old-passphrase:{challenge_doc['updates_digest']}".encode("utf-8")
        ).hexdigest()

        save_code, _save_headers, save_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config",
            method="POST",
            headers={"Cookie": session_cookie},
            payload={
                "updates": updates,
                "challenge_id": challenge_doc["challenge_id"],
                "proof": proof,
            },
        )
        save_doc = json.loads(save_body.decode("utf-8"))
        assert save_code == 200
        assert save_doc["ok"] is True
        assert save_doc["config"]["admin_web_username"] == "operator"
        assert save_doc["config"]["admin_web_password"] == ""

        auth_state = _http_json(f"http://127.0.0.1:{status_port}/api/auth/state")
        assert auth_state["auth_required"] is True
        assert auth_state["authenticated"] is False
        assert auth_state["username"] == "operator"

        stale_code, _stale_headers, stale_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config",
            headers={"Cookie": session_cookie},
        )
        assert stale_code == 401
        assert json.loads(stale_body.decode("utf-8")) == {
            "ok": False,
            "authenticated": False,
            "error": "authentication required",
        }

        old_login_challenge = _http_json(f"http://127.0.0.1:{status_port}/api/auth/challenge")
        old_login_proof = hashlib.sha256(
            f"{old_login_challenge['seed']}:operator:old-passphrase".encode("utf-8")
        ).hexdigest()
        old_login_code, _old_login_headers, old_login_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/auth/login",
            method="POST",
            payload={"challenge_id": old_login_challenge["challenge_id"], "proof": old_login_proof},
        )
        assert old_login_code == 403
        assert json.loads(old_login_body.decode("utf-8"))["error"] == "authentication failed"

        new_login_challenge = _http_json(f"http://127.0.0.1:{status_port}/api/auth/challenge")
        new_login_proof = hashlib.sha256(
            f"{new_login_challenge['seed']}:operator:new-passphrase".encode("utf-8")
        ).hexdigest()
        new_login_code, new_login_headers, new_login_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/auth/login",
            method="POST",
            payload={"challenge_id": new_login_challenge["challenge_id"], "proof": new_login_proof},
        )
        new_session_cookie = new_login_headers["Set-Cookie"].split(";", 1)[0]
        assert new_login_code == 200
        assert json.loads(new_login_body.decode("utf-8")) == {"authenticated": True, "ok": True}

        config_code, _config_headers, config_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config",
            headers={"Cookie": new_session_cookie},
        )
        config_doc = json.loads(config_body.decode("utf-8"))
        assert config_code == 200
        assert config_doc["config"]["admin_web_username"] == "operator"
        assert config_doc["config"]["admin_web_password"] == ""

        persisted = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        assert persisted["admin_web_username"] == "operator"
        assert persisted["admin_web_password"].startswith(CONFIG_SECRET_PREFIX)
        assert _decrypt_config_secret(persisted["admin_web_password"]) == "new-passphrase"
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_loads_and_persists_encrypted_secure_link_psk(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_auth_disable": True,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": _encrypt_config_secret("initial-shared-secret"),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        config_before = _http_json(f"http://127.0.0.1:{status_port}/api/config")
        assert status["security_advisor"]["enabled"] is True
        assert config_before["config"]["secure_link_mode"] == "psk"
        assert config_before["config"]["secure_link_psk"] == ""

        save_code, _save_headers, save_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/config",
            method="POST",
            payload={"updates": {"secure_link_psk": "rotated-shared-secret"}},
        )
        save_doc = json.loads(save_body.decode("utf-8"))
        assert save_code == 200
        assert save_doc["ok"] is True
        assert save_doc["config"]["secure_link_psk"] == ""
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )

    persisted = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    assert persisted["secure_link_psk"].startswith(CONFIG_SECRET_PREFIX)
    assert _decrypt_config_secret(persisted["secure_link_psk"]) == "rotated-shared-secret"

    restarted_port = _unused_tcp_port()
    persisted["admin_web_port"] = restarted_port
    runtime_config_path.write_text(json.dumps(persisted, sort_keys=True), encoding="utf-8")

    restart_process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(restarted_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        restarted_config = _wait_http_json(f"http://127.0.0.1:{restarted_port}/api/config")
        assert restarted_config["config"]["secure_link_mode"] == "psk"
        assert restarted_config["config"]["secure_link_psk"] == ""
    finally:
        restart_process.terminate()
        try:
            stdout, stderr = restart_process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            restart_process.kill()
            stdout, stderr = restart_process.communicate(timeout=5.0)
        if restart_process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {restart_process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_runner_knobs_drive_tcp_retry_and_restart_watchdog(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "overlay_reconnect_retry_delay_ms": 50,
                "client_restart_if_disconnected": 0.3,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "5",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        config = _http_json(f"http://127.0.0.1:{status_port}/api/config")
        runner_keys = {str(item["key"]) for item in config["schema"]["runner"]}
        assert {"overlay_transport", "client_restart_if_disconnected", "overlay_reconnect_retry_delay_ms"}.issubset(runner_keys)
        assert config["config"]["client_restart_if_disconnected"] == 0.3
        assert config["config"]["overlay_reconnect_retry_delay_ms"] == 50

        retrying_status = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/status",
            lambda doc: int(doc["transport_runtime"]["tcp"].get("reconnect_attempts", 0)) >= 2,
            timeout_sec=5.0,
        )
        tcp_runtime = retrying_status["transport_runtime"]["tcp"]
        assert tcp_runtime["reconnect_retry_delay_ms"] == 50
        assert tcp_runtime["overlay_connected"] is False

        restarted_status = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/status",
            lambda doc: int(doc["control_actions"].get("restart_count", 0)) >= 1,
            timeout_sec=5.0,
        )
        assert restarted_status["control_actions"]["restart_count"] >= 1
        assert restarted_status["transport_runtime"]["tcp"]["reconnect_retry_delay_ms"] == 50
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_live_websocket_requires_auth_when_credentials_configured(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 8443,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "admin_web_username": "admin",
                "admin_web_password": "s3cr3t-passphrase",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--status-port",
            str(status_port),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/auth/state")

        unauth_response, unauth_socket = _websocket_handshake_response("127.0.0.1", status_port)
        unauth_socket.close()

        challenge = _http_json(f"http://127.0.0.1:{status_port}/api/auth/challenge")
        proof = hashlib.sha256(f"{challenge['seed']}:admin:s3cr3t-passphrase".encode("utf-8")).hexdigest()
        login_code, login_headers, _login_body = _http_request(
            f"http://127.0.0.1:{status_port}/api/auth/login",
            method="POST",
            payload={"challenge_id": challenge["challenge_id"], "proof": proof},
        )
        session_cookie = login_headers.get("Set-Cookie", "").split(";", 1)[0]

        assert "401 Unauthorized" in unauth_response
        assert login_code == 200
        with contextlib.closing(
            _websocket_connect("127.0.0.1", status_port, headers={"Cookie": session_cookie})
        ) as live_socket:
            hello = _recv_ws_json(live_socket)
            assert hello["type"] == "hello"
            assert sorted(hello["topics"]) == ["connections", "meta", "peers", "status"]
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_accepts_grouped_obstaclebridge_config(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    documents_root = tmp_path / "documents"
    config_dir = documents_root / "config"
    config_dir.mkdir(parents=True)
    runtime_config_path = config_dir / "ObstacleBridge.cfg"
    runtime_config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": status_port,
                    "admin_web_dir": str(ROOT / "admin_web"),
                    "admin_web_path": "/",
                    "admin_web_name": "Grouped Config",
                },
                "ws_session": {
                    "overlay_transport": "ws",
                    "ws_peer": "grouped.example.net",
                    "ws_peer_port": 9443,
                    "ws_payload_mode": "binary",
                    "ws_static_dir": str(ROOT / "web"),
                },
                "secure_link": {
                    "secure_link": True,
                    "secure_link_mode": "psk",
                    "secure_link_psk": "grouped-psk",
                },
                "compress_layer": {
                    "compress_layer": True,
                    "compress_layer_algo": "zlib",
                    "compress_layer_level": 4,
                    "compress_layer_min_bytes": 80,
                    "compress_layer_types": "data,data_ack",
                },
                "channel_mux": {
                    "own_servers": [
                        {
                            "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": 18010},
                            "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 8010},
                            "name": "grouped tcp own_server",
                        }
                    ],
                    "remote_servers": [
                        {
                            "listen": {"protocol": "udp", "bind": "127.0.0.1", "port": 18011},
                            "target": {"protocol": "udp", "host": "127.0.0.1", "port": 8011},
                            "name": "grouped udp remote_server",
                        }
                    ],
                },
                "debug_logging": {
                    "log": "INFO",
                    "file_level": "INFO",
                    "console_level": "WARNING",
                    "log_file": "",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")
        config = _http_json(f"http://127.0.0.1:{status_port}/api/config")
        html = _http_text(f"http://127.0.0.1:{status_port}/")

        assert status["admin_port"] == status_port
        assert status["bootstrap_state"]["runtime_config_grouped"] is True
        assert status["bootstrap_state"]["peer_host"] == "grouped.example.net"
        assert status["transport_runtime"]["websocket"]["uri"] == "ws://grouped.example.net:9443/"
        assert config["config"]["admin_web_name"] == "Grouped Config"
        assert config["config"]["ws_peer"] == "grouped.example.net"
        assert config["config"]["compress_layer_level"] == 4
        assert config["config"]["secure_link_mode"] == "psk"
        assert len(config["config"]["own_servers"]) == 1
        assert config["config"]["own_servers"][0]["name"] == "grouped tcp own_server"
        assert len(config["config"]["remote_servers"]) == 1
        assert config["config"]["remote_servers"][0]["name"] == "grouped udp remote_server"
        assert meta["compress_layer"]["min_bytes"] == 80
        assert peers["peers"][0]["peer"] == {"host": "grouped.example.net", "port": 9443}
        assert "ObstacleBridge" in html
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_defaults_to_cwd_obstaclebridge_cfg(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    status_port = _unused_tcp_port()
    runtime_config_path = tmp_path / "ObstacleBridge.cfg"
    runtime_config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": status_port,
                    "admin_web_dir": str(ROOT / "admin_web"),
                    "admin_web_path": "/",
                    "admin_web_name": "cwd default config",
                },
                "ws_session": {
                    "overlay_transport": "ws",
                    "ws_peer": "cwd-default.example.net",
                    "ws_peer_port": 9443,
                    "ws_payload_mode": "binary",
                    "ws_static_dir": str(ROOT / "web"),
                },
                "debug_logging": {
                    "log": "INFO",
                    "file_level": "INFO",
                    "console_level": "WARNING",
                    "log_file": "",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--hold-sec",
            "20",
        ],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")

        assert status["runtime_config_path"] == str(runtime_config_path)
        assert status["bootstrap_state"]["peer_host"] == "cwd-default.example.net"
        assert meta["admin_web_name"] == "cwd default config"
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_tcp_ownserver_proxies_traffic_and_reports_connections(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    listen_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    overlay_peer = _TCPOverlayPeer("127.0.0.1", overlay_port)
    overlay_peer.start()

    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "own_servers": [
                    {
                        "name": "Local Echo Bridge",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "127.0.0.1",
                            "port": listen_port,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": target_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    client = None
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        overlay_peer.wait_connected()
        overlay_peer.start_mux_echo_loop()
        listening_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("tcp_listening", 0)) == 1,
        )
        assert listening_connections["counts"]["tcp"] == 0
        assert listening_connections["tcp"][0]["state"] == "listening"
        assert listening_connections["tcp"][0]["service_name"] == "Local Echo Bridge"

        client = socket.create_connection(("127.0.0.1", listen_port), timeout=2.0)
        client.sendall(b"swift-ownserver-test")
        echoed = client.recv(65535)
        assert echoed == b"swift-ownserver-test"

        active_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("tcp", 0)) == 1,
        )
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")

        connected_rows = [row for row in active_connections["tcp"] if row["state"] == "connected"]
        assert len(connected_rows) == 1
        connected = connected_rows[0]
        assert connected["service_name"] == "Local Echo Bridge"
        assert connected["local_port"] == listen_port
        assert connected["remote_destination"] == {"host": "127.0.0.1", "port": target_port}
        assert connected["stats"]["tx_bytes"] >= len(b"swift-ownserver-test")
        assert connected["stats"]["rx_bytes"] >= len(b"swift-ownserver-test")
        assert peers["peers"][0]["open_connections"]["tcp"] == 1
        assert peers["peers"][0]["runtime"]["tcp"]["overlay_connected"] is True
    finally:
        if client is not None:
            with contextlib.suppress(OSError):
                client.close()
        overlay_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_udp_ownserver_proxies_traffic_and_reports_connections(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    listen_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    overlay_peer = _TCPOverlayPeer("127.0.0.1", overlay_port)
    overlay_peer.start()

    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "own_servers": [
                    {
                        "name": "Local UDP Echo Bridge",
                        "listen": {
                            "protocol": "udp",
                            "bind": "127.0.0.1",
                            "port": listen_port,
                        },
                        "target": {
                            "protocol": "udp",
                            "host": "127.0.0.1",
                            "port": target_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    client = None
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        overlay_peer.wait_connected()
        overlay_peer.start_mux_echo_loop()
        listening_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("udp_listening", 0)) == 1,
        )
        assert listening_connections["counts"]["udp"] == 0
        assert listening_connections["udp"][0]["state"] == "listening"
        assert listening_connections["udp"][0]["service_name"] == "Local UDP Echo Bridge"

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        client.sendto(b"swift-udp-ownserver-test", ("127.0.0.1", listen_port))
        echoed, _addr = client.recvfrom(65535)
        assert echoed == b"swift-udp-ownserver-test"

        active_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("udp", 0)) == 1,
        )
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")

        connected_rows = [row for row in active_connections["udp"] if row["state"] == "connected"]
        assert len(connected_rows) == 1
        connected = connected_rows[0]
        assert connected["service_name"] == "Local UDP Echo Bridge"
        assert connected["local_port"] == listen_port
        assert connected["remote_destination"] == {"host": "127.0.0.1", "port": target_port}
        assert connected["stats"]["tx_bytes"] >= len(b"swift-udp-ownserver-test")
        assert connected["stats"]["rx_bytes"] >= len(b"swift-udp-ownserver-test")
        assert peers["peers"][0]["open_connections"]["udp"] == 1
        assert peers["peers"][0]["runtime"]["tcp"]["overlay_connected"] is True
    finally:
        if client is not None:
            with contextlib.suppress(OSError):
                client.close()
        overlay_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_tcp_overlay_owner_forwards_inbound_tcp_and_udp_mux(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    tcp_target_port = _unused_tcp_port()
    udp_target_port = _unused_tcp_port()
    overlay_peer = _TCPOverlayPeer("127.0.0.1", overlay_port)
    tcp_echo = _TCPEchoServer("127.0.0.1", tcp_target_port)
    udp_echo = _UDPEchoServer("127.0.0.1", udp_target_port)
    overlay_peer.start()
    tcp_echo.start()
    udp_echo.start()

    runtime_config_path = tmp_path / "runtime.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        overlay_peer.wait_connected()

        tcp_open = _build_open_payload(
            svc_id=41,
            l_proto="tcp",
            l_bind="127.0.0.1",
            l_port=18001,
            r_proto="tcp",
            r_host="127.0.0.1",
            r_port=tcp_target_port,
            name="Overlay TCP Client",
        )
        overlay_peer.send_mux(41, 1, 0, 1, tcp_open)
        overlay_peer.send_mux(41, 1, 1, 0, b"overlay-tcp-test")

        tcp_chan, tcp_proto, _tcp_counter, tcp_mtype, tcp_body = overlay_peer.recv_mux()
        assert (tcp_chan, tcp_proto, tcp_mtype, tcp_body) == (41, 1, 0, b"overlay-tcp-test")

        udp_open = _build_open_payload(
            svc_id=42,
            l_proto="udp",
            l_bind="127.0.0.1",
            l_port=18002,
            r_proto="udp",
            r_host="127.0.0.1",
            r_port=udp_target_port,
            name="Overlay UDP Client",
        )
        overlay_peer.send_mux(42, 0, 0, 1, udp_open)
        overlay_peer.send_mux(42, 0, 1, 0, b"overlay-udp-test")

        udp_chan, udp_proto, _udp_counter, udp_mtype, udp_body = overlay_peer.recv_mux()
        assert (udp_chan, udp_proto, udp_mtype, udp_body) == (42, 0, 0, b"overlay-udp-test")

        connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("tcp", 0)) >= 1 and int(doc["counts"].get("udp", 0)) >= 1,
        )
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")

        tcp_rows = [row for row in connections["tcp"] if row["state"] == "connected"]
        udp_rows = [row for row in connections["udp"] if row["state"] == "connected"]
        assert any(row["remote_destination"] == {"host": "127.0.0.1", "port": tcp_target_port} for row in tcp_rows)
        assert any(row["remote_destination"] == {"host": "127.0.0.1", "port": udp_target_port} for row in udp_rows)
        assert peers["peers"][0]["open_connections"]["tcp"] >= 1
        assert peers["peers"][0]["open_connections"]["udp"] >= 1
        assert peers["peers"][0]["runtime"]["tcp"]["overlay_connected"] is True
    finally:
        overlay_peer.stop()
        tcp_echo.stop()
        udp_echo.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_tcp_ownserver_proxies_wrapped_overlay_chain(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    listen_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    overlay_peer = _WrappedTCPOverlayPeer(
        "127.0.0.1",
        overlay_port,
        psk="ownserver-chain-psk",
        compress_level=5,
        compress_min_bytes=64,
    )
    overlay_peer.start()

    runtime_config_path = tmp_path / "runtime_wrapped.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "ownserver-chain-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "own_servers": [
                    {
                        "name": "Wrapped Echo Bridge",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "127.0.0.1",
                            "port": listen_port,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": target_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    client = None
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        overlay_peer.wait_connected()
        overlay_peer.start_mux_echo_loop()

        client = socket.create_connection(("127.0.0.1", listen_port), timeout=2.0)
        message = b"wrapped-chain-" + (b"A" * 256)
        client.sendall(message)
        echoed = client.recv(65535)
        assert echoed == message

        active_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("tcp", 0)) == 1,
        )
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")

        connected_rows = [row for row in active_connections["tcp"] if row["state"] == "connected"]
        assert len(connected_rows) == 1
        connected = connected_rows[0]
        assert connected["service_name"] == "Wrapped Echo Bridge"
        assert connected["local_port"] == listen_port
        assert connected["remote_destination"] == {"host": "127.0.0.1", "port": target_port}
        assert peers["peers"][0]["runtime"]["tcp"]["overlay_connected"] is True
        assert peers["peers"][0]["secure_link"]["authenticated"] is True
        assert peers["peers"][0]["secure_link"]["state"] == "authenticated"
        assert peers["peers"][0]["secure_link"]["session_id"] is not None
        assert meta["compress_layer"]["compress_applied_total"] >= 1
        assert meta["compress_layer"]["decompress_ok_total"] >= 1
    finally:
        if client is not None:
            with contextlib.suppress(OSError):
                client.close()
        overlay_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_udp_ownserver_proxies_wrapped_overlay_chain(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    listen_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    overlay_peer = _WrappedTCPOverlayPeer(
        "127.0.0.1",
        overlay_port,
        psk="ownserver-udp-chain-psk",
        compress_level=5,
        compress_min_bytes=64,
    )
    overlay_peer.start()

    runtime_config_path = tmp_path / "runtime_udp_wrapped.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "ownserver-udp-chain-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "own_servers": [
                    {
                        "name": "Wrapped UDP Echo Bridge",
                        "listen": {
                            "protocol": "udp",
                            "bind": "127.0.0.1",
                            "port": listen_port,
                        },
                        "target": {
                            "protocol": "udp",
                            "host": "127.0.0.1",
                            "port": target_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    client = None
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        overlay_peer.wait_connected()
        overlay_peer.start_mux_echo_loop()

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        message = b"wrapped-udp-chain-" + (b"B" * 256)
        client.sendto(message, ("127.0.0.1", listen_port))
        echoed, _addr = client.recvfrom(65535)
        assert echoed == message

        active_connections = _wait_http_condition(
            f"http://127.0.0.1:{status_port}/api/connections",
            lambda doc: int(doc["counts"].get("udp", 0)) == 1,
        )
        peers = _http_json(f"http://127.0.0.1:{status_port}/api/peers")
        meta = _http_json(f"http://127.0.0.1:{status_port}/api/meta")

        connected_rows = [row for row in active_connections["udp"] if row["state"] == "connected"]
        assert len(connected_rows) == 1
        connected = connected_rows[0]
        assert connected["service_name"] == "Wrapped UDP Echo Bridge"
        assert connected["local_port"] == listen_port
        assert connected["remote_destination"] == {"host": "127.0.0.1", "port": target_port}
        assert peers["peers"][0]["open_connections"]["udp"] == 1
        assert peers["peers"][0]["runtime"]["tcp"]["overlay_connected"] is True
        assert peers["peers"][0]["secure_link"]["authenticated"] is True
        assert peers["peers"][0]["secure_link"]["state"] == "authenticated"
        assert peers["peers"][0]["secure_link"]["session_id"] is not None
        assert meta["compress_layer"]["compress_applied_total"] >= 1
        assert meta["compress_layer"]["decompress_ok_total"] >= 1
    finally:
        if client is not None:
            with contextlib.suppress(OSError):
                client.close()
        overlay_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_pushes_remote_service_catalog_after_secure_link_auth(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    status_port = _unused_tcp_port()
    overlay_peer = _WrappedTCPOverlayPeer(
        "127.0.0.1",
        overlay_port,
        psk="remote-catalog-psk",
        compress_level=5,
        compress_min_bytes=64,
    )
    overlay_peer.start()

    runtime_config_path = tmp_path / "runtime_remote_catalog.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "remote-catalog-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": status_port,
                "remote_servers": [
                    {
                        "name": "Remote Admin",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "0.0.0.0",
                            "port": 14081,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": 18090,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{status_port}/api/status")
        chan_id, proto, _counter, mtype, body = overlay_peer.recv_secure_mux()
        assert chan_id == 0
        assert proto == 0
        assert mtype == 4
        assert body.startswith(b"RS3")
        payload_len = struct.unpack(">I", body[15:19])[0]
        doc = json.loads(body[19 : 19 + payload_len].decode("utf-8"))
        assert isinstance(doc, list)
        assert len(doc) == 1
        assert doc[0]["name"] == "Remote Admin"
        assert doc[0]["l_port"] == 14081
        assert doc[0]["r_port"] == 18090
    finally:
        overlay_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


def test_macos_swift_host_runner_remote_tcp_admin_web_handles_multiple_connections(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port()
    hostrunner_admin_port = _unused_tcp_port()
    python_peer_admin_port = _unused_tcp_port()
    remote_tcp_port = _unused_tcp_port()

    python_peer = _AsyncBridgeClientThread(
        {
            "overlay_transport": "tcp",
            "tcp_bind": "127.0.0.1",
            "tcp_own_port": overlay_port,
            "secure_link": True,
            "secure_link_mode": "psk",
            "secure_link_psk": "remote-admin-burst-psk",
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 64,
            "compress_layer_types": "data",
            "admin_web": True,
            "admin_web_bind": "127.0.0.1",
            "admin_web_port": python_peer_admin_port,
            "admin_web_auth_disable": True,
            "status": False,
        }
    )

    runtime_config_path = tmp_path / "runtime_remote_admin_burst.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": overlay_port,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "remote-admin-burst-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "overlay_reconnect_retry_delay_ms": 250,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": hostrunner_admin_port,
                "admin_web_dir": str((ROOT / "admin_web").resolve()),
                "admin_web_auth_disable": True,
                "remote_servers": [
                    {
                        "name": "Remote Admin Burst",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "127.0.0.1",
                            "port": remote_tcp_port,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": hostrunner_admin_port,
                        },
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_peer.start()
    _wait_http_json(f"http://127.0.0.1:{python_peer_admin_port}/api/status", timeout_sec=20.0)
    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/status", timeout_sec=20.0)
        _wait_http_condition(
            f"http://127.0.0.1:{hostrunner_admin_port}/api/peers",
            lambda doc: bool(doc.get("peers")) and bool(doc["peers"][0].get("secure_link", {}).get("authenticated")),
            timeout_sec=20.0,
        )
        _wait_http_json(f"http://127.0.0.1:{remote_tcp_port}/api/status", timeout_sec=20.0)

        def _fetch_path(path: str) -> tuple[str, object]:
            url = f"http://127.0.0.1:{remote_tcp_port}{path}"
            if path in {"/", "/app.js", "/style.css"}:
                deadline = time.time() + 10.0
                last_error = "unknown"
                while time.time() < deadline:
                    try:
                        return path, _http_text(url, timeout_sec=3.0)
                    except Exception as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                        time.sleep(0.1)
                raise AssertionError(f"timed out waiting for text response from {url}: {last_error}")
            return path, _wait_http_json(url, timeout_sec=10.0)

        paths = ["/api/status", "/api/meta", "/api/connections", "/api/peers", "/", "/app.js", "/style.css", "/api/status"]
        with ThreadPoolExecutor(max_workers=min(4, len(paths))) as executor:
            results = list(executor.map(_fetch_path, paths))

        result_map = {path: payload for path, payload in results}
        status = result_map["/api/status"]
        meta = result_map["/api/meta"]
        connections = result_map["/api/connections"]
        peers = result_map["/api/peers"]
        root_html = result_map["/"]
        app_js = result_map["/app.js"]
        style_css = result_map["/style.css"]

        assert isinstance(status, dict) and ("admin_ui" in status or "build" in status)
        assert isinstance(meta, dict) and "transport_runtime" in meta
        assert isinstance(connections, dict) and "counts" in connections
        assert isinstance(peers, dict) and "peers" in peers
        peer_row = peers["peers"][0]
        assert peer_row["transport"] == "tcp"
        assert peer_row["runtime"]["kind"] == "tcp"
        assert peer_row["peer"]["host"] == "127.0.0.1"
        assert int(peer_row["open_connections"]["tcp"]) >= 1
        assert isinstance(root_html, str) and ("ObstacleBridge" in root_html or "Admin Web" in root_html)
        assert isinstance(app_js, str) and "async function loadStatus()" in app_js
        assert isinstance(style_css, str) and "--bg:" in style_css
    finally:
        python_peer.stop()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )


@pytest.mark.parametrize(
    "transport",
    [
        "ws",
        pytest.param(
            "quic",
            marks=pytest.mark.xfail(
                reason="macOS Swift QUIC overlay connects but mixed Python-peer TCP own-service forwarding still stalls",
                strict=True,
            ),
        ),
    ],
)
def test_macos_swift_host_runner_tcp_ownserver_proxies_mixed_python_peer_for_ws_and_quic(
    tmp_path: Path,
    transport: str,
) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    overlay_port = _unused_tcp_port() if transport == "ws" else _unused_udp_port()
    hostrunner_admin_port = _unused_tcp_port()
    python_peer_admin_port = _unused_tcp_port()
    listen_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    cert_dir = materialize_localhost_tls_fixture_set(tmp_path / f"{transport}-localhost-fixtures") if transport == "quic" else None

    python_peer_config = _mixed_overlay_python_peer_config(
        transport=transport,
        overlay_port=overlay_port,
        admin_port=python_peer_admin_port,
        cert_dir=cert_dir,
        wrapped=False,
    )
    python_peer_env = {}
    if transport == "ws":
        python_peer_env = {
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
        }

    runtime_config_path = tmp_path / f"runtime_remote_admin_burst_{transport}.json"
    runtime_config_path.write_text(
        json.dumps(
            _mixed_overlay_hostrunner_runtime_config(
                transport=transport,
                overlay_port=overlay_port,
                admin_port=hostrunner_admin_port,
                wrapped=False,
                own_servers=[
                    {
                        "name": f"Mixed TCP Echo {transport}",
                        "listen": {
                            "protocol": "tcp",
                            "bind": "127.0.0.1",
                            "port": listen_port,
                        },
                        "target": {
                            "protocol": "tcp",
                            "host": "127.0.0.1",
                            "port": target_port,
                        },
                    }
                ],
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_peer_proc, python_peer_log_path, python_peer_log_fp = _start_python_bridge_process(
        name=f"python_peer_remote_admin_burst_{transport}",
        config=python_peer_config,
        tmp_path=tmp_path,
        env_extra=python_peer_env,
    )
    _wait_http_json(f"http://127.0.0.1:{python_peer_admin_port}/api/status", timeout_sec=20.0)
    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    target_server: _TCPEchoServer | None = None
    clients: list[socket.socket] = []
    try:
        _wait_http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/status", timeout_sec=20.0)
        _wait_http_condition(
            f"http://127.0.0.1:{hostrunner_admin_port}/api/peers",
            lambda doc: bool(doc.get("peers")) and str(doc["peers"][0].get("state") or "").strip().lower() == "connected",
            timeout_sec=20.0,
        )
        target_server = _TCPEchoServer("127.0.0.1", target_port)
        target_server.start()
        _wait_tcp_port_ready("127.0.0.1", listen_port)

        payloads = [
            b"\x01mixed-wsquic-tcp-" + transport.encode("utf-8") + b"-client1-" + (b"A" * 2048) + b"\n",
            b"\x01mixed-wsquic-tcp-" + transport.encode("utf-8") + b"-client2-" + (b"B" * 3072) + b"\n",
            b"\x01mixed-wsquic-tcp-" + transport.encode("utf-8") + b"-client3-" + (b"C" * 4096) + b"\n",
        ]
        echoed_payloads: list[bytes] = []
        for payload in payloads:
            client = socket.create_connection(("127.0.0.1", listen_port), timeout=5.0)
            clients.append(client)
            client.sendall(payload)
        for client, payload in zip(clients, payloads):
            client.settimeout(5.0)
            chunks = bytearray()
            while len(chunks) < len(payload):
                chunk = client.recv(len(payload) - len(chunks))
                if not chunk:
                    break
                chunks.extend(chunk)
            echoed_payloads.append(bytes(chunks))

        connections = _wait_http_condition(
            f"http://127.0.0.1:{hostrunner_admin_port}/api/connections",
            lambda doc: int(doc["counts"].get("tcp", 0)) >= 3,
            timeout_sec=20.0,
        )
        peers = _http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/peers")
        meta = _http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/meta")

        assert echoed_payloads == payloads
        assert sorted(target_server.received) == sorted(payloads)
        assert isinstance(connections, dict) and "counts" in connections
        assert isinstance(peers, dict) and "peers" in peers
        peer_row = peers["peers"][0]
        assert peer_row["transport"] == transport
        assert peer_row["runtime"]["kind"] == transport
        assert peer_row["peer"]["host"] == "127.0.0.1"
        assert int(peer_row["open_connections"]["tcp"]) >= 3
        assert meta["transport_runtime"]["kind"] == transport
    finally:
        for client in clients:
            with contextlib.suppress(OSError):
                client.close()
        if target_server is not None:
            target_server.stop()
        if python_peer_proc.poll() is None:
            python_peer_proc.terminate()
        python_peer_proc.wait(timeout=10.0)
        python_peer_log_fp.close()
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if python_peer_proc.returncode not in (0, -15, 143):
            raise AssertionError(
                f"Python bridge peer exited unexpectedly with code {python_peer_proc.returncode}. "
                f"Log file: {python_peer_log_path}\n{python_peer_log_path.read_text(encoding='utf-8', errors='replace')}"
            )
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )



def test_macos_swift_host_runner_bootstraps_quic_stack_and_serves_status(tmp_path: Path) -> None:
    artifact = build_macos_swift_artifact()
    binary_path = artifact.binary_path

    hostrunner_admin_port = _unused_tcp_port()
    overlay_port = _unused_udp_port()

    runtime_config_path = tmp_path / "runtime_remote_admin_burst_quic.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "overlay_transport": "quic",
                "quic_peer": "::1",
                "quic_peer_port": overlay_port,
                "quic_bind": "::",
                "quic_own_port": 0,
                "quic_alpn": "hq-29",
                "quic_insecure": True,
                "secure_link": True,
                "secure_link_mode": "psk",
                "secure_link_psk": "remote-admin-burst-psk",
                "compress_layer": True,
                "compress_layer_algo": "zlib",
                "compress_layer_level": 5,
                "compress_layer_min_bytes": 64,
                "compress_layer_types": "data",
                "overlay_reconnect_retry_delay_ms": 250,
                "admin_web": True,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": hostrunner_admin_port,
                "admin_web_dir": str((ROOT / "admin_web").resolve()),
                "admin_web_auth_disable": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [
            str(binary_path),
            "--runtime-config",
            str(runtime_config_path),
            "--hold-sec",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status = _wait_http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/status", timeout_sec=20.0)
        meta = _http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/meta")
        peers = _http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/peers")
        config = _http_json(f"http://127.0.0.1:{hostrunner_admin_port}/api/config")
        root_html = _http_text(f"http://127.0.0.1:{hostrunner_admin_port}/", timeout_sec=3.0)
        app_js = _http_text(f"http://127.0.0.1:{hostrunner_admin_port}/app.js", timeout_sec=3.0)
        style_css = _http_text(f"http://127.0.0.1:{hostrunner_admin_port}/style.css", timeout_sec=3.0)

        peer_row = peers["peers"][0]
        assert peer_row["transport"] == "quic"
        assert peer_row["runtime"]["kind"] == "quic"
        assert peer_row["peer"]["host"] in {"::1", "127.0.0.1"}
        assert status["transport_runtime"]["kind"] == "quic"
        assert status["transport_runtime"]["quic"]["overlay_alpn"] == "hq-29"
        assert meta["transport_runtime"]["quic"]["overlay_insecure"] is True
        assert config["config"]["overlay_transport"] == "quic"
        assert "quic_session" in config["schema"]
        assert isinstance(root_html, str) and ("ObstacleBridge" in root_html or "Admin Web" in root_html)
        assert isinstance(app_js, str) and "async function loadStatus()" in app_js
        assert isinstance(style_css, str) and "--bg:" in style_css
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5.0)
        if process.returncode not in (0, -15):
            raise AssertionError(
                f"macOS Swift host runner exited unexpectedly with code {process.returncode}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
