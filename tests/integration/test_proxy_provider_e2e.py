from __future__ import annotations

import asyncio
import base64
import socket
import ssl
import tempfile
from pathlib import Path

from obstacle_bridge.bridge_proxy_server import (
    ObstacleBridgeProxyServer,
    ObstacleBridgeProxyServerConfig,
    ProxyCredentials,
)
from tests.fixtures.localhost_tls import materialize_localhost_tls_fixture_set


CONCURRENT_CLIENTS_PER_PROTOCOL = 4


async def _start_http_target() -> tuple[asyncio.AbstractServer, int, list[bytes]]:
    captured: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        captured.append(data)
        first_line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
        body = f"python-target:{first_line}\n".encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    return server, port, captured


async def _start_tls_target(tls_dir: Path) -> tuple[asyncio.AbstractServer, int, list[bytes]]:
    captured: list[bytes] = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tls_dir / "cert.pem"), str(tls_dir / "key.pem"))

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        captured.append(data)
        first_line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
        body = f"python-tls-target:{first_line}\n".encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = int(server.sockets[0].getsockname()[1])
    return server, port, captured


async def _start_proxy(credentials: ProxyCredentials) -> tuple[ObstacleBridgeProxyServer, int]:
    proxy = ObstacleBridgeProxyServer(
        ObstacleBridgeProxyServerConfig(
            bind_host="127.0.0.1",
            port=0,
            credentials=credentials,
            allow_http=True,
            allow_socks5=True,
        )
    )
    await proxy.start()
    assert proxy._server is not None
    port = int(proxy._server.sockets[0].getsockname()[1])
    return proxy, port


def _read_http_response(sock: socket.socket) -> bytes:
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return response
        response += chunk


def _proxy_auth_header(credentials: ProxyCredentials) -> str:
    token = base64.b64encode(f"{credentials.username}:{credentials.password}".encode()).decode()
    return f"Basic {token}"


def _http_via_proxy(
    proxy_port: int,
    target_port: int,
    credentials: ProxyCredentials,
    request_path: str,
) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as sock:
        sock.sendall(
            (
                f"GET http://127.0.0.1:{target_port}{request_path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"Proxy-Authorization: {_proxy_auth_header(credentials)}\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: obstaclebridge-e2e\r\n"
                "\r\n"
            ).encode()
        )
        return _read_http_response(sock)


def _https_via_http_connect_proxy(
    proxy_port: int,
    target_port: int,
    tls_dir: Path,
    credentials: ProxyCredentials,
    request_path: str,
) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as raw_sock:
        raw_sock.sendall(
            (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"Proxy-Authorization: {_proxy_auth_header(credentials)}\r\n"
                "\r\n"
            ).encode()
        )
        response_head = b""
        while b"\r\n\r\n" not in response_head:
            response_head += raw_sock.recv(4096)
        assert response_head.startswith(b"HTTP/1.1 200 Connection Established"), response_head

        client_context = ssl.create_default_context(cafile=str(tls_dir / "cert.pem"))
        with client_context.wrap_socket(raw_sock, server_hostname="127.0.0.1") as tls_sock:
            tls_sock.sendall(
                f"GET {request_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
            )
            return _read_http_response(tls_sock)


def _socks5_via_proxy(
    proxy_port: int,
    target_port: int,
    credentials: ProxyCredentials,
    request_path: str,
) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as sock:
        sock.sendall(bytes([0x05, 0x01, 0x02]))
        assert sock.recv(2) == bytes([0x05, 0x02])

        username = credentials.username.encode()
        password = credentials.password.encode()
        sock.sendall(bytes([0x01, len(username)]) + username + bytes([len(password)]) + password)
        assert sock.recv(2) == bytes([0x01, 0x00])

        host = b"127.0.0.1"
        sock.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + target_port.to_bytes(2, "big"))
        assert sock.recv(10) == bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

        sock.sendall(f"GET {request_path} HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n".encode())
        return _read_http_response(sock)


def test_proxy_provider_e2e_python_http_https_and_socks5() -> None:
    asyncio.run(_test_proxy_provider_e2e_python_http_https_and_socks5())


async def _test_proxy_provider_e2e_python_http_https_and_socks5() -> None:
    credentials = ProxyCredentials("obproxy", "secret")
    tls_tmp = tempfile.TemporaryDirectory()
    tls_dir = materialize_localhost_tls_fixture_set(Path(tls_tmp.name))
    http_server, http_port, http_captured = await _start_http_target()
    tls_server, tls_port, tls_captured = await _start_tls_target(tls_dir)
    proxy, proxy_port = await _start_proxy(credentials)
    try:
        http_paths = [f"/plain/{index}?q={index}" for index in range(CONCURRENT_CLIENTS_PER_PROTOCOL)]
        https_paths = [f"/secure/{index}" for index in range(CONCURRENT_CLIENTS_PER_PROTOCOL)]
        socks_paths = [f"/socks/{index}" for index in range(CONCURRENT_CLIENTS_PER_PROTOCOL)]

        responses = await asyncio.gather(
            *[
                asyncio.to_thread(_http_via_proxy, proxy_port, http_port, credentials, path)
                for path in http_paths
            ],
            *[
                asyncio.to_thread(
                    _https_via_http_connect_proxy,
                    proxy_port,
                    tls_port,
                    tls_dir,
                    credentials,
                    path,
                )
                for path in https_paths
            ],
            *[
                asyncio.to_thread(_socks5_via_proxy, proxy_port, http_port, credentials, path)
                for path in socks_paths
            ],
        )

        http_responses = responses[:CONCURRENT_CLIENTS_PER_PROTOCOL]
        https_responses = responses[
            CONCURRENT_CLIENTS_PER_PROTOCOL : CONCURRENT_CLIENTS_PER_PROTOCOL * 2
        ]
        socks_responses = responses[CONCURRENT_CLIENTS_PER_PROTOCOL * 2 :]

        for path, response in zip(http_paths, http_responses):
            assert f"python-target:GET {path} HTTP/1.1".encode() in response
        for path, response in zip(https_paths, https_responses):
            assert f"python-tls-target:GET {path} HTTP/1.1".encode() in response
        for path, response in zip(socks_paths, socks_responses):
            assert f"python-target:GET {path} HTTP/1.1".encode() in response

        http_first_lines = {data.split(b"\r\n", 1)[0] for data in http_captured}
        assert {f"GET {path} HTTP/1.1".encode() for path in http_paths}.issubset(http_first_lines)
        assert {f"GET {path} HTTP/1.1".encode() for path in socks_paths}.issubset(http_first_lines)

        for data in http_captured:
            if data.startswith(b"GET /plain/"):
                assert b"Proxy-Authorization:" not in data
                assert b"Proxy-Connection:" not in data

        tls_first_lines = {data.split(b"\r\n", 1)[0] for data in tls_captured}
        assert tls_first_lines == {f"GET {path} HTTP/1.1".encode() for path in https_paths}
        assert len(tls_captured) == CONCURRENT_CLIENTS_PER_PROTOCOL

        snapshot = proxy.snapshot()
        assert snapshot["accepted_connections"] == CONCURRENT_CLIENTS_PER_PROTOCOL * 3
        assert snapshot["auth_required"] is True
        assert snapshot["http_enabled"] is True
        assert snapshot["socks5_enabled"] is True
        assert snapshot["rx_bytes"] > 0
        assert snapshot["tx_bytes"] > 0
    finally:
        await proxy.stop()
        http_server.close()
        tls_server.close()
        await http_server.wait_closed()
        await tls_server.wait_closed()
        tls_tmp.cleanup()
