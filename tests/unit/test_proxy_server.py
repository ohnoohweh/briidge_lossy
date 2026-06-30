from __future__ import annotations

import asyncio

from obstacle_bridge.bridge_proxy_server import (
    ObstacleBridgeProxyProtocolCodec,
    ObstacleBridgeProxyServer,
    ObstacleBridgeProxyServerConfig,
    ProxyCredentials,
)


async def _start_capture_server() -> tuple[asyncio.AbstractServer, int, list[bytes]]:
    captured: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(4096)
        captured.append(data)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, int(port), captured


def test_python_proxy_server_rewrites_http_absolute_form() -> None:
    asyncio.run(_test_python_proxy_server_rewrites_http_absolute_form())


async def _test_python_proxy_server_rewrites_http_absolute_form() -> None:
    target_server, target_port, captured = await _start_capture_server()
    proxy = ObstacleBridgeProxyServer(
        ObstacleBridgeProxyServerConfig(bind_host="127.0.0.1", port=0, allow_socks5=False)
    )
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            (
                f"GET http://127.0.0.1:{target_port}/path?q=1 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "\r\n"
            ).encode()
        )
        await writer.drain()
        response = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        assert response.startswith(b"HTTP/1.1 200 OK")
        assert captured == [
            (
                f"GET /path?q=1 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                "\r\n"
            ).encode()
        ]
        snapshot = proxy.snapshot()
        assert snapshot["accepted_connections"] == 1
        assert snapshot["auth_required"] is False
        assert snapshot["http_enabled"] is True
        assert snapshot["socks5_enabled"] is False
    finally:
        await proxy.stop()
        target_server.close()
        await target_server.wait_closed()


def test_python_proxy_server_rejects_missing_http_proxy_auth() -> None:
    asyncio.run(_test_python_proxy_server_rejects_missing_http_proxy_auth())


async def _test_python_proxy_server_rejects_missing_http_proxy_auth() -> None:
    proxy = ObstacleBridgeProxyServer(
        ObstacleBridgeProxyServerConfig(
            bind_host="127.0.0.1",
            port=0,
            credentials=ProxyCredentials("obproxy", "secret"),
            allow_socks5=False,
        )
    )
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        await writer.drain()
        response = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        assert response.startswith(b"HTTP/1.1 407 Proxy Authentication Required")
        assert b'Proxy-Authenticate: Basic realm="ObstacleBridge"' in response
        assert proxy.snapshot()["last_error"] == "proxy authentication required"
    finally:
        await proxy.stop()


def test_python_proxy_server_accepts_socks5_connect_with_user_password() -> None:
    asyncio.run(_test_python_proxy_server_accepts_socks5_connect_with_user_password())


async def _test_python_proxy_server_accepts_socks5_connect_with_user_password() -> None:
    target_server, target_port, captured = await _start_capture_server()
    proxy = ObstacleBridgeProxyServer(
        ObstacleBridgeProxyServerConfig(
            bind_host="127.0.0.1",
            port=0,
            credentials=ProxyCredentials("obproxy", "secret"),
            allow_http=False,
            allow_socks5=True,
        )
    )
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(bytes([0x05, 0x01, 0x02]))
        await writer.drain()
        assert await reader.readexactly(2) == bytes([0x05, 0x02])

        username = b"obproxy"
        password = b"secret"
        writer.write(bytes([0x01, len(username)]) + username + bytes([len(password)]) + password)
        await writer.drain()
        assert await reader.readexactly(2) == bytes([0x01, 0x00])

        host = b"127.0.0.1"
        writer.write(bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + target_port.to_bytes(2, "big"))
        await writer.drain()
        assert await reader.readexactly(10) == bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

        writer.write(b"GET /via-socks HTTP/1.1\r\nHost: target\r\n\r\n")
        await writer.drain()
        response = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        assert response.startswith(b"HTTP/1.1 200 OK")
        assert captured == [b"GET /via-socks HTTP/1.1\r\nHost: target\r\n\r\n"]
    finally:
        await proxy.stop()
        target_server.close()
        await target_server.wait_closed()


def test_python_proxy_codec_basic_auth_header_matches_swift_shape() -> None:
    assert (
        ObstacleBridgeProxyProtocolCodec.basic_authorization_header("obproxy", "secret")
        == "Basic b2Jwcm94eTpzZWNyZXQ="
    )
