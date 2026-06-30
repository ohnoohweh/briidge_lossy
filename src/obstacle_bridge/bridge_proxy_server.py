from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ProxyCredentials:
    username: str
    password: str


@dataclass(frozen=True)
class ProxyHTTPRequestHead:
    method: str
    target: str
    version: str
    headers: dict[str, str]
    header_length: int
    raw_header: bytes


@dataclass(frozen=True)
class ProxySOCKS5ConnectRequest:
    command: int
    host: str
    port: int
    consumed: int
    address_type: int


class ObstacleBridgeProxyProtocolCodec:
    @staticmethod
    def parse_http_request_head(data: bytes) -> Optional[ProxyHTTPRequestHead]:
        marker = data.find(b"\r\n\r\n")
        if marker < 0:
            return None
        header_length = marker + 4
        raw_header = data[:header_length]
        try:
            header_text = raw_header.decode("latin1")
        except UnicodeDecodeError:
            return None
        lines = header_text.split("\r\n")
        if not lines:
            return None
        parts = lines[0].split(" ", 2)
        if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
            return None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return ProxyHTTPRequestHead(
            method=parts[0],
            target=parts[1],
            version=parts[2],
            headers=headers,
            header_length=header_length,
            raw_header=raw_header,
        )

    @staticmethod
    def rewrite_http_request_for_origin_server(request: ProxyHTTPRequestHead) -> bytes:
        parsed = urlsplit(request.target)
        if parsed.scheme and parsed.netloc:
            origin_path = parsed.path or "/"
            if parsed.query:
                origin_path = f"{origin_path}?{parsed.query}"
        else:
            origin_path = request.target
        lines = [f"{request.method} {origin_path} {request.version}"]
        header_text = request.raw_header.decode("latin1")
        for line in header_text.split("\r\n")[1:]:
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("proxy-authorization:") or lower.startswith("proxy-connection:"):
                continue
            lines.append(line)
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    @staticmethod
    def parse_authority(raw: str, default_port: int) -> Optional[tuple[str, int]]:
        value = raw.strip()
        if value.startswith("["):
            end = value.find("]")
            if end < 0:
                return None
            host = value[1:end]
            remainder = value[end + 1 :]
            port = int(remainder[1:]) if remainder.startswith(":") and remainder[1:].isdigit() else default_port
            return host, port
        if ":" in value:
            host, maybe_port = value.rsplit(":", 1)
            if maybe_port.isdigit():
                return host, int(maybe_port)
        return None if not value else (value, default_port)

    @staticmethod
    def basic_authorization_header(username: str, password: str) -> str:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    @staticmethod
    def authorized(headers: dict[str, str], credentials: Optional[ProxyCredentials]) -> bool:
        if credentials is None:
            return True
        raw = headers.get("proxy-authorization")
        if raw is None:
            return False
        prefix = "basic "
        if not raw.lower().startswith(prefix):
            return False
        encoded = raw[len(prefix) :].strip()
        try:
            decoded = base64.b64decode(encoded).decode()
        except Exception:
            return False
        return decoded == f"{credentials.username}:{credentials.password}"

    @staticmethod
    def parse_socks5_connect_request(data: bytes) -> Optional[ProxySOCKS5ConnectRequest]:
        if len(data) < 4 or data[0] != 0x05:
            return None
        command = int(data[1])
        address_type = int(data[3])
        cursor = 4
        if address_type == 0x01:
            if len(data) < cursor + 4 + 2:
                return None
            host = ".".join(str(byte) for byte in data[cursor : cursor + 4])
            cursor += 4
        elif address_type == 0x03:
            if len(data) < cursor + 1:
                return None
            length = int(data[cursor])
            cursor += 1
            if len(data) < cursor + length + 2:
                return None
            host = data[cursor : cursor + length].decode("utf-8", errors="replace")
            cursor += length
        elif address_type == 0x04:
            if len(data) < cursor + 16 + 2:
                return None
            segments = [
                format((data[cursor + index * 2] << 8) | data[cursor + index * 2 + 1], "x")
                for index in range(8)
            ]
            host = ":".join(segments)
            cursor += 16
        else:
            return None
        port = (data[cursor] << 8) | data[cursor + 1]
        cursor += 2
        if not host or port <= 0:
            return None
        return ProxySOCKS5ConnectRequest(
            command=command,
            host=host,
            port=port,
            consumed=cursor,
            address_type=address_type,
        )


@dataclass(frozen=True)
class ObstacleBridgeProxyServerConfig:
    bind_host: str
    port: int
    credentials: Optional[ProxyCredentials] = None
    allow_http: bool = True
    allow_socks5: bool = True
    max_header_bytes: int = 64 * 1024


def _json_cli_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        return json.loads(value)
    return value


class ObstacleBridgeProxyProviderSettings:
    @staticmethod
    def register_cli(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--proxy-provider-enabled",
            dest="proxy_provider_enabled",
            action=argparse.BooleanOptionalAction,
            default=False,
            help="Enable the extension-owned explicit proxy provider.",
        )
        parser.add_argument(
            "--proxy-provider-bind",
            dest="proxy_provider_bind",
            default="127.0.0.1",
            help="Local bind address for the proxy listener inside the packet-tunnel extension.",
        )
        parser.add_argument(
            "--proxy-provider-http-port",
            dest="proxy_provider_http_port",
            type=int,
            default=13881,
            help="Local HTTP/CONNECT proxy listener port.",
        )
        parser.add_argument(
            "--proxy-provider-socks5-port",
            dest="proxy_provider_socks5_port",
            type=int,
            default=13882,
            help="Local SOCKS5 CONNECT proxy listener port.",
        )
        parser.add_argument(
            "--proxy-provider-protocols",
            dest="proxy_provider_protocols",
            nargs="+",
            choices=["http-connect", "socks5-connect", "http", "socks5"],
            default=["http-connect", "socks5-connect"],
            help="Enabled proxy protocol families.",
        )
        parser.add_argument(
            "--proxy-provider-auth",
            dest="proxy_provider_auth",
            type=_json_cli_value,
            default={"mode": "none", "username": "", "token": ""},
            help="Proxy authentication object. Use mode token/basic/password with username and token/password.",
        )
        parser.add_argument(
            "--proxy-provider-egress",
            dest="proxy_provider_egress",
            type=_json_cli_value,
            default={"mode": "direct", "address_families": ["ipv4", "ipv6"]},
            help="Proxy egress policy object for direct outbound connection behavior.",
        )
        parser.add_argument(
            "--proxy-provider-policy",
            dest="proxy_provider_policy",
            type=_json_cli_value,
            default={"allow_private_destinations": False, "blocked_host_patterns": []},
            help="Proxy destination policy object.",
        )


class ObstacleBridgeProxyServer:
    def __init__(
        self,
        config: ObstacleBridgeProxyServerConfig,
        *,
        open_connection: Callable[..., Any] = asyncio.open_connection,
    ) -> None:
        if config.port < 0 or config.port > 65535:
            raise ValueError(f"Invalid proxy server port: {config.port}")
        self.config = config
        self._open_connection = open_connection
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._log = logging.getLogger("proxy_provider")
        self._snapshot: dict[str, Any] = {
            "accepted_connections": 0,
            "active_connections": 0,
            "completed_connections": 0,
            "failed_connections": 0,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "last_error": "",
        }

    async def start(self) -> None:
        host = self._normalized_listener_host(self.config.bind_host)
        self._log.info(
            "[PROXY] starting listener bind=%s normalized_bind=%s port=%d http=%s socks5=%s auth=%s",
            self.config.bind_host,
            host if host is not None else "*",
            self.config.port,
            self.config.allow_http,
            self.config.allow_socks5,
            self.config.credentials is not None,
        )
        self._server = await asyncio.start_server(self._handle_client, host=host, port=self.config.port)
        sockets = self._server.sockets or []
        bound = [sock.getsockname() for sock in sockets]
        self._log.info("[PROXY] listener started port=%d bound=%r", self.config.port, bound)

    async def stop(self) -> None:
        if self._server is not None:
            self._log.info("[PROXY] stopping listener port=%d", self.config.port)
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._snapshot["active_connections"] = 0
        self._log.info("[PROXY] listener stopped port=%d", self.config.port)

    def snapshot(self) -> dict[str, Any]:
        return {
            **self._snapshot,
            "bind_host": self.config.bind_host,
            "port": self.config.port,
            "http_enabled": self.config.allow_http,
            "socks5_enabled": self.config.allow_socks5,
            "auth_required": self.config.credentials is not None,
        }

    @staticmethod
    def _normalized_listener_host(bind_host: str) -> Optional[str]:
        host = bind_host.strip().lower()
        if host in {"", "*", "0.0.0.0", "::", "[::]"}:
            return None
        if host == "localhost":
            return "127.0.0.1"
        return bind_host.strip()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._snapshot["accepted_connections"] += 1
        self._snapshot["active_connections"] += 1
        peer = writer.get_extra_info("peername")
        self._log.debug("[PROXY] accepted client peer=%r port=%d", peer, self.config.port)
        error: Optional[str] = None
        try:
            session = _ProxySession(self, reader, writer)
            await session.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
        finally:
            if task is not None:
                self._tasks.discard(task)
            self._snapshot["active_connections"] = max(0, int(self._snapshot["active_connections"]) - 1)
            if error:
                self._snapshot["failed_connections"] += 1
                self._snapshot["last_error"] = error
                self._log.warning("[PROXY] client failed peer=%r port=%d error=%s", peer, self.config.port, error)
            else:
                self._snapshot["completed_connections"] += 1
                self._log.debug("[PROXY] client completed peer=%r port=%d", peer, self.config.port)
            writer.close()
            await writer.wait_closed()

    def _on_bytes(self, rx_bytes: int, tx_bytes: int) -> None:
        self._snapshot["rx_bytes"] += rx_bytes
        self._snapshot["tx_bytes"] += tx_bytes


class _ProxySession:
    def __init__(
        self,
        server: ObstacleBridgeProxyServer,
        inbound_reader: asyncio.StreamReader,
        inbound_writer: asyncio.StreamWriter,
    ) -> None:
        self.server = server
        self.inbound_reader = inbound_reader
        self.inbound_writer = inbound_writer
        self.outbound_reader: Optional[asyncio.StreamReader] = None
        self.outbound_writer: Optional[asyncio.StreamWriter] = None
        self.buffer = b""

    async def run(self) -> None:
        while not self.buffer:
            data = await self.inbound_reader.read(16 * 1024)
            if not data:
                return
            self.buffer += data
        if self.buffer[0] == 0x05:
            if not self.server.config.allow_socks5:
                raise RuntimeError("socks5 disabled")
            await self._handle_socks5_greeting()
        else:
            if not self.server.config.allow_http:
                raise RuntimeError("http proxy disabled")
            await self._handle_http_initial()

    async def _handle_http_initial(self) -> None:
        while True:
            request = ObstacleBridgeProxyProtocolCodec.parse_http_request_head(self.buffer)
            if request is not None:
                await self._handle_http_request(request)
                return
            if len(self.buffer) > max(4096, self.server.config.max_header_bytes):
                await self._send_http_error("431 Request Header Fields Too Large", "request header too large")
                return
            data = await self.inbound_reader.read(16 * 1024)
            if not data:
                raise RuntimeError("incomplete request")
            self.buffer += data

    async def _handle_http_request(self, request: ProxyHTTPRequestHead) -> None:
        if not ObstacleBridgeProxyProtocolCodec.authorized(request.headers, self.server.config.credentials):
            body = b"proxy authentication required\n"
            response = (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"ObstacleBridge\"\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            self.inbound_writer.write(response)
            await self.inbound_writer.drain()
            raise RuntimeError("proxy authentication required")
        if request.method.upper() == "CONNECT":
            destination = ObstacleBridgeProxyProtocolCodec.parse_authority(request.target, default_port=443)
            if destination is None:
                await self._send_http_error("400 Bad Request", "invalid CONNECT authority")
                return
            await self._connect_outbound(*destination)
            self.inbound_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ObstacleBridge\r\n\r\n")
            await self.inbound_writer.drain()
            await self._start_tunnel(self.buffer[request.header_length :])
            return
        parsed = urlsplit(request.target)
        if not (parsed.scheme and parsed.netloc and parsed.hostname):
            await self._send_http_error("400 Bad Request", "absolute-form HTTP target required")
            return
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        await self._connect_outbound(parsed.hostname, port)
        forwarded = (
            ObstacleBridgeProxyProtocolCodec.rewrite_http_request_for_origin_server(request)
            + self.buffer[request.header_length :]
        )
        assert self.outbound_writer is not None
        self.outbound_writer.write(forwarded)
        await self.outbound_writer.drain()
        self.server._on_bytes(len(forwarded), 0)
        await self._start_tunnel(b"")

    async def _handle_socks5_greeting(self) -> None:
        while len(self.buffer) < 2 or len(self.buffer) < 2 + self.buffer[1]:
            data = await self.inbound_reader.read(1024)
            if not data:
                raise RuntimeError("incomplete socks5 greeting")
            self.buffer += data
        method_count = self.buffer[1]
        methods = self.buffer[2 : 2 + method_count]
        auth_required = self.server.config.credentials is not None
        if auth_required and 0x02 in methods:
            selected_method = 0x02
        elif not auth_required and 0x00 in methods:
            selected_method = 0x00
        else:
            self.inbound_writer.write(bytes([0x05, 0xFF]))
            await self.inbound_writer.drain()
            raise RuntimeError("no acceptable socks5 auth method")
        consumed = 2 + method_count
        self.buffer = self.buffer[consumed:]
        self.inbound_writer.write(bytes([0x05, selected_method]))
        await self.inbound_writer.drain()
        if selected_method == 0x02:
            await self._handle_socks5_user_password()
        await self._handle_socks5_request()

    async def _handle_socks5_user_password(self) -> None:
        while True:
            if len(self.buffer) >= 2:
                username_length = self.buffer[1]
                password_length_index = 2 + username_length
                if len(self.buffer) >= password_length_index + 1:
                    password_length = self.buffer[password_length_index]
                    consumed = password_length_index + 1 + password_length
                    if len(self.buffer) >= consumed:
                        break
            data = await self.inbound_reader.read(1024)
            if not data:
                raise RuntimeError("incomplete socks5 authentication")
            self.buffer += data
        username = self.buffer[2 : 2 + username_length].decode("utf-8", errors="replace")
        password_start = password_length_index + 1
        password = self.buffer[password_start:consumed].decode("utf-8", errors="replace")
        credentials = self.server.config.credentials
        authorized = credentials is not None and username == credentials.username and password == credentials.password
        self.buffer = self.buffer[consumed:]
        self.inbound_writer.write(bytes([0x01, 0x00 if authorized else 0x01]))
        await self.inbound_writer.drain()
        if not authorized:
            raise RuntimeError("socks5 authentication failed")

    async def _handle_socks5_request(self) -> None:
        while True:
            parsed = ObstacleBridgeProxyProtocolCodec.parse_socks5_connect_request(self.buffer)
            if parsed is not None:
                break
            data = await self.inbound_reader.read(4096)
            if not data:
                raise RuntimeError("incomplete socks5 request")
            self.buffer += data
        if parsed.command != 0x01:
            await self._send_socks5_reply(0x07)
            raise RuntimeError("unsupported socks5 command")
        await self._connect_outbound(parsed.host, parsed.port)
        await self._send_socks5_reply(0x00)
        await self._start_tunnel(self.buffer[parsed.consumed :])

    async def _connect_outbound(self, host: str, port: int) -> None:
        if port <= 0 or port > 65535:
            await self._send_http_error("400 Bad Request", "invalid destination port")
            raise RuntimeError("invalid destination port")
        self.outbound_reader, self.outbound_writer = await self.server._open_connection(host=host, port=port)

    async def _start_tunnel(self, pending_inbound_data: bytes) -> None:
        assert self.outbound_reader is not None
        assert self.outbound_writer is not None
        if pending_inbound_data:
            self.outbound_writer.write(pending_inbound_data)
            await self.outbound_writer.drain()
            self.server._on_bytes(len(pending_inbound_data), 0)
        await asyncio.gather(
            self._pipe(self.inbound_reader, self.outbound_writer, inbound=True),
            self._pipe(self.outbound_reader, self.inbound_writer, inbound=False),
            return_exceptions=True,
        )

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, inbound: bool) -> None:
        while True:
            data = await reader.read(64 * 1024)
            if not data:
                writer.close()
                return
            writer.write(data)
            await writer.drain()
            if inbound:
                self.server._on_bytes(len(data), 0)
            else:
                self.server._on_bytes(0, len(data))

    async def _send_http_error(self, status: str, message: str) -> None:
        body = f"{message}\n".encode()
        response = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        self.inbound_writer.write(response)
        await self.inbound_writer.drain()

    async def _send_socks5_reply(self, status: int) -> None:
        self.inbound_writer.write(bytes([0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await self.inbound_writer.drain()
