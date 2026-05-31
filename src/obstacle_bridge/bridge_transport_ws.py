from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ctypes
import hashlib
import importlib.util
import inspect
import json
import logging
import mimetypes
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from collections import deque
from contextlib import contextmanager
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from ctypes import wintypes

from . import bridge as _bridge
from .bridge_transport_common import (
    StreamRTT,
    StreamRTTRuntime,
    _listener_family_for_host,
    _resolve_cli_peer,
    _strip_brackets,
)

format_stream_endpoints = _bridge.format_stream_endpoints
ISession = _bridge.ISession
SessionMetrics = _bridge.SessionMetrics
_monotonic_age_seconds_from_ns = _bridge._monotonic_age_seconds_from_ns

class WebSocketPayloadCodec:
    mode = "binary"

    def encode(self, wire: bytes):
        raise NotImplementedError

    def decode(self, msg) -> Optional[bytes]:
        raise NotImplementedError

    def max_encoded_size(self, wire_size: int) -> int:
        return max(0, int(wire_size or 0))


class WebSocketBinaryPayloadCodec(WebSocketPayloadCodec):
    mode = "binary"

    def encode(self, wire: bytes):
        return wire

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        return None


class WebSocketBase64PayloadCodec(WebSocketPayloadCodec):
    mode = "base64"

    def encode(self, wire: bytes):
        return base64.b64encode(wire).decode("ascii")

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        if isinstance(msg, str):
            return base64.b64decode(msg.encode("ascii"), validate=True)
        return None

    def max_encoded_size(self, wire_size: int) -> int:
        size = max(0, int(wire_size or 0))
        if size <= 0:
            return 0
        return 4 * ((size + 2) // 3)


class WebSocketJsonBase64PayloadCodec(WebSocketPayloadCodec):
    mode = "json-base64"
    _JSON_WRAPPER_SIZE = len('{"data":""}')

    def encode(self, wire: bytes):
        return json.dumps({"data": base64.b64encode(wire).decode("ascii")}, separators=(",", ":"))

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        if not isinstance(msg, str):
            return None
        payload = json.loads(msg)
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        data = payload.get("data")
        if not isinstance(data, str):
            raise ValueError("JSON payload must contain string field 'data'")
        return base64.b64decode(data.encode("ascii"), validate=True)

    def max_encoded_size(self, wire_size: int) -> int:
        size = max(0, int(wire_size or 0))
        if size <= 0:
            return self._JSON_WRAPPER_SIZE
        return self._JSON_WRAPPER_SIZE + (4 * ((size + 2) // 3))


class WebSocketSemiTextShapePayloadCodec(WebSocketPayloadCodec):
    mode = "semi-text-shape"
    _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+"
    _DECODE_MAP = {ch: idx for idx, ch in enumerate(_ALPHABET)}
    _GROUP_SIZE = 8

    def encode(self, wire: bytes):
        bits = "".join(f"{byte:08b}" for byte in wire)
        if not bits:
            return ""
        symbols = []
        for start in range(0, len(bits), 6):
            chunk = bits[start:start + 6]
            if len(chunk) < 6:
                chunk = chunk.ljust(6, "0")
            symbols.append(self._ALPHABET[int(chunk, 2)])
        return " ".join(
            "".join(symbols[start:start + self._GROUP_SIZE])
            for start in range(0, len(symbols), self._GROUP_SIZE)
        )

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        if not isinstance(msg, str):
            return None
        normalized = "".join(str(msg).split())
        if not normalized:
            return b""
        bits = []
        for ch in normalized:
            value = self._DECODE_MAP.get(ch)
            if value is None:
                raise ValueError(f"invalid semi-text-shape symbol: {ch!r}")
            bits.append(f"{value:06b}")
        bit_stream = "".join(bits)
        full_bytes = (len(bit_stream) // 8) * 8
        trailing = bit_stream[full_bytes:]
        if trailing and any(bit != "0" for bit in trailing):
            raise ValueError("invalid semi-text-shape trailing padding")
        return bytes(int(bit_stream[start:start + 8], 2) for start in range(0, full_bytes, 8))

    def max_encoded_size(self, wire_size: int) -> int:
        size = max(0, int(wire_size or 0))
        if size <= 0:
            return 0
        symbols = (size * 8 + 5) // 6
        spaces = (symbols - 1) // self._GROUP_SIZE if symbols > 0 else 0
        return symbols + spaces


class _WsConnectionBootstrapError(RuntimeError):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = str(reason)
        self.detail = str(detail)


class WebSocketSession(ISession):
    """
    Overlay over one WebSocket (binary messages by default, optional base64, grouped semi-text, or JSON+base64 text frames):
      wire := KIND(1) + BYTES...
      KIND=0x00 -> APP (to upper layer)
      KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)
      KIND=0x02 -> PONG (payload: Q echo_tx_ns)

    Features:
      - Client mode (proactive connect) and Server mode (accept multiple overlay peers)
      - Auto-reconnect (client) with backoff
      - RTT estimation via StreamRTT/StreamRTTRuntime (drives overlay 'connected')
      - Per-connection counters + running CRC32 over wire bytes (KIND+payload)
      - Early-buffer for APP frames sent before WS is up
      - Loud/structured DEBUG logging mirroring TcpStreamSession style
    """
    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02
    _MUX_HDR = struct.Struct(">HBHBH")
    _PAYLOAD_CODECS = {
        WebSocketBinaryPayloadCodec.mode: WebSocketBinaryPayloadCodec,
        WebSocketBase64PayloadCodec.mode: WebSocketBase64PayloadCodec,
        WebSocketSemiTextShapePayloadCodec.mode: WebSocketSemiTextShapePayloadCodec,
        WebSocketJsonBase64PayloadCodec.mode: WebSocketJsonBase64PayloadCodec,
    }
    _WS_PAYLOAD_MODE_HEADER = "X-ObstacleBridge-WS-Payload-Mode"

    @staticmethod
    def _default_ws_proxy_mode() -> str:
        return "system" if sys.platform == "win32" else "env"

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        # WS-specific knobs:
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False

        if not _has('--ws-bind'):
            p.add_argument('--ws-bind', default='::', help='WebSocket overlay bind address')
        if not _has('--ws-own-port'):
            p.add_argument('--ws-own-port', dest='ws_own_port', type=int, default=8080, help='WebSocket overlay own port')
        if not _has('--ws-peer'):
            p.add_argument('--ws-peer', default=None, help='WebSocket peer IP/FQDN')
        if not _has('--ws-peer-port'):
            p.add_argument('--ws-peer-port', type=int, default=8080, help='WebSocket peer overlay port')
        if not _has('--ws-peer-resolve-family'):
            p.add_argument(
                '--ws-peer-resolve-family',
                dest='ws_peer_resolve_family',
                choices=['prefer-ipv6', 'ipv4', 'ipv6'],
                default='prefer-ipv6',
                help='WebSocket peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.'
            )

        if not _has('--ws-path'):
            p.add_argument('--ws-path', default='/', help='WebSocket HTTP path (default /)')
        if not _has('--ws-subprotocol'):
            p.add_argument('--ws-subprotocol', default=None,
                           help='Optional WebSocket subprotocol (e.g. mux2)')
        if not _has('--ws-tls'):
            p.add_argument('--ws-tls', action='store_true', default=False,
                           help='Use TLS (wss://). Provide cert/key via your deployment.')
        if not _has('--ws-max-size'):
            p.add_argument('--ws-max-size', type=int, default=65535,
                           help='Maximum binary message size to accept/send (default 65535).')
        if not _has('--ws-payload-mode'):
            p.add_argument(
                '--ws-payload-mode',
                choices=sorted(WebSocketSession._PAYLOAD_CODECS.keys()),
                default='binary',
                help='WebSocket payload transfer mode: raw binary frames (default), grouped semi-text frames, base64 text frames, or JSON text frames with the base64 payload in the data field.'
            )
        if not _has('--ws-static-dir'):
            p.add_argument(
                '--ws-static-dir',
                default='./web',
                help="Directory to serve as a static web root on the WS port (default ./web). "
                    "Set to '' to disable."
        )
        if not _has('--ws-send-timeout'):
            p.add_argument(
                '--ws-send-timeout',
                type=float,
                default=3.0,
                help='Seconds to wait for a WebSocket frame send before forcing reconnect (default 3.0).',
            )
        if not _has('--ws-tcp-user-timeout-ms'):
            p.add_argument(
                '--ws-tcp-user-timeout-ms',
                type=int,
                default=10000,
                help='TCP_USER_TIMEOUT in milliseconds for WebSocket sockets (default 10000, 0 disables).',
            )
        if not _has('--ws-reconnect-grace'):
            p.add_argument(
                '--ws-reconnect-grace',
                type=float,
                default=3.0,
                help='Seconds to wait before reporting DISCONNECTED after WS transport loss (default 3.0).',
            )
        if not _has('--ws-proxy-mode'):
            p.add_argument(
                '--ws-proxy-mode',
                choices=('off', 'env', 'manual', 'system'),
                default=WebSocketSession._default_ws_proxy_mode(),
                help='WebSocket client proxy mode: platform-default (`system` on Windows, `env` on Linux/POSIX), off, manual, or system (Windows only).',
            )
        if not _has('--ws-proxy-host'):
            p.add_argument('--ws-proxy-host', default='', help='Manual WebSocket proxy host.')
        if not _has('--ws-proxy-port'):
            p.add_argument('--ws-proxy-port', type=int, default=8080, help='Manual WebSocket proxy port (default 8080).')
        if not _has('--ws-proxy-auth'):
            p.add_argument(
                '--ws-proxy-auth',
                choices=('none', 'negotiate'),
                default='none',
                help='WebSocket proxy authentication mode: none or Negotiate (Negotiate is Windows-only).',
            )


    @staticmethod
    def from_args(args: argparse.Namespace) -> "WebSocketSession":
        return WebSocketSession(args)

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._log  = logging.getLogger("ws_session")

        # Callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # Mode / addressing (parity with TCP)
        self._listen_host, self._listen_port = _strip_brackets(self._args.ws_bind), int(self._args.ws_own_port)
        self._peer_name_host = _strip_brackets(getattr(self._args, "ws_peer", None) or "")
        self._peer_name_port = int(getattr(self._args, "ws_peer_port", 0) or 0)
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="ws_peer",
            peer_port_attr="ws_peer_port",
            resolve_attr="ws_peer_resolve_family",
            bind_host=self._listen_host,
            socktype=socket.SOCK_STREAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0
        self._ws_path: str = getattr(self._args, "ws_path", "/") or "/"
        self._ws_subprotocol: Optional[str] = getattr(self._args, "ws_subprotocol", None)
        self._use_tls: bool = bool(getattr(self._args, "ws_tls", False))
        self._ws_max_size: int = int(getattr(self._args, "ws_max_size", 65535))
        self._ws_payload_mode: str = str(getattr(self._args, "ws_payload_mode", "binary") or "binary").lower()
        self._ws_payload_codec: WebSocketPayloadCodec = self._build_ws_payload_codec(self._ws_payload_mode)
        self._ws_frame_max_size: int = max(0, self._ws_payload_codec.max_encoded_size(self._ws_max_size))
        self._ws_send_timeout_s: float = max(0.0, float(getattr(self._args, "ws_send_timeout", 3.0) or 0.0))
        self._ws_tcp_user_timeout_ms: int = max(0, int(getattr(self._args, "ws_tcp_user_timeout_ms", 10000) or 0))
        self._ws_reconnect_grace_s: float = max(0.0, float(getattr(self._args, "ws_reconnect_grace", 3.0) or 0.0))
        self._ws_proxy_mode: str = str(
            getattr(self._args, "ws_proxy_mode", self._default_ws_proxy_mode()) or self._default_ws_proxy_mode()
        ).lower()
        self._ws_proxy_host: str = _strip_brackets(str(getattr(self._args, "ws_proxy_host", "") or ""))
        self._ws_proxy_port: int = max(0, int(getattr(self._args, "ws_proxy_port", 8080) or 0))
        self._ws_proxy_auth: str = str(getattr(self._args, "ws_proxy_auth", "none") or "none").lower()
        # Reverse proxies can negotiate permessage-deflate but then stall or drop
        # tiny control messages. Keep overlay framing simple and deterministic.
        self._ws_compression = None

        # Runtime
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._run_flag: bool = False

        # WS connection & tasks
        self._ws = None                           # type: ignore
        self._server = None                       # websockets.server.Serve or similar
        self._rx_task: Optional[asyncio.Task] = None
        self._tx_task: Optional[asyncio.Task] = None
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_retry_delay_s: float = max(
            0.0,
            float(int(getattr(self._args, "overlay_reconnect_retry_delay_ms", 30000) or 0)) / 1000.0,
        )
        self._disconnect_task: Optional[asyncio.Task] = None
        self._tx_queue: "asyncio.Queue[tuple[bytes, Optional[Callable[[], None]]]]" = asyncio.Queue()
        self._server_connected_evt = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_peer_by_ws_id: Dict[int, int] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1

        # Early buffer (APP/CTRL frames preserved as individual WS messages)
        self._early_buf: Deque[tuple[bytes, Optional[Callable[[], None]]]] = deque()
        self._early_buf_bytes = 0
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0

        # Counters
        import zlib as _z
        self._z = _z
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG
        self._probe_id = f"{id(self)&0xFFFF:04x}"

        # RTT
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)
        self._overlay_connected = False
        self.connection_epoch: int = 0
        self._app_payload_passthrough: bool = False
        self._ws_connect_timeout_s: float = 5.0
        self._connection_failure_reason: Optional[str] = None
        self._connection_failure_detail: Optional[str] = None
        self._connection_failure_unix_ts: Optional[float] = None
        self._connection_last_event: str = ""
        self._connection_last_event_unix_ts: Optional[float] = None

        # Static HTTP root
        self._ws_static_dir: Optional[str] = getattr(self._args, "ws_static_dir", "./web") or None
        self._static_http_probe_delays_s: tuple[float, ...] = (0.0, 0.05, 0.25, 1.0)

    # ---- ISession wiring ------------------------------------------------------
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb
    def set_app_payload_passthrough(self, enabled: bool) -> None: self._app_payload_passthrough = bool(enabled)

    @classmethod
    def _build_ws_payload_codec(cls, payload_mode: str) -> WebSocketPayloadCodec:
        codec_cls = cls._PAYLOAD_CODECS.get(str(payload_mode or "").strip().lower())
        if codec_cls is None:
            raise ValueError(f"Unsupported --ws-payload-mode: {payload_mode}")
        return codec_cls()

    def _resolve_inbound_ws_payload_mode(self, requested_mode: Optional[str]) -> str:
        payload_mode = str(requested_mode or "").strip().lower()
        if not payload_mode:
            return self._ws_payload_mode
        if payload_mode in self._PAYLOAD_CODECS:
            return payload_mode
        self._log.warning(
            "[WS-SESSION] (%s) unsupported advertised payload mode %r; falling back to %s",
            self._probe_id,
            requested_mode,
            self._ws_payload_mode,
        )
        return self._ws_payload_mode

    @staticmethod
    def _websockets_header_kwarg(connect_callable: Any) -> Optional[str]:
        with contextlib.suppress(Exception):
            params = inspect.signature(connect_callable).parameters
            if "additional_headers" in params:
                return "additional_headers"
            if "extra_headers" in params:
                return "extra_headers"
        return None

    def _build_ws_upgrade_headers(self, connect_callable: Any) -> dict:
        header_key = self._websockets_header_kwarg(connect_callable)
        if not header_key:
            return {}
        return {
            header_key: {
                self._WS_PAYLOAD_MODE_HEADER: self._ws_payload_mode,
            }
        }

    def _resolve_ws_codec_context(self, ctx: Optional[dict] = None) -> Tuple[str, WebSocketPayloadCodec]:
        if isinstance(ctx, dict):
            payload_mode = str(ctx.get("payload_mode") or "").strip().lower()
            payload_codec = ctx.get("payload_codec")
            if payload_mode and isinstance(payload_codec, WebSocketPayloadCodec):
                return payload_mode, payload_codec
        return self._ws_payload_mode, self._ws_payload_codec

    def get_connection_failure_snapshot(self) -> dict:
        failed = bool(self._peer_tuple and self._connection_failure_reason and not self.is_connected())
        return {
            "failed": failed,
            "reason": self._connection_failure_reason,
            "detail": self._connection_failure_detail,
            "unix_ts": self._connection_failure_unix_ts,
            "last_event": self._connection_last_event,
            "last_event_unix_ts": self._connection_last_event_unix_ts,
            "transport": "ws",
        }

    def _format_connection_failure_detail(self, exc: BaseException) -> str:
        detail = str(exc).strip()
        return detail or repr(exc)

    def _record_connection_failure(self, reason: str, detail: str, *, event: str = "connect_failed") -> None:
        now = time.time()
        self._connection_failure_reason = str(reason)
        self._connection_failure_detail = str(detail or "")
        self._connection_failure_unix_ts = now
        self._connection_last_event = str(event or "connect_failed")
        self._connection_last_event_unix_ts = now

    def _clear_connection_failure(self) -> None:
        self._connection_failure_reason = None
        self._connection_failure_detail = None
        self._connection_failure_unix_ts = None
        self._connection_last_event = ""
        self._connection_last_event_unix_ts = None

    def _classify_connect_failure(self, exc: BaseException, *, proxy_active: bool) -> tuple[str, str]:
        if isinstance(exc, _WsConnectionBootstrapError):
            return exc.reason, exc.detail
        if isinstance(exc, socket.gaierror):
            return "dns_resolution_failed", self._format_connection_failure_detail(exc)
        if proxy_active:
            return "proxy_negotiation_failed", self._format_connection_failure_detail(exc)
        return "websocket_open_failed", self._format_connection_failure_detail(exc)

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True

        # Attach RTT driver (send function gets attached when WS is up)
        if self._peer_tuple:
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)

        if self._peer_tuple:
            # CLIENT
            self._peer_host = self._peer_name_host or self._peer_tuple[0]
            self._peer_port = self._peer_name_port or self._peer_tuple[1]
            self._log.info(
                f"[WS-SESSION] ({self._probe_id}) start; CLIENT -> "
                f"{self._peer_host}:{self._peer_port}{self._ws_path} "
                f"resolved={self._peer_tuple} tls={self._use_tls}"
            )
            self._ensure_connect_once()
        else:
            # SERVER
            self._log.info(f"[WS-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port}{self._ws_path} tls={self._use_tls}")
            await self._start_server()

    async def stop(self) -> None:
        self._log.info(f"[WS-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False

        if self._peer_tuple:
            self._rtt_rt.detach()

        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None
        if self._disconnect_task:
            self._disconnect_task.cancel()
            self._disconnect_task = None

        for attr in ("_rx_task", "_tx_task"):
            try:
                task = getattr(self, attr)
                if task:
                    task.cancel()
            except Exception:
                pass
            setattr(self, attr, None)

        try:
            if self._ws:
                await self._ws.close()           # type: ignore
        except Exception:
            pass
        self._ws = None

        for peer_id in list(self._server_peers.keys()):
            await self._close_server_peer(peer_id)
        self._server_connected_evt.clear()

        try:
            if self._server:
                self._server.close()             # type: ignore
                await self._server.wait_closed() # type: ignore
        except Exception:
            pass
        self._server = None

        self._set_overlay_connected(False)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if not self._peer_tuple:
            if self._server_peers:
                return True
            try:
                await asyncio.wait_for(self._server_connected_evt.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        return await self._rtt_rt.wait_connected(timeout)

    def is_connected(self) -> bool:
        if not self._peer_tuple:
            return bool(self._server_peers)
        return self._rtt.is_connected()

    def get_metrics(self) -> SessionMetrics:
        try:
            r = self._rtt
            rtt_est_ms = getattr(r, "rtt_est_ms", None)
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=rtt_est_ms,
                transmit_delay_est_ms=(0.5 * float(rtt_est_ms)) if rtt_est_ms is not None else None,
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
            )
        except Exception:
            return SessionMetrics()

    def get_max_app_payload_size(self) -> int:
        # send_app() prepends the 1-byte WS kind marker before payload encoding.
        return max(0, int(self._ws_max_size or 0) - 1)

    # ---- Data path (APP) ------------------------------------------------------
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        wire = bytes([self._K_APP]) + payload

        if not self._peer_tuple:
            if self._app_payload_passthrough and peer_id is not None:
                ctx = self._server_peers.get(int(peer_id))
                if not ctx:
                    self._log.debug(f"[WS/TX] ({self._probe_id}) drop APP for missing peer_id={peer_id}")
                    return 0
                self._schedule_server_send(ctx, wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
                return len(payload)
            if not self._server_peers and self._ws is not None:
                self._schedule_send(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
                return len(payload)
            routed = self._server_rewrite_outbound_app(payload)
            if routed is None:
                self._log.debug(f"[WS/TX] ({self._probe_id}) drop unroutable server APP len={len(payload)}")
                return 0
            peer_id, payload = routed
            ctx = self._server_peers.get(peer_id)
            if not ctx:
                self._log.debug(f"[WS/TX] ({self._probe_id}) drop APP for missing peer_id={peer_id}")
                return 0
            self._schedule_server_send(ctx, bytes([self._K_APP]) + payload, on_sent=lambda: self._notify_peer_tx(len(payload) + 1))
            return len(payload)

        if self._ws is None:
            self._buffer_early(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
            self._log.debug(f"[WS/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        self._schedule_send(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
        return len(payload)

    def _alloc_server_peer_id(self) -> int:
        peer_id = self._server_next_peer_id
        while peer_id in self._server_peers:
            peer_id += 1
            if peer_id > 0xFFFF:
                peer_id = 1
        self._server_next_peer_id = 1 if peer_id >= 0xFFFF else (peer_id + 1)
        return peer_id

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    def _rewrite_mux_chan_id(self, payload: bytes, new_chan: int) -> bytes:
        if len(payload) < self._MUX_HDR.size:
            return payload
        _, proto, counter, mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        if len(payload) < self._MUX_HDR.size + dlen:
            return payload
        return self._MUX_HDR.pack(new_chan, proto, counter, mtype, dlen) + payload[self._MUX_HDR.size:self._MUX_HDR.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        if len(payload) < self._MUX_HDR.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except Exception:
            return payload
        if len(payload) < self._MUX_HDR.size + dlen:
            return payload
        key = (peer_id, peer_chan)
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_rewrite_outbound_app(self, payload: bytes) -> Optional[Tuple[int, bytes]]:
        if len(payload) < self._MUX_HDR.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except Exception:
            return None
        if len(payload) < self._MUX_HDR.size + dlen:
            return None
        mapped = self._server_chan_to_peer.get(mux_chan)
        if mapped is None:
            # Server-initiated channels (for peer-installed services) may not have an
            # inbound mapping yet. If exactly one peer is connected, route directly.
            if len(self._server_peers) == 1:
                only_peer_id = next(iter(self._server_peers.keys()))
                mapped = (int(only_peer_id), int(mux_chan))
                self._server_peer_chan_to_mux[mapped] = int(mux_chan)
                self._server_chan_to_peer[int(mux_chan)] = mapped
            else:
                return None
        peer_id, peer_chan = mapped
        return peer_id, self._rewrite_mux_chan_id(payload, peer_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if key[0] != peer_id:
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    @staticmethod
    def _format_peer_label(host: Optional[object], port: Optional[object]) -> Optional[str]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return f"[{host_s}]:{port_i}" if ":" in host_s and not host_s.startswith("[") else f"{host_s}:{port_i}"
        except Exception:
            return None

    @staticmethod
    def _format_peer_endpoint(host: Optional[object], port: Optional[object]) -> Optional[dict]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return {"host": host_s, "port": port_i}
        except Exception:
            return None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        """
        Return per-overlay-peer rows for admin diagnostics.

        For WS server mode this returns one row per connected websocket peer and
        includes the mux channels owned by that peer, allowing higher layers to
        split UDP/TCP counters by peer.
        """
        rows: list[dict] = []
        if self._peer_tuple:
            peer_endpoint = self._format_peer_endpoint(self._peer_host, self._peer_port)
            rows.append(
                {
                    "peer_id": 0,
                    "connected": bool(self.is_connected()),
                    "state": "connected" if self.is_connected() else "connecting",
                    "peer": peer_endpoint,
                    "mux_chans": [],
                    "rtt_est_ms": getattr(self._rtt, "rtt_est_ms", None),
                    "last_incoming_age_seconds": _monotonic_age_seconds_from_ns(
                        int(getattr(self._rtt, "_last_rx_wall_ns", 0) or 0)
                    ),
                }
            )
            return rows

        rows.append(
            {
                "peer_id": -1,
                "connected": False,
                "state": "listening",
                "peer": None,
                "mux_chans": [],
                "rtt_est_ms": None,
                "last_incoming_age_seconds": None,
                "listening": True,
            }
        )

        mux_by_peer: Dict[int, list[int]] = {}
        for mux_chan, mapped in self._server_chan_to_peer.items():
            try:
                peer_id, _peer_chan = mapped
                mux_by_peer.setdefault(int(peer_id), []).append(int(mux_chan))
            except Exception:
                continue

        peer_ids: set[int] = set(int(p) for p in self._server_peers.keys())
        peer_ids.update(int(p) for p in mux_by_peer.keys())

        for peer_id in sorted(peer_ids):
            ctx = self._server_peers.get(peer_id, {})
            ws = ctx.get("ws") if isinstance(ctx, dict) else None
            remote = getattr(ws, "remote_address", None) if ws is not None else None
            host = remote[0] if isinstance(remote, tuple) and len(remote) >= 2 else None
            port = remote[1] if isinstance(remote, tuple) and len(remote) >= 2 else None
            peer_endpoint = self._format_peer_endpoint(host, port)
            rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
            last_incoming_age_seconds = None
            if isinstance(ctx, dict):
                last_incoming_age_seconds = _monotonic_age_seconds_from_ns(
                    int(ctx.get("last_incoming_wall_ns") or 0)
                )
            if last_incoming_age_seconds is None:
                last_incoming_age_seconds = _monotonic_age_seconds_from_ns(
                    int(getattr(rtt, "_last_rx_wall_ns", 0) or 0)
                )
            rows.append(
                {
                    "peer_id": peer_id,
                    "connected": bool(peer_id in self._server_peers),
                    "state": "connected" if peer_id in self._server_peers else "connecting",
                    "peer": peer_endpoint,
                    "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                    "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
                    "last_incoming_age_seconds": last_incoming_age_seconds,
                }
            )

        return rows

    # ---- Internals ------------------------------------------------------------

    @staticmethod
    def _format_connect_authority(host: str, port: int) -> str:
        host_s = _strip_brackets(str(host or ""))
        if ":" in host_s and not host_s.startswith("["):
            host_s = f"[{host_s}]"
        return f"{host_s}:{int(port)}"

    @staticmethod
    def _parse_proxy_authority(value: str, default_port: int = 8080) -> Optional[Tuple[str, int]]:
        text = str(value or "").strip()
        if not text:
            return None
        if "://" in text:
            text = text.split("://", 1)[1]
        text = text.split("/", 1)[0].strip()
        if not text:
            return None
        host = text
        port = int(default_port)
        if text.startswith("["):
            end = text.find("]")
            if end == -1:
                return None
            host = text[1:end]
            rest = text[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
        elif text.count(":") == 1:
            base, maybe_port = text.rsplit(":", 1)
            if maybe_port.isdigit():
                host = base
                port = int(maybe_port)
        return (_strip_brackets(host), int(port)) if host else None

    @classmethod
    def _parse_proxy_spec(cls, spec: str, secure: bool = False) -> Optional[Tuple[str, int]]:
        preferred = ("https", "wss") if secure else ("http", "ws")
        fallback = None
        for raw_item in str(spec or "").split(";"):
            item = raw_item.strip()
            if not item:
                continue
            if "=" not in item:
                parsed = cls._parse_proxy_authority(item)
                if parsed:
                    fallback = parsed
                continue
            scheme, value = item.split("=", 1)
            scheme = scheme.strip().lower()
            parsed = cls._parse_proxy_authority(value)
            if not parsed:
                continue
            if scheme in preferred:
                return parsed
            if fallback is None:
                fallback = parsed
        return fallback

    def _build_windows_negotiate_spn(self, host: str) -> str:
        host_s = _strip_brackets(str(host or "")).strip()
        if not host_s:
            raise RuntimeError("empty proxy host for Negotiate target name")
        upper = host_s.upper()
        if "." in upper:
            parts = upper.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else upper
            return f"HTTP/{host_s}@{domain}"
        return f"HTTP/{host_s}"

    def _build_proxy_connect_request(self, target_host: str, target_port: int, auth_header: Optional[str] = None) -> bytes:
        authority = self._format_connect_authority(target_host, target_port)
        lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "User-Agent: ObstacleBridge-ws-proxy/1.0",
        ]
        if auth_header:
            lines.append(f"Proxy-Authorization: {auth_header}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    def _proxy_feature_enabled(self) -> bool:
        return bool(self._peer_tuple) and self._ws_proxy_mode != "off"

    @contextmanager
    def _suspend_library_proxy_env(self):
        keys = (
            "HTTP_PROXY", "http_proxy",
            "HTTPS_PROXY", "https_proxy",
            "ALL_PROXY", "all_proxy",
            "NO_PROXY", "no_proxy",
        )
        saved = {key: os.environ.get(key) for key in keys}
        try:
            for key in keys:
                os.environ.pop(key, None)
            yield
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def _env_get_proxy_for_target(self, target_host: str, secure: bool = False) -> Optional[Tuple[str, int]]:
        host = _strip_brackets(str(target_host or "")).strip()
        if not host:
            return None
        if urllib.request.proxy_bypass(host):
            self._log.debug("[WS-PROXY] (%s) env bypass matched host=%s", self._probe_id, host)
            return None
        proxies = urllib.request.getproxies()
        proxy_url = proxies.get("https" if secure else "http")
        if not proxy_url:
            self._log.debug("[WS-PROXY] (%s) env mode found no %s proxy", self._probe_id, "HTTPS_PROXY" if secure else "HTTP_PROXY")
            return None
        parsed = urllib.parse.urlsplit(proxy_url)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https", "ws", "wss"):
            raise RuntimeError(f"unsupported websocket proxy scheme in environment: {parsed.scheme}")
        if parsed.hostname:
            return _strip_brackets(parsed.hostname), int(parsed.port or 8080)
        return self._parse_proxy_authority(proxy_url)

    def _test_system_proxy_override(self, secure: bool = False) -> Optional[Tuple[str, int]]:
        spec = str(os.environ.get("OBSTACLEBRIDGE_TEST_SYSTEM_PROXY", "") or "").strip()
        if not spec:
            return None
        parsed = self._parse_proxy_spec(spec, secure=secure)
        if parsed is None:
            raise RuntimeError("invalid OBSTACLEBRIDGE_TEST_SYSTEM_PROXY value")
        self._log.debug(
            "[WS-PROXY] (%s) using test system proxy override endpoint=%s:%d",
            self._probe_id,
            parsed[0],
            int(parsed[1]),
        )
        return parsed

    def _get_ws_proxy_endpoint(self, target_host: str, target_port: int) -> Optional[Tuple[str, int]]:
        self._log.debug(
            "[WS-PROXY] (%s) endpoint lookup target=%s mode=%s peer_configured=%s platform=%s tls=%s",
            self._probe_id,
            self._format_connect_authority(target_host, target_port),
            self._ws_proxy_mode,
            bool(self._peer_tuple),
            sys.platform,
            self._use_tls,
        )
        if not self._proxy_feature_enabled():
            self._log.debug("[WS-PROXY] (%s) proxy feature disabled", self._probe_id)
            return None
        if self._ws_proxy_mode == "env":
            endpoint = self._env_get_proxy_for_target(target_host, secure=self._use_tls)
            if endpoint is None:
                self._log.debug("[WS-PROXY] (%s) env proxy lookup returned no endpoint", self._probe_id)
                return None
            self._log.debug("[WS-PROXY] (%s) env proxy selected endpoint=%s:%d", self._probe_id, endpoint[0], int(endpoint[1]))
            return endpoint
        if self._ws_proxy_mode == "manual":
            if not self._ws_proxy_host or self._ws_proxy_port <= 0:
                self._log.debug(
                    "[WS-PROXY] (%s) manual mode missing host/port host=%r port=%s",
                    self._probe_id,
                    self._ws_proxy_host,
                    self._ws_proxy_port,
                )
                raise RuntimeError("manual WebSocket proxy mode requires --ws-proxy-host and --ws-proxy-port")
            self._log.debug(
                "[WS-PROXY] (%s) manual proxy selected endpoint=%s:%d",
                self._probe_id,
                self._ws_proxy_host,
                int(self._ws_proxy_port),
            )
            return self._ws_proxy_host, int(self._ws_proxy_port)
        if self._ws_proxy_mode == "system":
            test_override = self._test_system_proxy_override(secure=self._use_tls)
            if test_override is not None:
                return test_override
        if sys.platform != "win32":
            self._log.debug("[WS-PROXY] (%s) rejecting proxy lookup on unsupported platform=%s", self._probe_id, sys.platform)
            raise RuntimeError("WebSocket proxy support is currently available on Windows only")
        if self._ws_proxy_mode == "system":
            lookup_url = f"http://{self._format_connect_authority(target_host, target_port)}"
            self._log.debug("[WS-PROXY] (%s) system proxy lookup url=%s secure=%s", self._probe_id, lookup_url, self._use_tls)
            endpoint = self._win_get_proxy_for_url(
                lookup_url,
                secure=self._use_tls,
            )
            if endpoint is None:
                self._log.debug("[WS-PROXY] (%s) system proxy lookup returned no endpoint", self._probe_id)
                return None
            self._log.debug("[WS-PROXY] (%s) system proxy selected endpoint=%s:%d", self._probe_id, endpoint[0], int(endpoint[1]))
            return endpoint
        self._log.debug("[WS-PROXY] (%s) unsupported mode=%s", self._probe_id, self._ws_proxy_mode)
        raise RuntimeError(f"unsupported --ws-proxy-mode: {self._ws_proxy_mode}")

    def _win_get_proxy_for_url(self, url: str, secure: bool = False) -> Optional[Tuple[str, int]]:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        HINTERNET = ctypes.c_void_p

        winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = wintypes.BOOL
        winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [ctypes.c_void_p]
        winhttp.WinHttpOpen.restype = HINTERNET
        winhttp.WinHttpOpen.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        winhttp.WinHttpGetProxyForUrl.restype = wintypes.BOOL
        winhttp.WinHttpGetProxyForUrl.argtypes = [
            HINTERNET,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
        winhttp.WinHttpCloseHandle.argtypes = [HINTERNET]

        class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
            _fields_ = [
                ("fAutoDetect", wintypes.BOOL),
                ("lpszAutoConfigUrl", ctypes.c_void_p),
                ("lpszProxy", ctypes.c_void_p),
                ("lpszProxyBypass", ctypes.c_void_p),
            ]

        class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
            _fields_ = [
                ("dwFlags", wintypes.DWORD),
                ("dwAutoDetectFlags", wintypes.DWORD),
                ("lpszAutoConfigUrl", wintypes.LPCWSTR),
                ("lpvReserved", wintypes.LPVOID),
                ("dwReserved", wintypes.DWORD),
                ("fAutoLogonIfChallenged", wintypes.BOOL),
            ]

        class WINHTTP_PROXY_INFO(ctypes.Structure):
            _fields_ = [
                ("dwAccessType", wintypes.DWORD),
                ("lpszProxy", ctypes.c_void_p),
                ("lpszProxyBypass", ctypes.c_void_p),
            ]

        WINHTTP_ACCESS_TYPE_NO_PROXY = 1
        WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
        WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
        WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002
        WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
        WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

        def _wide(ptr: int) -> str:
            return ctypes.wstring_at(ptr) if ptr else ""

        def _free(ptr: int) -> None:
            if ptr:
                kernel32.GlobalFree(ctypes.c_void_p(ptr))

        manual_proxy = ""
        auto_url = ""
        auto_detect = True
        ie_cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
        try:
            if bool(winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ie_cfg))):
                auto_detect = bool(ie_cfg.fAutoDetect)
                manual_proxy = _wide(ie_cfg.lpszProxy)
                auto_url = _wide(ie_cfg.lpszAutoConfigUrl)
                self._log.debug(
                    "[WS-PROXY] (%s) IE proxy config auto_detect=%s auto_config_url=%r manual_proxy=%r",
                    self._probe_id,
                    auto_detect,
                    auto_url,
                    manual_proxy,
                )
            else:
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetIEProxyConfigForCurrentUser failed last_error=%s",
                    self._probe_id,
                    ctypes.get_last_error(),
                )
            parsed = self._parse_proxy_spec(manual_proxy, secure=secure)
            if parsed:
                self._log.debug(
                    "[WS-PROXY] (%s) using manual IE proxy endpoint=%s:%d",
                    self._probe_id,
                    parsed[0],
                    int(parsed[1]),
                )
                return parsed
        finally:
            _free(getattr(ie_cfg, "lpszAutoConfigUrl", 0))
            _free(getattr(ie_cfg, "lpszProxy", 0))
            _free(getattr(ie_cfg, "lpszProxyBypass", 0))

        session = winhttp.WinHttpOpen(
            "ObstacleBridge/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            None,
            None,
            0,
        )
        if not session:
            raise RuntimeError(f"WinHttpOpen failed: {ctypes.get_last_error()}")
        try:
            opts = WINHTTP_AUTOPROXY_OPTIONS()
            if auto_url:
                opts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
                opts.lpszAutoConfigUrl = auto_url
                self._log.debug("[WS-PROXY] (%s) WinHTTP auto-proxy using PAC url=%r for %s", self._probe_id, auto_url, url)
            else:
                opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
                opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
                self._log.debug(
                    "[WS-PROXY] (%s) WinHTTP auto-proxy using auto_detect=%s flags=DHCP|DNS_A for %s",
                    self._probe_id,
                    auto_detect,
                    url,
                )
            opts.fAutoLogonIfChallenged = True
            info = WINHTTP_PROXY_INFO()
            if not bool(winhttp.WinHttpGetProxyForUrl(session, str(url), ctypes.byref(opts), ctypes.byref(info))):
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetProxyForUrl returned no proxy last_error=%s url=%s",
                    self._probe_id,
                    ctypes.get_last_error(),
                    url,
                )
                return None
            try:
                raw_proxy = _wide(info.lpszProxy)
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetProxyForUrl access_type=%s raw_proxy=%r",
                    self._probe_id,
                    int(info.dwAccessType),
                    raw_proxy,
                )
                if int(info.dwAccessType) != WINHTTP_ACCESS_TYPE_NAMED_PROXY:
                    self._log.debug("[WS-PROXY] (%s) WinHTTP access type is not named proxy", self._probe_id)
                    return None
                parsed = self._parse_proxy_spec(raw_proxy, secure=secure)
                self._log.debug("[WS-PROXY] (%s) parsed WinHTTP proxy endpoint=%r", self._probe_id, parsed)
                return parsed
            finally:
                _free(getattr(info, "lpszProxy", 0))
                _free(getattr(info, "lpszProxyBypass", 0))
        finally:
            winhttp.WinHttpCloseHandle(session)

    def _win_build_negotiate_token(self, target_name: str, challenge: Optional[bytes] = None) -> str:
        secur32 = ctypes.WinDLL("secur32", use_last_error=True)

        class CredHandle(ctypes.Structure):
            _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

        class CtxtHandle(ctypes.Structure):
            _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

        class TimeStamp(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.DWORD)]

        class SecBuffer(ctypes.Structure):
            _fields_ = [
                ("cbBuffer", wintypes.ULONG),
                ("BufferType", wintypes.ULONG),
                ("pvBuffer", ctypes.c_void_p),
            ]

        class SecBufferDesc(ctypes.Structure):
            _fields_ = [
                ("ulVersion", wintypes.ULONG),
                ("cBuffers", wintypes.ULONG),
                ("pBuffers", ctypes.POINTER(SecBuffer)),
            ]

        SECPKG_CRED_OUTBOUND = 2
        SECURITY_NATIVE_DREP = 0x00000010
        ISC_REQ_CONFIDENTIALITY = 0x00000010
        SECBUFFER_VERSION = 0
        SECBUFFER_TOKEN = 2
        SEC_E_OK = 0x00000000
        SEC_I_CONTINUE_NEEDED = 0x00090312

        expiry = TimeStamp()
        cred = CredHandle()
        status = secur32.AcquireCredentialsHandleW(
            None,
            "Negotiate",
            SECPKG_CRED_OUTBOUND,
            None,
            None,
            None,
            None,
            ctypes.byref(cred),
            ctypes.byref(expiry),
        )
        if int(status) != SEC_E_OK:
            raise RuntimeError(f"AcquireCredentialsHandleW failed: 0x{int(status) & 0xFFFFFFFF:08x}")

        ctx = CtxtHandle()
        attrs = wintypes.ULONG()
        out_buf_raw = ctypes.create_string_buffer(65536)
        out_buf = SecBuffer(len(out_buf_raw), SECBUFFER_TOKEN, ctypes.cast(out_buf_raw, ctypes.c_void_p))
        out_desc = SecBufferDesc(SECBUFFER_VERSION, 1, ctypes.pointer(out_buf))

        # Keep this aligned with the existing Windows sample's narrow behavior:
        # generate an outbound Negotiate token from the current logon context.
        # A full multi-round SSPI challenge exchange can be added later if needed.
        _ignored_challenge = challenge
        in_desc_ptr = None

        try:
            status = secur32.InitializeSecurityContextW(
                ctypes.byref(cred),
                None,
                ctypes.c_wchar_p(target_name),
                ISC_REQ_CONFIDENTIALITY,
                0,
                SECURITY_NATIVE_DREP,
                in_desc_ptr,
                0,
                ctypes.byref(ctx),
                ctypes.byref(out_desc),
                ctypes.byref(attrs),
                ctypes.byref(expiry),
            )
            if int(status) not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED):
                raise RuntimeError(f"InitializeSecurityContextW failed: 0x{int(status) & 0xFFFFFFFF:08x}")
            if int(out_buf.cbBuffer) <= 0:
                raise RuntimeError("InitializeSecurityContextW returned no token")
            return base64.b64encode(out_buf_raw.raw[: int(out_buf.cbBuffer)]).decode("ascii")
        finally:
            with contextlib.suppress(Exception):
                if ctx.dwLower or ctx.dwUpper:
                    secur32.DeleteSecurityContext(ctypes.byref(ctx))
            with contextlib.suppress(Exception):
                secur32.FreeCredentialsHandle(ctypes.byref(cred))

    def _read_http_proxy_response(self, sock: socket.socket) -> Tuple[int, Dict[str, List[str]]]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                raise RuntimeError("proxy response headers too large")
        header_blob, _, _rest = data.partition(b"\r\n\r\n")
        lines = header_blob.decode("iso-8859-1", "replace").split("\r\n")
        if not lines or len(lines[0].split(" ")) < 2:
            raise RuntimeError("invalid proxy response")
        parts = lines[0].split(" ", 2)
        status_code = int(parts[1]) if parts[1].isdigit() else 0
        headers: Dict[str, List[str]] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())
        return status_code, headers

    def _open_ws_proxy_socket_blocking(self, target_host: str, target_port: int) -> socket.socket:
        proxy = self._get_ws_proxy_endpoint(target_host, target_port)
        if proxy is None:
            raise RuntimeError("no proxy endpoint available")
        proxy_host, proxy_port = proxy
        auth_mode = self._ws_proxy_auth
        challenge_blob = None
        attempts = 0
        self._log.debug(
            "[WS-PROXY] (%s) opening proxy tunnel target=%s via=%s:%d auth=%s",
            self._probe_id,
            self._format_connect_authority(target_host, target_port),
            proxy_host,
            int(proxy_port),
            auth_mode,
        )
        while attempts < 3:
            attempts += 1
            self._log.debug("[WS-PROXY] (%s) CONNECT attempt=%d proxy=%s:%d", self._probe_id, attempts, proxy_host, int(proxy_port))
            sock = socket.create_connection(
                (proxy_host, int(proxy_port)),
                timeout=self._ws_connect_timeout_s,
            )
            try:
                auth_header = None
                if auth_mode == "negotiate" and attempts > 1:
                    self._log.debug(
                        "[WS-PROXY] (%s) building Negotiate token challenge_present=%s",
                        self._probe_id,
                        challenge_blob is not None,
                    )
                    auth_header = "Negotiate " + self._win_build_negotiate_token(
                        self._build_windows_negotiate_spn(proxy_host),
                        challenge=challenge_blob,
                    )
                request = self._build_proxy_connect_request(target_host, target_port, auth_header=auth_header)
                sock.sendall(request)
                status_code, headers = self._read_http_proxy_response(sock)
                self._log.debug(
                    "[WS-PROXY] (%s) CONNECT response status=%s proxy_authenticate=%s",
                    self._probe_id,
                    status_code,
                    headers.get("proxy-authenticate", []),
                )
                if status_code == 200:
                    self._log.debug("[WS-PROXY] (%s) CONNECT tunnel established on attempt=%d", self._probe_id, attempts)
                    sock.setblocking(False)
                    return sock
                if status_code != 407:
                    raise RuntimeError(f"proxy CONNECT failed with HTTP {status_code}")
                if auth_mode != "negotiate":
                    raise RuntimeError("proxy requires authentication but --ws-proxy-auth is not negotiate")
                negotiate_headers = []
                for value in headers.get("proxy-authenticate", []):
                    if value.lower().startswith("negotiate"):
                        negotiate_headers.append(value)
                if not negotiate_headers:
                    raise RuntimeError("proxy does not offer Negotiate authentication")
                challenge_blob = None
                token = negotiate_headers[0][len("Negotiate"):].strip()
                if token:
                    self._log.debug("[WS-PROXY] (%s) proxy supplied Negotiate challenge token", self._probe_id)
                    challenge_blob = base64.b64decode(token)
                else:
                    self._log.debug("[WS-PROXY] (%s) proxy requested Negotiate without challenge token", self._probe_id)
            except Exception:
                sock.close()
                raise
            sock.close()
        raise RuntimeError("proxy authentication failed after multiple attempts")

    async def _open_ws_proxy_socket(self, target_host: str, target_port: int) -> socket.socket:
        return await asyncio.to_thread(self._open_ws_proxy_socket_blocking, target_host, int(target_port))

    def _describe_transport_state(self, connection) -> str:
        transport = getattr(connection, "transport", None)
        if transport is None:
            return "transport=missing"

        parts: list[str] = []
        try:
            parts.append(f"wbuf={transport.get_write_buffer_size()}")
        except Exception as e:
            parts.append(f"wbuf=?({e!r})")
        try:
            parts.append(f"closing={bool(transport.is_closing())}")
        except Exception as e:
            parts.append(f"closing=?({e!r})")

        try:
            sockname = transport.get_extra_info("sockname")
            if sockname is not None:
                parts.append(f"sockname={sockname}")
        except Exception:
            pass
        try:
            peername = transport.get_extra_info("peername")
            if peername is not None:
                parts.append(f"peer={peername}")
        except Exception:
            pass
        return " ".join(parts)

    def _log_static_http_decision(
        self,
        *,
        method: str,
        req_path: str,
        status: int,
        target,
        ctype: str,
        content_length: int,
        body_length: int,
        note: str = "",
    ) -> None:
        target_txt = "-" if target is None else str(target)
        suffix = f" note={note}" if note else ""
        self._log.debug(
            f"[WS/HTTP] ({self._probe_id}) method={method} path={req_path} status={status} "
            f"target={target_txt} ctype={ctype} content_length={content_length} body_length={body_length}{suffix}"
        )

    def _schedule_static_http_debug_probes(
        self,
        connection,
        *,
        method: str,
        req_path: str,
        status: int,
        target,
        body_length: int,
    ) -> None:
        loop = self._loop
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
        if loop is None:
            return

        target_txt = "-" if target is None else str(target)

        def _emit_probe(delay_s: float) -> None:
            self._log.debug(
                f"[WS/HTTP] ({self._probe_id}) probe dt={delay_s:.3f}s method={method} "
                f"path={req_path} status={status} body_length={body_length} target={target_txt} "
                f"{self._describe_transport_state(connection)}"
            )

        for delay_s in self._static_http_probe_delays_s:
            try:
                if delay_s <= 0:
                    loop.call_soon(_emit_probe, delay_s)
                else:
                    loop.call_later(delay_s, _emit_probe, delay_s)
            except Exception as e:
                self._log.debug(
                    f"[WS/HTTP] ({self._probe_id}) failed to schedule probe delay={delay_s:.3f}s "
                    f"path={req_path}: {e!r}"
                )

    async def _start_server(self) -> None:
        """
        Start a combined HTTP/WebSocket listener on the configured WS port.

        Plain HTTP requests are served directly from the front listener so the
        same TCP connection may remain open for additional requests. Upgrade
        requests on that same socket are then promoted into the overlay WS path.
        """
        # Optional TLS
        ssl_ctx = None
        if self._use_tls:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        from pathlib import Path
        from urllib.parse import unquote
        import mimetypes
        mimetypes.add_type("text/javascript", ".js")   # or "application/javascript"
        mimetypes.add_type("image/svg+xml", ".svg")
        import datetime

        ws_subprotocol = self._ws_subprotocol
        ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        # Resolve static root if present
        static_root = None
        if self._ws_static_dir:
            try:
                p = Path(self._ws_static_dir).resolve(strict=False)
                if p.exists() and p.is_dir():
                    static_root = p
                    self._log.info(f"[WS-SESSION] ({self._probe_id}) static HTTP root: {static_root}")
                else:
                    self._log.info(f"[WS-SESSION] ({self._probe_id}) --ws-static-dir set but not present; static HTTP disabled")
            except Exception as e:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) failed to resolve --ws-static-dir: {e!r}")

        def _http_headers(
            status: int,
            length: int,
            ctype: str = "application/octet-stream",
            *,
            connection: str = "keep-alive",
        ):
            now = datetime.datetime.now(datetime.timezone.utc)
            return [
                ("Date", now.strftime("%a, %d %b %Y %H:%M:%S GMT")),
                ("Server", "ws-mini/1.0"),
                ("Content-Type", ctype),
                ("Content-Length", str(max(0, length))),
                ("Connection", connection),
                ("Cache-Control", "public, max-age=60"),
            ]

        def _safe_join(root: Path, url_path: str):
            path = (url_path or "/").split("?", 1)[0].split("#", 1)[0]
            path = unquote(path)
            while path.startswith("/"):
                path = path[1:]
            try:
                candidate = (root / path).resolve(strict=False)
                if str(candidate).startswith(str(root)):
                    return candidate
            except Exception:
                pass
            return None

        def _static_http_response(method: str, req_path: str) -> tuple[int, list[tuple[str, str]], bytes, Optional[Path], int]:
            if method not in ("GET", "HEAD"):
                body = b"Method Not Allowed\n"
                return 405, [("Allow", "GET, HEAD")] + _http_headers(405, len(body), "text/plain"), body, None, len(body)

            target = _safe_join(static_root, req_path)
            if target is None:
                body = b"Forbidden\n"
                return 403, _http_headers(403, len(body), "text/plain"), body, None, len(body)

            if target.is_dir():
                index = target / "index.html"
                if not (index.exists() and index.is_file()):
                    body = b"Not Found\n"
                    return 404, _http_headers(404, len(body), "text/plain"), body, target, len(body)
                target = index

            if not target.exists() or not target.is_file():
                body = b"Not Found\n"
                return 404, _http_headers(404, len(body), "text/plain"), body, target, len(body)

            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            try:
                data = target.read_bytes()
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) static read error: {e!r}")
                body = b"Internal Server Error\n"
                return 500, _http_headers(500, len(body), "text/plain"), body, target, len(body)

            if method == "HEAD":
                return 200, _http_headers(200, len(data), ctype), b"", target, 0
            return 200, _http_headers(200, len(data), ctype), data, target, len(data)

        def _status_reason(status: int) -> str:
            return {
                200: "OK",
                400: "Bad Request",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                426: "Upgrade Required",
                500: "Internal Server Error",
            }.get(int(status), "OK")

        async def _send_http_response(
            writer: asyncio.StreamWriter,
            *,
            status: int,
            headers: list[tuple[str, str]],
            body: bytes,
        ) -> None:
            head = [f"HTTP/1.1 {int(status)} {_status_reason(status)}"]
            head.extend(f"{key}: {value}" for key, value in headers)
            writer.write(("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1") + body)
            await writer.drain()

        def _headers_get(headers: Dict[str, str], name: str) -> str:
            return str(headers.get(str(name).lower(), "") or "")

        def _should_keep_alive(http_version: str, headers: Dict[str, str]) -> bool:
            conn = _headers_get(headers, "connection").lower()
            if http_version.upper() == "HTTP/1.0":
                return "keep-alive" in conn
            return "close" not in conn

        def _is_ws_upgrade_request(method: str, headers: Dict[str, str]) -> bool:
            if str(method or "").upper() != "GET":
                return False
            conn = _headers_get(headers, "connection").lower()
            upgrade = _headers_get(headers, "upgrade").lower()
            return "upgrade" in conn and upgrade == "websocket"

        async def _read_http_request(reader: asyncio.StreamReader) -> Optional[tuple[str, str, str, Dict[str, str]]]:
            try:
                reqline = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                return None
            if not reqline:
                return None
            parts = reqline.decode("iso-8859-1", "replace").strip().split()
            if len(parts) != 3:
                raise RuntimeError(f"invalid HTTP request line: {reqline!r}")
            method, req_path, http_version = parts
            headers: Dict[str, str] = {}
            content_length = 0
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                text = line.decode("iso-8859-1", "replace")
                if ":" not in text:
                    continue
                key, value = text.split(":", 1)
                hk = key.strip().lower()
                hv = value.strip()
                headers[hk] = hv
                if hk == "content-length":
                    with contextlib.suppress(Exception):
                        content_length = max(0, int(hv))
            if content_length > 0:
                await reader.readexactly(content_length)
            return method, req_path, http_version, headers

        class _ServerSideWsConnection:
            def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, req_path: str, subprotocol: Optional[str], payload_mode: str) -> None:
                self._reader = reader
                self._writer = writer
                self.path = req_path
                self.subprotocol = subprotocol
                self.payload_mode = payload_mode
                self.transport = writer.transport
                self.remote_address = writer.get_extra_info("peername")
                self.local_address = writer.get_extra_info("sockname")
                self._closed_evt = asyncio.Event()
                self._close_sent = False

            async def recv(self):
                while True:
                    opcode, payload = await self._read_frame()
                    if opcode == 0x8:
                        if not self._close_sent:
                            with contextlib.suppress(Exception):
                                await self._send_frame(0x8, payload[:125])
                        await self._shutdown()
                        raise EOFError("websocket close frame received")
                    if opcode == 0x9:
                        await self._send_frame(0xA, payload)
                        continue
                    if opcode == 0xA:
                        continue
                    if opcode == 0x1:
                        return payload.decode("utf-8", "replace")
                    if opcode == 0x2:
                        return payload
                    raise RuntimeError(f"unsupported websocket opcode: {opcode}")

            async def send(self, message) -> None:
                if isinstance(message, str):
                    await self._send_frame(0x1, message.encode("utf-8"))
                else:
                    await self._send_frame(0x2, bytes(message))

            async def close(self) -> None:
                if self._closed_evt.is_set():
                    return
                if not self._close_sent:
                    with contextlib.suppress(Exception):
                        await self._send_frame(0x8, b"")
                await self._shutdown()

            async def wait_closed(self) -> None:
                await self._closed_evt.wait()

            async def _read_frame(self) -> tuple[int, bytes]:
                hdr = await self._reader.readexactly(2)
                b1, b2 = hdr[0], hdr[1]
                fin = bool(b1 & 0x80)
                opcode = b1 & 0x0F
                masked = bool(b2 & 0x80)
                length = b2 & 0x7F
                if length == 126:
                    length = struct.unpack("!H", await self._reader.readexactly(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", await self._reader.readexactly(8))[0]
                if length > self_ref._ws_frame_max_size:
                    raise RuntimeError(f"websocket frame too large: {length}")
                mask_key = await self._reader.readexactly(4) if masked else b""
                payload = await self._reader.readexactly(length) if length else b""
                if masked and mask_key:
                    payload = bytes(byte ^ mask_key[idx % 4] for idx, byte in enumerate(payload))
                if not fin and opcode in (0x0, 0x1, 0x2):
                    raise RuntimeError("fragmented websocket frames are not supported")
                return opcode, payload

            async def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
                if self._closed_evt.is_set():
                    return
                if opcode == 0x8:
                    self._close_sent = True
                length = len(payload)
                header = bytearray([0x80 | (opcode & 0x0F)])
                if length < 126:
                    header.append(length)
                elif length < (1 << 16):
                    header.append(126)
                    header.extend(struct.pack("!H", length))
                else:
                    header.append(127)
                    header.extend(struct.pack("!Q", length))
                self._writer.write(bytes(header) + payload)
                await self._writer.drain()

            async def _shutdown(self) -> None:
                if self._closed_evt.is_set():
                    return
                self._writer.close()
                with contextlib.suppress(Exception):
                    await self._writer.wait_closed()
                self._closed_evt.set()

        self_ref = self

        async def _accept_websocket(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            req_path: str,
            headers: Dict[str, str],
        ) -> _ServerSideWsConnection:
            key = _headers_get(headers, "sec-websocket-key")
            version = _headers_get(headers, "sec-websocket-version")
            if not key or version != "13":
                raise RuntimeError("bad websocket handshake")
            try:
                raw_key = base64.b64decode(key.encode("ascii"), validate=True)
            except Exception as exc:
                raise RuntimeError("invalid Sec-WebSocket-Key") from exc
            if len(raw_key) != 16:
                raise RuntimeError("invalid Sec-WebSocket-Key length")

            chosen_subprotocol = None
            if ws_subprotocol:
                requested = []
                for item in _headers_get(headers, "sec-websocket-protocol").split(","):
                    token = item.strip()
                    if token:
                        requested.append(token)
                if ws_subprotocol not in requested:
                    raise RuntimeError("missing required websocket subprotocol")
                chosen_subprotocol = ws_subprotocol

            accept = base64.b64encode(hashlib.sha1((key + ws_guid).encode("ascii")).digest()).decode("ascii")
            response_headers = [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Accept", accept),
            ]
            if chosen_subprotocol:
                response_headers.append(("Sec-WebSocket-Protocol", chosen_subprotocol))
            payload_mode = self_ref._resolve_inbound_ws_payload_mode(
                _headers_get(headers, self_ref._WS_PAYLOAD_MODE_HEADER.lower()),
            )
            await _send_http_response(writer, status=101, headers=response_headers, body=b"")
            return _ServerSideWsConnection(reader, writer, req_path, chosen_subprotocol, payload_mode)

        async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            upgraded = False
            try:
                self._log.info(
                    f"[WS-SESSION] ({self._probe_id}) incoming connection {format_stream_endpoints(writer)}"
                )
                while True:
                    request = await _read_http_request(reader)
                    if request is None:
                        return
                    method, req_path, http_version, headers = request

                    if _is_ws_upgrade_request(method, headers):
                        self._log.debug(
                            f"[WS-SESSION] ({self._probe_id}) websocket upgrade requested "
                            f"path={req_path} {format_stream_endpoints(writer)}"
                        )
                        try:
                            ws = await _accept_websocket(reader, writer, req_path, headers)
                        except Exception as exc:
                            body = (f"Failed to open a WebSocket connection: {exc}.\n").encode("utf-8", "replace")
                            await _send_http_response(
                                writer,
                                status=400,
                                headers=_http_headers(400, len(body), "text/plain; charset=utf-8", connection="close"),
                                body=body,
                            )
                            return
                        upgraded = True
                        self._log.debug(f"[WS-SESSION] ({self._probe_id}) HTTP path={req_path}")
                        await self._on_accept(ws)
                        try:
                            await ws.wait_closed()
                        except Exception:
                            pass
                        return

                    keep_alive = _should_keep_alive(http_version, headers)

                    if static_root is None:
                        body = (
                            b"Failed to open a WebSocket connection: missing or invalid Upgrade header.\n\n"
                            b"You cannot access a WebSocket server directly with a browser. You need a WebSocket client.\n"
                        )
                        self._log_static_http_decision(
                            method=method,
                            req_path=req_path,
                            status=426,
                            target=None,
                            ctype="text/plain; charset=utf-8",
                            content_length=len(body),
                            body_length=len(body),
                            note="upgrade-required-static-disabled",
                        )
                        await _send_http_response(
                            writer,
                            status=426,
                            headers=[("Upgrade", "websocket")] + _http_headers(426, len(body), "text/plain; charset=utf-8", connection="close"),
                            body=body,
                        )
                        return

                    status, response_headers, body, target, body_length = _static_http_response(method, req_path)
                    connection_header = "keep-alive" if keep_alive else "close"
                    response_headers = [
                        (key, connection_header if key.lower() == "connection" else value)
                        for key, value in response_headers
                    ]

                    ctype = next((value for key, value in response_headers if key.lower() == "content-type"), "application/octet-stream")
                    note = {
                        200: "head-response" if method == "HEAD" else "static-hit",
                        403: "safe-join-rejected",
                        404: "missing-file",
                        405: "method-not-allowed",
                        500: "read-error",
                    }.get(status, "response")
                    self._log_static_http_decision(
                        method=method,
                        req_path=req_path,
                        status=status,
                        target=target,
                        ctype=ctype,
                        content_length=int(next((value for key, value in response_headers if key.lower() == "content-length"), "0") or "0"),
                        body_length=body_length,
                        note=note,
                    )
                    await _send_http_response(writer, status=status, headers=response_headers, body=body)
                    self._schedule_static_http_debug_probes(
                        writer,
                        method=method,
                        req_path=req_path,
                        status=status,
                        target=target,
                        body_length=body_length,
                    )
                    if not keep_alive:
                        return
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) front-listener client error: {e!r}")
                with contextlib.suppress(Exception):
                    body = b"Internal Server Error\n"
                    await _send_http_response(
                        writer,
                        status=500,
                        headers=_http_headers(500, len(body), "text/plain; charset=utf-8", connection="close"),
                        body=body,
                    )
            finally:
                if not upgraded:
                    with contextlib.suppress(Exception):
                        writer.close()
                        await writer.wait_closed()

        try:
            family = _listener_family_for_host(self._listen_host)
            self._server = await asyncio.start_server(
                _handle_client,
                host=self._listen_host,
                port=self._listen_port,
                ssl=ssl_ctx,
                family=family,
            )
        except TypeError:
            self._server = await asyncio.start_server(
                _handle_client,
                host=self._listen_host,
                port=self._listen_port,
                ssl=ssl_ctx,
            )

        sockets = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        self._log.info(
            f"[WS-SESSION] ({self._probe_id}) server listening on {sockets} path={self._ws_path}"
            + ("" if not static_root else f" (static={static_root})")
        )
                
    def _ensure_connect_once(self) -> None:
        if self._connecting_task is not None or not self._peer_tuple or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _connect(): await self._connect_to(host, port)
        self._connecting_task = self._loop.create_task(_connect())  # type: ignore

    def _start_reconnect_loop(self) -> None:
        if not self._peer_tuple or not self._run_flag:
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        self._reconnect_task = None
        host, port = self._peer_tuple
        async def _reconnect():
            delay = self._reconnect_retry_delay_s
            try:
                while self._run_flag:
                    # If TCP writer exists, exit (RTT runtime will flip overlay state)
                    if self._ws is not None:
                        return
                    await self._connect_to(host, port)
                    if self._ws is not None:
                        return
                    try:
                        await asyncio.sleep(delay)
                    except asyncio.CancelledError:
                        return
            finally:
                if self._reconnect_task is asyncio.current_task():
                    self._reconnect_task = None
        self._reconnect_task = self._loop.create_task(_reconnect())  # type: ignore

    def request_reconnect(self) -> bool:
        if not self._peer_tuple or not self._run_flag:
            return False
        ws = self._ws
        self._ws = None
        if self._disconnect_task:
            self._disconnect_task.cancel()
            self._disconnect_task = None
        if ws is not None:
            try:
                self._loop.create_task(ws.close())  # type: ignore[arg-type]
            except Exception:
                pass
        self._schedule_overlay_disconnect()
        self._start_reconnect_loop()
        return True

    async def _on_accept(self, ws) -> None:
        if not self._peer_tuple:
            payload_mode = self._resolve_inbound_ws_payload_mode(getattr(ws, "payload_mode", None))
            rtt = StreamRTT(log=self._log)
            rtt_rt = StreamRTTRuntime(rtt)
            peer_id = self._alloc_server_peer_id()
            ctx = {
                "peer_id": peer_id,
                "ws": ws,
                "payload_mode": payload_mode,
                "payload_codec": self._build_ws_payload_codec(payload_mode),
                "tx_queue": asyncio.Queue(),
                "tx_task": None,
                "rx_task": None,
                "rtt": rtt,
                "rtt_rt": rtt_rt,
            }
            self._server_peers[peer_id] = ctx
            self._server_peer_by_ws_id[id(ws)] = peer_id
            self._configure_ws_socket(ws)
            peer = getattr(ws, "remote_address", None)
            sockname = getattr(ws, "local_address", None)
            self._log.info(
                f"[WS-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={sockname} "
                f"peer={peer} payload_mode={payload_mode}"
            )
            try:
                if isinstance(peer, tuple) and len(peer) >= 2:
                    self._peer_host, self._peer_port = peer[0], int(peer[1])
            except Exception:
                pass
            self._reset_counters()
            self._ensure_server_tx_task(ctx)
            rtt_rt.attach(
                send_ping_fn=lambda payload, _peer_id=peer_id: self._send_ping_frame_for_peer(_peer_id, payload),
                on_state_change=lambda _connected, _peer_id=peer_id: self._update_server_overlay_connected(),
            )
            ctx["rx_task"] = self._loop.create_task(self._rx_pump(ws=ws, peer_id=peer_id))  # type: ignore
            self._ws = ws
            self._rx_task = ctx["rx_task"]
            self._tx_task = ctx.get("tx_task")
            self._update_server_overlay_connected()
            if callable(self._on_peer_set_cb):
                try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                except Exception: pass
            return

        try:
            if self._ws:
                await self._ws.close()
        except Exception:
            pass

        self._ws = ws
        if self._disconnect_task:
            self._disconnect_task.cancel()
            self._disconnect_task = None
        self._configure_ws_socket(ws)
        peer = getattr(ws, "remote_address", None)
        sockname = getattr(ws, "local_address", None)
        self._log.info(f"[WS-SESSION] ({self._probe_id}) accept: local={sockname} peer={peer}")

        try:
            if isinstance(peer, tuple) and len(peer) >= 2:
                self._peer_host, self._peer_port = peer[0], int(peer[1])
        except Exception:
            pass

        self._reset_counters()
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) on_accept ready; starting RX pump and RTT runtime")
        self._ensure_tx_task()
        self._rx_task = self._loop.create_task(self._rx_pump())      # type: ignore
        self._flush_early()

        if callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        self._server_peer_by_ws_id.pop(id(ctx.get("ws")), None)
        self._server_unregister_peer_channels(peer_id)
        rtt_rt = ctx.get("rtt_rt")
        if rtt_rt is not None:
            with contextlib.suppress(Exception):
                rtt_rt.detach()
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) peer_disconnect callback err: {e!r}")
        tx_task = ctx.get("tx_task")
        if tx_task:
            tx_task.cancel()
        rx_task = ctx.get("rx_task")
        if rx_task and rx_task is not asyncio.current_task():
            rx_task.cancel()
        ws = ctx.get("ws")
        if self._ws is ws:
            self._ws = None
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        self._update_server_overlay_connected()

    async def _connect_to(self, host: str, port: int) -> None:
        if not self._run_flag:
            return
        try:
            import websockets
        except Exception:
            self._log.error("websockets package is required for WebSocketSession")
            self._connecting_task = None
            return

        ssl_ctx = None
        scheme = "wss" if self._use_tls else "ws"
        if self._use_tls:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        uri_host = _strip_brackets(self._peer_name_host or host)
        if ":" in uri_host:
            uri_host = f"[{uri_host}]"
        uri_port = int(self._peer_name_port or port)
        uri = f"{scheme}://{uri_host}:{uri_port}{self._ws_path}"
        subprotocols = [self._ws_subprotocol] if self._ws_subprotocol else None
        connect_kwargs = {}
        proxy_sock = None
        proxy_target_host = _strip_brackets(self._peer_name_host or host)
        proxy_target_port = uri_port
        proxy_endpoint = None
        if self._proxy_feature_enabled():
            try:
                proxy_endpoint = self._get_ws_proxy_endpoint(proxy_target_host, proxy_target_port)
            except Exception as exc:
                raise _WsConnectionBootstrapError(
                    "proxy_negotiation_failed",
                    self._format_connection_failure_detail(exc),
                ) from exc
        try:
            if proxy_endpoint is not None:
                proxy_open_task: Optional[asyncio.Task[socket.socket]] = None
                try:
                    proxy_open_task = self._loop.create_task(  # type: ignore[arg-type]
                        self._open_ws_proxy_socket(proxy_target_host, proxy_target_port)
                    )
                    done, _pending = await asyncio.wait({proxy_open_task}, timeout=self._ws_connect_timeout_s)
                    if proxy_open_task not in done:
                        proxy_open_task.cancel()

                        def _cleanup_late_proxy_socket(task: asyncio.Task[socket.socket]) -> None:
                            with contextlib.suppress(Exception):
                                late_sock = task.result()
                                late_sock.close()

                        proxy_open_task.add_done_callback(_cleanup_late_proxy_socket)
                        raise _WsConnectionBootstrapError(
                            "proxy_negotiation_failed",
                            f"timed out opening proxy tunnel after {self._ws_connect_timeout_s:.1f}s",
                        )
                    connect_kwargs["sock"] = proxy_sock = proxy_open_task.result()
                except _WsConnectionBootstrapError:
                    raise
                except asyncio.TimeoutError as exc:
                    raise _WsConnectionBootstrapError(
                        "proxy_negotiation_failed",
                        f"timed out opening proxy tunnel after {self._ws_connect_timeout_s:.1f}s",
                    ) from exc
                except Exception as exc:
                    raise _WsConnectionBootstrapError(
                        "proxy_negotiation_failed",
                        self._format_connection_failure_detail(exc),
                    ) from exc
                if ssl_ctx is not None:
                    connect_kwargs["server_hostname"] = proxy_target_host
            elif self._peer_name_host and (self._peer_name_host != host or uri_port != int(port)):
                connect_kwargs["host"] = host
                connect_kwargs["port"] = int(port)
                if ssl_ctx is not None:
                    connect_kwargs["server_hostname"] = self._peer_name_host

            had_previous_connection = self.connection_epoch > 0
            if connect_kwargs.get("sock") is not None:
                self._log.info(
                    f"[WS-SESSION] ({self._probe_id}) connecting to {uri} through proxy "
                    f"{proxy_endpoint[0]}:{proxy_endpoint[1]} auth={self._ws_proxy_auth}"
                )
            elif connect_kwargs:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) connecting to {uri} via {host}:{int(port)}")
            else:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) connecting to {uri}")
            if connect_kwargs.get("sock") is None:
                self._log.debug(
                    f"[WS-SESSION] ({self._probe_id}) using direct HTTP preflight before websocket upgrade"
                )
                try:
                    await self._load_default_http_page(
                        host=host,
                        port=int(port),
                        ssl_ctx=ssl_ctx,
                        server_hostname=connect_kwargs.get("server_hostname", self._peer_name_host or None),
                        host_header=uri_host.strip("[]"),
                    )
                except Exception as exc:
                    if isinstance(exc, _WsConnectionBootstrapError):
                        raise
                    if isinstance(exc, socket.gaierror):
                        raise _WsConnectionBootstrapError(
                            "dns_resolution_failed",
                            self._format_connection_failure_detail(exc),
                        ) from exc
                    raise _WsConnectionBootstrapError(
                        "http_preflight_failed",
                        self._format_connection_failure_detail(exc),
                    ) from exc
            else:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) skipping HTTP preflight because proxy tunneling is active")
            t0 = time.perf_counter()
            with self._suspend_library_proxy_env():
                connect_kwargs.update(self._build_ws_upgrade_headers(websockets.connect))
                ws = await websockets.connect(
                    uri,
                    ssl=ssl_ctx,
                    subprotocols=subprotocols,
                    max_size=self._ws_frame_max_size,
                    compression=self._ws_compression,
                    ping_interval=None,    # we run our own RTT ping
                    ping_timeout=None,
                    **connect_kwargs,
                )
            dt = (time.perf_counter() - t0) * 1000.0
            local = getattr(ws, "local_address", None)
            remote = getattr(ws, "remote_address", None)
            self._clear_connection_failure()
            self._log.info(f"[WS-SESSION] ({self._probe_id}) connected in {dt:.1f} ms local={local} peer={remote}")
            if had_previous_connection:
                stale_frames = len(self._early_buf)
                stale_bytes = int(self._early_buf_bytes or 0)
                while True:
                    try:
                        wire, _on_sent = self._tx_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    stale_frames += 1
                    stale_bytes += len(wire)
                    with contextlib.suppress(Exception):
                        self._tx_queue.task_done()
                if stale_frames > 0 or stale_bytes > 0:
                    self._log.info(
                        f"[WS/TX] ({self._probe_id}) dropping stale early-buf on transport epoch change "
                        f"frames={stale_frames} bytes={stale_bytes}"
                    )
                self._early_buf.clear()
                self._early_buf_bytes = 0
                self._early_deadline = 0.0
            await self._on_accept(ws)
            if self._ws is ws:
                self.connection_epoch += 1
                self._log.debug("[WS-SESSION] (%s) transport epoch=%d", self._probe_id, self.connection_epoch)
                if had_previous_connection and callable(self._on_transport_epoch_change):
                    try:
                        self._on_transport_epoch_change(self.connection_epoch)
                    except Exception:
                        pass
            if self._peer_name_host:
                self._peer_host = self._peer_name_host
                self._peer_port = self._peer_name_port or int(port)
                if callable(self._on_peer_set_cb):
                    try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                    except Exception: pass
        except Exception as e:
            if proxy_sock is not None:
                with contextlib.suppress(Exception):
                    proxy_sock.close()
            failure_reason, failure_detail = self._classify_connect_failure(
                e,
                proxy_active=proxy_endpoint is not None,
            )
            self._record_connection_failure(failure_reason, failure_detail)
            self._log.warning(f"[WS-SESSION] ({self._probe_id}) connect failed to {uri}: {e!r}")
        finally:
            self._connecting_task = None

    # --- counters / logging ----------------------------------------------------
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[WS/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[WS/CTR] ({self._probe_id}) {direction} "
            f"TX={self._tx_bytes} CRC32_TX=0x{self._tx_crc32:08x} "
            f"RX={self._rx_bytes} CRC32_RX=0x{self._rx_crc32:08x}"
        )

    def _bump_tx(self, data: bytes) -> None:
        self._tx_bytes += len(data)
        self._tx_crc32 = self._z.crc32(data, self._tx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _bump_rx(self, data: bytes) -> None:
        self._rx_bytes += len(data)
        self._rx_crc32 = self._z.crc32(data, self._rx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    # --- early buffer ----------------------------------------------------------
    def _buffer_early(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[WS/TX] ({self._probe_id}) early-buf TTL expired; discarding {self._early_buf_bytes}B")
            self._early_buf.clear()
            self._early_buf_bytes = 0
        self._early_deadline = now + self._early_ttl

        self._early_buf.append((bytes(wire), on_sent))
        self._early_buf_bytes += len(wire)
        while self._early_buf_bytes > self._early_max and self._early_buf:
            dropped, _ = self._early_buf.popleft()
            self._early_buf_bytes -= len(dropped)
            self._log.info(
                f"[WS/TX] ({self._probe_id}) early-buf capped: dropped={len(dropped)} keep={self._early_buf_bytes} cap={self._early_max}"
            )

    def _flush_early(self) -> None:
        if not self._early_buf or not self._ws:
            return
        try:
            pending = list(self._early_buf)
            self._log.info(
                f"[WS/TX] ({self._probe_id}) flushing early-buf frames={len(pending)} bytes={self._early_buf_bytes}"
            )
            for wire, on_sent in pending:
                self._schedule_send(wire, on_sent=on_sent)
        except Exception as e:
            self._log.info(f"[WS/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_buf_bytes = 0
            self._early_deadline = 0.0

    # --- sending helpers -------------------------------------------------------
    def _ensure_tx_task(self) -> None:
        if self._tx_task is not None or not self._ws:
            return

        async def _tx_loop():
            try:
                while True:
                    wire, on_sent = await self._tx_queue.get()
                    try:
                        if not self._ws:
                            continue
                        send_coro = self._ws.send(self._ws_payload_codec.encode(wire))
                        if self._ws_send_timeout_s > 0:
                            await asyncio.wait_for(send_coro, timeout=self._ws_send_timeout_s)
                        else:
                            await send_coro
                        self._bump_tx(wire)
                        if callable(on_sent):
                            try:
                                on_sent()
                            except Exception:
                                pass
                    except asyncio.TimeoutError:
                        self._log.warning(
                            f"[WS/TX] ({self._probe_id}) send timeout after {self._ws_send_timeout_s:.3f}s; forcing reconnect"
                        )
                        try:
                            await asyncio.wait_for(self._ws.close(), timeout=1.0)
                        except Exception:
                            pass
                    except Exception as e:
                        self._log.info(f"[WS/TX] ({self._probe_id}) send error: {e!r}")
                    finally:
                        self._tx_queue.task_done()
            except asyncio.CancelledError:
                return

        self._tx_task = self._loop.create_task(_tx_loop())  # type: ignore

    def _ensure_server_tx_task(self, ctx: dict) -> None:
        if ctx.get("tx_task") is not None or not ctx.get("ws"):
            return

        async def _tx_loop():
            q = ctx["tx_queue"]
            try:
                while True:
                    wire, on_sent = await q.get()
                    ws = ctx.get("ws")
                    try:
                        if ws is None:
                            continue
                        _payload_mode, payload_codec = self._resolve_ws_codec_context(ctx)
                        send_coro = ws.send(payload_codec.encode(wire))
                        if self._ws_send_timeout_s > 0:
                            await asyncio.wait_for(send_coro, timeout=self._ws_send_timeout_s)
                        else:
                            await send_coro
                        self._bump_tx(wire)
                        if callable(on_sent):
                            try:
                                on_sent()
                            except Exception:
                                pass
                    except asyncio.TimeoutError:
                        self._log.warning(
                            f"[WS/TX] ({self._probe_id}) server peer_id={ctx['peer_id']} send timeout after {self._ws_send_timeout_s:.3f}s; closing peer"
                        )
                        await self._close_server_peer(ctx["peer_id"])
                        return
                    except Exception as e:
                        self._log.info(f"[WS/TX] ({self._probe_id}) server peer_id={ctx['peer_id']} send error: {e!r}")
                    finally:
                        q.task_done()
            except asyncio.CancelledError:
                return

        ctx["tx_task"] = self._loop.create_task(_tx_loop())  # type: ignore

    def _schedule_send(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        if not self._ws:
            return
        self._ensure_tx_task()
        self._tx_queue.put_nowait((bytes(wire), on_sent))

    def _schedule_server_send(self, ctx: dict, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        if not ctx.get("ws"):
            return
        self._ensure_server_tx_task(ctx)
        ctx["tx_queue"].put_nowait((bytes(wire), on_sent))

    def _configure_ws_socket(self, ws) -> None:
        try:
            transport = getattr(ws, "transport", None)
            sock = transport.get_extra_info("socket") if transport else None
            if not sock:
                return
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self._log.info(f"[WS-SESSION] ({self._probe_id}) SO_KEEPALIVE=1 set")
            user_timeout = self._ws_tcp_user_timeout_ms
            tcp_user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
            if user_timeout > 0 and tcp_user_timeout is not None:
                sock.setsockopt(socket.IPPROTO_TCP, tcp_user_timeout, user_timeout)
                self._log.info(
                    f"[WS-SESSION] ({self._probe_id}) TCP_USER_TIMEOUT={user_timeout}ms set"
                )
        except Exception as e:
            self._log.debug(f"[WS-SESSION] ({self._probe_id}) socket sockopt failed: {e!r}")


    def _notify_peer_tx(self, nbytes: int) -> None:
        if self._on_peer_tx:
            try:
                self._on_peer_tx(nbytes)
            except Exception:
                pass

    def _schedule_overlay_disconnect(self) -> None:
        if self._disconnect_task or not self._run_flag:
            return
        if self._ws_reconnect_grace_s <= 0:
            self._set_overlay_connected(False)
            return

        async def _delayed_disconnect():
            try:
                await asyncio.sleep(self._ws_reconnect_grace_s)
                if self._ws is None:
                    self._set_overlay_connected(False)
            except asyncio.CancelledError:
                return
            finally:
                self._disconnect_task = None

        self._disconnect_task = self._loop.create_task(_delayed_disconnect())  # type: ignore

    def _decode_ws_message(self, msg, *, ctx: Optional[dict] = None) -> Optional[bytes]:
        payload_mode, payload_codec = self._resolve_ws_codec_context(ctx)
        if isinstance(msg, str):
            try:
                return payload_codec.decode(msg)
            except Exception as e:
                self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {payload_mode} text frame: {e!r}")
                return None
        try:
            return payload_codec.decode(msg)
        except Exception as e:
            self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {payload_mode} frame: {e!r}")
            return None

    async def _load_default_http_page(
        self,
        *,
        host: str,
        port: int,
        ssl_ctx=None,
        server_hostname: Optional[str] = None,
        host_header: Optional[str] = None,
    ) -> None:
        request_host = host_header or server_hostname or host
        reader = None
        writer = None
        try:
            self._log.debug(
                f"[WS-SESSION] ({self._probe_id}) HTTP preflight GET / start "
                f"host={host} port={int(port)} request_host={request_host} tls={bool(ssl_ctx)}"
            )
            open_kwargs = {}
            if ssl_ctx is not None:
                open_kwargs["ssl"] = ssl_ctx
                open_kwargs["server_hostname"] = server_hostname or request_host
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port, **open_kwargs),
                    timeout=self._ws_connect_timeout_s,
                )
            except asyncio.TimeoutError as exc:
                raise _WsConnectionBootstrapError(
                    "http_channel_open_failed",
                    f"timed out opening HTTP preflight channel after {self._ws_connect_timeout_s:.1f}s",
                ) from exc
            except Exception as exc:
                if isinstance(exc, socket.gaierror):
                    raise _WsConnectionBootstrapError(
                        "dns_resolution_failed",
                        self._format_connection_failure_detail(exc),
                    ) from exc
                raise _WsConnectionBootstrapError(
                    "http_channel_open_failed",
                    self._format_connection_failure_detail(exc),
                ) from exc
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {request_host}\r\n"
                "Connection: close\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "User-Agent: ObstacleBridge-ws-preflight/1.0\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(request)
            await writer.drain()
            try:
                status_line = await asyncio.wait_for(reader.readline(), timeout=self._ws_connect_timeout_s)
            except asyncio.TimeoutError as exc:
                raise _WsConnectionBootstrapError(
                    "http_preflight_failed",
                    f"timed out waiting for HTTP preflight response after {self._ws_connect_timeout_s:.1f}s",
                ) from exc
            if not status_line:
                raise _WsConnectionBootstrapError("http_preflight_failed", "empty HTTP response")
            parts = status_line.decode("iso-8859-1", "replace").strip().split(" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            response_headers: Dict[str, str] = {}
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=self._ws_connect_timeout_s)
                except asyncio.TimeoutError as exc:
                    raise _WsConnectionBootstrapError(
                        "http_preflight_failed",
                        f"timed out reading HTTP preflight headers after {self._ws_connect_timeout_s:.1f}s",
                    ) from exc
                if not line or line in (b"\r\n", b"\n"):
                    break
                header_text = line.decode("iso-8859-1", "replace")
                if ":" not in header_text:
                    continue
                key, value = header_text.split(":", 1)
                response_headers[key.strip().lower()] = value.strip()
            try:
                body = await asyncio.wait_for(reader.read(), timeout=self._ws_connect_timeout_s)
            except asyncio.TimeoutError as exc:
                raise _WsConnectionBootstrapError(
                    "http_preflight_failed",
                    f"timed out downloading HTTP preflight body after {self._ws_connect_timeout_s:.1f}s",
                ) from exc
            content_length_header = response_headers.get("content-length", "")
            content_length = int(content_length_header) if content_length_header.isdigit() else None
            if content_length is not None and len(body) != content_length:
                raise _WsConnectionBootstrapError(
                    "http_preflight_failed",
                    f"incomplete HTTP body {len(body)}/{content_length} for status {status_code}",
                )
            self._log.debug(
                f"[WS-SESSION] ({self._probe_id}) HTTP preflight GET / response "
                f"status={status_code} content_length={content_length if content_length is not None else '-'} "
                f"body_bytes={len(body)}"
            )
            if status_code != 200:
                self._log.debug(
                    f"[WS-SESSION] ({self._probe_id}) refusing websocket upgrade because "
                    f"HTTP preflight returned status={status_code}"
                )
                raise _WsConnectionBootstrapError(
                    "http_preflight_failed",
                    f"unexpected HTTP status {status_code}",
                )
            self._log.debug(
                f"[WS-SESSION] ({self._probe_id}) HTTP preflight GET / ok "
                f"status={status_code} downloaded_body_bytes={len(body)}"
            )
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    def _send_ping_frame(self, ping_payload: bytes) -> None:
        """
        Called by StreamRTTRuntime. Sends a PING control frame if WS exists.
        """
        if not self._peer_tuple:
            return
        if not self._ws:
            return

        body = bytes([self._K_PING]) + ping_payload

        # Guard log (tx_ns, echo_ns) for quick visibility
        try:
            if len(ping_payload) >= 16:
                tx_ns, echo_ns = struct.unpack(">QQ", ping_payload[:16])
                self._log.debug(f"[WS/GUARD] ({self._probe_id}) PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        except Exception:
            pass

        self._schedule_send(body, on_sent=lambda: self._notify_peer_tx(len(body)))
        self._log.debug(f"[WS/TX] ({self._probe_id}) PING queued")
            
    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._ws:
            return

        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)

        # Guard log
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG tx: echo_tx_ns={echo_tx_ns}")

        self._schedule_send(body, on_sent=lambda: self._notify_peer_tx(len(body)))
        self._log.debug(f"[WS/TX] ({self._probe_id}) PONG queued")

    def _send_ping_frame_for_peer(self, peer_id: int, ping_payload: bytes) -> None:
        ctx = self._server_peers.get(peer_id)
        if not isinstance(ctx, dict) or not ctx.get("ws"):
            return
        body = bytes([self._K_PING]) + ping_payload
        self._log.debug(f"[WS/TX] ({self._probe_id}) peer_id={peer_id} PING queued")
        self._schedule_server_send(ctx, body, on_sent=lambda: self._notify_peer_tx(len(body)))

    def _send_pong_frame_server(self, ctx: dict, echo_tx_ns: int) -> None:
        rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
        if rtt is None:
            return
        body = bytes([self._K_PONG]) + rtt.build_pong_bytes(echo_tx_ns)
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG tx peer_id={ctx['peer_id']}: echo_tx_ns={echo_tx_ns}")
        self._schedule_server_send(ctx, body, on_sent=lambda: self._notify_peer_tx(len(body)))

    # --- RX pump ---------------------------------------------------------------
    async def _rx_pump(self, ws=None, peer_id: Optional[int] = None) -> None:
        client_mode = self._peer_tuple is not None
        active_ws = self._ws if ws is None else ws
        ctx = self._server_peers.get(peer_id) if (not client_mode and peer_id is not None) else None
        suffix = "" if peer_id is None else f" peer_id={peer_id}"
        self._log.debug(f"[WS/RX] ({self._probe_id}) pump start{suffix}")
        try:
            while True:
                if active_ws is None:
                    return
                msg = await active_ws.recv()  # type: ignore
                b = self._decode_ws_message(msg, ctx=ctx)
                if b is None:
                    continue
                if not b:
                    continue

                self._bump_rx(b)
                if self._on_peer_rx:
                    try: self._on_peer_rx(len(b))
                    except Exception: pass

                kind = b[0]
                payload = b[1:]

                if kind == self._K_APP:
                    if not client_mode and peer_id is not None and not self._app_payload_passthrough:
                        payload = self._server_rewrite_inbound_app(peer_id, payload)
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try:
                            self._on_app(payload, peer_id=peer_id)
                        except TypeError:
                            try:
                                self._on_app(payload)
                            except Exception as e:
                                self._log.debug(f"[WS/RX] ({self._probe_id}) app callback err: {e!r}")
                        except Exception as e:
                            self._log.debug(f"[WS/RX] ({self._probe_id}) app callback err: {e!r}")

                elif kind == self._K_PING:
                    if len(payload) >= 16:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])

                        # Guard log: we received PING (both original tx_ns and echo_ns)
                        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PING rx: tx_ns={tx_ns} echo_ns={echo_ns}")

                        if client_mode:
                            self._rtt.on_ping_received(tx_ns)
                            if echo_ns:
                                # Courtesy update
                                self._rtt.on_pong_received(echo_ns)
                            self._send_pong_frame(tx_ns)
                        elif ctx is not None:
                            ctx_rtt = ctx.get("rtt")
                            if ctx_rtt is not None:
                                ctx_rtt.on_ping_received(tx_ns)
                                if echo_ns:
                                    ctx_rtt.on_pong_received(echo_ns)
                            self._send_pong_frame_server(ctx, tx_ns)
                    else:
                        self._log.debug(f"[WS/RX] ({self._probe_id}) malformed PING len={len(payload)}")

                elif kind == self._K_PONG:
                    if len(payload) >= 8:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])

                        # Take the sample before state flip for better logging
                        sample_ms = (time.monotonic_ns() - int(echo_tx_ns)) / 1e6

                        if client_mode:
                            self._rtt.on_pong_received(echo_tx_ns)

                            # Guard log: PONG received with the measured RTT sample
                            self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG rx: echo_tx_ns={echo_tx_ns} sample_ms={sample_ms:.3f}")

                            # Fast nudge (state transition)
                            was = self._overlay_connected
                            now = self._rtt.is_connected()
                            if now != was:
                                self._set_overlay_connected(now)
                        elif ctx is not None:
                            ctx_rtt = ctx.get("rtt")
                            if ctx_rtt is not None:
                                ctx_rtt.on_pong_received(echo_tx_ns)
                            self._log.debug(
                                f"[WS/GUARD] ({self._probe_id}) PONG rx peer_id={ctx['peer_id']}: "
                                f"echo_tx_ns={echo_tx_ns} sample_ms={sample_ms:.3f}"
                            )
                    elif client_mode:
                        self._log.debug(f"[WS/RX] ({self._probe_id}) malformed PONG len={len(payload)}")
                    elif ctx is not None:
                        self._log.debug(f"[WS/RX] ({self._probe_id}) malformed PONG peer_id={ctx['peer_id']} len={len(payload)}")

                else:
                    self._log.debug(f"[WS/RX] ({self._probe_id}) unknown KIND=0x{kind:02x} n={len(b)}")

        except asyncio.CancelledError:
            self._log.debug(f"[WS/RX] ({self._probe_id}) cancelled")
            return
        except Exception as e:
            self._log.info(f"[WS/RX] ({self._probe_id}) pump error/close{suffix}: {e!r}")
        finally:
            if client_mode:
                try:
                    if self._ws:
                        await self._ws.close()   # type: ignore
                except Exception:
                    pass
                self._ws = None
                self._schedule_overlay_disconnect()
                if self._peer_tuple:
                    self._start_reconnect_loop()
            elif peer_id is not None:
                await self._close_server_peer(peer_id)
            self._log.debug(f"[WS/RX] ({self._probe_id}) pump stop{suffix}")

    # --- overlay state (RTT-driven) -------------------------------------------
    def _on_rtt_state_change(self, connected: bool) -> None:
        self._set_overlay_connected(connected)

    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        mode = "RTT" if self._peer_tuple else "peer-count"
        self._log.info(f"[WS-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} ({mode})")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

# -----------------------------------------------------------------------------


def now_ns() -> int:
    return time.monotonic_ns()
