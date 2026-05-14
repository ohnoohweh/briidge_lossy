from __future__ import annotations

import argparse
import asyncio
import importlib.util
import logging
import socket
import ssl
import struct
import time
from typing import Any, Callable, Dict, Optional, Tuple

from . import bridge as _bridge
from .bridge_transport_common import (
    StreamRTT,
    StreamRTTRuntime,
    _resolve_cli_peer,
    _strip_brackets,
)

ISession = _bridge.ISession
SessionMetrics = _bridge.SessionMetrics
_monotonic_age_seconds_from_ns = _bridge._monotonic_age_seconds_from_ns

class QuicSession(ISession):
    """
    Overlay Session over one QUIC connection + one bidirectional stream.

    Framing (same as TcpStreamSession):
        frame := LEN(4) + KIND(1) + BYTES...
        KIND=0x00 -> APP
        KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)
        KIND=0x02 -> PONG (payload: Q echo_tx_ns)

    Features:
      - Server & client roles via --quic-bind/--quic-own-port and --quic-peer/--quic-peer-port
      - TLS via aioquic (server: --quic-cert/--quic-key; client: --quic-insecure for labs)
      - Auto-reconnect (client) with backoff
      - RTT estimation (StreamRTT/StreamRTTRuntime) drives overlay 'connected'
      - Per-connection counters + running CRC32 (LEN+KIND+payload)
      - Early buffer for APP frames before QUIC stream exists
      - Structured DEBUG logging (parity with TCP/WS style)
    """

    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False

        if not _has('--quic-bind'):
            p.add_argument('--quic-bind', default='::', help='QUIC overlay bind address')
        if not _has('--quic-own-port'):
            p.add_argument('--quic-own-port', dest='quic_own_port', type=int, default=443, help='QUIC overlay own port')
        if not _has('--quic-peer'):
            p.add_argument('--quic-peer', default=None, help='QUIC peer IP/FQDN')
        if not _has('--quic-peer-port'):
            p.add_argument('--quic-peer-port', type=int, default=443, help='QUIC peer overlay port')

        if not _has('--quic-alpn'):
            p.add_argument('--quic-alpn', default='hq-29',
                           help="ALPN protocol ID (default hq-29)")
        if not _has('--quic-cert'):
            p.add_argument('--quic-cert', default=None,
                           help='Server certificate file (PEM)')
        if not _has('--quic-key'):
            p.add_argument('--quic-key', default=None,
                           help='Server private key file (PEM)')
        if not _has('--quic-insecure'):
            p.add_argument('--quic-insecure', action='store_true', default=False,
                           help='Client: disable certificate verification (TEST ONLY)')
        if not _has('--quic-max-size'):
            p.add_argument('--quic-max-size', type=int, default=65535,
                           help='Maximum app message size accepted/sent (default 65535).')

    @staticmethod
    def from_args(args: argparse.Namespace) -> "QuicSession":
        return QuicSession(args)

    def __init__(self, args: argparse.Namespace):
        if importlib.util.find_spec("aioquic") is None:
            raise RuntimeError(
                "overlay_transport=quic requires optional dependency 'aioquic'. "
                "Install it with: pip install aioquic"
            )
        aioquic = _load_aioquic_symbols()

        import zlib as _z
        self._args = args
        self._log  = logging.getLogger("quic_session")
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # Addressing / role
        self._listen_host, self._listen_port = _strip_brackets(args.quic_bind), int(args.quic_own_port)
        self._peer_name_host = _strip_brackets(getattr(args, "quic_peer", None) or "")
        self._peer_name_port = int(getattr(args, "quic_peer_port", 0) or 0)
        peer_info = _resolve_cli_peer(
            args,
            peer_attr="quic_peer",
            peer_port_attr="quic_peer_port",
            bind_host=self._listen_host,
            socktype=socket.SOCK_DGRAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0

        # AIOQUIC handles
        self._server = None
        self._proto: Optional[Any] = None
        self._quic = None
        self._stream_id: Optional[int] = None
        self._rx_task: Optional[asyncio.Task] = None
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_retry_delay_s: float = max(
            0.0,
            float(int(getattr(self._args, "overlay_reconnect_retry_delay_ms", 30000) or 0)) / 1000.0,
        )
        self._run_flag: bool = False
        self._server_connected_evt = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_proto_to_peer_id: Dict[int, int] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1
        self._quic_serve = aioquic["quic_serve"]
        self._quic_connect = aioquic["quic_connect"]
        self._quic_protocol_cls = aioquic["QuicConnectionProtocol"]
        self._quic_configuration_cls = aioquic["QuicConfiguration"]
        self._quic_event_stream_data = aioquic["StreamDataReceived"]
        self._quic_event_handshake = aioquic["HandshakeCompleted"]
        self._quic_event_terminated = aioquic["ConnectionTerminated"]
        self._quic_event_negotiated = aioquic["ProtocolNegotiated"]

        # Framing / buffers
        self._LEN = struct.Struct(">I")
        self._rx_buf = bytearray()
        self._early_buf = bytearray()        # fully-framed (LEN+KIND+payload)
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0
        self._max_app = int(getattr(args, "quic_max_size", 65535))

        # Counters
        self._z = _z
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG

        # RTT runtime
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)
        self._overlay_connected: bool = False
        self._probe_id = f"{id(self)&0xFFFF:04x}"
        self._app_payload_passthrough: bool = False

        # TLS/ALPN
        self._alpn = getattr(args, "quic_alpn", "hq-29") or "hq-29"
        self._server_cert = getattr(args, "quic_cert", None)
        self._server_key  = getattr(args, "quic_key", None)
        self._client_insecure = bool(getattr(args, "quic_insecure", False))

    # ---- ISession callbacks ----
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb
    def set_app_payload_passthrough(self, enabled: bool) -> None: self._app_payload_passthrough = bool(enabled)

    # ---- lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True
        if self._peer_tuple:
            # Attach RTT driver; we’ll attach send_pings once we have a stream
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)
            # CLIENT
            self._peer_host = self._peer_name_host or self._peer_tuple[0]
            self._peer_port = self._peer_name_port or self._peer_tuple[1]
            self._log.info(
                f"[QUIC-SESSION] ({self._probe_id}) start; CLIENT -> "
                f"{self._peer_host}:{self._peer_port} resolved={self._peer_tuple} "
                f"alpn={self._alpn} insecure={self._client_insecure}"
            )
            self._ensure_connect_once()
        else:
            # SERVER
            self._log.info(f"[QUIC-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port} alpn={self._alpn}")
            await self._start_server()

    async def stop(self) -> None:
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False
        if self._peer_tuple:
            self._rtt_rt.detach()
        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None
        try:
            if self._rx_task: self._rx_task.cancel()
        except Exception: pass
        self._rx_task = None

        if not self._peer_tuple:
            for peer_id in list(self._server_peers.keys()):
                await self._close_server_peer(peer_id)
        else:
            # close connection (client role)
            try:
                if self._proto:
                    self._proto.close()
            except Exception:
                pass
            self._proto = None
            self._quic = None
            self._stream_id = None

        # close server (server role)
        try:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
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

    # ---- metrics (for dashboard) ----
    def get_metrics(self) -> SessionMetrics:
        try:
            r = self._rtt
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=getattr(r, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
            )
        except Exception:
            return SessionMetrics()

    def get_max_app_payload_size(self) -> int:
        return max(1, int(self._max_app or 65535))

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
    def _extract_quic_peer_addr(proto: Any) -> Tuple[Optional[str], Optional[int]]:
        try:
            quic = getattr(proto, "_quic", None)
            paths = getattr(quic, "_network_paths", None) if quic is not None else None
            if paths:
                addr = getattr(paths[0], "addr", None)
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return str(addr[0]), int(addr[1])
        except Exception:
            pass
        try:
            transport = getattr(proto, "_transport", None)
            peer = transport.get_extra_info("peername") if transport is not None else None
            if isinstance(peer, tuple) and len(peer) >= 2:
                return str(peer[0]), int(peer[1])
        except Exception:
            pass
        return None, None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        if self._peer_tuple:
            return [{
                "peer_id": 0,
                "connected": bool(self.is_connected()),
                "state": "connected" if self.is_connected() else "connecting",
                "peer": self._format_peer_label(self._peer_host, self._peer_port),
                "mux_chans": [],
                "rtt_est_ms": getattr(self._rtt, "rtt_est_ms", None),
                "last_incoming_age_seconds": _monotonic_age_seconds_from_ns(
                    int(getattr(self._rtt, "_last_rx_wall_ns", 0) or 0)
                ),
            }]

        rows = [{
            "peer_id": -1,
            "connected": False,
            "state": "listening",
            "peer": None,
            "mux_chans": [],
            "rtt_est_ms": None,
            "last_incoming_age_seconds": None,
            "listening": True,
        }]
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
            host = ctx.get("peer_host") if isinstance(ctx, dict) else None
            port = ctx.get("peer_port") if isinstance(ctx, dict) else None
            if (host is None or port is None) and isinstance(ctx, dict):
                proto = ctx.get("proto")
                host, port = self._extract_quic_peer_addr(proto)
                if host is not None and port is not None:
                    ctx["peer_host"], ctx["peer_port"] = host, port
            peer_label = self._format_peer_label(host, port)
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
            rows.append({
                "peer_id": peer_id,
                "connected": bool(peer_id in self._server_peers),
                "state": "connected" if peer_id in self._server_peers else "connecting",
                "peer": peer_label,
                "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
                "last_incoming_age_seconds": last_incoming_age_seconds,
            })
        return rows

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
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return payload
        if len(payload) < mux_hdr.size + dlen:
            return payload
        return mux_hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[mux_hdr.size:mux_hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return payload
        if len(payload) < mux_hdr.size + dlen:
            return payload
        key = (int(peer_id), int(peer_chan))
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = int(peer_chan)
            mapped = self._server_chan_to_peer.get(mux_chan)
            if mapped is not None and mapped != key:
                mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if int(key[0]) != int(peer_id):
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _resolve_server_send_target(self, payload: bytes, peer_id: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return None
        if len(payload) < mux_hdr.size + dlen:
            return None
        target_peer_id = int(peer_id) if peer_id is not None else None
        mapped = self._server_chan_to_peer.get(int(mux_chan))
        if target_peer_id is None and mapped is not None:
            target_peer_id = int(mapped[0])
        if target_peer_id is None:
            if len(self._server_peers) == 1:
                target_peer_id = next(iter(self._server_peers.keys()))
            else:
                return None
        target_ctx = self._server_peers.get(target_peer_id)
        if not target_ctx:
            return None
        peer_chan = int(mux_chan)
        if mapped is not None:
            if int(mapped[0]) != target_peer_id:
                return None
            peer_chan = int(mapped[1])
        else:
            key = (target_peer_id, int(mux_chan))
            self._server_peer_chan_to_mux[key] = int(mux_chan)
            self._server_chan_to_peer[int(mux_chan)] = key
        return target_peer_id, self._rewrite_mux_chan_id(payload, peer_chan) if peer_chan != int(mux_chan) else payload

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    # ---- data path (APP) ----
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        if len(payload) > self._max_app:
            self._log.error(f"[QUIC/TX] ({self._probe_id}) app payload too large ({len(payload)} > {self._max_app}); drop")
            return 0
        if not self._peer_tuple:
            if self._app_payload_passthrough and peer_id is not None:
                ctx = self._server_peers.get(int(peer_id))
                if not ctx:
                    return 0
                wire = self._LEN.pack(len(payload) + 1) + bytes([self._K_APP]) + payload
                if not self._send_wire_ctx(ctx, wire):
                    return 0
                return len(payload)
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                self._log.debug(f"[QUIC/TX] ({self._probe_id}) drop unroutable server APP len={len(payload)} peer_id={peer_id}")
                return 0
            target_peer_id, routed_payload = target
            ctx = self._server_peers.get(target_peer_id)
            if not ctx:
                return 0
            wire = self._LEN.pack(len(routed_payload) + 1) + bytes([self._K_APP]) + routed_payload
            if not self._send_wire_ctx(ctx, wire):
                return 0
            return len(payload)
        body = bytes([self._K_APP]) + payload
        wire = self._LEN.pack(len(body)) + body

        if not self._quic or self._stream_id is None:
            self._buffer_early(wire)
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        try:
            self._send_wire(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            return len(payload)
        except Exception as e:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) write error: {e!r}")
            return 0

    # ---- server/client wiring ----
    async def _start_server(self) -> None:
        """
        Server role: listen for QUIC connections and adopt the connection once
        the TLS handshake completes. Compatible with aioquic variants that do
        NOT expose a '.sockets' attribute on the returned server object.
        """
        if not self._server_cert or not self._server_key:
            raise RuntimeError("QUIC server requires --quic-cert and --quic-key (PEM files)")

        cfg = self._quic_configuration_cls(is_client=False, alpn_protocols=[self._alpn])
        cfg.load_cert_chain(self._server_cert, self._server_key)

        parent = self

        class _Proto(self._quic_protocol_cls):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._parent = parent
                self._accepted = False  # adopt only once per connection

            def quic_event_received(self, event):
                # On first completed TLS handshake, adopt this connection at the session layer.
                if isinstance(event, self._parent._quic_event_handshake) and not self._accepted:
                    self._accepted = True
                    self._parent._on_accept(self)
                # Forward all events to the session’s demux
                self._parent._on_quic_event(self, event)

        # Start listening
        self._server = await self._quic_serve(
            self._listen_host,
            self._listen_port,
            configuration=cfg,
            create_protocol=_Proto,
        )

        # Log a "we are listening" message that never touches .sockets
        # Try to extract addresses from transports (if present); otherwise print host:port.
        try:
            transports_attr = getattr(self._server, "transports", None)
            if transports_attr:
                addrs = []
                for tr in transports_attr:
                    try:
                        a = tr.get_extra_info("sockname")
                        if a is not None:
                            addrs.append(str(a))
                    except Exception:
                        pass
                if addrs:
                    self._log.info(f"[QUIC-SESSION] ({self._probe_id}) server listening on {', '.join(addrs)}")
                    return
        except Exception:
            pass

        # Definitive fallback banner to confirm we are running the new function
        self._log.info(
            f"[QUIC-SESSION] ({self._probe_id}) LISTEN READY (no .sockets on server object) at {self._listen_host}:{self._listen_port}"
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
                    if self._quic is not None:
                        return
                    await self._connect_to(host, port)
                    if self._quic is not None:
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
        proto = self._proto
        self._proto = None
        self._quic = None
        self._stream_id = None
        if proto is not None:
            with contextlib.suppress(Exception):
                proto.close()
        self._set_overlay_connected(False)
        self._start_reconnect_loop()
        return True

    async def _connect_to(self, host: str, port: int) -> None:
        """
        Client role: establish QUIC connection to (host, port).
        Compatible with aioquic versions that do NOT accept 'server_name=' in connect().
        - Uses cfg.server_name for SNI
        - No 'server_name=' kwarg passed to quic_connect()
        """
        if not self._run_flag:
            return

        # Prepare client configuration
        cfg = self._quic_configuration_cls(is_client=True, alpn_protocols=[self._alpn])
        if self._client_insecure:
            cfg.verify_mode = ssl.CERT_NONE  # TEST ONLY
        # SNI for server name indication (works across aioquic versions)
        cfg.server_name = self._peer_name_host or host

        # Lightweight protocol wrapper that forwards events back to the session
        parent = self

        class _Proto(self._quic_protocol_cls):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._parent = parent
            def quic_event_received(self, event):
                self._parent._on_quic_event(self, event)

        self._log.info(
            f"[QUIC-SESSION] ({self._probe_id}) connecting to "
            f"{self._peer_name_host or host}:{self._peer_name_port or port} via {host}:{port} "
            f"alpn={self._alpn} insecure={self._client_insecure}"
        )
        t0 = time.perf_counter()
        try:
            # NOTE: do NOT pass 'server_name=' kwarg (older aioquic will raise TypeError)
            async with self._quic_connect(host, port, configuration=cfg, create_protocol=_Proto) as proto:
                # Adopt this live connection and keep the context open until it closes.
                self._connecting_task = None
                self._on_accept(proto)
                if self._peer_name_host:
                    self._peer_host = self._peer_name_host
                    self._peer_port = self._peer_name_port or int(port)
                    if callable(self._on_peer_set_cb):
                        try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                        except Exception: pass

                dt = (time.perf_counter() - t0) * 1000.0
                local = getattr(proto._transport, "getsockname", lambda: None)()
                remote = getattr(proto._transport, "getpeername",  lambda: None)()
                self._log.info(
                    f"[QUIC-SESSION] ({self._probe_id}) connected in {dt:.1f} ms "
                    f"local={local} peer={remote}"
                )

                # Keep the context alive while our RX task runs.
                await self._rx_task  # set in _on_accept
        except asyncio.CancelledError:
            return
        except Exception as e:
            self._log.warning(
                f"[QUIC-SESSION] ({self._probe_id}) connect failed to {host}:{port}: {e!r}"
            )
        finally:
            self._connecting_task = None
            
        """
    Client role: establish QUIC connection to (host, port).
       """
 
    # ---- accept / on-connection ----
    def _on_accept(self, proto: Any) -> None:
        """
        Adopt the live QUIC connection. Only the CLIENT proactively opens a stream;
        the SERVER waits and adopts the first incoming stream id.
        """
        if not self._peer_tuple:
            peer_id = self._alloc_server_peer_id()
            ctx = {
                "peer_id": peer_id,
                "proto": proto,
                "quic": getattr(proto, "_quic", None),
                "stream_id": None,
                "rx_buf": bytearray(),
                "rtt": StreamRTT(log=self._log.getChild(f"rtt.{peer_id}")),
                "connected": True,
                "peer_host": None,
                "peer_port": None,
            }
            self._server_peers[peer_id] = ctx
            self._server_proto_to_peer_id[id(proto)] = peer_id
            try:
                tr = getattr(proto, "_transport", None)
                laddr = tr.get_extra_info("sockname") if tr else None
                rhost, rport = self._extract_quic_peer_addr(proto)
                raddr = (rhost, rport) if rhost is not None and rport is not None else None
            except Exception:
                laddr = raddr = None
            self._log.info(f"[QUIC-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={laddr} peer={raddr}")
            try:
                if isinstance(raddr, tuple) and len(raddr) >= 2:
                    ctx["peer_host"], ctx["peer_port"] = raddr[0], int(raddr[1])
                    self._peer_host, self._peer_port = raddr[0], int(raddr[1])
                    if callable(self._on_peer_set_cb):
                        try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                        except Exception: pass
            except Exception:
                pass
            self._update_server_overlay_connected()
            return

        # Close any previous overlay peer
        try:
            if self._proto:
                self._proto.close()
        except Exception:
            pass

        self._proto = proto
        self._quic = proto._quic

        # Peer addresses (cosmetic; may be None on some stacks)
        try:
            tr = getattr(proto, "_transport", None)
            laddr = tr.get_extra_info("sockname") if tr else None
            raddr = tr.get_extra_info("peername") if tr else None
        except Exception:
            laddr = raddr = None
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) accept: local={laddr} peer={raddr}")

        # Record peer host:port if available for the dashboard
        try:
            if isinstance(raddr, tuple) and len(raddr) >= 2:
                self._peer_host, self._peer_port = raddr[0], int(raddr[1])
        except Exception:
            pass
        if callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass

        self._reset_counters()

        # === Stream selection policy =========================================
        # Client pre-opens a stream (so it can start RTT). Server waits and adopts.
        self._stream_id = None
        if self._peer_tuple:
            # We are in CLIENT role (peer_tuple != None) -> pre-open one stream
            try:
                self._stream_id = self._quic.get_next_available_stream_id()
                self._log.debug(f"[QUIC/STREAM] ({self._probe_id}) client picked stream_id={self._stream_id}")
            except Exception as e:
                self._log.debug(f"[QUIC/STREAM] ({self._probe_id}) get_next_available_stream_id() failed: {e!r}")

        # Attach RTT sender now that we can (it will only send if stream_id exists)
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)

        # Keep a dummy task to align lifecycle (keeps client connect() context alive)
        self._rx_task = self._loop.create_task(self._rx_dummy())  # type: ignore

        # Flush any early APP frames if we already have a stream
        self._flush_early()

    async def _rx_dummy(self):
        try:
            while self._proto and self._run_flag:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            return

    # ---- QUIC event demux ----
    def _on_quic_event(self, proto: Any, event) -> None:
        """
        Handle QUIC events. On first StreamDataReceived, adopt that stream id if we
        don't have one yet; if we already picked a different id, switch to the incoming
        id so both peers use the *same* bidirectional stream.
        """
        if not self._peer_tuple:
            peer_id = self._server_proto_to_peer_id.get(id(proto))
            if peer_id is None:
                return
            ctx = self._server_peers.get(peer_id)
            if ctx is None:
                return

            if isinstance(event, self._quic_event_negotiated):
                self._log.info(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} ALPN negotiated: {getattr(event, 'alpn_protocol', '?')}")
                return

            if isinstance(event, self._quic_event_handshake):
                self._log.debug(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} handshake completed")
                return

            if isinstance(event, self._quic_event_stream_data):
                sid = event.stream_id
                if ctx.get("peer_host") is None or ctx.get("peer_port") is None:
                    host, port = self._extract_quic_peer_addr(proto)
                    if host is not None and port is not None:
                        ctx["peer_host"], ctx["peer_port"] = host, port
                if ctx.get("stream_id") is None:
                    ctx["stream_id"] = sid
                    self._log.info(f"[QUIC/STREAM] ({self._probe_id}) peer_id={peer_id} adopted incoming stream_id={sid}")
                elif sid != ctx.get("stream_id"):
                    old = ctx.get("stream_id")
                    ctx["stream_id"] = sid
                    self._log.info(f"[QUIC/STREAM] ({self._probe_id}) peer_id={peer_id} switching stream_id {old} -> {sid} to match peer")
                self._on_stream_bytes(event.data, ctx=ctx, peer_id=peer_id)
                return

            if isinstance(event, self._quic_event_terminated):
                self._log.info(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} connection terminated: {event.error_code} {event.reason_phrase!r}")
                if self._loop is not None:
                    self._loop.create_task(self._close_server_peer(peer_id))
                return
            return

        if self._proto is not proto:
            return

        if isinstance(event, self._quic_event_negotiated):
            self._log.info(f"[QUIC/RX] ({self._probe_id}) ALPN negotiated: {getattr(event, 'alpn_protocol', '?')}")
            return

        if isinstance(event, self._quic_event_handshake):
            self._log.debug(f"[QUIC/RX] ({self._probe_id}) handshake completed")
            return

        if isinstance(event, self._quic_event_stream_data):
            sid = event.stream_id

            # If we don't have a stream, adopt the incoming one.
            if self._stream_id is None:
                self._stream_id = sid
                # Ensure RTT sender is attached now that we have a stream id
                self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
                self._log.info(f"[QUIC/STREAM] ({self._probe_id}) adopted incoming stream_id={sid}")

            # If we picked a different stream earlier (e.g., both sides opened one),
            # switch to the incoming id so that both sides converge on ONE stream.
            elif sid != self._stream_id:
                old = self._stream_id
                self._stream_id = sid
                self._log.info(f"[QUIC/STREAM] ({self._probe_id}) switching stream_id {old} -> {sid} to match peer")

            # Now process the bytes on the (adopted) stream.
            self._on_stream_bytes(event.data)
            return

        if isinstance(event, self._quic_event_terminated):
            self._log.info(f"[QUIC/RX] ({self._probe_id}) connection terminated: {event.error_code} {event.reason_phrase!r}")
            self._cleanup_after_close()
            return

    def _cleanup_after_close(self) -> None:
        self._proto = None
        self._quic = None
        self._stream_id = None
        self._set_overlay_connected(False)
        if self._peer_tuple:
            self._start_reconnect_loop()

    # ---- stream reassembly (LEN + KIND) ----
    def _on_stream_bytes(self, data: bytes, ctx: Optional[dict] = None, peer_id: Optional[int] = None) -> None:
        if not data:
            return
        self._bump_rx(data)
        if self._on_peer_rx:
            try: self._on_peer_rx(len(data))
            except Exception: pass

        rx_buf = self._rx_buf if ctx is None else ctx.setdefault("rx_buf", bytearray())
        rx_buf += data
        while True:
            if len(rx_buf) < self._LEN.size:
                return
            (n,) = self._LEN.unpack_from(rx_buf, 0)
            if n <= 0:
                del rx_buf[:self._LEN.size]
                continue
            need = self._LEN.size + n
            if len(rx_buf) < need:
                return
            body = bytes(rx_buf[self._LEN.size:need])
            del rx_buf[:need]

            kind = body[0]
            payload = body[1:]

            if kind == self._K_APP:
                if self._on_app_from_peer_bytes:
                    try: self._on_app_from_peer_bytes(len(payload))
                    except Exception: pass
                if callable(self._on_app):
                    try:
                        if peer_id is not None:
                            if not self._app_payload_passthrough:
                                payload = self._server_rewrite_inbound_app(peer_id, payload)
                            self._on_app(payload, peer_id=peer_id)
                        else:
                            self._on_app(payload)
                    except TypeError:
                        try:
                            self._on_app(payload)
                        except Exception as e:
                            self._log.debug(f"[QUIC/RX] ({self._probe_id}) app callback err: {e!r}")
                    except Exception as e:
                        self._log.debug(f"[QUIC/RX] ({self._probe_id}) app callback err: {e!r}")

            elif kind == self._K_PING:
                if len(payload) >= 16:
                    tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                    rtt = self._rtt if ctx is None else ctx.get("rtt")
                    if rtt is not None:
                        rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            rtt.on_pong_received(echo_ns)
                    if ctx is None:
                        self._send_pong_frame(tx_ns)
                    else:
                        self._send_pong_frame_for_peer(ctx, tx_ns)
                else:
                    self._log.debug(f"[QUIC/RX] ({self._probe_id}) malformed PING len={len(payload)}")

            elif kind == self._K_PONG:
                if len(payload) >= 8:
                    (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                    rtt = self._rtt if ctx is None else ctx.get("rtt")
                    if rtt is not None:
                        rtt.on_pong_received(echo_tx_ns)
                    if ctx is None:
                        was = self._overlay_connected
                        now = self._rtt.is_connected()
                        if now != was:
                            self._set_overlay_connected(now)
                else:
                    self._log.debug(f"[QUIC/RX] ({self._probe_id}) malformed PONG len={len(payload)}")

            else:
                self._log.debug(f"[QUIC/RX] ({self._probe_id}) unknown KIND=0x{kind:02x} n={n}")

    # ---- sending helpers ----
    def _send_wire_ctx(self, ctx: dict, wire: bytes) -> bool:
        quic = ctx.get("quic")
        stream_id = ctx.get("stream_id")
        proto = ctx.get("proto")
        if quic is None or stream_id is None or proto is None or not wire:
            return False
        try:
            quic.send_stream_data(int(stream_id), wire, end_stream=False)
            proto.transmit()
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            return True
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) server send_stream_data error peer_id={ctx.get('peer_id')}: {e!r}")
            return False

    def _send_wire(self, wire: bytes) -> None:
        if not self._quic or self._stream_id is None or not wire:
            return
        try:
            self._quic.send_stream_data(self._stream_id, wire, end_stream=False)
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) send_stream_data error: {e!r}")
        self._schedule_transmit()

    def _schedule_transmit(self) -> None:
        """
        Ensure pending QUIC data is flushed. On some aioquic versions
        QuicConnectionProtocol.transmit() is a plain function (not a coroutine).
        Call it synchronously and do NOT 'await' it.
        """
        if not self._proto:
            return
        try:
            # Synchronous call – do NOT await
            self._proto.transmit()
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) transmit() exception: {e!r}")
            
    def _send_ping_frame(self, ping_payload: bytes) -> None:
        if not self._quic or self._stream_id is None:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            if len(ping_payload) >= 16:
                tx_ns, echo_ns = struct.unpack(">QQ", ping_payload[:16])
                self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        except Exception:
            pass
        self._send_wire(wire)
        self._bump_tx(wire)
        if self._on_peer_tx:
            try: 
                self._on_peer_tx(len(wire))
            except Exception as e: 
                pass
        self._log.debug(f"[QUIC/TX] ({self._probe_id}) PING")

    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._quic or self._stream_id is None:
            return
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PONG tx: echo_tx_ns={echo_tx_ns}")
        self._send_wire(wire)
        self._bump_tx(wire)
        if self._on_peer_tx:
            try: 
                self._on_peer_tx(len(wire))
            except Exception as e: 
                pass
        self._log.debug(f"[QUIC/TX] ({self._probe_id}) PONG")

    def _send_pong_frame_for_peer(self, ctx: dict, echo_tx_ns: int) -> None:
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PONG tx peer_id={ctx.get('peer_id')}: echo_tx_ns={echo_tx_ns}")
        self._send_wire_ctx(ctx, wire)

    # ---- counters/logging ----
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[QUIC/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[QUIC/CTR] ({self._probe_id}) {direction} "
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

    # ---- early buffer ----
    def _buffer_early(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) early-buf TTL expired; discarding {len(self._early_buf)}B")
            self._early_buf.clear()
        self._early_deadline = now + self._early_ttl
        over = (len(self._early_buf) + len(wire)) - self._early_max
        if over > 0:
            drop = min(over, len(self._early_buf))
            if drop:
                del self._early_buf[:drop]
                self._log.info(f"[QUIC/TX] ({self._probe_id}) early-buf capped: dropped={drop} keep={len(self._early_buf)} cap={self._early_max}")
        self._early_buf += wire

    def _flush_early(self) -> None:
        if not self._early_buf or not self._quic or self._stream_id is None:
            return
        try:
            n = len(self._early_buf)
            self._log.info(f"[QUIC/TX] ({self._probe_id}) flushing early-buf bytes={n}")
            self._send_wire(bytes(self._early_buf))
            self._bump_tx(self._early_buf)
        except Exception as e:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_deadline = 0.0

    # ---- overlay state (RTT-driven) ----
    def _on_rtt_state_change(self, connected: bool) -> None:
        self._set_overlay_connected(connected)

    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        mode = "RTT" if self._peer_tuple else "peer-count"
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} ({mode})")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        proto = ctx.get("proto")
        if proto is not None:
            self._server_proto_to_peer_id.pop(id(proto), None)
        self._server_unregister_peer_channels(peer_id)
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception as e:
                self._log.debug(f"[QUIC-SESSION] ({self._probe_id}) peer_disconnect callback err: {e!r}")
        try:
            if proto is not None:
                proto.close()
        except Exception:
            pass
        self._update_server_overlay_connected()

# -----------------------------------------------------------------------------

# --- WebSocket overlay ---------------------------------------------------------
# Requires: pip install websockets
