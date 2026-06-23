from __future__ import annotations

import struct

from ._bridge_import import export_bridge_globals
from .bridge_transport_common import (
    EgressThroughputTracker,
    StreamRTT,
    StreamRTTRuntime,
    _listener_family_for_host,
    _resolve_cli_peer,
    _strip_brackets,
    _wildcard_host_for_family,
)

_bridge = export_bridge_globals(globals())

_MUX_HDR = struct.Struct(">HHBBH")

class TcpStreamSession(ISession):
    """
    Overlay Session over one TCP stream with an internal control sub-framing:

      frame := LEN(4) + KIND(1) + BYTES...
        KIND=0x00 -> APP (forward to upper layer)
        KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)  -- internal
        KIND=0x02 -> PONG (payload: Q echo_tx_ns)        -- internal

    Features:
      - OS-level TCP keepalive on accept/connect
      - Proactive connect on start() in client mode + auto-reconnect with backoff
      - RTT runtime (StreamRTTRuntime) -> drives overlay "connected" state
      - Backpressure + early buffering (APP frames)
      - Per-connection counters + running CRC32 over wire bytes (LEN+KIND+payload)
    """
    # stream kinds
    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        """
        TCP overlay backpressure knobs (disabled-by-default time-based).
        - --tcp-bp-wbuf-threshold: drain() trigger based on OS write buffer size (bytes)
        - --tcp-bp-latency-ms    : if > 0, drain after this many ms with any pending bytes
        - --tcp-bp-poll-interval-ms: how often to check the buffer/time condition
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--tcp-bind'):
            p.add_argument('--tcp-bind', default='::', help='TCP overlay bind address')
        if not _has('--tcp-own-port'):
            p.add_argument('--tcp-own-port', dest='tcp_own_port', type=int, default=8081, help='TCP overlay own port')
        if not _has('--tcp-peer'):
            p.add_argument('--tcp-peer', default=None, help='TCP peer IP/FQDN')
        if not _has('--tcp-peer-port'):
            p.add_argument('--tcp-peer-port', type=int, default=8081, help='TCP peer overlay port')
        if not _has('--tcp-peer-resolve-family'):
            p.add_argument(
                '--tcp-peer-resolve-family',
                dest='tcp_peer_resolve_family',
                choices=['prefer-ipv6', 'ipv4', 'ipv6'],
                default='prefer-ipv6',
                help='TCP peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.'
            )

        if not _has('--tcp-bp-wbuf-threshold'):
            p.add_argument('--tcp-bp-wbuf-threshold', type=int, default=128 * 1024,
                        help='TCP overlay: write() buffer size threshold in bytes to signal drain (default 131072).')

        if not _has('--tcp-bp-latency-ms'):
            p.add_argument('--tcp-bp-latency-ms', type=int, default=300,
                        help='TCP overlay: if > 0, trigger drain after this latency (ms) whenever pending bytes exist.')

        if not _has('--tcp-bp-poll-interval-ms'):
            p.add_argument('--tcp-bp-poll-interval-ms', type=int, default=50,
                        help='TCP overlay: polling interval for time-based backpressure checks (ms; default 50).')
    @staticmethod
    def from_args(args: argparse.Namespace) -> "TcpStreamSession":
        s = TcpStreamSession(args)
        # Apply CLI tuning (safe even if attributes were pre-set in __init__)
        try:
            s._wbuf_threshold = int(getattr(args, 'tcp_bp_wbuf_threshold', s._wbuf_threshold))
        except Exception:
            pass
        # New: time-based knobs
        try:
            s._bp_latency_ms = int(getattr(args, 'tcp_bp_latency_ms', 0))
        except Exception:
            s._bp_latency_ms = 0
        try:
            s._bp_poll_interval_s = float(getattr(args, 'tcp_bp_poll_interval_ms', 50)) / 1000.0
        except Exception:
            s._bp_poll_interval_s = 0.05
        return s
    def __init__(self, args: argparse.Namespace):
        import zlib  # local import if not at top
        self._zlib = zlib

        self._args = args
        self._log = logging.getLogger("tcp_session")
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # tcp state
        self._server: Optional[asyncio.base_events.Server] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._rx_task: Optional[asyncio.Task] = None
        self._run_flag: bool = False

        # peer endpoints (client/server)
        self._listen_host, self._listen_port = _strip_brackets(self._args.tcp_bind), int(self._args.tcp_own_port)
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="tcp_peer",
            peer_port_attr="tcp_peer_port",
            resolve_attr="tcp_peer_resolve_family",
            bind_host=self._listen_host,
            socktype=socket.SOCK_STREAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0
        self._server_connected_evt: asyncio.Event = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1

        # framing
        self._LEN = struct.Struct(">I")

        # backpressure
        self._wbuf_threshold = 128 * 1024
        self._bp_evt: Optional[asyncio.Event] = None
        self._bp_task: Optional[asyncio.Task] = None

        # early buffer (APP frames only; store fully-framed bytes incl LEN+KIND)
        self._early_buf = bytearray()
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0

        # counters (wire bytes)
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG

        # RTT
        self._rtt = StreamRTT()
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)

        # reconnect
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_retry_delay_s: float = max(
            0.0,
            float(int(getattr(self._args, "overlay_reconnect_retry_delay_ms", 30000) or 0)) / 1000.0,
        )

        # cosmetics
        self._probe_id = f"{id(self)&0xFFFF:04x}"

        # overlay "connected" view is RTT-driven
        self._overlay_connected: bool = False
        self._app_payload_passthrough: bool = False
        self._egress_tracker = EgressThroughputTracker()

    # ---- ISession: callback wiring ----
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb
    def set_app_payload_passthrough(self, enabled: bool) -> None: self._app_payload_passthrough = bool(enabled)

    # ---- ISession: lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True

        if self._peer_tuple:
            # CLIENT: proactive connect so RTT can flow immediately
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)
            self._peer_host, self._peer_port = self._peer_tuple
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) start; CLIENT bind={self._listen_host}:{self._listen_port} peer={self._peer_tuple}")
            self._ensure_connect_once()
        else:
            # SERVER: listen and accept multiple overlay peers
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port}")
            async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await self._on_accept(reader, writer)

            try:
                family = _listener_family_for_host(self._listen_host)
                self._server = await asyncio.start_server(_handle, host=self._listen_host, port=self._listen_port, family=family)
            except TypeError:
                self._server = await asyncio.start_server(_handle, host=self._listen_host, port=self._listen_port)
            sockets = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) server listening on {sockets}")

    async def stop(self) -> None:
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False

        # tear down timers / tasks
        self._rtt_rt.detach()
        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None

        for peer_id in list(self._server_peers.keys()):
            await self._close_server_peer(peer_id)
        self._server_connected_evt.clear()

        if self._bp_task:
            self._bp_task.cancel()
            self._bp_task = None
        self._bp_evt = None

        try:
            if self._rx_task: self._rx_task.cancel()
        except Exception: pass
        self._rx_task = None

        # close writer
        try:
            if self._writer:
                self._writer.close()
                aw = getattr(self._writer, "wait_closed", None)
                if callable(aw): await aw()
        except Exception: pass
        self._writer = None
        self._reader = None

        # close server
        try:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
        except Exception: pass
        self._server = None

        # state off
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

    # ---- metrics surface for StatsBoard (RTT plumbing) ----
    def get_metrics(self) -> SessionMetrics:
        """
        Publish RTT numbers to the dashboard (transport-agnostic).
        Only RTT fields are populated for TCP; other congestion stats are n/a.
        """
        try:
            r = self._rtt
            rtt_est_ms = getattr(r, "rtt_est_ms", None)
            tracker = getattr(self, "_egress_tracker", None)
            prev_bytes, curr_bytes = tracker.snapshot() if tracker is not None else (0, 0)
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=rtt_est_ms,
                transmit_delay_est_ms=(0.5 * float(rtt_est_ms)) if rtt_est_ms is not None else None,
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
                waiting_count=self.waiting_count() if hasattr(self, "_send_queue") else 0,
                egress_prev_window_bytes=prev_bytes,
                egress_curr_window_bytes=curr_bytes,
            )
        except Exception:
            return SessionMetrics()

    def waiting_count(self) -> int:
        pending = 0
        try:
            pending += 1 if len(self._early_buf) > 0 else 0
        except Exception:
            pass

        def _writer_pending(writer: Any) -> int:
            try:
                transport = getattr(writer, "transport", None)
                if transport is None and hasattr(writer, "get_extra_info"):
                    transport = writer.get_extra_info("transport")
                size_getter = getattr(transport, "get_write_buffer_size", None)
                size = int(size_getter()) if callable(size_getter) else 0
                return 1 if size > 0 else 0
            except Exception:
                return 0

        pending += _writer_pending(getattr(self, "_writer", None))
        try:
            for ctx in list(self._server_peers.values()):
                pending += _writer_pending(ctx.get("writer"))
        except Exception:
            pass
        return max(0, int(pending))

    def get_max_app_payload_size(self) -> int:
        return 65535

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
                "peer": self._format_peer_endpoint(self._peer_host, self._peer_port),
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
        for peer_id in sorted(self._server_peers.keys()):
            ctx = self._server_peers.get(peer_id, {})
            addr = ctx.get("addr") if isinstance(ctx, dict) else None
            host = addr[0] if isinstance(addr, tuple) and len(addr) >= 2 else None
            port = addr[1] if isinstance(addr, tuple) and len(addr) >= 2 else None
            rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
            rows.append({
                "peer_id": peer_id,
                "connected": bool(ctx.get("connected")) if isinstance(ctx, dict) else False,
                "state": "connected" if bool(ctx.get("connected")) else "connecting",
                "peer": self._format_peer_endpoint(host, port),
                "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
                "last_incoming_age_seconds": _monotonic_age_seconds_from_ns(
                    int(getattr(rtt, "_last_rx_wall_ns", 0) or 0)
                ),
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
        hdr = _MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        return hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[hdr.size:hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        hdr = _MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
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
        if self._app_payload_passthrough and peer_id is not None:
            target_peer_id = int(peer_id)
            target_ctx = self._server_peers.get(target_peer_id)
            if not target_ctx:
                return None
            return target_peer_id, payload
        hdr = _MUX_HDR
        if len(payload) < hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return None
        if len(payload) < hdr.size + dlen:
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

    # ---- ISession: data path (APP) ----
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        if not self._peer_tuple:
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                return 0
            target_peer_id, routed_payload = target
            ctx = self._server_peers.get(target_peer_id)
            writer = ctx.get("writer") if isinstance(ctx, dict) else None
            if writer is None:
                return 0
            wire = self._LEN.pack(len(routed_payload) + 1) + bytes([self._K_APP]) + routed_payload
            try:
                writer.write(wire)
                if ctx is not None:
                    self._bump_tx_for_ctx(ctx, wire)
                if self._on_peer_tx:
                    try: self._on_peer_tx(len(wire))
                    except Exception: pass
                self._egress_tracker.record(len(routed_payload))
                return len(payload)
            except Exception as e:
                self._log.info(f"[TCP/TX] ({self._probe_id}) server write error peer_id={target_peer_id}: {e!r}")
                return 0
        frame = bytes([self._K_APP]) + payload
        body_len = len(frame)
        wire = self._LEN.pack(body_len) + frame

        if self._writer is None:
            # buffer APP frame until TCP exists
            self._buffer_early(wire)
            self._log.debug(f"[TCP/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            self._egress_tracker.record(len(payload))
            return len(payload)
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) write error: {e!r}")
            return 0

    # ---- accept/connect wiring ----
    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        p = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        if not self._peer_tuple:
            peer_id = self._alloc_server_peer_id()
            rtt = StreamRTT(log=self._log.getChild(f"rtt.{peer_id}"))
            rtt_rt = StreamRTTRuntime(rtt)
            ctx = {
                "peer_id": peer_id,
                "reader": reader,
                "writer": writer,
                "addr": p if isinstance(p, tuple) and len(p) >= 2 else None,
                "connected": False,
                "rtt": rtt,
                "rtt_rt": rtt_rt,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_crc32": 0,
                "tx_crc32": 0,
                "rx_task": None,
            }
            self._server_peers[peer_id] = ctx
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={sockname} peer={p}")
            try:
                if isinstance(p, tuple) and len(p) >= 2:
                    self._peer_host, self._peer_port = p[0], int(p[1])
                    if callable(self._on_peer_set_cb):
                        self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception:
                pass
            self._enable_os_keepalive(writer)
            rtt_rt.attach(
                send_ping_fn=lambda payload, _peer_id=peer_id: self._send_ping_frame_for_peer(_peer_id, payload),
                on_state_change=lambda connected, _peer_id=peer_id: self._on_state_change_for_peer(_peer_id, connected),
            )
            ctx["rx_task"] = self._loop.create_task(self._rx_pump_for_peer(peer_id))  # type: ignore[union-attr]
            self._update_server_overlay_connected()
            return

        # Replace any previous peer
        if self._writer is not None:
            try:
                self._writer.close()
                aw = getattr(self._writer, "wait_closed", None)
                if callable(aw): await aw()
            except Exception: pass

        self._reader, self._writer = reader, writer
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) accept: local={sockname} peer={p}")
        try:
            if isinstance(p, tuple) and len(p) >= 2:
                self._peer_host, self._peer_port = p[0], int(p[1])
        except Exception: pass

        self._enable_os_keepalive(writer)
        self._reset_counters()
        self._ensure_bp_task()

        # give RTT runtime the send function (PING)
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)

        # start RX and flush any buffered APP frames
        self._rx_task = self._loop.create_task(self._rx_pump())
        self._flush_early()

    def _ensure_connect_once(self) -> None:
        if self._connecting_task is not None or not self._peer_tuple or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _connect():
            await self._connect_to(host, port)
        self._connecting_task = self._loop.create_task(_connect())

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
                    if self._writer is not None:
                        return
                    await self._connect_to(host, port)
                    if self._writer is not None:
                        return
                    try:
                        await asyncio.sleep(delay)
                    except asyncio.CancelledError:
                        return
            finally:
                if self._reconnect_task is asyncio.current_task():
                    self._reconnect_task = None
        self._reconnect_task = self._loop.create_task(_reconnect())

    def request_reconnect(self) -> bool:
        if not self._peer_tuple or not self._run_flag:
            return False
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
        self._writer = None
        self._reader = None
        self._set_overlay_connected(False)
        self._start_reconnect_loop()
        return True

    def _enable_os_keepalive(self, writer: asyncio.StreamWriter) -> None:
        try:
            transport = writer.transport  # type: ignore[attr-defined]
            sock = transport.get_extra_info("socket") if transport else None
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._log.info(f"[TCP-SESSION] ({self._probe_id}) SO_KEEPALIVE=1 set")
        except Exception as e:
            self._log.debug(f"[TCP-SESSION] ({self._probe_id}) keepalive sockopt failed: {e!r}")

    async def _connect_to(self, host: str, port: int) -> None:
        if not self._run_flag:
            return
        try:
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) connecting to {host}:{port}")
            t0 = time.perf_counter()
            transport, _ = await loop.create_connection(lambda: protocol, host=host, port=int(port))
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            dt = (time.perf_counter() - t0) * 1000.0
            laddr = transport.get_extra_info("sockname")
            raddr = transport.get_extra_info("peername")
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) connected in {dt:.1f} ms local={laddr} peer={raddr}")

            self._reader, self._writer = reader, writer
            self._peer_host, self._peer_port = host, int(port)

            self._enable_os_keepalive(writer)
            self._reset_counters()
            self._ensure_bp_task()

            # attach RTT sender and start RX; buffered APP gets flushed
            self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
            self._rx_task = loop.create_task(self._rx_pump())
            self._flush_early()
        except Exception as e:
            self._log.warning(f"[TCP-SESSION] ({self._probe_id}) connect failed to {host}:{port}: {e!r}")
        finally:
            self._connecting_task = None

    # ---- RX/TX internals ----
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[TCP/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[TCP/CTR] ({self._probe_id}) {direction} "
            f"TX={self._tx_bytes} CRC32_TX=0x{self._tx_crc32:08x}  "
            f"RX={self._rx_bytes} CRC32_RX=0x{self._rx_crc32:08x}"
        )

    def _bump_tx(self, data: bytes) -> None:
        self._tx_bytes += len(data)
        self._tx_crc32 = self._zlib.crc32(data, self._tx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _bump_rx(self, data: bytes) -> None:
        self._rx_bytes += len(data)
        self._rx_crc32 = self._zlib.crc32(data, self._rx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _ensure_bp_task(self) -> None:
        """
        Ensure a single background drain() worker exists.

        Triggers:
        1) Size-based: if transport.get_write_buffer_size() >= self._wbuf_threshold
        2) Time-based: if _bp_latency_ms > 0 and there have been pending bytes
            for at least _bp_latency_ms; polled every _bp_poll_interval_s.

        Notes:
        - Works even if _bp_* attributes were not set in __init__ (defaults here).
        - Stops automatically when writer is gone or task is cancelled on stop().
        """
        if self._bp_task or not self._writer:
            return

        # Event used by size-based path (_maybe_signal_bp)
        self._bp_evt = asyncio.Event()

        # Safe defaults if caller didn't configure
        wbuf_threshold = int(getattr(self, "_wbuf_threshold", 128 * 1024))
        latency_ms = int(getattr(self, "_bp_latency_ms", 0))
        poll_s = float(getattr(self, "_bp_poll_interval_s", 0.05))
        latency_ns = int(max(0, latency_ms) * 1e6)

        async def _bp():
            try:
                # Track how long we've had *any* pending bytes.
                nonzero_since_ns = 0
                while self._run_flag and self._writer:
                    # Wait for either a size-based signal OR a short timeout to poll time-based condition
                    try:
                        await asyncio.wait_for(self._bp_evt.wait(), timeout=poll_s)
                        self._bp_evt.clear()
                    except asyncio.TimeoutError:
                        pass  # fall through to polling checks

                    writer = self._writer
                    if not writer:
                        break

                    transport = getattr(writer, "transport", None)  # type: ignore[attr-defined]
                    if not transport:
                        break

                    try:
                        wbs = transport.get_write_buffer_size()
                    except Exception:
                        wbs = 0

                    now_ns = time.monotonic_ns()

                    # Track the time window during which wbs > 0
                    if wbs > 0:
                        if nonzero_since_ns == 0:
                            nonzero_since_ns = now_ns
                    else:
                        nonzero_since_ns = 0  # reset when buffer empties

                    # Should we drain now?
                    do_drain = False
                    reason = ""
                    if wbs >= wbuf_threshold:
                        do_drain = True
                        reason = f"wbuf={wbs} thr={wbuf_threshold}"
                    elif latency_ns > 0 and nonzero_since_ns and (now_ns - nonzero_since_ns) >= latency_ns:
                        do_drain = True
                        waited_ms = (now_ns - nonzero_since_ns) / 1e6
                        reason = f"latency_ms={waited_ms:.1f} (>= {latency_ms})"

                    if do_drain:
                        try:
                            t0 = time.perf_counter()
                            await writer.drain()
                            dt = (time.perf_counter() - t0) * 1000.0
                            self._log.debug(f"[TCP/BP] ({self._probe_id}) drain() done in {dt:.2f} ms; reason: {reason}")
                        except Exception as e:
                            self._log.info(f"[TCP/BP] ({self._probe_id}) drain failed: {e!r}")
                            break

            except asyncio.CancelledError:
                return

        self._bp_task = self._loop.create_task(_bp())
        
    def _maybe_signal_bp(self) -> None:
        """
        Size-based path: if OS write buffer crosses threshold, poke the drain worker.
        Time-based path is handled inside _ensure_bp_task polling loop.
        """
        try:
            if not self._writer:
                return
            transport = self._writer.transport  # type: ignore[attr-defined]
            if not transport:
                return
            wbs = transport.get_write_buffer_size()
            thr = int(getattr(self, "_wbuf_threshold", 128 * 1024))
            if wbs >= thr and self._bp_evt:
                self._log.debug(f"[TCP/BP] ({self._probe_id}) signal drain; wbuf={wbs} thr={thr}")
                self._bp_evt.set()
        except Exception:
            pass

    def _buffer_early(self, wire_frame: bytes) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[TCP/TX] ({self._probe_id}) early-buf TTL expired; discarding {len(self._early_buf)}B")
            self._early_buf.clear()
        self._early_deadline = now + self._early_ttl

        over = (len(self._early_buf) + len(wire_frame)) - self._early_max
        if over > 0:
            drop = min(over, len(self._early_buf))
            if drop:
                del self._early_buf[:drop]
                self._log.info(f"[TCP/TX] ({self._probe_id}) early-buf capped: dropped={drop} keep={len(self._early_buf)} cap={self._early_max}")

        self._early_buf += wire_frame

    def _flush_early(self) -> None:
        if not self._early_buf or not self._writer:
            return
        try:
            n = len(self._early_buf)
            self._log.info(f"[TCP/TX] ({self._probe_id}) flushing early-buf bytes={n}")
            self._writer.write(self._early_buf)
            self._bump_tx(self._early_buf)
            self._maybe_signal_bp()
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_deadline = 0.0

    def _send_ping_frame(self, ping_payload: bytes) -> None:
        """
        Called by StreamRTTRuntime. Sends a PING control frame if TCP writer exists.
        """
        if not self._writer:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            self._log.debug(f"[TCP/TX] ({self._probe_id}) PING")
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PING write error: {e!r}")

    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._writer:
            return
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            self._log.debug(f"[TCP/TX] ({self._probe_id}) PONG")
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PONG write error: {e!r}")

    def _bump_tx_for_ctx(self, ctx: dict, data: bytes) -> None:
        ctx["tx_bytes"] = int(ctx.get("tx_bytes", 0) or 0) + len(data)
        ctx["tx_crc32"] = self._zlib.crc32(data, int(ctx.get("tx_crc32", 0) or 0)) & 0xFFFFFFFF

    def _bump_rx_for_ctx(self, ctx: dict, data: bytes) -> None:
        ctx["rx_bytes"] = int(ctx.get("rx_bytes", 0) or 0) + len(data)
        ctx["rx_crc32"] = self._zlib.crc32(data, int(ctx.get("rx_crc32", 0) or 0)) & 0xFFFFFFFF

    def _send_ping_frame_for_peer(self, peer_id: int, ping_payload: bytes) -> None:
        ctx = self._server_peers.get(peer_id)
        writer = ctx.get("writer") if isinstance(ctx, dict) else None
        if writer is None:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            writer.write(wire)
            self._bump_tx_for_ctx(ctx, wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PING write error peer_id={peer_id}: {e!r}")

    def _send_pong_frame_for_peer(self, peer_id: int, echo_tx_ns: int) -> None:
        ctx = self._server_peers.get(peer_id)
        writer = ctx.get("writer") if isinstance(ctx, dict) else None
        rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
        if writer is None or rtt is None:
            return
        body = bytes([self._K_PONG]) + rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        try:
            writer.write(wire)
            self._bump_tx_for_ctx(ctx, wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PONG write error peer_id={peer_id}: {e!r}")

    async def _rx_pump(self) -> None:
        self._log.debug(f"[TCP/RX] ({self._probe_id}) pump start")
        try:
            while True:
                # read 4B length
                hdr = await self._reader.readexactly(self._LEN.size)  # type: ignore[arg-type]
                if not hdr:
                    self._log.info(f"[TCP/RX] ({self._probe_id}) EOF on length")
                    break
                self._bump_rx(hdr)
                (n,) = self._LEN.unpack(hdr)
                if n <= 0:
                    continue

                body = await self._reader.readexactly(n)  # type: ignore[arg-type]
                self._bump_rx(body)
                kind = body[0]
                payload = body[1:]

                # per-direction meters
                if self._on_peer_rx:
                    try: self._on_peer_rx(len(hdr) + len(body))
                    except Exception: pass

                # demux kinds
                if kind == self._K_APP:
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try: self._on_app(payload)
                        except Exception as e:
                            self._log.debug(f"[TCP/RX] ({self._probe_id}) app callback err: {e!r}")
                elif kind == self._K_PING:
                    # payload must be 16 bytes (tx_ns, echo_ns)
                    if len(payload) >= 16:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                        self._log.debug(f"[TCP/RX] PING recv {tx_ns} {echo_ns}")                        
                        self._rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            # update our RTT immediately as a courtesy (optional)
                            self._rtt.on_pong_received(echo_ns)
                        # immediate PONG reflecting their tx_ns
                        self._send_pong_frame(tx_ns)
                    else:
                        self._log.debug(f"[TCP/RX] ({self._probe_id}) malformed PING len={len(payload)}")
                elif kind == self._K_PONG:
                    self._log.debug(f"[TCP/RX] PONG recv {len(payload)}")
                    if len(payload) >= 8:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                        self._log.debug(f"[TCP/RX] PONG recv {echo_tx_ns}")                        
                        self._rtt.on_pong_received(echo_tx_ns)
                        # state transition handled by runtime tick; this makes it near-immediate
                        if self._on_state:
                            # nudge UI quickly if this is the first success
                            was = self._overlay_connected
                            now = self._rtt.is_connected()
                            if now != was:
                                self._set_overlay_connected(now)
                    else:
                        self._log.debug(f"[TCP/RX] ({self._probe_id}) malformed PONG len={len(payload)}")
                else:
                    self._log.debug(f"[TCP/RX] ({self._probe_id}) unknown KIND=0x{kind:02x}, n={n}")
        except asyncio.IncompleteReadError as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) incomplete-read: expected={getattr(e,'expected',-1)} partial={len(getattr(e,'partial',b''))}")
        except asyncio.CancelledError:
            self._log.debug(f"[TCP/RX] ({self._probe_id}) cancelled")
            return
        except Exception as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) pump error: {e!r}")
        finally:
            # writer cleanup and reconnect policy
            try:
                if self._writer:
                    self._writer.close()
                    aw = getattr(self._writer, "wait_closed", None)
                    if callable(aw): await aw()
            except Exception: pass
            self._writer = None
            self._reader = None

            # overlay becomes disconnected (RTT view)
            self._set_overlay_connected(False)

            # client: attempt reconnect
            if self._peer_tuple:
                self._start_reconnect_loop()

            self._log.debug(f"[TCP/RX] ({self._probe_id}) pump stop")

    async def _rx_pump_for_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.get(peer_id)
        if not ctx:
            return
        reader = ctx.get("reader")
        writer = ctx.get("writer")
        rtt = ctx.get("rtt")
        self._log.debug(f"[TCP/RX] ({self._probe_id}) server pump start peer_id={peer_id}")
        try:
            while True:
                hdr = await reader.readexactly(self._LEN.size)
                if not hdr:
                    break
                self._bump_rx_for_ctx(ctx, hdr)
                (n,) = self._LEN.unpack(hdr)
                if n <= 0:
                    continue
                body = await reader.readexactly(n)
                self._bump_rx_for_ctx(ctx, body)
                kind = body[0]
                payload = body[1:]

                if self._on_peer_rx:
                    try: self._on_peer_rx(len(hdr) + len(body))
                    except Exception: pass

                if kind == self._K_APP:
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try:
                            rewritten = self._server_rewrite_inbound_app(peer_id, payload)
                            try: self._on_app(rewritten, peer_id=peer_id)
                            except TypeError: self._on_app(rewritten)
                        except Exception as e:
                            self._log.debug(f"[TCP/RX] ({self._probe_id}) server app callback err peer_id={peer_id}: {e!r}")
                elif kind == self._K_PING:
                    if len(payload) >= 16 and rtt is not None:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                        rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            rtt.on_pong_received(echo_ns)
                        self._send_pong_frame_for_peer(peer_id, tx_ns)
                elif kind == self._K_PONG:
                    if len(payload) >= 8 and rtt is not None:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                        rtt.on_pong_received(echo_tx_ns)
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) server pump error peer_id={peer_id}: {e!r}")
        finally:
            try:
                if writer:
                    writer.close()
                    aw = getattr(writer, "wait_closed", None)
                    if callable(aw): await aw()
            except Exception:
                pass
            await self._close_server_peer(peer_id)
            self._log.debug(f"[TCP/RX] ({self._probe_id}) server pump stop peer_id={peer_id}")

    # ---- overlay state (RTT-driven) ----
    def _on_rtt_state_change(self, connected: bool) -> None:
        # Called by RTT runtime tick
        prev = self._overlay_connected
        if connected != prev:
            self._log.info(f"[WS/GUARD] ({self._probe_id}) RTT state flip: {'CONNECTED' if connected else 'DISCONNECTED'}")
        self._set_overlay_connected(connected)


    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} (RTT)")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

    def _on_state_change_for_peer(self, peer_id: int, connected: bool) -> None:
        ctx = self._server_peers.get(peer_id)
        if ctx is not None:
            ctx["connected"] = bool(connected)
        self._update_server_overlay_connected()

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        self._server_unregister_peer_channels(peer_id)
        rtt_rt = ctx.get("rtt_rt")
        if rtt_rt is not None:
            with contextlib.suppress(Exception):
                rtt_rt.detach()
        rx_task = ctx.get("rx_task")
        if rx_task and rx_task is not asyncio.current_task():
            rx_task.cancel()
        writer = ctx.get("writer")
        if writer is self._writer:
            self._writer = None
            self._reader = None
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception:
                pass
        try:
            if writer:
                writer.close()
                aw = getattr(writer, "wait_closed", None)
                if callable(aw): await aw()
        except Exception:
            pass
        self._update_server_overlay_connected()
