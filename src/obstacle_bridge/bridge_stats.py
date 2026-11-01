from __future__ import annotations

from ._bridge_import import export_bridge_globals

_bridge = export_bridge_globals(globals())

class StatsBoard:
    """
    WebAdmin statistics aggregator.

    Responsibilities:
      - Track byte counters and state
      - Sample aggregate rates periodically for status snapshots
      - Consume events from Runner (on_* methods)
      - Read RTT/inflight from a myUDP2 transport reference
    """

    # ---- lifecycle & state -----------------------------------------------------
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("stats_board")
        DebugLoggingConfigurator.debug_logger_status(self.log)

        # References provided by Runner
        self.session: Optional[MyUDP2Session] = None     # for RTT/inflight/ACK counters
        self._status_session: Optional[ISession] = None
        self.mux: Optional["ChannelMux"] = None         # for open connection counts
        self.peer_proto: Optional[PeerProtocol] = None  # for decode error counters (optional)

        # Task control
        self._stop_evt = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

        # Throughput totals
        self.app_rx_total = 0  # local->peer (overlay direction)
        self.app_tx_total = 0  # peer->local (local sockets direction)
        self.peer_rx_total = 0
        self.peer_tx_total = 0

        self._last_app_rx_rate_kbps = 0.0
        self._last_app_tx_rate_kbps = 0.0
        self._last_peer_rx_rate_kbps = 0.0
        self._last_peer_tx_rate_kbps = 0.0

        # Rate snapshot
        self._last_meter_ts = time.time()
        self._last_app_rx = 0
        self._last_app_tx = 0
        self._last_peer_rx = 0
        self._last_peer_tx = 0

        # Status presentation is owned by WebAdmin; retain only snapshot data.
        self._overlay_peer_str = "n/a"
        first_transport = str(getattr(args, "overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
        self._has_fixed_overlay_peer = _has_configured_overlay_peer(args, first_transport)
        bind_attr, _, _, listen_port_attr = _overlay_cli_attrs(first_transport)
        bind_val = getattr(args, bind_attr, "::")
        default_listen_port = {"myudp": 4433, "tcp": 8081, "quic": 443, "ws": 8080}.get(first_transport, 4433)
        listen_port = int(getattr(args, listen_port_attr, default_listen_port))
        self._overlay_bind_str = f"{bind_val}:{listen_port}"
        if self._has_fixed_overlay_peer:
            self._overlay_peer_str = "—"
        self._local_side_str = self._summarize_local_sides(args)

        # Connection state
        self._conn_state = STATE_DISCONNECTED
        self._last_rtt_ok_ns: int = 0

        self.session_is_connected = lambda: False
        self.session_get_metrics  = lambda: SessionMetrics()
        self.session_get_connection_failure = lambda: {
            "failed": False,
            "reason": None,
            "detail": None,
            "unix_ts": None,
            "last_event": "",
            "last_event_unix_ts": None,
            "transport": None,
        }

    # ---- wiring from Runner ----------------------------------------------------
    def set_session_ref(self, s: Optional[MyUDP2Session]) -> None:
        self.session = s

    def set_mux_ref(self, m: Optional["ChannelMux"]) -> None:
        self.mux = m

    def set_peer_proto(self, pp: Optional[PeerProtocol]) -> None:
        self.peer_proto = pp

    # ---- event sinks (Runner calls these) -------------------------------------
    def on_peer_set(self, host: str, port: int) -> None:
        if not self._has_fixed_overlay_peer:
            self._overlay_peer_str = "n/a"
            return
        self._overlay_peer_str = f"[{host}]:{port}" if ':' in host and not host.startswith('[') else f"{host}:{port}"
        self.log.debug(f"on_peer_set({host} {port} )")

    def on_state_change(self, connected: bool) -> None:
        self.log.debug(f"on_state_change({self._conn_state} -> {connected})")
        self._conn_state = STATE_CONNECTED if connected else STATE_DISCONNECTED

    def on_rtt_success(self, echo_tx_ns: int) -> None:
        self._last_rtt_ok_ns = now_ns()
        self.log.debug(f"on_rtt_success({echo_tx_ns})")

    def on_peer_rx_bytes(self, n: int) -> None:
        self.peer_rx_total += n
        self.log.debug(f"on_peer_rx_bytes(+{int(n)})")

    def on_peer_tx_bytes(self, n: int) -> None:
        self.peer_tx_total += n
        self.log.debug(f"on_peer_tx_bytes(+{int(n)})")

    def on_app_rx_bytes(self, n: int) -> None:
        self.app_rx_total += n
        self.log.debug(f"on_app_rx_bytes(+{int(n)})")

    def on_app_tx_bytes(self, n: int) -> None:        
        self.app_tx_total += n
        self.log.debug(f"on_app_tx_bytes(+{int(n)})")


    def bind_session(self, session: ISession):
        self._status_session = session
        self.session_is_connected = session.is_connected
        self.session_get_metrics  = session.get_metrics
        getter = getattr(session, "get_connection_failure_snapshot", None)
        if callable(getter):
            self.session_get_connection_failure = getter
        else:
            self.session_get_connection_failure = lambda: {
                "failed": False,
                "reason": None,
                "detail": None,
                "unix_ts": None,
                "last_event": "",
                "last_event_unix_ts": None,
                "transport": None,
            }


    # ---- lifecycle (status task) ----------------------------------------------
    async def start(self) -> None:
        if self._task is None:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._status_task_fn())

    async def stop(self) -> None:
        self._stop_evt.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
    # ---- snapshot helpers ------------------------------------------------------
    def _summarize_local_sides(self, a: argparse.Namespace) -> str:
        return f""

    async def _status_task_fn(self) -> None:
        try:
            while not self._stop_evt.is_set():
                await asyncio.sleep(1.0)
                now_t = time.time()
                dt = max(1e-6, now_t - self._last_meter_ts)
                da_rx = self.app_rx_total - self._last_app_rx
                da_tx = self.app_tx_total - self._last_app_tx
                dp_rx = self.peer_rx_total - self._last_peer_rx
                dp_tx = self.peer_tx_total - self._last_peer_tx
                kb = 1024.0
                app_rx_r = da_rx / kb / dt
                app_tx_r = da_tx / kb / dt
                peer_rx_r = dp_rx / kb / dt
                peer_tx_r = dp_tx / kb / dt
                self._last_meter_ts = now_t
                self._last_app_rx = self.app_rx_total
                self._last_app_tx = self.app_tx_total
                self._last_peer_rx = self.peer_rx_total
                self._last_peer_tx = self.peer_tx_total

                self._last_app_rx_rate_kbps = app_rx_r
                self._last_app_tx_rate_kbps = app_tx_r
                self._last_peer_rx_rate_kbps = peer_rx_r
                self._last_peer_tx_rate_kbps = peer_tx_r

                self._conn_state = STATE_CONNECTED if self.session_is_connected() else STATE_DISCONNECTED

        except asyncio.CancelledError:
            return
    def snapshot_status(self) -> dict:
        """
        Machine-readable snapshot of the same data shown in the text dashboard.
        Safe to call from the admin web handler.
        """
        kb_tot = 1024.0
        now_wall = time.time()
        now_ns_v = now_ns()

        m = self.session_get_metrics()

        last_ok = (
            ((getattr(self.session, "last_rtt_ok_ns", 0) if self.session else 0) or 0)
            or (m.last_rtt_ok_ns or 0)
            or self._last_rtt_ok_ns
        )
        last_rtt_ok_age_sec = ((now_ns_v - last_ok) / 1e9) if last_ok else None

        udp_count = self.mux.udp_open_count() if self.mux else 0
        tcp_count = self.mux.tcp_open_count() if self.mux else 0
        tun_count = self.mux.tun_open_count() if self.mux and hasattr(self.mux, "tun_open_count") else 0

        def _num(v):
            return None if v is None else v

        hist = dict(getattr(self.session, "stats_hist", {}) or {})
        repeated_multiple = int(hist.get("thrice", 0)) + int(hist.get("gt3", 0))
        failure = dict(self.session_get_connection_failure() or {})
        peer_state = self._conn_state
        if peer_state != STATE_CONNECTED and bool(failure.get("failed")):
            peer_state = STATE_FAILED

        return {
            "updated_unix_ts": now_wall,
            "peer_state": peer_state,
            "overlay": {
                "bind": self._overlay_bind_str,
                "peer": self._overlay_peer_str,
                "local_side": self._local_side_str,
            },
            "connection_failure_reason": failure.get("reason"),
            "connection_failure_detail": failure.get("detail"),
            "connection_failure_unix_ts": failure.get("unix_ts"),
            "connection_last_event": failure.get("last_event") or "",
            "connection_last_event_unix_ts": failure.get("last_event_unix_ts"),
            "connection_failure_transport": failure.get("transport"),
            "open_connections": {
                "udp": int(udp_count),
                "tcp": int(tcp_count),
                "tun": int(tun_count),
            },
            "traffic": {
                "app": {
                    "rx_total_bytes": int(self.app_rx_total),
                    "tx_total_bytes": int(self.app_tx_total),
                    "rx_total_kb": self.app_rx_total / kb_tot,
                    "tx_total_kb": self.app_tx_total / kb_tot,
                },
                "peer": {
                    "rx_total_bytes": int(self.peer_rx_total),
                    "tx_total_bytes": int(self.peer_tx_total),
                    "rx_total_kb": self.peer_rx_total / kb_tot,
                    "tx_total_kb": self.peer_tx_total / kb_tot,
                },
                "rates_kBps": {
                    "app_rx": self._last_app_rx_rate_kbps,
                    "app_tx": self._last_app_tx_rate_kbps,
                    "peer_rx": self._last_peer_rx_rate_kbps,
                    "peer_tx": self._last_peer_tx_rate_kbps,
                },
            },
            "transport": {
                "last_rtt_ok_age_sec": last_rtt_ok_age_sec,
                "rtt_sample_ms": _num(m.rtt_sample_ms),
                "rtt_est_ms": _num(m.rtt_est_ms),
                "transmit_delay_sample_ms": _num(m.transmit_delay_sample_ms),
                "transmit_delay_est_ms": _num(m.transmit_delay_est_ms),
                "inflight": _num(m.inflight),
                "max_inflight": _num(m.max_inflight),
                "waiting_count": _num(m.waiting_count),
                "last_ack_peer": _num(m.last_ack_peer),
                "last_sent_ctr": _num(m.last_sent_ctr),
                "expected": _num(m.expected),
                "peer_missed_count": _num(m.peer_missed_count),
                "our_missed_count": _num(m.our_missed_count),
                "batch_datagrams_sent": _num(m.batch_datagrams_sent),
                "batch_chunks_sent": _num(m.batch_chunks_sent),
                "batch_datagrams_received": _num(m.batch_datagrams_received),
                "batch_chunks_received": _num(m.batch_chunks_received),
                "malformed_batches": _num(m.malformed_batches),
                "batch_stream_bytes_sent": _num(m.batch_stream_bytes_sent),
                "batch_stream_bytes_received": _num(m.batch_stream_bytes_received),
                "queued_stream_bytes": _num(m.queued_stream_bytes),
                "stream_queue_age_ms": _num(m.stream_queue_age_ms),
                "retransmitted_chunks": _num(m.retransmitted_chunks),
                "stream_decode_errors": _num(m.stream_decode_errors),
                "frames_to_securelink": _num(m.frames_to_securelink),
                "frames_from_securelink": _num(m.frames_from_securelink),
            },
            "myudp": {
                "retransmit": {
                    "created_total": int(hist.get("created_total", 0)),
                    "confirmed_total": int(hist.get("confirmed_total", 0)),
                    "first_pass": int(hist.get("once", 0)),
                    "repeated_once": int(hist.get("twice", 0)),
                    "repeated_multiple": repeated_multiple,
                    "repeated_three_times": int(hist.get("thrice", 0)),
                    "repeated_over_three_times": int(hist.get("gt3", 0)),
                },
            },
        }
        
        self.log.debug(
            "[STATS/SNAPSHOT] peer_state=%s overlay_peer=%s "
            "peer_rx=%d peer_tx=%d app_rx=%d app_tx=%d rtt_est_ms=%s",
            payload["peer_state"],
            payload["overlay"]["peer"],
            payload["traffic"]["peer"]["rx_total_bytes"],
            payload["traffic"]["peer"]["tx_total_bytes"],
            payload["traffic"]["app"]["rx_total_bytes"],
            payload["traffic"]["app"]["tx_total_bytes"],
            payload["transport"]["rtt_est_ms"],
        )

# ============================================================================
