from __future__ import annotations

from . import bridge as _bridge

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

class StatsBoard:
    """
    Dashboard + statistics aggregator.

    Responsibilities:
      - Encapsulate UI flags via register_cli()
      - Track byte counters and state
      - Render dashboard / line output periodically (status task)
      - Consume events from Runner (on_* methods)
      - Read RTT/inflight from a Session reference
    """

    # ---- CLI integration -------------------------------------------------------
    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        """
        Register only the UI-related flags so other classes remain unaware.
        Mirrors previous defaults/behavior.
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--status'):
            # Keep previous behavior: status enabled by default.
            p.add_argument('--status', action='store_true', default=True,
                           help='enable periodic status (default: on)')
        if not _has('--no-dashboard'):
            p.add_argument('--no-dashboard', action='store_true',
                           help='disable non-scrolling dashboard (print multiline blocks instead)')

    # ---- lifecycle & state -----------------------------------------------------
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("stats_board")
        DebugLoggingConfigurator.debug_logger_status(self.log)

        # References provided by Runner
        self.session: Optional[Session] = None     # for RTT/inflight/ACK counters
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

        # UI cosmetics
        self._dashboard_enabled = not args.no_dashboard
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
    def set_session_ref(self, s: Optional[Session]) -> None:
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
        if not getattr(self.args, "status", True):
            return
        if self._dashboard_enabled:
            sys.stdout.write(ANSI_HIDE_CURSOR)
            sys.stdout.flush()
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
        if self._dashboard_enabled:
            sys.stdout.write(ANSI_SHOW_CURSOR)
            sys.stdout.flush()

    # ---- helpers moved from Runner (unchanged strings) ------------------------
    def _summarize_local_sides(self, a: argparse.Namespace) -> str:
#        if a.udp_role == 'server':
#            udp = f"UDP srv {a.udp_listen_bind}:{a.udp_own_port}"
#        else:
#            udp = f"UDP cli -> {a.udp_target_host}:{a.udp_target_port} (bind {a.udp_bind}:ephem)"
#        if a.tcp_role == 'server':
#            tcp = f"TCP srv {a.tcp_listen_bind}:{a.tcp_own_port}"
#        else:
#            tcp = f"TCP cli -> {a.tcp_target_host}:{a.tcp_target_port} (bind {a.tcp_bind}:ephem)"
#        return f"{udp}\n {tcp}"
        return f""

    def _render_retx_stats(self) -> str:
        s = self.session
        if not s:
            return ""
        h = s.stats_hist
        confirmed = max(1, int(h.get('confirmed_total', 0)))
        def pct(n): return (100.0 * float(h.get(n, 0))) / confirmed
        return (
            "Retransmit distribution (confirmed app DATA only)\n"
            f" once : {h.get('once', 0):6d} ({pct('once'):5.1f}%)\n"
            f" twice : {h.get('twice', 0):6d} ({pct('twice'):5.1f}%)\n"
            f" thrice : {h.get('thrice', 0):6d} ({pct('thrice'):5.1f}%)\n"
            f" > three: {h.get('gt3', 0):6d} ({pct('gt3'):5.1f}%)\n"
            f" confirmed / created : {h.get('confirmed_total', 0)} / {h.get('created_total', 0)}"
        )

    def _render_error_counters(self) -> str:
        unknown = 0
        pp = self.peer_proto
        if pp is not None and hasattr(pp, "unidentified_frames"):
            try:
                unknown = int(getattr(pp, "unidentified_frames", 0))
            except Exception:
                pass
        return (
            "----------------------------------------------------------------\n"
            f"Decode errors: Unidentified frames={unknown}\n"
        )

    def _render_status_block(
        self,
        dt: float,
        app_rx_r: float,
        app_tx_r: float,
        peer_rx_r: float,
        peer_tx_r: float,
        *,
        compact: bool,
    ) -> str:
        """
        Unified renderer for both dashboard and line-by-line modes.
        If compact=True -> minimal header/title and no ANSI/non-scrolling tips.
        If compact=False -> full dashboard title and footer.
        """
        s = self.session
        kb_tot = 1024.0
        now_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        m = self.session_get_metrics()
        last_ok = (
            ((self.session.last_rtt_ok_ns if self.session else 0) or 0)
            or (m.last_rtt_ok_ns or 0)
            or self._last_rtt_ok_ns
        )
        age_str = f"{max(0.0, (now_ns() - last_ok)/1e9):0.1f}s ago" if last_ok else "—"

        udp_count = self.mux.udp_open_count() if self.mux else 0
        tcp_count = self.mux.tcp_open_count() if self.mux else 0
        tun_count = self.mux.tun_open_count() if self.mux and hasattr(self.mux, "tun_open_count") else 0

        def _fmt(v, nd=None):
            if v is None:
                return "n/a"
            if isinstance(v, float) and nd is not None:
                return f"{v:.{nd}f}"
            return str(v)

        title = (
            "UDP/TCP Multiplexed Transfer — DASHBOARD (non-scrolling)\n"
            "----------------------------------------------------------------\n"
            if not compact else
            "=== STATUS =======================================================\n"
        )

        header = (
            f"Updated: {now_s} (Δ~{dt:.1f}s) "
            f"Peer State: {self._conn_state} "
            f"Last RTT OK: {age_str}\n"
            f"Overlay bind : {self._overlay_bind_str}\n"
            f"Overlay peer : {self._overlay_peer_str}\n"
            f"Local I/F : {self._local_side_str}\n"
            f"Open Conns : UDP={udp_count} TCP={tcp_count}\n"
        )

        # RTT + flow (transport-agnostic: values may be 'n/a' on TCP)
        rtt_and_flow = (
            f"RTT(ms): "
            f"cur={_fmt(m.rtt_sample_ms, 1)} "
            f"est={_fmt(m.rtt_est_ms, 1)} "
        )
        if m.transmit_delay_sample_ms is not None or m.transmit_delay_est_ms is not None:
            rtt_and_flow += (
                f"TXDLY(ms): "
                f"cur={_fmt(m.transmit_delay_sample_ms, 1)} "
                f"est={_fmt(m.transmit_delay_est_ms, 1)} "
            )
        if s:
           rtt_and_flow += ( 
                f"inflight={_fmt(m.inflight)}/{_fmt(m.max_inflight)} "
                f"waiting={_fmt(m.waiting_count)}\n"
                f"ACKed={_fmt(m.last_ack_peer)} "
                f"sent_ctr={_fmt(m.last_sent_ctr)} "
                f"expected={_fmt(m.expected)} "
                f"peer_missed={_fmt(m.peer_missed_count)} "
                f"our_missed={_fmt(m.our_missed_count)}"
           )
        rtt_and_flow += ( f"\n" )
    
        meters = (
            "----------------------------------------------------------------\n"
            f"App I/F : RX={app_rx_r:7.1f} kB/s TX={app_tx_r:7.1f} kB/s "
            f"(tot RX={self.app_rx_total/kb_tot:,.0f} kB, TX={self.app_tx_total/kb_tot:,.0f} kB)\n"
            f"Peer I/F: RX={peer_rx_r:7.1f} kB/s TX={peer_tx_r:7.1f} kB/s "
            f"(tot RX={self.peer_rx_total/kb_tot:,.0f} kB, TX={self.peer_tx_total/kb_tot:,.0f} kB)\n"
        )

        errors = self._render_error_counters()
        retx = "----------------------------------------------------------------\n" + self._render_retx_stats() + "\n"

        footer = (
            "----------------------------------------------------------------\n"
            "Press Ctrl+C to exit. Use --no-dashboard to switch to line-by-line output.\n"
            if not compact else
            "=================================================================\n"
        )

        return (title + header + rtt_and_flow + meters + errors + retx + footer)

    def _render_dashboard(
        self,
        dt: float,
        app_rx_r: float,
        app_tx_r: float,
        peer_rx_r: float,
        peer_tx_r: float
    ) -> str:
        # Keep existing call sites: delegate to unified renderer
        return self._render_status_block(
            dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r, compact=False
        )

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

                if self._dashboard_enabled:
                    sys.stdout.write(ANSI_HOME_CLEAR)
                    sys.stdout.write(self._render_dashboard(dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r))
                    sys.stdout.flush()
                else:
                    # Reuse the unified renderer in compact mode (no ANSI, concise title/footer)
                    block = self._render_status_block(
                        dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r, compact=True
                    )
                    print(block, flush=True)

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
            ((self.session.last_rtt_ok_ns if self.session else 0) or 0)
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
