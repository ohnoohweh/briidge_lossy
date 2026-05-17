from __future__ import annotations

from . import bridge as _bridge

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

class RunnerMuxAggregate:
    def __init__(self, muxes: List["ChannelMux"]):
        self._muxes = list(muxes)

    def udp_open_count(self) -> int:
        return sum(m.udp_open_count() for m in self._muxes)

    def tcp_open_count(self) -> int:
        return sum(m.tcp_open_count() for m in self._muxes)

    def tun_open_count(self) -> int:
        total = 0
        for mux in self._muxes:
            getter = getattr(mux, "tun_open_count", None)
            if callable(getter):
                total += int(getter())
        return total

    def snapshot_connections(self) -> dict:
        udp_rows: list[dict] = []
        tcp_rows: list[dict] = []
        tun_rows: list[dict] = []
        udp_listening = 0
        tcp_listening = 0
        tun_listening = 0
        for mux in self._muxes:
            snap = mux.snapshot_connections()
            udp_rows.extend(snap.get("udp", []))
            tcp_rows.extend(snap.get("tcp", []))
            tun_rows.extend(snap.get("tun", []))
            counts = snap.get("counts", {}) or {}
            udp_listening += int(counts.get("udp_listening", 0) or 0)
            tcp_listening += int(counts.get("tcp_listening", 0) or 0)
            tun_listening += int(counts.get("tun_listening", 0) or 0)
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "tun": tun_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "tun": len(tun_rows) - tun_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
                "tun_listening": tun_listening,
            },
        }

    @staticmethod
    def _default_secure_link_snapshot() -> dict:
        return {
            "enabled": False,
            "mode": "off",
            "state": "disabled",
            "authenticated": False,
            "session_id": None,
            "rekey_in_progress": False,
            "last_rekey_trigger": "",
            "rekey_due_unix_ts": None,
            "failure_code": None,
            "failure_reason": None,
            "failure_detail": None,
            "failure_unix_ts": None,
            "failure_session_id": None,
            "consecutive_failures": 0,
            "retry_backoff_sec": 0.0,
            "next_retry_unix_ts": None,
            "recovery_enabled": False,
            "recovery_delay_sec": 0.0,
            "recovery_reconnect_sec": 0.0,
            "next_recovery_reconnect_unix_ts": None,
            "handshake_attempts_total": 0,
            "last_event": "",
            "last_event_unix_ts": None,
            "last_authenticated_unix_ts": None,
            "connected_since_unix_ts": None,
            "authenticated_sessions_total": 0,
            "rekeys_completed_total": 0,
            "transport": None,
            "active_material_generation": 0,
            "last_material_reload_unix_ts": None,
            "last_material_reload_scope": "",
            "last_material_reload_result": "",
            "last_material_reload_detail": "",
            "trust_enforced_unix_ts": None,
            "disconnect_reason": "",
            "disconnect_detail": "",
        }

    @staticmethod
    def _default_compress_layer_snapshot() -> dict:
        return {
            "enabled": False,
            "algorithm": "",
            "transport": None,
            "level": 0,
            "min_bytes": 0,
            "compress_attempts_total": 0,
            "compress_applied_total": 0,
            "compress_skipped_no_gain_total": 0,
            "compress_input_bytes_total": 0,
            "compress_output_bytes_total": 0,
            "decompress_ok_total": 0,
            "decompress_fail_total": 0,
        }


class Runner:
    """
    Thin orchestrator: wires ISession + ChannelMux + StatsBoard and manages lifecycle.
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("runner")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self._stop: Optional[asyncio.Event] = None
        self._stop_requested = False
        self._session_obj: Optional[ISession] = None
        self.mux: Optional["ChannelMux"] = None
        self._sessions: List[ISession] = []
        self._muxes: List["ChannelMux"] = []
        self._session_labels: List[str] = []
        self.stats = StatsBoard(args )
        self.admin_web = None
        self._restart_requested: Optional[asyncio.Event] = None
        self._restart_requested_flag = False
        self._restart_exit_code: int = RESTART_EXIT_CODE_IMMEDIATE
        self._shutdown_exit_code: Optional[int] = None
        self._last_connected_monotonic: Optional[float] = None
        self._last_disconnected_monotonic: Optional[float] = None
        self._client_restart_watchdog_task: Optional[asyncio.Task] = None        
        self._peer_traffic_rate_state: Dict[str, Tuple[float, int, int]] = {}

    def _ensure_runtime_events(self) -> None:
        if self._stop is None:
            self._stop = asyncio.Event()
        if self._stop_requested:
            self._stop.set()
        if self._restart_requested is None:
            self._restart_requested = asyncio.Event()
        if self._restart_requested_flag:
            self._restart_requested.set()

    async def start(self) -> None:
        ios_admin_ui = str(_admin_ui_platform()).strip().lower() == "ios"
        self.log.debug("[SERVER] Runner start on session id=%x", id(self))
        self.log.info(
            "[SERVER] ObstacleBridge build=%r crypto_extract=%r",
            _detect_build_info(),
            available_crypto_extract(),
        )
        self._ensure_runtime_events()

        # Make the local admin UI available before overlay/session startup can
        # block on network state. This is especially important for iOS packet
        # tunnel providers where WebAdmin is the recovery/config surface.
        if getattr(self.args, "admin_web", False) and self.admin_web is None:
            self.admin_web = AdminWebUI(self.args, self)
            await self.admin_web.start()

        loop = asyncio.get_running_loop()
        transport_sessions = Runner.build_sessions_from_overlay(self.args)
        self._sessions = []
        self._muxes = []
        self._session_labels = []
        for transport_name, session in transport_sessions:
            session.set_on_state_change(lambda connected, transport_name=transport_name, session=session: self._on_state_change(transport_name, session, connected))
            # Keep status snapshot callbacks wired on iOS too. We still disable
            # the terminal dashboard there, but WebAdmin's /api/status needs
            # the learned peer endpoint and traffic counters to reflect the
            # active overlay session.
            session.set_on_peer_rx(self.stats.on_peer_rx_bytes)
            session.set_on_peer_tx(self.stats.on_peer_tx_bytes)
            session.set_on_peer_set(self.stats.on_peer_set)
            mux = ChannelMux.from_args(
                session,
                loop,
                self.args,
                on_local_rx_bytes=self.stats.on_app_rx_bytes,
                on_local_tx_bytes=self.stats.on_app_tx_bytes
            )
            self._sessions.append(session)
            self._muxes.append(mux)
            self._session_labels.append(transport_name)
            session.set_on_transport_epoch_change(
                lambda epoch, transport_name=transport_name, session=session, mux=mux:
                    self._on_transport_epoch_change(transport_name, session, mux, epoch)
            )
            await session.start()
            await mux.start()

        self._session_obj = self._sessions[0] if self._sessions else None
        self.stats.bind_session(self._session_obj)
        if self._muxes:
            self.mux = RunnerMuxAggregate(self._muxes)
        else:
            self.mux = None

        
        # 4) Provide references to StatsBoard and start it
        # For UDP overlays we still expose the inner Session (to render retransmit histograms).
        # For TCP overlays this will be None and the board will omit that section.
        inner = None
        real = getattr(self._session_obj, "_real", self._session_obj)  # unwrap SessionDebugShim if present

        try:
            if isinstance(real, UdpSession):
                self.stats.set_peer_proto(real.peer_proto)
        except Exception:
            pass

        if not ios_admin_ui:
            if isinstance(real, UdpSession):
                inner = real.inner_session
            self.stats.set_session_ref(inner)  # now the dashboard can show inflight/ACKed/etc.
            self.stats.set_mux_ref(self.mux)
            if self.args.status:
                await self.stats.start()
        else:
            self.log.info("[SERVER] iOS admin UI detected; stats board disabled")

        self._last_connected_monotonic = time.monotonic() if self._session_obj and self._session_obj.is_connected() else None
        self._last_disconnected_monotonic = None if self._session_obj and self._session_obj.is_connected() else time.monotonic()

        self._client_restart_watchdog_task = asyncio.create_task(
            self._client_restart_watchdog()
        )

    async def run(self):
        self.log.debug("[SERVER] Run entered")
        await self.start()
        self.log.debug("[SERVER] Run after start")

        assert self._stop is not None
        assert self._restart_requested is not None
        stop_task = asyncio.create_task(self._stop.wait())
        restart_task = asyncio.create_task(self._restart_requested.wait())

        try:
            done, pending = await asyncio.wait(
                [stop_task, restart_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            self.log.debug("[SERVER] Run Terminating Event")

            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        finally:
            try:
                self.log.debug("[RUNNER] wait for stop with 2.0 timeout")
                await asyncio.wait_for(self.stop(), timeout=2.0)
            except Exception:
                self.log.debug("[RUNNER] stop timed out during restart")

        if self._restart_requested is not None and self._restart_requested.is_set():
            self.log.warning("[RUNNER] exiting rc=%d", int(self._restart_exit_code))
            raise SystemExit(int(self._restart_exit_code))

        if self._shutdown_exit_code is not None:
            self.log.warning("[RUNNER] exiting rc=%d", self._shutdown_exit_code)
            raise SystemExit(self._shutdown_exit_code)

        self.log.debug("[RUNNER] Leaving stop")


    async def stop(self):
        self.log.debug("[SERVER] Stop entered")

        async def _run_stop_step(label: str, awaitable, timeout_s: float = 5.0) -> None:
            started = time.monotonic()
            try:
                await asyncio.wait_for(awaitable, timeout=timeout_s)
                self.log.info(
                    "[RUNNER] stop step %s completed duration_ms=%.1f",
                    label,
                    (time.monotonic() - started) * 1000.0,
                )
            except asyncio.TimeoutError:
                self.log.warning(
                    "[RUNNER] stop step %s timed out after %.1fs",
                    label,
                    timeout_s,
                )
            except Exception:
                self.log.exception("[RUNNER] stop step %s failed", label)

        if self._client_restart_watchdog_task is not None:
            self._client_restart_watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._client_restart_watchdog_task
            self._client_restart_watchdog_task = None
        if self.admin_web is not None:
            await _run_stop_step("admin_web.stop", self.admin_web.stop(), timeout_s=2.0)
            self.admin_web = None        
        if self._stop is not None:
            self._stop.set()

        self.log.debug("[RUNNER] stop: entering stats.stop")
        await _run_stop_step("stats.stop", self.stats.stop(), timeout_s=2.0)

        self.log.debug("[RUNNER] stop: entering mux.stop")
        for idx, mux in enumerate(reversed(self._muxes)):
            await _run_stop_step(f"mux.stop[{idx}]", mux.stop(), timeout_s=5.0)

        self.log.debug("[RUNNER] stop: entering _session_obj")
        for idx, session in enumerate(reversed(self._sessions)):
            await _run_stop_step(f"session.stop[{idx}]", session.stop(), timeout_s=5.0)
        self.log.debug("[RUNNER] stop leaving")


    # ---- overlay state propagation (unchanged behavior) -----------------------
    def _on_state_change(self, transport_name: str, session: ISession, connected: bool):
        self.log.debug(f"[SERVER] _on_state_change transport={transport_name} connected={connected}")

        now_mono = time.monotonic()
        aggregate_connected = any(s.is_connected() for s in self._sessions) if self._sessions else connected
        if aggregate_connected:
            self._last_connected_monotonic = now_mono
            self._last_disconnected_monotonic = None
        else:
            if self._last_disconnected_monotonic is None:
                self._last_disconnected_monotonic = now_mono        
        # Update board
        self.stats.on_state_change(aggregate_connected)
        # Inform mux
        mux = None
        try:
            idx = self._sessions.index(session)
            mux = self._muxes[idx]
        except Exception:
            mux = None
        if mux:
            try:
                asyncio.get_running_loop().create_task(mux.on_overlay_state(connected))
            except RuntimeError:
                pass
        # Reset reliability sender state on disconnect so reconnect starts clean.
        if not aggregate_connected:
            resetter = getattr(session, "reset_sender", None)
            if callable(resetter):
                with contextlib.suppress(Exception):
                    resetter()

    def _on_transport_epoch_change(self, transport_name: str, session: ISession, mux: "ChannelMux", epoch: int) -> None:
        self.log.info(
            "[SERVER] transport epoch changed transport=%s session=%x epoch=%d",
            transport_name,
            id(session),
            epoch,
        )
        try:
            asyncio.get_running_loop().create_task(mux.on_transport_epoch_change(epoch))
        except RuntimeError:
            pass

    def _restart_requires_delay(self) -> bool:
        raw = str(getattr(self.args, "overlay_transport", "") or "")
        parts = [item.strip().lower() for item in raw.split(",") if item.strip()]
        return "myudp" in parts

    def request_restart(self) -> None:
        self.log.debug("[SERVER] Runner restart requested")
        callback = getattr(self, "_embedded_restart_callback", None)
        if callable(callback):
            self.log.debug("[SERVER] dispatching embedded restart callback")
            try:
                result = callback()
            except Exception:
                self.log.exception("[SERVER] embedded restart callback failed")
            else:
                if inspect.isawaitable(result):
                    try:
                        asyncio.get_running_loop().create_task(result)
                    except RuntimeError:
                        self.log.exception("[SERVER] no running loop for embedded restart callback")
            return
        self._restart_requested_flag = True
        self._restart_exit_code = RESTART_EXIT_CODE_DELAYED if self._restart_requires_delay() else RESTART_EXIT_CODE_IMMEDIATE
        if self._restart_requested is not None:
            self._restart_requested.set()

    def request_overlay_reconnect(self, target_peer_id: Optional[str] = None) -> dict:
        target = str(target_peer_id or "").strip()
        requested = 0
        sessions = 0
        transports: list[str] = []
        matched_target = False
        for idx, session in enumerate(self._sessions):
            sessions += 1
            peer_row_ids = self._session_peer_row_ids(idx, session)
            if target:
                if target not in peer_row_ids:
                    continue
                matched_target = True
            method = getattr(session, "request_reconnect", None)
            if not callable(method):
                continue
            ok = False
            with contextlib.suppress(Exception):
                ok = bool(method())
            if ok:
                requested += 1
                label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
                transports.append(str(label))
        if target and not matched_target:
            return {
                "ok": False,
                "target_peer_id": target,
                "requested": 0,
                "sessions": sessions,
                "transports": [],
                "reason": "unknown_peer_id",
            }
        return {
            "ok": requested > 0,
            "target_peer_id": target or None,
            "requested": requested,
            "sessions": sessions,
            "transports": transports,
            "reason": "" if requested > 0 else "no reconnect-capable client overlay session is currently running",
        }

    def get_status_snapshot(self) -> dict:
        payload = dict(self.stats.snapshot_status())
        summaries: list[dict] = []
        compress_summaries: list[dict] = []
        for session in self._sessions:
            getter = getattr(session, "get_secure_link_operational_summary", None)
            if callable(getter):
                with contextlib.suppress(Exception):
                    summary = dict(getter() or {})
                    if summary:
                        summaries.append(summary)
            compress_getter = getattr(session, "get_compress_layer_status_snapshot", None)
            if callable(compress_getter):
                with contextlib.suppress(Exception):
                    csum = dict(compress_getter() or {})
                    if csum:
                        compress_summaries.append(csum)
        enabled = [s for s in summaries if bool(s.get("enabled"))]
        payload["secure_link_material_generation"] = max((int(s.get("secure_link_material_generation") or 0) for s in enabled), default=0)
        latest = None
        for item in enabled:
            ts = item.get("secure_link_last_reload_unix_ts")
            if ts is None:
                continue
            if latest is None or float(ts) >= float(latest.get("secure_link_last_reload_unix_ts") or 0.0):
                latest = item
        payload["secure_link_last_reload_unix_ts"] = latest.get("secure_link_last_reload_unix_ts") if latest is not None else None
        payload["secure_link_last_reload_scope"] = str(latest.get("secure_link_last_reload_scope") or "") if latest is not None else ""
        payload["secure_link_last_reload_result"] = str(latest.get("secure_link_last_reload_result") or "") if latest is not None else ""
        payload["secure_link_last_reload_detail"] = str(latest.get("secure_link_last_reload_detail") or "") if latest is not None else ""
        payload["secure_link_peers_dropped_total"] = sum(int(s.get("secure_link_peers_dropped_total") or 0) for s in enabled)

        compress_enabled = [s for s in compress_summaries if bool(s.get("enabled"))]
        algorithms = sorted({
            str(s.get("algorithm") or "").strip().lower()
            for s in compress_enabled
            if str(s.get("algorithm") or "").strip()
        })
        transports = sorted({
            str(s.get("transport") or "").strip().lower()
            for s in compress_enabled
            if str(s.get("transport") or "").strip()
        })
        input_total = sum(int(s.get("compress_input_bytes_total") or 0) for s in compress_enabled)
        output_total = sum(int(s.get("compress_output_bytes_total") or 0) for s in compress_enabled)
        savings_ratio = None
        if input_total > 0:
            savings_ratio = max(0.0, min(1.0, 1.0 - (float(output_total) / float(input_total))))
        payload["compress_layer"] = {
            "enabled": bool(compress_enabled),
            "sessions_enabled": int(len(compress_enabled)),
            "algorithm": algorithms[0] if len(algorithms) == 1 else ("mixed" if algorithms else ""),
            "algorithms": algorithms,
            "transports": transports,
            "compress_attempts_total": sum(int(s.get("compress_attempts_total") or 0) for s in compress_enabled),
            "compress_applied_total": sum(int(s.get("compress_applied_total") or 0) for s in compress_enabled),
            "compress_skipped_no_gain_total": sum(int(s.get("compress_skipped_no_gain_total") or 0) for s in compress_enabled),
            "compress_input_bytes_total": int(input_total),
            "compress_output_bytes_total": int(output_total),
            "decompress_ok_total": sum(int(s.get("decompress_ok_total") or 0) for s in compress_enabled),
            "decompress_fail_total": sum(int(s.get("decompress_fail_total") or 0) for s in compress_enabled),
            "compression_saving_ratio": savings_ratio,
        }
        return payload

    def get_connections_snapshot(self) -> dict:
        if not self._muxes:
            return {
                "udp": [],
                "tcp": [],
                "tun": [],
                "counts": {"udp": 0, "tcp": 0, "tun": 0, "udp_listening": 0, "tcp_listening": 0, "tun_listening": 0},
            }

        udp_rows: list[dict] = []
        tcp_rows: list[dict] = []
        tun_rows: list[dict] = []
        udp_listening = 0
        tcp_listening = 0
        tun_listening = 0

        for idx, mux in enumerate(self._muxes):
            snap = mux.snapshot_connections()
            mux_udp_rows = list(snap.get("udp", []))
            mux_tcp_rows = list(snap.get("tcp", []))
            mux_tun_rows = list(snap.get("tun", []))

            chan_to_peer_id: dict[int, str] = {}
            owner_peer_to_label: dict[int, str] = {}
            with contextlib.suppress(Exception):
                session = self._sessions[idx] if idx < len(self._sessions) else None
                getter = getattr(session, "get_overlay_peers_snapshot", None) if session is not None else None
                overlay_rows = list(getter() or []) if callable(getter) else []
                for p in overlay_rows:
                    peer_label = f"{idx}:{p.get('peer_id', 0)}"
                    with contextlib.suppress(Exception):
                        owner_peer_to_label[int(p.get("peer_id", 0))] = peer_label
                    for chan in (p.get("mux_chans") or []):
                        with contextlib.suppress(Exception):
                            chan_to_peer_id[int(chan)] = peer_label

            for row in mux_udp_rows:
                r = dict(row)
                chan = r.get("chan_id")
                if chan is not None:
                    r["peer_id"] = chan_to_peer_id.get(int(chan), str(idx))
                else:
                    owner_peer_id = r.get("svc_owner_peer_id")
                    if owner_peer_id is None:
                        # Locally owned listening services are still tied to this
                        # mux/peer slot; once traffic arrives the resulting channel
                        # will use the same slot-derived peer label fallback.
                        r["peer_id"] = str(idx)
                    else:
                        with contextlib.suppress(Exception):
                            owner_peer_id = int(owner_peer_id)
                        r["peer_id"] = owner_peer_to_label.get(owner_peer_id, f"{idx}:{owner_peer_id}")
                udp_rows.append(r)

            for row in mux_tcp_rows:
                r = dict(row)
                chan = r.get("chan_id")
                if chan is not None:
                    r["peer_id"] = chan_to_peer_id.get(int(chan), str(idx))
                else:
                    owner_peer_id = r.get("svc_owner_peer_id")
                    if owner_peer_id is None:
                        # Locally owned listening services are still tied to this
                        # mux/peer slot; once traffic arrives the resulting channel
                        # will use the same slot-derived peer label fallback.
                        r["peer_id"] = str(idx)
                    else:
                        with contextlib.suppress(Exception):
                            owner_peer_id = int(owner_peer_id)
                        r["peer_id"] = owner_peer_to_label.get(owner_peer_id, f"{idx}:{owner_peer_id}")
                tcp_rows.append(r)

            for row in mux_tun_rows:
                r = dict(row)
                chan = r.get("chan_id")
                if chan is not None:
                    aliases = r.get("channel_aliases") if isinstance(r.get("channel_aliases"), list) else [chan]
                    peer_label = str(idx)
                    for alias in aliases:
                        with contextlib.suppress(Exception):
                            peer_label = chan_to_peer_id.get(int(alias), peer_label)
                            if peer_label != str(idx):
                                break
                    r["peer_id"] = peer_label
                else:
                    owner_peer_id = r.get("svc_owner_peer_id")
                    if owner_peer_id is None:
                        r["peer_id"] = str(idx)
                    else:
                        with contextlib.suppress(Exception):
                            owner_peer_id = int(owner_peer_id)
                        r["peer_id"] = owner_peer_to_label.get(owner_peer_id, f"{idx}:{owner_peer_id}")
                tun_rows.append(r)

            counts = snap.get("counts", {}) or {}
            udp_listening += int(counts.get("udp_listening", 0) or 0)
            tcp_listening += int(counts.get("tcp_listening", 0) or 0)
            tun_listening += int(counts.get("tun_listening", 0) or 0)

        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "tun": tun_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "tun": len(tun_rows) - tun_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
                "tun_listening": tun_listening,
            },
        }

    def get_config_snapshot(self, include_secrets: bool = False) -> dict:
        blocked = {
            "config", "dump_config", "save_config", "save_format", "force",
            "help",
        }
        secret_keys = AdminWebUI._secret_config_keys()
        data = {}
        for k, v in vars(self.args).items():
            if k.startswith("_") or k in blocked:
                continue
            if k in secret_keys and not include_secrets:
                data[k] = ""
                continue
            if isinstance(v, (str, int, float, bool, list, dict)) or v is None:
                data[k] = v
            else:
                data[k] = str(v)
        return data

    def get_config_schema_snapshot(self) -> dict:
        sections = {k: set(v) for k, v in (getattr(self.args, "_config_sections", {}) or {}).items()}
        defaults = getattr(self.args, "_config_defaults", {}) or {}
        descriptions = getattr(self.args, "_config_help", {}) or {}
        choices = getattr(self.args, "_config_choices", {}) or {}

        # Keep transport endpoint knobs grouped with their transport sessions in the
        # admin UI, even when those options were originally registered elsewhere.
        transport_key_targets = {
            "udp_bind": "udp_session",
            "udp_own_port": "udp_session",
            "udp_peer": "udp_session",
            "udp_peer_port": "udp_session",
            "tcp_bind": "tcp_session",
            "tcp_own_port": "tcp_session",
            "tcp_peer": "tcp_session",
            "tcp_peer_port": "tcp_session",
            "quic_bind": "quic_session",
            "quic_own_port": "quic_session",
            "quic_peer": "quic_session",
            "quic_peer_port": "quic_session",
            "ws_bind": "ws_session",
            "ws_own_port": "ws_session",
            "ws_peer": "ws_session",
            "ws_peer_port": "ws_session",
        }
        for key, target_section in transport_key_targets.items():
            if not hasattr(self.args, key):
                continue
            for section_keys in sections.values():
                section_keys.discard(key)
            sections.setdefault(target_section, set()).add(key)

        schema: dict = {}
        for section in sorted(sections.keys()):
            section_keys = set(sections.get(section, []))
            section_log_key = f"log_{section}"
            if hasattr(self.args, section_log_key):
                section_keys.add(section_log_key)
            items = []
            for key in sorted(section_keys):
                if not hasattr(self.args, key):
                    continue
                row = {
                    "key": key,
                    "description": descriptions.get(key, "(no description)"),
                    "default": defaults.get(key, None),
                }
                if key in AdminWebUI._secret_config_keys():
                    row["secret"] = True
                if key in AdminWebUI._readonly_config_keys():
                    row["readonly"] = True
                if key in choices:
                    row["choices"] = list(choices.get(key, []))
                items.append(row)
            if items:
                schema[section] = items
        return schema

    def get_debug_logs(self, limit: int = 400) -> list:
        lim = max(1, min(int(limit), 1000))
        if DEBUG_LOG_RING:
            return list(DEBUG_LOG_RING)[-lim:]
        log_file = str(getattr(self.args, "log_file", "") or "").strip()
        if not log_file:
            return []
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read().splitlines()[-lim:]
        except Exception:
            return []

    def _unwrap_snapshot_session(self, session_obj):
        current = session_obj
        seen: set[int] = set()
        while current is not None:
            current_id = id(current)
            if current_id in seen:
                break
            seen.add(current_id)
            next_obj = getattr(current, "_real", None)
            if next_obj is None or next_obj is current:
                next_obj = getattr(current, "_inner", None)
            if next_obj is None or next_obj is current:
                break
            current = next_obj
        return current

    def _session_metrics_snapshot(self, session_obj, fallback: Optional[SessionMetrics] = None) -> SessionMetrics:
        if session_obj is None:
            return fallback or SessionMetrics()
        getter = getattr(session_obj, "get_metrics", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                return getter()
        try:
            return SessionMetrics(
                rtt_sample_ms=getattr(session_obj, "rtt_sample_ms", None),
                rtt_est_ms=getattr(session_obj, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(session_obj, "last_rtt_ok_ns", None),
                inflight=int(session_obj.in_flight()) if hasattr(session_obj, "in_flight") else None,
                max_inflight=getattr(session_obj, "max_in_flight", None),
                waiting_count=int(session_obj.waiting_count()) if hasattr(session_obj, "waiting_count") else None,
                last_ack_peer=getattr(session_obj, "last_ack_peer", None),
                last_sent_ctr=getattr(session_obj, "last_sent_ctr", None),
                expected=getattr(session_obj, "expected", None),
                peer_missed_count=getattr(session_obj, "peer_missed_count", None),
                our_missed_count=len(getattr(session_obj, "missing", [])) if hasattr(session_obj, "missing") else None,
            )
        except Exception:
            return fallback or SessionMetrics()

    def _session_retransmit_stats(self, session_obj) -> dict:
        hist: dict = {}
        buffered_frames = 0
        with contextlib.suppress(Exception):
            source = self._unwrap_snapshot_session(session_obj)
            inner = getattr(source, "inner_session", source)
            hist = dict(getattr(inner, "stats_hist", {}) or {})
            waiting_count = getattr(inner, "waiting_count", None)
            if callable(waiting_count):
                buffered_frames = int(waiting_count())
        return {
            "buffered_frames": buffered_frames,
            "first_pass": int(hist.get("once", 0)),
            "repeated_once": int(hist.get("twice", 0)),
            "repeated_multiple": int(hist.get("thrice", 0)) + int(hist.get("gt3", 0)),
            "confirmed_total": int(hist.get("confirmed_total", 0)),
        }

    def _overlay_listen_label(self, transport: str, session: ISession) -> Optional[str]:
        t = str(transport or "myudp").strip().lower()
        bind_attr, _, _, listen_port_attr = _overlay_cli_attrs(t)
        source_args = getattr(session, "_args", None) or self.args
        bind_host = str(getattr(source_args, bind_attr, "") or "")
        raw_port = getattr(source_args, listen_port_attr, None)
        if raw_port is None:
            return None
        with contextlib.suppress(Exception):
            listen_port = int(raw_port)
            if listen_port <= 0:
                return None
            host = bind_host or "0.0.0.0"
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            return f"{host}:{listen_port}"
        return None

    @staticmethod
    def _session_last_incoming_age_seconds(session: Any) -> Optional[float]:
        candidates = [
            session,
            getattr(session, "proto", None),
            getattr(session, "_rtt", None),
            getattr(session, "inner_session", None),
            getattr(getattr(session, "inner_session", None), "proto", None),
            getattr(session, "peer_proto", None),
            getattr(getattr(session, "peer_proto", None), "proto", None),
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            with contextlib.suppress(Exception):
                last_rx_wall_ns = int(getattr(candidate, "_last_rx_wall_ns", 0) or 0)
                age = _monotonic_age_seconds_from_ns(last_rx_wall_ns)
                if age is not None:
                    return age
        return None

    @staticmethod
    def _session_decode_errors(session: Any) -> int:
        candidates = [
            session,
            getattr(session, "peer_proto", None),
            getattr(getattr(session, "peer_proto", None), "proto", None),
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            with contextlib.suppress(Exception):
                value = int(getattr(candidate, "unidentified_frames", 0) or 0)
                if value > 0:
                    return value
        return 0

    def _session_compress_layer_snapshot(self, session_obj: Any, peer_id: Optional[int] = None) -> dict:
        getter = getattr(session_obj, "get_compress_layer_status_snapshot", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                try:
                    snap = dict(getter(peer_id=peer_id) or {})
                except TypeError:
                    snap = dict(getter() or {})
                if snap:
                    return snap
        return RunnerMuxAggregate._default_compress_layer_snapshot()

    def _apply_peer_traffic_rates(self, peers: list[dict]) -> None:
        now = time.monotonic()
        seen: set[str] = set()
        for peer in peers:
            peer_id = str(peer.get("id", ""))
            seen.add(peer_id)
            traffic = peer.setdefault("traffic", {})
            rx_bytes = int(traffic.get("rx_bytes", 0) or 0)
            tx_bytes = int(traffic.get("tx_bytes", 0) or 0)
            prev = self._peer_traffic_rate_state.get(peer_id)
            rx_rate = 0.0
            tx_rate = 0.0
            if prev is not None:
                prev_ts, prev_rx, prev_tx = prev
                rx_bytes = max(rx_bytes, int(prev_rx))
                tx_bytes = max(tx_bytes, int(prev_tx))
                dt = max(1e-6, now - float(prev_ts))
                rx_rate = max(0.0, float(rx_bytes - int(prev_rx)) / dt)
                tx_rate = max(0.0, float(tx_bytes - int(prev_tx)) / dt)
            traffic["rx_bytes"] = rx_bytes
            traffic["tx_bytes"] = tx_bytes
            traffic["rx_bytes_per_sec"] = rx_rate
            traffic["tx_bytes_per_sec"] = tx_rate
            self._peer_traffic_rate_state[peer_id] = (now, rx_bytes, tx_bytes)
        for peer_id in list(self._peer_traffic_rate_state.keys()):
            if peer_id not in seen:
                self._peer_traffic_rate_state.pop(peer_id, None)

    def get_peer_connections_snapshot(self) -> dict:
        peers: list = []
        def _active_connection_count(rows: list) -> int:
            return sum(
                1
                for row in rows
                if row.get("chan_id") is not None
                and str(row.get("state", "connected")).lower() != "listening"
            )

        for idx, session in enumerate(self._sessions):
            mux = self._muxes[idx] if idx < len(self._muxes) else None
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            real_session = self._unwrap_snapshot_session(session)
            listen_endpoint = self._overlay_listen_label(label, session)
            m = self._session_metrics_snapshot(session)
            udp_rows: list = []
            tcp_rows: list = []
            peer_payload_totals: dict[int, dict] = {}
            if mux is not None:
                snap = mux.snapshot_connections()
                udp_rows = list(snap.get("udp", []))
                tcp_rows = list(snap.get("tcp", []))
                tun_rows = list(snap.get("tun", []))
                payload_getter = getattr(mux, "snapshot_peer_payload_totals", None)
                if callable(payload_getter):
                    with contextlib.suppress(Exception):
                        peer_payload_totals = dict(payload_getter() or {})
            else:
                tun_rows = []
            overlay_rows = []
            with contextlib.suppress(Exception):
                getter = getattr(session, "get_overlay_peers_snapshot", None)
                if callable(getter):
                    overlay_rows = list(getter() or [])

            if overlay_rows:
                for p in overlay_rows:
                    if bool(p.get("listening")):
                        listener_session = getattr(real_session, "inner_session", None)
                        listener_metrics = self._session_metrics_snapshot(listener_session)
                        peers.append({
                            "id": f"{idx}:{p.get('peer_id', 0)}",
                            "transport": label,
                            "state": "listening",
                            "connected": False,
                            "listen": listen_endpoint,
                            "peer": p.get("peer"),
                            "rtt_est_ms": p.get("rtt_est_ms", listener_metrics.rtt_est_ms),
                            "last_incoming_age_seconds": p.get("last_incoming_age_seconds"),
                            "inflight": listener_metrics.inflight,
                            "decode_errors": 0,
                            "open_connections": {
                                "udp": 0,
                                "tcp": 0,
                                "tun": 0,
                            },
                            "traffic": {
                                "rx_bytes": 0,
                                "tx_bytes": 0,
                            },
                            "myudp": self._session_retransmit_stats(listener_session),
                            "secure_link": dict(p.get("secure_link") or RunnerMuxAggregate._default_secure_link_snapshot()),
                            "compress_layer": dict(self._session_compress_layer_snapshot(session, peer_id=p.get("peer_id"))),
                        })
                        continue
                    row_session = session
                    row_decode_errors = int(p.get("decode_errors") or 0)
                    server_peers = getattr(real_session, "_server_peers", None)
                    if isinstance(server_peers, dict):
                        ctx = server_peers.get(int(p.get("peer_id", 0)))
                        if isinstance(ctx, dict) and ctx.get("session") is not None:
                            row_session = ctx.get("session")
                        if isinstance(ctx, dict) and ctx.get("peer_proto") is not None:
                            with contextlib.suppress(Exception):
                                row_decode_errors = int(getattr(ctx.get("peer_proto"), "unidentified_frames", 0) or row_decode_errors)
                    row_metrics = self._session_metrics_snapshot(row_session, fallback=m)
                    mux_chans = set(int(c) for c in (p.get("mux_chans") or []))
                    p_rx = 0
                    p_tx = 0
                    udp_open = 0
                    tcp_open = 0
                    tun_open = 0
                    for row in udp_rows:
                        chan_id = row.get("chan_id")
                        if chan_id is None:
                            continue
                        if str(row.get("state", "connected")).lower() == "listening":
                            continue
                        if mux_chans and chan_id not in mux_chans:
                            continue
                        st = row.get("stats", {})
                        p_rx += int(st.get("rx_bytes", 0) or 0)
                        p_tx += int(st.get("tx_bytes", 0) or 0)
                        udp_open += 1
                    for row in tcp_rows:
                        chan_id = row.get("chan_id")
                        if chan_id is None:
                            continue
                        if str(row.get("state", "connected")).lower() == "listening":
                            continue
                        if mux_chans and chan_id not in mux_chans:
                            continue
                        st = row.get("stats", {})
                        p_rx += int(st.get("rx_bytes", 0) or 0)
                        p_tx += int(st.get("tx_bytes", 0) or 0)
                        tcp_open += 1
                    for row in tun_rows:
                        chan_id = row.get("chan_id")
                        if chan_id is None:
                            continue
                        if str(row.get("state", "connected")).lower() == "listening":
                            continue
                        aliases = row.get("channel_aliases") if isinstance(row.get("channel_aliases"), list) else [chan_id]
                        if mux_chans and not any(alias in mux_chans for alias in aliases):
                            continue
                        st = row.get("stats", {})
                        p_rx += int(st.get("rx_bytes", 0) or 0)
                        p_tx += int(st.get("tx_bytes", 0) or 0)
                        tun_open += 1
                    archived = peer_payload_totals.get(int(p.get("peer_id", 0))) or {}
                    p_rx += int(archived.get("rx_bytes", 0) or 0)
                    p_tx += int(archived.get("tx_bytes", 0) or 0)

                    row_connected = bool(p.get("connected", session.is_connected()))
                    row_state = str(p.get("state") or ("connected" if row_connected else "connecting"))
                    peers.append({
                        "id": f"{idx}:{p.get('peer_id', 0)}",
                        "transport": label,
                        "state": row_state,
                        "connected": row_connected,
                        "listen": listen_endpoint,
                        "peer": p.get("peer"),
                        "rtt_est_ms": p.get("rtt_est_ms", row_metrics.rtt_est_ms),
                        "last_incoming_age_seconds": p.get(
                            "last_incoming_age_seconds",
                            self._session_last_incoming_age_seconds(row_session),
                        ),
                        "inflight": row_metrics.inflight,
                        "decode_errors": row_decode_errors,
                        "open_connections": {
                            "udp": udp_open,
                            "tcp": tcp_open,
                            "tun": tun_open,
                        },
                        "traffic": {
                            "rx_bytes": p_rx,
                            "tx_bytes": p_tx,
                        },
                        "myudp": self._session_retransmit_stats(row_session),
                        "secure_link": dict(p.get("secure_link") or RunnerMuxAggregate._default_secure_link_snapshot()),
                        "compress_layer": dict(self._session_compress_layer_snapshot(session, peer_id=p.get("peer_id"))),
                    })
                continue

            rx_bytes = 0
            tx_bytes = 0
            for row in udp_rows + tcp_rows + tun_rows:
                st = row.get("stats", {})
                rx_bytes += int(st.get("rx_bytes", 0) or 0)
                tx_bytes += int(st.get("tx_bytes", 0) or 0)
            for archived in peer_payload_totals.values():
                rx_bytes += int(archived.get("rx_bytes", 0) or 0)
                tx_bytes += int(archived.get("tx_bytes", 0) or 0)
            peer_label = None
            with contextlib.suppress(Exception):
                if hasattr(session, "peer_proto") and getattr(session, "peer_proto"):
                    pa = getattr(getattr(session, "peer_proto"), "send_port").peer_addr
                    if pa:
                        peer_label = f"{pa[0]}:{pa[1]}"
            with contextlib.suppress(Exception):
                if not peer_label and hasattr(session, "_peer_host") and hasattr(session, "_peer_port"):
                    host = str(getattr(session, "_peer_host") or "")
                    port = int(getattr(session, "_peer_port") or 0)
                    if host and port > 0:
                        peer_label = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
            decode_errors = 0
            with contextlib.suppress(Exception):
                pp = getattr(session, "peer_proto", None)
                if pp is not None:
                    decode_errors = int(getattr(pp, "unidentified_frames", 0) or 0)
            peers.append({
                "id": idx,
                "transport": label,
                "state": "connected" if bool(session.is_connected()) else "connecting",
                "connected": bool(session.is_connected()),
                "listen": listen_endpoint,
                "peer": peer_label,
                "rtt_est_ms": m.rtt_est_ms,
                "last_incoming_age_seconds": self._session_last_incoming_age_seconds(real_session),
                "inflight": m.inflight,
                "decode_errors": decode_errors,
                "open_connections": {
                    "udp": _active_connection_count(udp_rows),
                    "tcp": _active_connection_count(tcp_rows),
                    "tun": _active_connection_count(tun_rows),
                },
                "traffic": {
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                },
                "myudp": self._session_retransmit_stats(session),
                "secure_link": dict(
                    getattr(
                        session,
                        "get_secure_link_status_snapshot",
                        RunnerMuxAggregate._default_secure_link_snapshot,
                    )()
                ),
                "compress_layer": dict(self._session_compress_layer_snapshot(session)),
            })
        self._apply_peer_traffic_rates(peers)
        return {"peers": peers, "count": len(peers)}

    def _session_peer_row_ids(self, idx: int, session: ISession) -> list[str]:
        rows: list[str] = []
        peer_rows_fn = getattr(session, "get_overlay_peers_snapshot", None)
        if callable(peer_rows_fn):
            with contextlib.suppress(Exception):
                for row in list(peer_rows_fn() or []):
                    peer_id = row.get("peer_id")
                    if peer_id is None:
                        continue
                    rows.append(f"{idx}:{peer_id}")
        if not rows:
            rows.append(str(idx))
        return rows

    def request_secure_link_rekey(self, target_peer_id: Optional[str] = None) -> dict:
        target = str(target_peer_id or "").strip()
        requested = 0
        skipped = 0
        results: list[dict] = []
        matched_target = False
        for idx, session in enumerate(self._sessions):
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            peer_row_ids = self._session_peer_row_ids(idx, session)
            if target:
                if target not in peer_row_ids:
                    continue
                matched_target = True
            requester = getattr(session, "request_secure_link_rekey", None)
            if not callable(requester):
                skipped += 1
                results.append({
                    "transport": label,
                    "peer_ids": peer_row_ids,
                    "ok": False,
                    "reason": "secure_link_not_enabled",
                })
                continue
            try:
                ok, reason = requester()
            except Exception as e:
                skipped += 1
                results.append({
                    "transport": label,
                    "peer_ids": peer_row_ids,
                    "ok": False,
                    "reason": f"error:{e}",
                })
                continue
            if ok:
                requested += 1
            else:
                skipped += 1
            results.append({
                "transport": label,
                "peer_ids": peer_row_ids,
                "ok": bool(ok),
                "reason": str(reason or ""),
            })
        if target and not matched_target:
            return {
                "ok": False,
                "target_peer_id": target,
                "requested": 0,
                "skipped": 0,
                "results": [],
                "error": "unknown peer_id",
            }
        return {
            "ok": requested > 0,
            "target_peer_id": target or None,
            "requested": requested,
            "skipped": skipped,
            "results": results,
        }

    def request_secure_link_reload(self, scope: str, target_peer_id: Optional[str] = None) -> dict:
        normalized_scope = str(scope or "").strip().lower()
        target = str(target_peer_id or "").strip()
        requested = 0
        reloaded = 0
        dropped = 0
        failed = 0
        results: list[dict] = []
        matched_target = False
        for idx, session in enumerate(self._sessions):
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            peer_row_ids = self._session_peer_row_ids(idx, session)
            if target:
                if target not in peer_row_ids:
                    continue
                matched_target = True
            requester = getattr(session, "request_secure_link_reload", None)
            if not callable(requester):
                failed += 1
                results.append({
                    "transport": label,
                    "peer_ids": peer_row_ids,
                    "ok": False,
                    "reason": "secure_link_reload_not_supported",
                })
                continue
            requested += 1
            try:
                result = dict(requester(scope=normalized_scope, target_peer_id=target or None) or {})
            except Exception as e:
                failed += 1
                results.append({
                    "transport": label,
                    "peer_ids": peer_row_ids,
                    "ok": False,
                    "reason": f"error:{e}",
                })
                continue
            if bool(result.get("ok")):
                reloaded += 1
            else:
                failed += 1
            dropped += int(result.get("dropped") or 0)
            result.setdefault("transport", label)
            result.setdefault("peer_ids", peer_row_ids)
            results.append(result)
        if target and not matched_target:
            return {
                "ok": False,
                "scope": normalized_scope,
                "target_peer_id": target,
                "requested": 0,
                "reloaded": 0,
                "dropped": 0,
                "failed": 0,
                "results": [],
                "reason": "unknown_peer_id",
            }
        return {
            "ok": reloaded > 0 and failed == 0,
            "scope": normalized_scope,
            "target_peer_id": target or None,
            "requested": requested,
            "reloaded": reloaded,
            "dropped": dropped,
            "failed": failed,
            "results": results,
        }

    def _group_config_snapshot(self, config: dict) -> dict:
        sections = getattr(self.args, "_config_sections", {}) or {}
        if not isinstance(sections, dict) or not sections:
            return dict(config)
        grouped: dict = {}
        assigned: set = set()
        for section in sorted(sections.keys()):
            keys = sections.get(section, []) or []
            block = {}
            for key in keys:
                if key in config:
                    block[key] = config[key]
            if block:
                grouped[section] = block
                assigned.update(block.keys())
        misc = {k: v for k, v in config.items() if k not in assigned}
        if misc:
            grouped["misc"] = misc
        return grouped

    def save_runtime_config(self) -> tuple[bool, str]:
        cfg_path = getattr(self.args, "config", None)
        if not cfg_path:
            return (True, "")
        try:
            path = pathlib.Path(str(cfg_path))
            config_secret_transform = _encrypt_config_secret
            if str(_admin_ui_platform()).strip().lower() == "ios":
                config_secret_transform = lambda value: value
            payload = _transform_config_secrets(
                self._group_config_snapshot(self.get_config_snapshot(include_secrets=True)),
                config_secret_transform,
            )
            parent = path.parent
            if parent and str(parent) not in ("", "."):
                parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
            tmp.replace(path)
        except Exception as e:
            logging.getLogger("obstacle_bridge.config").exception(
                "failed to persist runtime config path=%s crypto_extract=%r build=%r",
                cfg_path,
                available_crypto_extract(),
                _detect_build_info(),
            )
            return (False, f"failed to persist config to {cfg_path}: {e}")
        # Persisted runtime config is now present and no longer a first-start state.
        setattr(self.args, "_first_start_detected", False)
        setattr(self.args, "_config_file_state", "loaded")
        return (True, "")

    def update_config(self, updates: dict) -> tuple[bool, str]:
        if not isinstance(updates, dict):
            return (False, "updates must be an object")
        normalized_updates = dict(updates)
        if normalized_updates.get("admin_web_auth_disable") is True:
            normalized_updates["admin_web_username"] = ""
            normalized_updates["admin_web_password"] = ""
        elif (
            "admin_web_password" in normalized_updates
            and str(normalized_updates.get("admin_web_password", "") or "") == ""
            and bool(getattr(self.args, "admin_web_auth_disable", False))
            and "admin_web_auth_disable" not in normalized_updates
        ):
            normalized_updates["admin_web_username"] = ""
            normalized_updates["admin_web_auth_disable"] = True
        for key, value in normalized_updates.items():
            if not hasattr(self.args, key):
                return (False, f"unknown config key: {key}")
            cur = getattr(self.args, key)
            if key in AdminWebUI._readonly_config_keys():
                return (False, f"{key} is read-only")
            if key in AdminWebUI._secret_config_keys():
                if not isinstance(value, str):
                    return (False, f"{key} expects string")
                setattr(self.args, key, value)
                continue
            if isinstance(cur, bool):
                if not isinstance(value, bool):
                    return (False, f"{key} expects boolean")
            elif isinstance(cur, int) and not isinstance(cur, bool):
                if not isinstance(value, int):
                    return (False, f"{key} expects integer")
            elif isinstance(cur, float):
                if not isinstance(value, (int, float)):
                    return (False, f"{key} expects number")
                value = float(value)
            elif isinstance(cur, str):
                if not isinstance(value, str):
                    return (False, f"{key} expects string")
            elif isinstance(cur, list):
                if not isinstance(value, list):
                    return (False, f"{key} expects list")
            elif cur is None:
                if not isinstance(value, (str, int, float, bool, list, dict)) and value is not None:
                    return (False, f"{key} has unsupported type")
            setattr(self.args, key, value)
        return self.save_runtime_config()

    def request_shutdown(self, exit_code: Optional[int] = None) -> None:
        if exit_code is not None:
            self._shutdown_exit_code = int(exit_code)
            self.log.debug("[SERVER] Runner shutdown requested rc=%d", self._shutdown_exit_code)
        else:
            self.log.debug("[SERVER] Runner shutdown requested")
        self._stop_requested = True
        if self._stop is not None:
            self._stop.set()

    async def _client_restart_watchdog(self) -> None:
        assert self._stop is not None
        assert self._restart_requested is not None
        try:
            while not self._stop.is_set():
                await asyncio.sleep(1.0)

                # Disabled by CLI
                timeout_s = float(getattr(self.args, "client_restart_if_disconnected", 0.0) or 0.0)
                if timeout_s <= 0:
                    continue

                # Only for configured peer clients
                if not _has_configured_overlay_peer(self.args):
                    continue

                # Need a live session object
                sess = self._session_obj
                if sess is None:
                    continue

                # Do nothing if already stopping or restart already requested
                if self._restart_requested.is_set() or self._stop.is_set():
                    continue

                # If connected, watchdog is idle
                if sess.is_connected():
                    continue

                # No disconnect timestamp yet -> initialize defensively
                if self._last_disconnected_monotonic is None:
                    self._last_disconnected_monotonic = time.monotonic()
                    continue

                down_for = time.monotonic() - self._last_disconnected_monotonic
                if down_for < timeout_s:
                    continue

                self.log.warning(
                    "[RUNNER] client disconnected for %.1fs (threshold %.1fs); requesting restart",
                    down_for,
                    timeout_s,
                )
                self.request_restart()
                return

        except asyncio.CancelledError:
            return
        except Exception as e:
            self.log.exception("[RUNNER] client restart watchdog failed: %r", e)

    # ---------- Runner-scoped CLI registrar ----------
    @staticmethod
    def register_overlay_cli(p: argparse.ArgumentParser) -> None:
        """
        Select the overlay transport (Session) used between peers.
        Default keeps current behavior: 'myudp'.
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False
        if not _has('--overlay-transport'):
            p.add_argument(
                '--overlay-transport',
                default='myudp',
                help="Overlay transport between peers: "
                     "comma-separated list from myudp,tcp,quic,ws. "
                     "Multiple transports are supported simultaneously for listening instances."
            )
        for proto in ("tcp", "quic", "ws"):
            bind_opt = f"--{proto}-bind"
            listen_port_opt = f"--{proto}-own-port"
            peer_opt = f"--{proto}-peer"
            peer_port_opt = f"--{proto}-peer-port"
            if not _has(bind_opt):
                p.add_argument(bind_opt, default='::', help=f'{proto.upper()} overlay bind address')
            if not _has(listen_port_opt):
                default_port = {"tcp": 8081, "quic": 443, "ws": 8080}[proto]
                p.add_argument(listen_port_opt, dest=f"{proto}_own_port", type=int, default=default_port, help=f'{proto.upper()} overlay own port')
            if not _has(peer_opt):
                p.add_argument(peer_opt, default=None, help=f'{proto.upper()} peer IP/FQDN')
            if not _has(peer_port_opt):
                default_peer_port = {"tcp": 8081, "quic": 443, "ws": 8080}[proto]
                p.add_argument(peer_port_opt, type=int, default=default_peer_port, help=f'{proto.upper()} peer overlay port')
        if not _has('--client-restart-if-disconnected'):
            p.add_argument(
                '--client-restart-if-disconnected',
                type=float,
                default=0.0,
                help='If configured as a peer client (for example --udp-peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables.'
            )
        if not _has('--overlay-reconnect-retry-delay-ms'):
            p.add_argument(
                '--overlay-reconnect-retry-delay-ms',
                type=int,
                default=30000,
                help='Delay in milliseconds between failed reconnect attempts for tcp/quic/ws client overlays (default 30000).'
            )
    @staticmethod
    def _parse_overlay_transports(args: argparse.Namespace) -> List[str]:
        raw = str(getattr(args, "overlay_transport", "myudp") or "myudp")
        parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
        if not parts:
            parts = ["myudp"]
        allowed = {"myudp", "tcp", "quic", "ws"}
        bad = [p for p in parts if p not in allowed]
        if bad:
            raise ValueError(f"Unsupported overlay transport(s): {', '.join(sorted(set(bad)))}")
        seen: List[str] = []
        for part in parts:
            if part not in seen:
                seen.append(part)
        if len(seen) > 1 and any(_has_configured_overlay_peer(args, transport=t) for t in seen):
            raise ValueError("Multiple --overlay-transport values are currently supported only for listening instances without configured transport peers.")
        return seen

    @staticmethod
    def _overlay_port_for(args: argparse.Namespace, transport: str, multi_count: int) -> int:
        listen_attr = _overlay_cli_attrs(transport)[3]
        base_default = {"myudp": 4433, "tcp": 8081, "quic": 443, "ws": 8080}[transport]
        return int(getattr(args, listen_attr, base_default))

    @staticmethod
    def _maybe_wrap_secure_link(args: argparse.Namespace, transport_name: str, session: ISession) -> ISession:
        enabled = bool(getattr(args, "secure_link", False))
        mode = str(getattr(args, "secure_link_mode", "off") or "off").strip().lower()
        if not enabled or mode == "off":
            return session
        if mode not in {"psk", "cert"}:
            raise ValueError(f"secure_link_mode={mode} is not implemented yet")
        if transport_name not in {"myudp", "tcp", "ws", "quic"}:
            raise ValueError(f"secure_link_mode={mode} is not supported for overlay_transport={transport_name}")
        if mode == "psk" and not str(getattr(args, "secure_link_psk", "") or ""):
            raise ValueError("secure_link_mode=psk requires --secure-link-psk")
        return SecureLinkPskSession(session, args, transport_name)

    @staticmethod
    def _maybe_wrap_compress_layer(args: argparse.Namespace, transport_name: str, session: ISession) -> ISession:
        enabled = bool(getattr(args, "compress_layer", True))
        peer_host = str(getattr(args, "peer", "") or "").strip()
        # Peer servers keep a passive compression wrapper even when their local
        # config disables outbound compression. This lets a compression-capable
        # listener decode client-selected compressed frames and activate
        # compression only for peers that actually use it.
        if not enabled and peer_host:
            return session
        algo = str(getattr(args, "compress_layer_algo", "zlib") or "zlib").strip().lower()
        if algo != "zlib":
            raise ValueError(f"compress_layer_algo={algo} is not implemented yet")
        return CompressLayerSession(session, args, transport_name)

    @staticmethod
    def build_sessions_from_overlay(args: argparse.Namespace) -> List[Tuple[str, ISession]]:
        """
        Return the ISession(s) that implement the chosen overlay transport(s).
        """
        out: List[Tuple[str, ISession]] = []
        choices = Runner._parse_overlay_transports(args)
        for choice in choices:
            session_args = argparse.Namespace(**vars(args))
            session_args.overlay_transport = choice
            bind_attr, peer_attr, peer_port_attr, listen_port_attr = _overlay_cli_attrs(choice)
            session_args.bind443 = getattr(session_args, bind_attr, "::")
            session_args.peer = getattr(session_args, peer_attr, getattr(session_args, "peer", None))
            session_args.peer_port = int(getattr(session_args, peer_port_attr, getattr(session_args, "peer_port", 443)) or 443)
            setattr(session_args, listen_port_attr, Runner._overlay_port_for(args, choice, len(choices)))
            if choice == "tcp":
                session = TcpStreamSession.from_args(session_args)
            elif choice == "quic":
                session = QuicSession.from_args(session_args)
            elif choice == "ws":
                session = WebSocketSession.from_args(session_args)
            else:
                session = UdpSession.from_args(session_args)
            wrapped = Runner._maybe_wrap_secure_link(session_args, choice, session)
            wrapped = Runner._maybe_wrap_compress_layer(session_args, choice, wrapped)
            out.append((choice, wrapped))
        return out

# ------------ Admin Webinterface ------------

from .bridge_webadmin import AdminWebUI

class ConfigAwareCLI:
    """
    JSON-only, stdlib-only config layer around argparse that:
      - bootstraps --config / --dump-config [/ format] / --save-config / --save-format / --force
      - registers options via provided (section_name, register_fn) list
      - applies JSON as argparse defaults by inspecting argparse actions (no duplication)
      - tracks which dests each registrar added for grouped dumps
      - can print or save the effective configuration and EXIT gracefully by itself
      - supports a human-readable dump that comments out unchanged values and shows descriptions
    """

    def __init__(self, *, description: str) -> None:
        self.description = description
        self._sections: Dict[str, Set[str]] = {}
        self._bootstrap: Optional[argparse.ArgumentParser] = None
        self._parser: Optional[argparse.ArgumentParser] = None
        self._raw_config: Optional[Dict[str, Any]] = None
        self._config_file_state: str = "unknown"  # unknown|missing|empty|loaded|invalid
        self._first_start_detected: bool = False

        # Snapshots captured right AFTER registrars add their options,
        # and BEFORE we apply any JSON config.
        self._baseline_defaults: Dict[str, Any] = {}
        self._action_help: Dict[str, str] = {}
        self._action_choices: Dict[str, List[Any]] = {}

    # ---------- public surface ----------
    def parse_args(
        self,
        argv: Optional[List[str]],
        registrars: List[Tuple[str, Callable[[argparse.ArgumentParser], None]]],
    ) -> argparse.Namespace:
        # Phase 0: bootstrap to get config & dump/save wants
        boot_args, remaining = self._parse_bootstrap(argv)
        argv_list = list(argv) if argv is not None else sys.argv[1:]
        explicit_config_flag = any(a in ("-c", "--config") for a in argv_list)

        # Phase 1: build full parser and register CLI from single source of truth
        parser = self._build_full_parser(registrars)

        # Phase 2: apply JSON config as defaults (if provided)
        if boot_args.config:
            config_path = pathlib.Path(boot_args.config)
            self._config_file_state = "unknown"
            self._first_start_detected = False
            if explicit_config_flag or config_path.exists():
                try:
                    cfg = self._load_json_config(boot_args.config)
                except FileNotFoundError:
                    # Missing config should not prevent startup; continue with
                    # built-in argparse defaults unless a readable config exists.
                    sys.stderr.write(
                        f"Config file not found, continuing with defaults: {config_path}\n"
                    )
                    sys.stderr.flush()
                    self._config_file_state = "missing"
                except ValueError:
                    self._config_file_state = "invalid"
                    raise
                else:
                    self._raw_config = cfg
                    self._apply_config_defaults_from_json(parser, cfg)
                    self._config_file_state = "empty" if not cfg else "loaded"
            else:
                # Default startup path where config was not explicitly passed and does not exist.
                self._config_file_state = "missing"

            default_cfg_name = "ObstacleBridge.cfg"
            cfg_name = pathlib.Path(str(boot_args.config)).name
            self._first_start_detected = cfg_name == default_cfg_name and self._config_file_state in {"missing", "empty"}

        # Phase 3: final parse; CLI overrides config/defaults
        args = parser.parse_args(remaining)

        # Promote bootstrap flags to final args for convenience
        args.config = boot_args.config
        args.dump_config = boot_args.dump_config       # "human" | "json" | "json-flat" | None
        args.save_config = boot_args.save_config       # file path or None
        args.save_format = boot_args.save_format       # "json" | "json-flat"
        args.force = boot_args.force                   # bool
        args._config_file_state = self._config_file_state
        args._first_start_detected = self._first_start_detected
        args._config_path = str(pathlib.Path(boot_args.config).expanduser().resolve()) if boot_args.config else ""

        # If dumping or saving was requested, perform it and exit right here.
        self._maybe_dump_or_save_and_exit(args)

        #Tweak loggers
        self._apply_per_section_overrides(args)

        return args

    def dump_effective_config_json(self, args: argparse.Namespace) -> str:
        """
        Serialize effective args (post-parse) to JSON, grouped by registrars.
        (Useful if you prefer to call it manually; not needed for --dump-config.)
        """
        grouped = self._group_effective(self._effective_dict(vars(args)))
        return json.dumps(grouped, indent=2, ensure_ascii=False) + "\n"

    @property
    def sections(self) -> Dict[str, Set[str]]:
        return self._sections

    # ---------- internal: bootstrap / build ----------
    def _parse_bootstrap(self, argv: Optional[List[str]]):
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("--config", "-c", default="ObstacleBridge.cfg",
                       help="Path to a JSON config file. Values become defaults that CLI can override.")
        # Optional argument: if omitted -> const="human"
        p.add_argument("--dump-config", nargs="?", const="human",
                       choices=("human", "json", "json-flat"),
                       help="Dump effective configuration and exit. "
                            "Default format is 'human'; others: 'json', 'json-flat'.")
        p.add_argument("--save-config", metavar="FILE", default=None,
                       help="Write effective configuration to FILE and exit (JSON).")
        p.add_argument("--save-format", choices=("json", "json-flat"), default="json",
                       help="Format used with --save-config (default: json = grouped/sectioned).")
        p.add_argument("--force", "-f", action="store_true",
                       help="Overwrite the target FILE if it already exists (with --save-config).")
        self._bootstrap = p
        return p.parse_known_args(argv)

    def _build_full_parser(self, registrars):
        p = argparse.ArgumentParser(
            description=self.description,
            parents=[self._bootstrap] if self._bootstrap else [],
            add_help=True,
        )

        sections = {}

        # 1) run all registrars and collect sections
        for section, registrar in registrars:
            before = {a.dest for a in p._actions if getattr(a, "dest", None)}
            registrar(p)
            after  = {a.dest for a in p._actions if getattr(a, "dest", None)}
            new_dests = {d for d in (after - before) if d and d != "help"}
            if new_dests:
                sections.setdefault(section, set()).update(new_dests)

        # 2) Add auto-generated per-section log options
        for section in sections.keys():
            opt_name = f"log_{section}"       # internal dest
            cli_flag = f"--log-{section.replace('_', '-')}"
            p.add_argument(cli_flag, dest=opt_name, default=None,
                        help=f"Override log level for component '{section}'")

            # 3) Add them directly into the SAME section
            sections[section].add(opt_name)

        # 4) Snapshot defaults + help text (now that all options exist)
        self._baseline_defaults = {}
        self._action_help = {}
        self._action_choices = {}
        for a in p._actions:
            d = getattr(a, "dest", None)
            if not d or d == "help":
                continue
            self._baseline_defaults[d] = getattr(a, "default", None)
            self._action_help[d] = getattr(a, "help", "") or "(no description)"
            choices = getattr(a, "choices", None)
            if choices is not None:
                self._action_choices[d] = list(choices)

        self._sections = sections
        self._parser = p
        return p

    # ---------- internal: dump/save & formatting ----------
    def _apply_per_section_overrides(self, args: argparse.Namespace) -> None:
        import logging

        self._log_object_attributes(args)
        self._log_registered_loggers()

        # Keep third-party library logger names aligned with our section names.
        # Example: "log_ws_session" should also control websockets' own logger
        # hierarchy so the admin debug ring doesn't get flooded by frame dumps.
        logger_aliases = {
            "ws_session": ("websockets", "websockets.client", "websockets.server"),
        }

        # Automatic section → logger name mapping
        # All section loggers become: runner.<section>
        for key, val in vars(args).items():
            if not key.startswith("log_"):
                continue
            if not val:
                continue

            section = key[4:]
            logger_name = f"{section}"

            try:
                level = getattr(logging, val.upper())
            except Exception:
                continue

            lg = logging.getLogger(logger_name)
            lg.setLevel(level)

            DebugLoggingConfigurator.debug_logger_status(lg)

            for alias_name in logger_aliases.get(section, ()):
                alias_logger = logging.getLogger(alias_name)
                alias_logger.setLevel(level)
                DebugLoggingConfigurator.debug_logger_status(alias_logger)


    def _log_registered_loggers(self)  -> None:
        root = logging.getLogger()

        # Iterate through all registered logger objects
        for name, logger_obj in logging.Logger.manager.loggerDict.items():
            if isinstance(logger_obj, logging.Logger):
                root.info(f"Registered logger: {name}")
            else:
                root.info(f"Placeholder logger: {name}")


    def _log_object_attributes(self, args: argparse.Namespace)  -> None:
        """Log all attributes from vars(obj) into the root logger."""
        root = logging.getLogger()

        for key, value in vars(args).items():
            root.info(f"Key: {key} | Value: {value!r}")



    def _maybe_dump_or_save_and_exit(self, args: argparse.Namespace) -> None:
        """
        If --dump-config and/or --save-config were requested, perform the action(s) and sys.exit(0).
        """
        want_dump = bool(args.dump_config)
        want_save = bool(args.save_config)

        if not (want_dump or want_save):
            return

        # Build effective mappings
        eff_all = self._effective_dict(vars(args))
        grouped = self._group_effective(eff_all)        # sectioned (for human and json)
        flat    = self._flat_effective(eff_all)         # flat

        # (A) Dump
        if want_dump:
            fmt = args.dump_config  # "human" | "json" | "json-flat"
            if fmt == "human":
                text = self._format_human(grouped)
            elif fmt == "json":
                text = json.dumps(grouped, indent=2, ensure_ascii=False) + "\n"
            else:  # "json-flat"
                text = json.dumps(flat, indent=2, ensure_ascii=False) + "\n"
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                # Allow piping to commands that close early (e.g., `head`)
                pass

        # (B) Save
        if want_save:
            path = pathlib.Path(args.save_config)
            if path.exists() and not args.force:
                sys.stderr.write(f"Refusing to overwrite existing file: {path} (use --force)\n")
                sys.stderr.flush()
                sys.exit(2)
            fmt = args.save_format  # "json" | "json-flat"
            payload = _transform_config_secrets(grouped if fmt == "json" else flat, _encrypt_config_secret)
            with path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
            sys.stderr.write(f"Saved configuration to {path}\n")
            sys.stderr.flush()

        # We did what the user asked, so exit gracefully.
        sys.exit(0)

    def _format_human(self, grouped: Dict[str, Dict[str, Any]]) -> str:
        """
        Human-friendly dump formatted like a commented config:
          [section]
          # <description of param A>
          <param_a> : <value>         # active if value differs from built-in default
          # <description of param B>
          # <param_b> : <value>        # commented if value equals built-in default
        """
        lines: List[str] = []

        # Iterate sections deterministically
        for section in sorted(grouped.keys()):
            block = grouped[section]
            if not block:
                continue

            # Compute per-section alignment width
            key_width = max((len(k) for k in block.keys()), default=0)
            lines.append(f"[{section}]")

            # Stable key order inside section
            for k in sorted(block.keys()):
                effective_val = block[k]
                desc = (self._action_help.get(k) or "").strip()
                changed = self._is_changed_from_default(k, effective_val)

                # 1) Description line (always a comment)
                if desc:
                    for line in desc.splitlines():
                        lines.append(f";# {line}")
                else:
                    lines.append(";# (no description)")

                # 2) Parameter line
                rendered_val = self._repr_human(effective_val)
                default_val = self._baseline_defaults.get(k, None)
                rendered_default = self._repr_human(default_val)

                if changed:
                    # Active line + show built-in default
                    lines.append(f"{k.ljust(key_width)} = {rendered_val}  ; default is {rendered_default}")
                else:
                    # Commented line if unchanged (kept '=' for consistency)
                    lines.append(f"; {k.ljust(key_width)} = {rendered_val}")

            # blank line between sections
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def _repr_human(self, v: Any) -> str:
        """Render values compactly for human output."""
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, (list, tuple)):
            # Recurse for inner values
            return "[" + ", ".join(self._repr_human(x) for x in v) + "]"
        s = str(v)
        # Quote strings with whitespace
        if any(ch.isspace() for ch in s):
            return f'"{s}"'
        return s

    def _is_changed_from_default(self, dest: str, effective_val: Any) -> bool:
        """
        Compare effective value to the built-in default captured after registration.
        Treat lists/tuples robustly; simple string/number/bool comparisons otherwise.
        """
        if dest not in self._baseline_defaults:
            return True  # if unknown, consider changed (conservative)
        default = self._baseline_defaults[dest]

        def norm(x):
            if isinstance(x, (list, tuple)):
                return list(x)
            return x

        return norm(effective_val) != norm(default)

    def _effective_dict(self, ns_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strip argparse/bookkeeping internals and return only real CLI/config keys.
        """
        exclude = {
            "config", "dump_config", "save_config", "save_format", "force",
        }
        return {k: v for k, v in ns_dict.items() if not k.startswith("_") and k not in exclude}

    def _group_effective(self, eff: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}
        assigned: Set[str] = set()
        for sec, dests in self._sections.items():
            block = {k: eff[k] for k in dests if k in eff}
            if block:
                grouped[sec] = block
                assigned |= set(block.keys())
        misc = {k: v for k, v in eff.items() if k not in assigned}
        if misc:
            grouped["misc"] = misc
        return grouped

    def _flat_effective(self, eff: Dict[str, Any]) -> Dict[str, Any]:
        return dict(eff)

    # ---------- internal: JSON -> argparse.defaults ----------
    def _expand_env(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return os.path.expanduser(os.path.expandvars(obj))
        if isinstance(obj, list):
            return [self._expand_env(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self._expand_env(v) for k, v in obj.items()}
        return obj

    def _load_json_config(self, path: str) -> Dict[str, Any]:
        p = pathlib.Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        raw = p.read_text(encoding="utf-8")
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON config in {p}: {e}") from e
        expanded = self._expand_env(data)
        return _transform_config_secrets(expanded, _decrypt_config_secret)

    def _scan_actions(self, parser: argparse.ArgumentParser) -> Dict[str, argparse.Action]:
        out: Dict[str, argparse.Action] = {}
        for a in parser._actions:
            d = getattr(a, "dest", None)
            if d and d != "help":
                out[d] = a
        return out

    def _coerce_for_action(self, val: Any, action: argparse.Action) -> Any:
        # booleans (store_true/false)
        if isinstance(action, argparse._StoreTrueAction):
            return bool(val)
        if isinstance(action, argparse._StoreFalseAction):
            return bool(val)

        choices = getattr(action, "choices", None)

        def apply_type(x: Any) -> Any:
            t = getattr(action, "type", None)
            if x is None:
                return None
            return x if t is None else t(x)

        # nargs / append list semantics
        nargs = getattr(action, "nargs", None)
        if nargs in ("*", "+") or isinstance(action, argparse._AppendAction):
            if not isinstance(val, list):
                if isinstance(val, str):
                    items = [s for s in (v.strip() for v in val.split(",")) if s]
                else:
                    items = [val]
            else:
                items = val
            coerced = [apply_type(v) for v in items]
            if choices is not None:
                for v in coerced:
                    if v is None:
                        continue
                    if v not in choices:
                        raise ValueError(f"Invalid value {v!r}; expected one of {sorted(choices)}")
            return coerced

        # count action: allow integer
        if isinstance(action, argparse._CountAction):
            return int(val)

        # scalar
        v = apply_type(val)
        if choices is not None and v is not None and v not in choices:
            raise ValueError(f"Invalid value {v!r}; expected one of {sorted(choices)}")
        return v

    def _apply_config_defaults_from_json(self, parser: argparse.ArgumentParser, cfg: Dict[str, Any]) -> None:
        actions = self._scan_actions(parser)
        # Flatten sectioned or flat JSON
        flat: Dict[str, Any] = {}
        for k, v in cfg.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    flat[kk] = vv
            else:
                flat[k] = v
        # Coerce/validate and set defaults
        defaults: Dict[str, Any] = {}
        for dest, val in flat.items():
            a = actions.get(dest)
            if not a:  # unknown keys -> ignore (or raise if you want strict mode)
                continue
            defaults[dest] = self._coerce_for_action(val, a)
        if defaults:
            parser.set_defaults(**defaults)
# ========================= End ConfigAwareCLI (JSON) ==========================

RUNTIME_CLI_DESCRIPTION = (
    'Bidirectional UDP/TCP multiplexed transfer with keepalive, '
    'auto-discovery, meters, dashboard, and overlay state machine'
)


def default_runtime_registrars() -> List[Tuple[str, Callable[[argparse.ArgumentParser], None]]]:
    return [
        ("stats_board",        StatsBoard.register_cli),
        ("secure_link",       SecureLinkPskSession.register_cli),
        ("compress_layer",    CompressLayerSession.register_cli),
        ("udp_session",        UdpSession.register_cli),
        ("ws_session",         WebSocketSession.register_cli),
        ("tcp_session",        TcpStreamSession.register_cli),
        ("quic_session",       QuicSession.register_cli),
        ("channel_mux",        ChannelMux.register_cli),
        ("admin_web",          AdminWebUI.register_cli),
        ("debug_logging",      DebugLoggingConfigurator.register_cli),
        ("runner",             Runner.register_overlay_cli),
    ]


def _attach_runtime_cli_metadata(args: argparse.Namespace, cli: ConfigAwareCLI) -> argparse.Namespace:
    args._config_sections = {k: sorted(v) for k, v in cli.sections.items()}
    args._config_defaults = dict(cli._baseline_defaults)
    args._config_help = dict(cli._action_help)
    args._config_choices = dict(cli._action_choices)
    return args


def parse_runtime_args(
    argv: Optional[List[str]] = None,
    *,
    apply_logging: bool = True,
) -> argparse.Namespace:
    cli = ConfigAwareCLI(description=RUNTIME_CLI_DESCRIPTION)
    args = cli.parse_args(argv, default_runtime_registrars())
    _attach_runtime_cli_metadata(args, cli)
    if apply_logging:
        DebugLoggingConfigurator.from_args(args).apply()
    return args


def build_runtime_args_from_config(
    config: Optional[Mapping[str, Any]] = None,
    argv: Optional[Sequence[str]] = None,
    *,
    config_path: Optional[str] = None,
    apply_logging: bool = False,
) -> argparse.Namespace:
    """
    Build a runtime argparse namespace from an in-memory config mapping.

    This is the programmatic counterpart to ``parse_runtime_args``. It avoids
    CLI-only actions such as ``--dump-config``/``--save-config`` and gives
    embedders a stable way to create a ``Runner`` without invoking the process
    entrypoint.
    """
    cli = ConfigAwareCLI(description=RUNTIME_CLI_DESCRIPTION)
    parser = cli._build_full_parser(default_runtime_registrars())
    if config:
        cli._raw_config = dict(config)
        cli._apply_config_defaults_from_json(parser, dict(config))
        cli._config_file_state = "loaded"
    else:
        cli._config_file_state = "missing"
    argv_list = list(argv or [])
    args = parser.parse_args(argv_list)
    persisted_config_path = str(config_path or "")
    args.config = persisted_config_path
    args.dump_config = None
    args.save_config = None
    args.save_format = "json"
    args.force = False
    args._config_file_state = cli._config_file_state
    args._first_start_detected = False
    args._config_path = str(pathlib.Path(persisted_config_path).expanduser().resolve()) if persisted_config_path else ""
    _attach_runtime_cli_metadata(args, cli)
    cli._apply_per_section_overrides(args)
    if apply_logging:
        DebugLoggingConfigurator.from_args(args).apply()
    return args


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_runtime_args(argv, apply_logging=True)

    r = Runner(args)
    try:
        asyncio.run(r.run())
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
