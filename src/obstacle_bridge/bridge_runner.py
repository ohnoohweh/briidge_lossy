from __future__ import annotations

from ._bridge_import import export_bridge_globals
import base64
import contextlib as _process_contextlib
import ctypes
import secrets
import shutil
import signal as _process_signal
import subprocess
import tempfile
import threading
from typing import Mapping

from .bridge_tun_helper_client import _open_local_helper_connection

_bridge = export_bridge_globals(globals())

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
        tun_icmp_stage_counts: dict[str, int] = {}
        tun_probe_boundary_counts: dict[str, int] = {}
        tun_local_reply_stage_counts: dict[str, int] = {}
        tun_probe_last_timeout_diag: dict[str, Any] = {}
        tun_probe_last_timeout_diag_by_transport: dict[str, dict[str, Any]] = {}
        for idx, mux in enumerate(self._muxes):
            snap = mux.snapshot_connections()
            udp_rows.extend(snap.get("udp", []))
            tcp_rows.extend(snap.get("tcp", []))
            tun_rows.extend(snap.get("tun", []))
            counts = snap.get("counts", {}) or {}
            udp_listening += int(counts.get("udp_listening", 0) or 0)
            tcp_listening += int(counts.get("tcp_listening", 0) or 0)
            tun_listening += int(counts.get("tun_listening", 0) or 0)
            for key, value in dict(snap.get("tun_icmp_stage_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_icmp_stage_counts[stage] = int(tun_icmp_stage_counts.get(stage, 0) or 0) + int(value or 0)
            for key, value in dict(snap.get("tun_probe_boundary_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_probe_boundary_counts[stage] = int(tun_probe_boundary_counts.get(stage, 0) or 0) + int(value or 0)
            for key, value in dict(snap.get("tun_local_reply_stage_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_local_reply_stage_counts[stage] = int(tun_local_reply_stage_counts.get(stage, 0) or 0) + int(value or 0)
            timeout_diag = dict(snap.get("tun_probe_last_timeout_diag") or {})
            if timeout_diag:
                label = f"session-{idx}"
                tun_probe_last_timeout_diag_by_transport[label] = timeout_diag
                captured_at = float(timeout_diag.get("captured_at_unix_ts") or 0.0)
                current_at = float(tun_probe_last_timeout_diag.get("captured_at_unix_ts") or 0.0)
                if captured_at >= current_at:
                    tun_probe_last_timeout_diag = timeout_diag
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
            "tun_icmp_stage_counts": tun_icmp_stage_counts,
            "tun_probe_boundary_counts": tun_probe_boundary_counts,
            "tun_local_reply_stage_counts": tun_local_reply_stage_counts,
            "tun_probe_last_timeout_diag": tun_probe_last_timeout_diag,
            "tun_probe_last_timeout_diag_by_transport": tun_probe_last_timeout_diag_by_transport,
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

    @staticmethod
    def _peer_label_for_ui(value) -> Optional[object]:
        if value is None:
            return None
        if isinstance(value, Mapping):
            host = str(value.get("host") or "").strip()
            try:
                port = int(value.get("port") or 0)
            except Exception:
                port = 0
            if host and port > 0:
                return {"host": host, "port": port}
            if host:
                return {"host": host, "port": 0}
            return None
        text = str(value).strip()
        return text or None


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
        self._proxy_provider_servers: Dict[str, ObstacleBridgeProxyServer] = {}
        self._proxy_provider_last_error: str = ""
        self._tun_helper_settings = TunExecutionSettings.from_mapping(vars(args))
        self._tun_helper_client: Optional[TunHelperClient] = None
        self._tun_helper_backend: Optional[LinuxTunHelperInMemoryBackend] = None
        self._tun_helper_process: Optional[asyncio.subprocess.Process] = None
        self._tun_helper_prestarted: bool = False
        self._tun_helper_session_token: str = ""
        self._tun_helper_socket_path: str = ""
        self._tun_helper_config_path: str = ""
        self._tun_helper_last_error: str = ""
        self._tun_helper_runtime_snapshot: dict[str, Any] = {}
        self._tun_helper_last_repair_snapshot: dict[str, Any] = {}
        self._tun_helper_lifecycle_phase: str = (
            "disabled" if self._tun_helper_settings.mode != "helper" else "idle"
        )
        self.stats = StatsBoard(args )
        self.admin_web = None
        self._restart_requested: Optional[asyncio.Event] = None
        self._restart_requested_flag = False
        self._restart_exit_code: int = RESTART_EXIT_CODE_IMMEDIATE
        self._shutdown_exit_code: Optional[int] = None
        self._shutdown_reason: str = ""
        self._restart_reason: str = ""
        self._rotation_restart_requested = False
        self._last_connected_monotonic: Optional[float] = None
        self._last_disconnected_monotonic: Optional[float] = None
        self._last_connection_lifecycle_monotonic: Optional[float] = None
        self._client_restart_watchdog_task: Optional[asyncio.Task] = None        
        self._peer_traffic_rate_state: Dict[str, Tuple[float, int, int]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_diag_lock = threading.Lock()
        self._async_diag: Dict[str, Any] = {
            "last_started_name": "",
            "last_started_kind": "",
            "last_started_monotonic": None,
            "last_finished_name": "",
            "last_finished_kind": "",
            "last_finished_monotonic": None,
            "last_failed_name": "",
            "last_failed_kind": "",
            "last_failed_monotonic": None,
            "last_failed_error": "",
        }
        self._sync_diag: Dict[str, Any] = {
            "last_started_name": "",
            "last_started_kind": "",
            "last_started_monotonic": None,
            "last_finished_name": "",
            "last_finished_kind": "",
            "last_finished_monotonic": None,
            "last_failed_name": "",
            "last_failed_kind": "",
            "last_failed_monotonic": None,
            "last_failed_error": "",
        }

    def _record_async_activity(self, name: str, *, kind: str, phase: str, error: str = "") -> None:
        now_mono = time.monotonic()
        with self._async_diag_lock:
            if phase == "started":
                self._async_diag["last_started_name"] = str(name or "")
                self._async_diag["last_started_kind"] = str(kind or "")
                self._async_diag["last_started_monotonic"] = now_mono
            elif phase == "finished":
                self._async_diag["last_finished_name"] = str(name or "")
                self._async_diag["last_finished_kind"] = str(kind or "")
                self._async_diag["last_finished_monotonic"] = now_mono
            elif phase == "failed":
                self._async_diag["last_failed_name"] = str(name or "")
                self._async_diag["last_failed_kind"] = str(kind or "")
                self._async_diag["last_failed_monotonic"] = now_mono
                self._async_diag["last_failed_error"] = str(error or "")

    def record_sync_activity(self, name: str, *, kind: str = "callback", phase: str, error: str = "") -> None:
        now_mono = time.monotonic()
        with self._async_diag_lock:
            if phase == "started":
                self._sync_diag["last_started_name"] = str(name or "")
                self._sync_diag["last_started_kind"] = str(kind or "")
                self._sync_diag["last_started_monotonic"] = now_mono
            elif phase == "finished":
                self._sync_diag["last_finished_name"] = str(name or "")
                self._sync_diag["last_finished_kind"] = str(kind or "")
                self._sync_diag["last_finished_monotonic"] = now_mono
            elif phase == "failed":
                self._sync_diag["last_failed_name"] = str(name or "")
                self._sync_diag["last_failed_kind"] = str(kind or "")
                self._sync_diag["last_failed_monotonic"] = now_mono
                self._sync_diag["last_failed_error"] = str(error or "")

    async def _await_with_async_diag(self, name: str, awaitable, *, kind: str = "await") -> Any:
        self._record_async_activity(name, kind=kind, phase="started")
        try:
            result = await awaitable
        except Exception as exc:
            self._record_async_activity(name, kind=kind, phase="failed", error=type(exc).__name__)
            raise
        self._record_async_activity(name, kind=kind, phase="finished")
        return result

    def _task_diag_name(self, coro: Any) -> str:
        code = getattr(coro, "cr_code", None)
        if code is not None:
            qualname = getattr(code, "co_qualname", "") or getattr(code, "co_name", "")
            if qualname:
                return str(qualname)
        qualname = getattr(type(coro), "__qualname__", "") or getattr(type(coro), "__name__", "")
        return str(qualname or repr(coro))

    def _install_async_task_factory(self, loop: asyncio.AbstractEventLoop) -> None:
        previous_factory = loop.get_task_factory()
        runner = self

        def _factory(loop_obj, coro, **kwargs):
            task = previous_factory(loop_obj, coro, **kwargs) if previous_factory is not None else asyncio.tasks.Task(coro, loop=loop_obj, **kwargs)
            name = runner._task_diag_name(coro)
            runner._record_async_activity(name, kind="task", phase="started")

            def _done(done_task):
                try:
                    exc = done_task.exception()
                except asyncio.CancelledError:
                    runner._record_async_activity(name, kind="task", phase="finished")
                    return
                except Exception as err:
                    runner._record_async_activity(name, kind="task", phase="failed", error=type(err).__name__)
                    return
                if exc is None:
                    runner._record_async_activity(name, kind="task", phase="finished")
                else:
                    runner._record_async_activity(name, kind="task", phase="failed", error=type(exc).__name__)

            with contextlib.suppress(Exception):
                task.add_done_callback(_done)
            return task

        loop.set_task_factory(_factory)

    def get_async_diagnostics_snapshot(self) -> dict:
        with self._async_diag_lock:
            snapshot = dict(self._async_diag)
            sync_snapshot = dict(self._sync_diag)
        now_mono = time.monotonic()

        def _age(value: Any) -> Optional[float]:
            if value is None:
                return None
            with contextlib.suppress(Exception):
                return max(0.0, now_mono - float(value))
            return None

        return {
            "async": {
                "last_started_name": str(snapshot.get("last_started_name") or ""),
                "last_started_kind": str(snapshot.get("last_started_kind") or ""),
                "last_started_age_sec": _age(snapshot.get("last_started_monotonic")),
                "last_finished_name": str(snapshot.get("last_finished_name") or ""),
                "last_finished_kind": str(snapshot.get("last_finished_kind") or ""),
                "last_finished_age_sec": _age(snapshot.get("last_finished_monotonic")),
                "last_failed_name": str(snapshot.get("last_failed_name") or ""),
                "last_failed_kind": str(snapshot.get("last_failed_kind") or ""),
                "last_failed_age_sec": _age(snapshot.get("last_failed_monotonic")),
                "last_failed_error": str(snapshot.get("last_failed_error") or ""),
            },
            "sync": {
                "last_started_name": str(sync_snapshot.get("last_started_name") or ""),
                "last_started_kind": str(sync_snapshot.get("last_started_kind") or ""),
                "last_started_age_sec": _age(sync_snapshot.get("last_started_monotonic")),
                "last_finished_name": str(sync_snapshot.get("last_finished_name") or ""),
                "last_finished_kind": str(sync_snapshot.get("last_finished_kind") or ""),
                "last_finished_age_sec": _age(sync_snapshot.get("last_finished_monotonic")),
                "last_failed_name": str(sync_snapshot.get("last_failed_name") or ""),
                "last_failed_kind": str(sync_snapshot.get("last_failed_kind") or ""),
                "last_failed_age_sec": _age(sync_snapshot.get("last_failed_monotonic")),
                "last_failed_error": str(sync_snapshot.get("last_failed_error") or ""),
            },
        }

    def _ensure_runtime_events(self) -> None:
        if self._stop is None:
            self._stop = asyncio.Event()
        if self._stop_requested:
            self._stop.set()
        if self._restart_requested is None:
            self._restart_requested = asyncio.Event()
        if self._restart_requested_flag:
            self._restart_requested.set()

    def _proxy_provider_config_snapshot(self) -> dict:
        def _int_config(name: str, default: int) -> int:
            value = getattr(self.args, name, default)
            if value is None or value == "":
                return default
            return int(value)

        raw_auth = getattr(self.args, "proxy_provider_auth", None)
        auth = dict(raw_auth) if isinstance(raw_auth, Mapping) else {}
        raw_egress = getattr(self.args, "proxy_provider_egress", None)
        egress = dict(raw_egress) if isinstance(raw_egress, Mapping) else {}
        raw_policy = getattr(self.args, "proxy_provider_policy", None)
        policy = dict(raw_policy) if isinstance(raw_policy, Mapping) else {}
        protocols = getattr(self.args, "proxy_provider_protocols", None)
        if isinstance(protocols, str):
            protocols = [p.strip() for p in protocols.split(",") if p.strip()]
        if not isinstance(protocols, list):
            protocols = []
        return {
            "enabled": bool(getattr(self.args, "proxy_provider_enabled", False)),
            "bind": str(getattr(self.args, "proxy_provider_bind", "127.0.0.1") or "127.0.0.1"),
            "http_port": _int_config("proxy_provider_http_port", 13881),
            "socks5_port": _int_config("proxy_provider_socks5_port", 13882),
            "protocols": [str(p).strip().lower() for p in protocols if str(p).strip()],
            "auth": auth,
            "egress": egress,
            "policy": policy,
        }

    @staticmethod
    def _proxy_provider_credentials(auth: Mapping[str, Any]) -> Optional[ProxyCredentials]:
        mode = str(auth.get("mode") or "none").strip().lower()
        if mode in {"", "none", "off", "disabled"}:
            return None
        username = str(auth.get("username") or "").strip()
        password = str(auth.get("token") or auth.get("password") or "").strip()
        if not username or not password:
            return None
        return ProxyCredentials(username, password)

    async def _start_proxy_provider(self) -> None:
        cfg = self._proxy_provider_config_snapshot()
        log = logging.getLogger("proxy_provider")
        log.info(
            "[PROXY] provider config enabled=%s bind=%s http_port=%s socks5_port=%s protocols=%r auth_mode=%s",
            cfg["enabled"],
            cfg["bind"],
            cfg["http_port"],
            cfg["socks5_port"],
            cfg["protocols"],
            (cfg.get("auth") or {}).get("mode", "none"),
        )
        if not cfg["enabled"]:
            log.info("[PROXY] provider disabled; listeners will not be started")
            return
        protocols = set(cfg["protocols"] or [])
        http_enabled = bool({"http", "http-connect"} & protocols)
        socks_enabled = bool({"socks5", "socks5-connect"} & protocols)
        if not http_enabled and not socks_enabled:
            self._proxy_provider_last_error = "no proxy protocols enabled"
            log.warning("[PROXY] provider enabled but no supported protocols are configured")
            return
        credentials = self._proxy_provider_credentials(cfg.get("auth") or {})
        if (cfg.get("auth") or {}).get("mode") not in (None, "", "none") and credentials is None:
            log.warning("[PROXY] auth mode requested but username/token are incomplete; proxy starts without auth")
        listener_specs: list[tuple[str, int, bool, bool]] = []
        if http_enabled:
            listener_specs.append(("http", int(cfg["http_port"]), True, False))
        if socks_enabled:
            listener_specs.append(("socks5", int(cfg["socks5_port"]), False, True))
        for name, port, allow_http, allow_socks5 in listener_specs:
            server = ObstacleBridgeProxyServer(
                ObstacleBridgeProxyServerConfig(
                    bind_host=str(cfg["bind"]),
                    port=int(port),
                    credentials=credentials,
                    allow_http=allow_http,
                    allow_socks5=allow_socks5,
                    egress=cfg.get("egress") if isinstance(cfg.get("egress"), dict) else None,
                )
            )
            try:
                await self._await_with_async_diag(f"proxy_provider.{name}.start", server.start())
            except Exception as exc:
                self._proxy_provider_last_error = f"{name}:{type(exc).__name__}:{exc}"
                log.exception("[PROXY] failed to start %s listener bind=%s port=%s", name, cfg["bind"], port)
                raise
            self._proxy_provider_servers[name] = server
        self._proxy_provider_last_error = ""
        log.info("[PROXY] provider started listeners=%s", sorted(self._proxy_provider_servers.keys()))

    async def _stop_proxy_provider(self) -> None:
        log = logging.getLogger("proxy_provider")
        for name, server in list(self._proxy_provider_servers.items()):
            try:
                await self._await_with_async_diag(f"proxy_provider.{name}.stop", server.stop())
            except Exception:
                log.exception("[PROXY] failed to stop %s listener", name)
            finally:
                self._proxy_provider_servers.pop(name, None)

    def _proxy_provider_snapshot(self) -> dict:
        cfg = self._proxy_provider_config_snapshot()
        return {
            "enabled": bool(cfg["enabled"]),
            "configured": cfg,
            "listeners": {
                name: server.snapshot()
                for name, server in sorted(self._proxy_provider_servers.items())
            },
            "last_error": self._proxy_provider_last_error,
        }

    async def _start_tun_helper(self) -> None:
        settings = self._tun_helper_settings
        if settings.mode != "helper":
            self._tun_helper_lifecycle_phase = "disabled"
            return
        settings.ensure_supported_platform()
        if self._tun_helper_process is not None and self._tun_helper_client is not None:
            self._tun_helper_lifecycle_phase = "connected"
            return
        attach_config = self._load_prestarted_tun_helper_config()
        self._tun_helper_prestarted = bool(attach_config)
        self._tun_helper_session_token = (
            str(attach_config.get("session_token") or "") if attach_config else secrets.token_urlsafe(18)
        )
        self._tun_helper_socket_path = (
            str(attach_config.get("socket_path") or "") if attach_config else settings.resolved_socket_path()
        )
        self._tun_helper_backend = None
        try:
            await self._reap_stale_tun_helper_processes(self._tun_helper_socket_path)
            if self._tun_helper_prestarted:
                self._tun_helper_process = None
                self._tun_helper_lifecycle_phase = "attaching_prestarted"
            else:
                self._tun_helper_lifecycle_phase = "launching_process"
                self._tun_helper_process = await self._await_with_async_diag(
                    "tun_helper.process.start",
                    self._launch_tun_helper_process(),
                )
            self._tun_helper_lifecycle_phase = "waiting_for_socket"
            await self._await_with_async_diag(
                "tun_helper.process.ready",
                self._wait_for_tun_helper_socket_ready(
                    timeout_s=self._tun_helper_socket_ready_timeout_s(),
                ),
            )
            self._tun_helper_client = TunHelperClient(
                socket_path=self._tun_helper_socket_path,
                session_token=self._tun_helper_session_token,
                response_timeout_s=self._tun_helper_response_timeout_s(),
                logger=logging.getLogger("tun_helper_client"),
            )
            self._tun_helper_lifecycle_phase = "connecting_client"
            await self._await_with_async_diag(
                "tun_helper.client.connect",
                self._tun_helper_client.connect(),
            )
            setattr(self.args, "_tun_helper_settings", settings)
            setattr(self.args, "_tun_helper_client", self._tun_helper_client)
            self._tun_helper_last_error = ""
            self._tun_helper_lifecycle_phase = "connected"
        except Exception as exc:
            self._tun_helper_last_error = f"{type(exc).__name__}:{exc}"
            self._tun_helper_lifecycle_phase = "start_failed"
            with contextlib.suppress(Exception):
                if self._tun_helper_client is not None:
                    await self._tun_helper_client.close()
            self._tun_helper_client = None
            with contextlib.suppress(Exception):
                await self._stop_tun_helper_process()
            self._tun_helper_process = None
            self._tun_helper_prestarted = False
            self._tun_helper_backend = None
            raise

    def _load_prestarted_tun_helper_config(self) -> dict[str, Any]:
        config_path = str(os.environ.get("OBSTACLEBRIDGE_PRESTARTED_TUN_HELPER_CONFIG") or "").strip()
        if not config_path:
            return {}
        with open(config_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("prestarted tun helper config must be a JSON object")
        socket_path = str(payload.get("socket_path") or "").strip()
        session_token = str(payload.get("session_token") or "").strip()
        if not socket_path:
            raise ValueError("prestarted tun helper config is missing socket_path")
        if not session_token:
            raise ValueError("prestarted tun helper config is missing session_token")
        return {
            "socket_path": socket_path,
            "session_token": session_token,
        }

    async def _reap_stale_tun_helper_processes(self, planned_socket_path: str) -> None:
        socket_path = str(planned_socket_path or "").strip()
        if not socket_path:
            return
        runtime_dirs = {pathlib.Path(self._tun_helper_settings.resolved_runtime_dir()).expanduser()}
        if not (is_local_tcp_endpoint(socket_path) or is_windows_pipe_path(socket_path)):
            runtime_dirs.add(pathlib.Path(socket_path).expanduser().parent)
        for runtime_dir in runtime_dirs:
            if not runtime_dir.is_dir():
                continue
            for config_path in runtime_dir.glob("tun-helper-launch-*.json"):
                await self._reap_stale_tun_helper_launch_record(config_path, socket_path)

    async def _reap_stale_tun_helper_launch_record(self, config_path: pathlib.Path, planned_socket_path: str) -> None:
        socket_path = str(planned_socket_path or "").strip()
        if not socket_path:
            return
        helper_socket = ""
        helper_token = ""
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if not isinstance(payload, dict):
                return
            helper_socket = str(payload.get("socket_path") or "").strip()
            helper_token = str(payload.get("session_token") or "").strip()
            owner_pid = int(payload.get("owner_pid") or 0)
        except Exception:
            return
        if not helper_socket or not helper_token or helper_socket == socket_path:
            return
        if owner_pid > 0 and self._process_is_running(owner_pid):
            # Another bridge process may still be starting its helper and has
            # not authenticated a client yet. It is not a stale launch record.
            return
        if not self._helper_endpoint_candidate_exists(helper_socket):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(config_path)
            return
        client = TunHelperClient(
            socket_path=helper_socket,
            session_token=helper_token,
            response_timeout_s=0.5,
            logger=logging.getLogger("tun_helper_reaper"),
        )
        try:
            await client.connect()
            snapshot = await client.snapshot()
            active_clients = int(snapshot.get("active_authenticated_clients") or 0)
            if active_clients > 1:
                return
            with contextlib.suppress(Exception):
                await client.request("STOP", {})
        except Exception:
            return
        finally:
            with contextlib.suppress(Exception):
                await client.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(config_path)

    @staticmethod
    def _helper_endpoint_candidate_exists(socket_path: str) -> bool:
        helper_socket = str(socket_path or "").strip()
        if not helper_socket:
            return False
        if is_local_tcp_endpoint(helper_socket) or is_windows_pipe_path(helper_socket):
            return True
        return os.path.exists(helper_socket)

    @staticmethod
    def _process_is_running(pid: int) -> bool:
        if int(pid) <= 0:
            return False
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    async def _stop_tun_helper(self) -> None:
        if self._tun_helper_settings.mode == "helper":
            self._tun_helper_lifecycle_phase = "stopping"
        for attr in ("_tun_helper_settings", "_tun_helper_client", "_tun_helper_backend"):
            with contextlib.suppress(Exception):
                delattr(self.args, attr)
        if self._tun_helper_client is not None:
            with contextlib.suppress(Exception):
                await self._await_with_async_diag(
                    "tun_helper.client.close",
                    self._tun_helper_client.close(),
                )
            self._tun_helper_client = None
        with contextlib.suppress(Exception):
            await self._await_with_async_diag(
                "tun_helper.process.stop",
                self._stop_tun_helper_process(),
            )
        self._tun_helper_process = None
        self._tun_helper_backend = None
        self._tun_helper_prestarted = False
        self._tun_helper_session_token = ""
        self._tun_helper_config_path = ""
        self._tun_helper_lifecycle_phase = (
            "disabled" if self._tun_helper_settings.mode != "helper" else "stopped"
        )

    def _tun_helper_snapshot(self) -> dict:
        settings = self._tun_helper_settings
        process_returncode = None if self._tun_helper_process is None else self._tun_helper_process.returncode
        client_connected = bool(self._tun_helper_client is not None)
        client_last_error = ""
        if self._tun_helper_client is not None:
            status_getter = getattr(self._tun_helper_client, "connection_status", None)
            if callable(status_getter):
                with contextlib.suppress(Exception):
                    conn = dict(status_getter() or {})
                    client_connected = bool(conn.get("connected"))
                    client_last_error = str(conn.get("last_error") or "")
        payload: dict[str, Any] = {
            "enabled": settings.mode == "helper",
            "mode": settings.mode,
            "lifecycle_phase": self._tun_helper_lifecycle_phase,
            "backend": settings.helper_backend,
            "apply_network": bool(settings.helper_apply_network),
            "socket_path": self._tun_helper_socket_path or settings.resolved_socket_path(),
            "connected": client_connected,
            "server_started": bool(self._tun_helper_prestarted or (self._tun_helper_process is not None and process_returncode is None)),
            "server_prestarted": bool(self._tun_helper_prestarted),
            "pid": None if self._tun_helper_process is None else int(self._tun_helper_process.pid or 0),
            "process_returncode": None if process_returncode is None else int(process_returncode),
            "last_error": str(self._tun_helper_last_error or client_last_error or ""),
        }
        if self._tun_helper_client is not None:
            getter = getattr(self._tun_helper_client, "cached_snapshot", None)
            if callable(getter):
                with contextlib.suppress(Exception):
                    self._tun_helper_runtime_snapshot = dict(getter() or {})
        if self._tun_helper_runtime_snapshot:
            payload["runtime"] = dict(self._tun_helper_runtime_snapshot)
        process_identity = dict((payload.get("runtime") or {}).get("process_identity") or {})
        if not process_identity:
            process_identity = self._current_process_identity_snapshot()
        if process_identity:
            payload["process_identity"] = process_identity
        if bool(payload.get("enabled")) and not bool(payload.get("connected")):
            if bool(payload.get("server_started")):
                payload["lifecycle_phase"] = "waiting_for_client"
            elif isinstance(process_returncode, int) and self._tun_helper_lifecycle_phase == "connected":
                payload["lifecycle_phase"] = "process_exited"
        recovery = self._tun_helper_recovery_snapshot(payload)
        if recovery:
            payload["recovery"] = recovery
        if self._tun_helper_last_repair_snapshot:
            payload["last_repair"] = dict(self._tun_helper_last_repair_snapshot)
        return payload

    @staticmethod
    def _current_process_identity_snapshot() -> dict[str, Any]:
        uid: Optional[int] = None
        gid: Optional[int] = None
        user = ""
        group = ""
        geteuid = getattr(os, "geteuid", None)
        getegid = getattr(os, "getegid", None)
        with contextlib.suppress(Exception):
            if callable(geteuid):
                uid = int(geteuid())
        with contextlib.suppress(Exception):
            if callable(getegid):
                gid = int(getegid())
        if uid is not None:
            with contextlib.suppress(Exception):
                import pwd

                user = str(pwd.getpwuid(uid).pw_name or "")
        if gid is not None:
            with contextlib.suppress(Exception):
                import grp

                group = str(grp.getgrgid(gid).gr_name or "")
        return {
            "uid": uid,
            "gid": gid,
            "user": user,
            "group": group,
            "is_root": bool(uid == 0),
        }

    @staticmethod
    def _tun_helper_recovery_snapshot(helper_snapshot: dict[str, Any]) -> dict[str, Any]:
        helper = dict(helper_snapshot or {})
        runtime = dict(helper.get("runtime") or {})
        if not bool(helper.get("enabled")):
            return {}
        if bool(helper.get("connected")):
            return {}
        if bool(helper.get("server_started")):
            return {}
        process_returncode = helper.get("process_returncode")
        if not isinstance(process_returncode, int):
            return {}

        stale_firewall = bool(runtime.get("firewall_manager")) or bool(runtime.get("applied_firewall_rules"))
        stale_network = bool(runtime.get("network_applied"))
        stale_network = stale_network or bool(runtime.get("applied_ipv4_cidr")) or bool(runtime.get("applied_ipv6_cidr"))
        stale_network = stale_network or bool(runtime.get("applied_ipv4_routes")) or bool(runtime.get("applied_ipv6_routes"))
        stale_network = stale_network or bool(runtime.get("policy_rules4")) or bool(runtime.get("policy_rules6"))
        stale_network = stale_network or bool(runtime.get("applied_dns_servers"))
        if not stale_firewall and not stale_network:
            return {}

        warnings: list[str] = []
        if stale_firewall:
            warnings.append("firewall_rules_may_remain")
        if stale_network:
            warnings.append("helper_owned_network_state_may_remain")
        summary = "Privileged TUN helper exited while helper-owned host state may still need manual cleanup."
        repair_hint = "Manual cleanup may be required: inspect helper-owned firewall, routes, addresses, and DNS state before restarting helper-backed TUN."
        return {
            "needs_manual_cleanup": True,
            "stale_firewall_possible": stale_firewall,
            "stale_network_possible": stale_network,
            "warnings": warnings,
            "summary": summary,
            "repair_hint": repair_hint,
        }

    async def _launch_tun_helper_process(self) -> asyncio.subprocess.Process:
        repo_src = str(pathlib.Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        existing_pythonpath = str(env.get("PYTHONPATH") or "").strip()
        env["PYTHONPATH"] = repo_src if not existing_pythonpath else os.pathsep.join([repo_src, existing_pythonpath])
        self._tun_helper_config_path = self._write_tun_helper_launch_config()
        helper_executable = self._tun_helper_executable()
        module_argv = [
            helper_executable,
            "-m",
            "obstacle_bridge.bridge_tun_helper_server",
            "--config-path",
            self._tun_helper_config_path,
        ]
        exec_argv = list(module_argv)
        backend_name = str(self._tun_helper_settings.helper_backend or DEFAULT_TUN_HELPER_BACKEND).strip().lower()
        geteuid = getattr(os, "geteuid", None)
        needs_linux_helper_privilege = bool(
            sys.platform.startswith("linux")
            and backend_name in {"linux-native", "linux_native", "linux-real"}
            and callable(geteuid)
            and int(geteuid()) != 0
        )
        needs_darwin_helper_privilege = bool(
            sys.platform.startswith("darwin")
            and backend_name in {"darwin-native", "darwin_native", "macos-native", "macos_native"}
            and callable(geteuid)
            and int(geteuid()) != 0
        )
        needs_windows_helper_privilege = bool(
            sys.platform.startswith("win")
            and backend_name in {"windows-native", "windows_native", "wintun-native", "wintun_native"}
            and not _is_windows_admin()
        )
        if needs_linux_helper_privilege and not _linux_native_tun_helper_can_launch_without_sudo(helper_executable):
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise RuntimeError(
                    "Linux helper mode with the native backend needs elevated privileges, but sudo is not available. "
                    "Install sudo, run as root, or select the linux-python helper backend."
                )
            print(
                "ObstacleBridge helper mode needs elevated privileges to create/configure the local Linux TUN device. "
                "sudo may now ask for your password for the helper subprocess only.",
                file=sys.stderr,
                flush=True,
            )
            self.log.warning("[RUNNER] launching elevated Linux TUN helper subprocess for native helper backend")
            exec_argv = _sudo_tun_helper_exec_argv(module_argv)
        elif needs_linux_helper_privilege:
            self.log.info("[RUNNER] launching native Linux TUN helper without sudo because CAP_NET_ADMIN/CAP_SYS_ADMIN is already available")
        elif needs_darwin_helper_privilege:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise RuntimeError(
                    "macOS helper mode with the native backend needs elevated privileges, but sudo is not available. "
                    "Install sudo, run as root, or select inline mode."
                )
            print(
                "ObstacleBridge helper mode needs elevated privileges to create/configure the local macOS utun device. "
                "sudo may now ask for your password for the helper subprocess only.",
                file=sys.stderr,
                flush=True,
            )
            self.log.warning("[RUNNER] launching elevated macOS TUN helper subprocess for native helper backend")
            exec_argv = _sudo_tun_helper_exec_argv(module_argv)
        elif needs_windows_helper_privilege:
            print(
                "ObstacleBridge helper mode needs elevated privileges to create/configure the local Windows TUN device. "
                "A UAC prompt may now appear for the helper subprocess only.",
                file=sys.stderr,
                flush=True,
            )
            self.log.warning("[RUNNER] launching elevated Windows TUN helper subprocess for windows-native helper backend")
            return _launch_windows_elevated_helper_process(
                module_argv,
                env_updates={"PYTHONPATH": str(env.get("PYTHONPATH") or "")},
            )
        return await asyncio.create_subprocess_exec(
            *exec_argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )

    def _tun_helper_launch_config_payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "owner_pid": int(os.getpid()),
            "socket_path": str(self._tun_helper_socket_path or ""),
            "session_token": str(self._tun_helper_session_token or ""),
            "backend": str(self._tun_helper_settings.helper_backend or DEFAULT_TUN_HELPER_BACKEND),
            "log_level": str(self._tun_helper_settings.helper_log_level or "INFO"),
            "authenticated_client_idle_timeout_s": self._tun_helper_authenticated_client_idle_timeout_s(),
        }

    def _write_tun_helper_launch_config(self) -> str:
        socket_path = str(self._tun_helper_socket_path or "").strip()
        if not socket_path:
            raise RuntimeError("tun helper socket path is not prepared before helper launch config write")
        runtime_dir = pathlib.Path(self._tun_helper_settings.resolved_runtime_dir()).expanduser().resolve()
        runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix="tun-helper-launch-", suffix=".json", dir=str(runtime_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(
                    self._tun_helper_launch_config_payload(),
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            with contextlib.suppress(Exception):
                os.unlink(path)
            raise
        with contextlib.suppress(Exception):
            os.chmod(path, 0o600)
        return str(path)

    async def _wait_for_tun_helper_socket_ready(self, *, timeout_s: float = 2.0) -> None:
        deadline = time.monotonic() + float(timeout_s)
        while time.monotonic() < deadline:
            proc = self._tun_helper_process
            if proc is not None and proc.returncode is not None:
                raise RuntimeError(f"tun helper process exited early with code {proc.returncode}")
            if str(self._tun_helper_socket_path or "").startswith("\\\\.\\pipe\\") or is_local_tcp_endpoint(self._tun_helper_socket_path):
                try:
                    probe_reader, probe_writer = await _open_local_helper_connection(self._tun_helper_socket_path)
                except (FileNotFoundError, ConnectionError, OSError, TimeoutError):
                    pass
                else:
                    probe_writer.close()
                    with contextlib.suppress(Exception):
                        await probe_writer.wait_closed()
                    return
            if os.path.exists(self._tun_helper_socket_path):
                return
            await asyncio.sleep(0.02)
        raise TimeoutError(f"timed out waiting for tun helper socket {self._tun_helper_socket_path}")

    def _tun_helper_socket_ready_timeout_s(self) -> float:
        settings = self._tun_helper_settings
        backend_name = str(getattr(settings, "helper_backend", "") or DEFAULT_TUN_HELPER_BACKEND).strip().lower()
        helper_executable = self._tun_helper_executable()
        geteuid = getattr(os, "geteuid", None)
        needs_linux_helper_privilege = bool(
            sys.platform.startswith("linux")
            and backend_name in {"linux-native", "linux_native", "linux-real"}
            and callable(geteuid)
            and int(geteuid()) != 0
        )
        needs_darwin_helper_privilege = bool(
            sys.platform.startswith("darwin")
            and backend_name in {"darwin-native", "darwin_native", "macos-native", "macos_native"}
            and callable(geteuid)
            and int(geteuid()) != 0
        )
        if needs_linux_helper_privilege and not _linux_native_tun_helper_can_launch_without_sudo(helper_executable):
            return 30.0
        if needs_darwin_helper_privilege:
            return 30.0
        if sys.platform.startswith("win") and backend_name in {"windows-native", "windows_native", "wintun-native", "wintun_native"} and not _is_windows_admin():
            return 30.0
        return 2.0

    def _tun_helper_executable(self) -> str:
        override = str(os.environ.get("OBSTACLEBRIDGE_TUN_HELPER_EXECUTABLE") or "").strip()
        return override or sys.executable

    def _tun_helper_response_timeout_s(self) -> float:
        settings = self._tun_helper_settings
        backend_name = str(getattr(settings, "helper_backend", "") or DEFAULT_TUN_HELPER_BACKEND).strip().lower()
        if sys.platform.startswith("win") and backend_name in {"windows-native", "windows_native", "wintun-native", "wintun_native"}:
            return 20.0
        if sys.platform.startswith("darwin") and backend_name in {"darwin-native", "darwin_native", "macos-native", "macos_native"}:
            # Creating and bringing up utun can take longer than the generic
            # local IPC budget. Do not abandon OPEN_TUN before APPLY_NETWORK.
            return 10.0
        return 1.0

    def _tun_helper_authenticated_client_idle_timeout_s(self) -> float:
        if self._tun_helper_prestarted or str(os.environ.get("OBSTACLEBRIDGE_PRESTARTED_TUN_HELPER_CONFIG") or "").strip():
            return 30.0
        return 5.0

    async def _stop_tun_helper_process(self) -> None:
        proc = self._tun_helper_process
        if self._tun_helper_prestarted:
            self._cleanup_tun_helper_launch_config()
            return
        if proc is None:
            self._cleanup_tun_helper_launch_config()
            return
        if proc.returncode is not None:
            self._cleanup_tun_helper_launch_config()
            return
        if self._tun_helper_client is not None:
            with contextlib.suppress(Exception):
                await self._tun_helper_client.request("STOP", {})
            request_shutdown = getattr(proc, "request_shutdown", None)
            if callable(request_shutdown):
                with contextlib.suppress(Exception):
                    request_shutdown()
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
            self._cleanup_tun_helper_launch_config()
            return
        except asyncio.TimeoutError:
            proc.terminate()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        if proc.returncode is None:
            proc.kill()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=1.0)
        self._cleanup_tun_helper_launch_config()

    def _cleanup_tun_helper_launch_config(self) -> None:
        path = str(self._tun_helper_config_path or "").strip()
        self._tun_helper_config_path = ""
        if not path:
            return
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    async def start(self) -> None:
        ios_admin_ui = str(_admin_ui_platform()).strip().lower() == "ios"
        self._loop = asyncio.get_running_loop()
        self._install_async_task_factory(self._loop)
        self.log.debug("[SERVER] Runner start on session id=%x", id(self))
        self.log.info(
            "[SERVER] ObstacleBridge build=%r crypto_extract=%r",
            _detect_build_info(),
            available_crypto_extract(),
        )
        self._ensure_runtime_events()
        await self._start_tun_helper()
        await self._start_proxy_provider()

        # Make the local admin UI available before overlay/session startup can
        # block on network state. This is especially important for iOS packet
        # tunnel providers where WebAdmin is the recovery/config surface.
        if getattr(self.args, "admin_web", False) and self.admin_web is None:
            self.admin_web = AdminWebUI(self.args, self)
            await self._await_with_async_diag("AdminWebUI.start", self.admin_web.start())

        loop = asyncio.get_running_loop()
        transport_sessions = Runner.build_sessions_from_overlay(self.args)
        shared_tun_registry = ProcessSharedTunRegistry()
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
            mux = ChannelMux.from_args(
                session,
                loop,
                self.args,
                on_local_rx_bytes=self.stats.on_app_rx_bytes,
                on_local_tx_bytes=self.stats.on_app_tx_bytes
            )
            setattr(mux, "_runner_sync_diag_cb", self.record_sync_activity)
            mux.set_on_connection_rotation_result(
                lambda result, transport_name=transport_name: self._on_connection_rotation_result(transport_name, result)
            )
            mux._process_shared_tun_registry = shared_tun_registry
            session.set_on_peer_set(
                lambda host, port, mux=mux: (
                    self.stats.on_peer_set(host, port),
                    mux.on_overlay_peer_set(host, port),
                )
            )
            self._sessions.append(session)
            self._muxes.append(mux)
            self._session_labels.append(transport_name)
            session.set_on_transport_epoch_change(
                lambda epoch, transport_name=transport_name, session=session, mux=mux:
                    self._on_transport_epoch_change(transport_name, session, mux, epoch)
            )
            set_lifecycle = getattr(session, "set_on_connection_lifecycle", None)
            if callable(set_lifecycle):
                set_lifecycle(
                    lambda event, transport_name=transport_name, session=session, mux=mux:
                    self._on_connection_lifecycle(transport_name, session, mux, event)
                )
            await self._await_with_async_diag(f"{transport_name}.session.start", session.start())
            await self._await_with_async_diag(f"{transport_name}.mux.start", mux.start())

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
                await self._await_with_async_diag("StatsBoard.start", self.stats.start())
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
                await asyncio.wait_for(self.stop(reason="run-finally"), timeout=2.0)
            except Exception:
                self.log.debug("[RUNNER] stop timed out during restart")

        if self._restart_requested is not None and self._restart_requested.is_set():
            self.log.warning("[RUNNER] exiting rc=%d", int(self._restart_exit_code))
            raise SystemExit(int(self._restart_exit_code))

        if self._shutdown_exit_code is not None:
            self.log.warning("[RUNNER] exiting rc=%d", self._shutdown_exit_code)
            raise SystemExit(self._shutdown_exit_code)

        self.log.debug("[RUNNER] Leaving stop")


    async def stop(self, reason: str = ""):
        stop_reason = str(reason or self._shutdown_reason or self._restart_reason or "unspecified")
        self.log.info(
            "[SERVER] Stop entered reason=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_reason=%r",
            stop_reason,
            self._shutdown_exit_code,
            self._shutdown_reason,
            self._restart_requested_flag,
            self._restart_reason,
        )

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

        self.log.debug("[RUNNER] stop: entering proxy_provider.stop")
        await _run_stop_step("proxy_provider.stop", self._stop_proxy_provider(), timeout_s=3.0)

        self.log.debug("[RUNNER] stop: entering stats.stop")
        await _run_stop_step("stats.stop", self.stats.stop(), timeout_s=2.0)

        self.log.debug("[RUNNER] stop: entering mux.stop")
        for idx, mux in enumerate(reversed(self._muxes)):
            await _run_stop_step(f"mux.stop[{idx}]", mux.stop(reason=stop_reason), timeout_s=5.0)

        self.log.debug("[RUNNER] stop: entering tun_helper.stop")
        await _run_stop_step("tun_helper.stop", self._stop_tun_helper(), timeout_s=3.0)

        self.log.debug("[RUNNER] stop: entering _session_obj")
        for idx, session in enumerate(reversed(self._sessions)):
            await _run_stop_step(f"session.stop[{idx}]", session.stop(), timeout_s=5.0)
        self.log.info("[RUNNER] stop leaving reason=%s", stop_reason)

    @staticmethod
    def _session_connection_layers_snapshot(session: Optional[ISession]) -> list[dict]:
        if session is None:
            return []
        getter = getattr(session, "get_connection_layers_snapshot", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                layers = list(getter() or [])
                return [dict(layer) for layer in layers if isinstance(layer, dict)]
        connected = False
        with contextlib.suppress(Exception):
            connected = bool(session.is_connected())
        return [{
            "layer": "session",
            "transport": "",
            "state": "connected" if connected else "disconnected",
            "epoch": 0,
            "connected": connected,
            "app_ready": connected,
        }]

    @classmethod
    def _session_app_ready(cls, session: Optional[ISession]) -> bool:
        layers = cls._session_connection_layers_snapshot(session)
        if layers:
            return bool(layers[-1].get("app_ready"))
        return False

    @staticmethod
    def _session_transport_connected_since_unix_ts(session: Optional[ISession], *, peer_id: Optional[int] = None) -> Optional[float]:
        if session is None:
            return None
        getter = getattr(session, "get_transport_connected_since_unix_ts", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                value = getter(peer_id=peer_id)
                return float(value) if value is not None else None
        return None

    # ---- overlay state propagation (unchanged behavior) -----------------------
    def _on_state_change(self, transport_name: str, session: ISession, connected: bool):
        self.log.debug(f"[SERVER] _on_state_change transport={transport_name} connected={connected}")

        now_mono = time.monotonic()
        aggregate_connected = any(self._session_app_ready(s) for s in self._sessions) if self._sessions else self._session_app_ready(session)
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
        if mux and not callable(getattr(session, "set_on_connection_lifecycle", None)):
            try:
                asyncio.get_running_loop().create_task(mux.on_overlay_state(self._session_app_ready(session)))
            except RuntimeError:
                pass
        # Reset overlay epoch state on disconnect so reconnect starts clean.
        if not aggregate_connected:
            resetter = getattr(session, "reset_transport_epoch", None)
            if not callable(resetter):
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
        resetter = getattr(session, "reset_transport_epoch", None)
        if not callable(resetter):
            resetter = getattr(session, "reset_sender", None)
        if callable(resetter):
            with contextlib.suppress(Exception):
                resetter()
        try:
            asyncio.get_running_loop().create_task(mux.on_transport_epoch_change(epoch))
        except RuntimeError:
            pass

    def _on_connection_lifecycle(self, transport_name: str, session: ISession, mux: "ChannelMux", event) -> None:
        self._last_connection_lifecycle_monotonic = time.monotonic()
        self.log.debug(
            "[SERVER] lifecycle transport=%s session=%x state=%s epoch=%s reason=%s",
            transport_name, id(session), event.state.value, int(event.epoch), event.reason,
        )
        try:
            asyncio.get_running_loop().create_task(mux.on_connection_lifecycle(event))
        except RuntimeError:
            pass

    def _on_connection_rotation_result(self, transport_name: str, result) -> None:
        if not bool(getattr(result, "restart_required", False)) or self._rotation_restart_requested:
            return
        self._rotation_restart_requested = True
        cycle = getattr(result, "candidate_cycle", None)
        self.request_restart(reason=f"transport_candidate_cycles_exhausted transport={transport_name} cycle={cycle}")

    def _restart_requires_delay(self) -> bool:
        raw = str(getattr(self.args, "overlay_transport", "") or "")
        parts = [item.strip().lower() for item in raw.split(",") if item.strip()]
        return "myudp" in parts

    @staticmethod
    def _emit_lifecycle_warning(message: str, *args) -> None:
        with contextlib.suppress(Exception):
            logging.getLogger().warning(message, *args)

    def request_restart(self, reason: str = "") -> None:
        self._restart_reason = str(reason or getattr(self, "_restart_reason", "") or "unspecified")
        self._emit_lifecycle_warning("[RUNNER] restart requested reason=%s", self._restart_reason)
        self.log.info("[SERVER] Runner restart requested reason=%s", self._restart_reason)
        callback = getattr(self, "_embedded_restart_callback", None)
        if callable(callback):
            self.log.debug("[SERVER] dispatching embedded restart callback reason=%s", self._restart_reason)
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
        restart_fallback_labels: list[str] = []
        for idx, session in enumerate(self._sessions):
            sessions += 1
            peer_row_ids = self._session_peer_row_ids(idx, session)
            if target:
                if target not in peer_row_ids:
                    continue
                matched_target = True
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            method = getattr(session, "request_reconnect", None)
            if not callable(method):
                if str(label or "").strip().lower() == "myudp":
                    restart_fallback_labels.append(str(label))
                continue
            ok = False
            with contextlib.suppress(Exception):
                ok = bool(method())
            if ok:
                requested += 1
                transports.append(str(label))
                continue
            if str(label or "").strip().lower() == "myudp":
                restart_fallback_labels.append(str(label))
        if target and not matched_target:
            return {
                "ok": False,
                "target_peer_id": target,
                "requested": 0,
                "sessions": sessions,
                "transports": [],
                "reason": "unknown_peer_id",
            }
        if requested <= 0 and restart_fallback_labels:
            self.request_restart(reason=f"admin_web:/api/reconnect myudp target={target or 'all'}")
            embedded = callable(getattr(self, "_embedded_restart_callback", None))
            return {
                "ok": True,
                "target_peer_id": target or None,
                "requested": 1,
                "sessions": sessions,
                "transports": restart_fallback_labels[:1],
                "reason": "",
                "reconnect_requested": True,
                "reconnect_supported": True,
                "restart_requested": True,
                "restart_embedded": embedded,
                "restart_delay_sec": 0,
                "restart_mode": "immediate",
            }
        return {
            "ok": requested > 0,
            "target_peer_id": target or None,
            "requested": requested,
            "sessions": sessions,
            "transports": transports,
            "reason": "" if requested > 0 else "no reconnect-capable client overlay session is currently running",
        }

    def request_tun_helper_repair(self) -> dict:
        helper = self._tun_helper_snapshot()
        recovery = dict(helper.get("recovery") or {})
        runtime = dict(helper.get("runtime") or {})
        if not bool(helper.get("enabled")):
            return {"ok": False, "reason": "tun_helper_disabled", "repaired": [], "failed": []}
        if bool(helper.get("connected")) or bool(helper.get("server_started")):
            return {"ok": False, "reason": "helper_still_running", "repaired": [], "failed": []}
        if not bool(recovery.get("needs_manual_cleanup")):
            return {"ok": False, "reason": "no_stale_helper_state_detected", "repaired": [], "failed": []}
        backend_name = str(helper.get("backend") or "").strip().lower()
        repair_backend = None
        if backend_name == "linux-native":
            repair_backend = LinuxTunHelperBackend
        elif backend_name == "windows-native":
            repair_backend = WindowsTunHelperBackend
        if repair_backend is None:
            return {"ok": False, "reason": "repair_unsupported_for_helper_backend", "repaired": [], "failed": []}

        result = repair_backend.repair_runtime_snapshot(runtime)
        verification = repair_backend.verify_runtime_snapshot_repaired(runtime)
        if bool(result.get("ok")):
            repaired_runtime = dict(result.get("runtime") or {})
            repaired_runtime["ifname"] = str(runtime.get("ifname") or repaired_runtime.get("ifname") or "")
            repaired_runtime["backend"] = str(runtime.get("backend") or repaired_runtime.get("backend") or backend_name)
            self._tun_helper_runtime_snapshot = repaired_runtime
        status = self._tun_helper_snapshot()
        status_helper = dict(status.get("tun_helper") or {})
        status_recovery = dict(status_helper.get("recovery") or {})
        stale_state_remaining = bool(verification.get("stale_state_remaining")) or bool(status_recovery.get("needs_manual_cleanup"))
        overall_ok = not stale_state_remaining
        cleanup_ok = bool(result.get("ok"))
        if overall_ok and cleanup_ok:
            summary = "Repair succeeded and post-repair verification did not find remaining helper-owned state."
        elif overall_ok:
            summary = "Repair verification did not find remaining helper-owned state, although some cleanup steps reported errors."
        else:
            summary = "Repair attempted but some stale helper-owned state may still remain."
        self._tun_helper_last_repair_snapshot = {
            "attempted": True,
            "ok": overall_ok,
            "cleanup_ok": cleanup_ok,
            "stale_state_remaining": stale_state_remaining,
            "repaired": list(result.get("repaired") or []),
            "failed": list(result.get("failed") or []),
            "verification": dict(verification or {}),
            "verified_state": "stale_state_may_remain" if stale_state_remaining else "stale_state_cleared",
            "summary": summary,
            "unix_ts": float(time.time()),
        }
        return {
            "ok": overall_ok,
            "cleanup_ok": cleanup_ok,
            "reason": "" if overall_ok else "repair_incomplete",
            "repaired": list(result.get("repaired") or []),
            "failed": list(result.get("failed") or []),
            "verification": dict(verification or {}),
            "status": self._tun_helper_snapshot(),
        }

    async def request_tun_enabled(self, enabled: bool) -> dict:
        helper = self._tun_helper_snapshot()
        runtime = dict(helper.get("runtime") or {})
        if not bool(helper.get("enabled")):
            return {"ok": False, "reason": "tun_helper_disabled"}
        if not bool(helper.get("apply_network")):
            return {"ok": False, "reason": "helper_apply_network_disabled"}
        if not bool(runtime.get("included_routes_toggle_supported")):
            return {"ok": False, "reason": "toggle_unsupported_for_helper_backend"}
        if not bool(runtime.get("network_applied")):
            return {"ok": False, "reason": "tun_network_not_applied"}

        payload = {
            "enabled": bool(enabled),
            "ifname": str(runtime.get("ifname") or ""),
            "tun_routing": dict(vars(TunRoutingSettings.from_mapping(vars(self.args)))),
        }
        if self._tun_helper_backend is not None:
            setter = getattr(self._tun_helper_backend, "set_tun_enabled", None)
            if not callable(setter):
                return {"ok": False, "reason": "toggle_unsupported_for_helper_backend"}
            updated = await setter(payload)
        elif self._tun_helper_client is not None:
            updated = await self._tun_helper_client.set_tun_enabled(payload)
        else:
            return {"ok": False, "reason": "tun_helper_unavailable"}

        self._tun_helper_runtime_snapshot = dict(updated or {})
        return {
            "ok": True,
            "enabled": bool(updated.get("included_routes_active")),
            "status": self._tun_helper_snapshot(),
        }

    async def probe_tun_connectivity_verification(
        self,
        *,
        ifname: str,
        target: str,
        timeout_seconds: float,
        probe_kind: str,
    ) -> dict[str, Any]:
        text_ifname = str(ifname or "").strip()
        text_target = str(target or "").strip()
        for mux in self._muxes:
            prober = getattr(mux, "probe_tun_connectivity", None)
            if not callable(prober):
                continue
            try:
                result = await prober(
                    ifname=text_ifname,
                    target=text_target,
                    timeout_s=float(timeout_seconds),
                    probe_kind=str(probe_kind or ""),
                )
            except Exception as exc:
                return {
                    "label": "TUN connectivity verification",
                    "ok": False,
                    "state": "failed",
                    "summary": "TUN connectivity verification: failed",
                    "detail": f"Runner probe dispatch failed: {type(exc).__name__}: {exc}",
                    "target": text_target,
                    "method": "internal_icmp_echo",
                    "checked_at_unix_ts": float(time.time()),
                    "value_ms": None,
                    "last_success_ago_s": None,
                    "last_success_rtt_ms": None,
                }
            if isinstance(result, dict) and str(result.get("state") or "") != "skipped":
                return dict(result)
        return {
            "label": "TUN connectivity verification",
            "ok": False,
            "state": "skipped",
            "summary": "TUN connectivity verification: skipped",
            "detail": "No active mux exposed the requested TUN interface for verification.",
            "target": text_target,
            "method": "internal_icmp_echo",
            "checked_at_unix_ts": float(time.time()),
            "value_ms": None,
            "last_success_ago_s": None,
            "last_success_rtt_ms": None,
        }

    def get_status_snapshot(self) -> dict:
        try:
            payload = dict(self.stats.snapshot_status())
        except Exception as exc:
            self.log.warning("[RUNNER] stats snapshot failed; returning minimal status: %r", exc)
            connected = False
            sess = self._session_obj
            if sess is not None:
                with contextlib.suppress(Exception):
                    connected = bool(self._session_app_ready(sess))
            payload = {
                "peer_state": STATE_CONNECTED if connected else STATE_DISCONNECTED,
                "stats_snapshot_error": type(exc).__name__,
            }
        payload["connection_layers"] = [
            {
                "transport": str(label),
                "layers": self._session_connection_layers_snapshot(session),
            }
            for label, session in zip(self._session_labels, self._sessions)
        ]
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
        payload["proxy_provider"] = self._proxy_provider_snapshot()
        payload["tun_helper"] = self._tun_helper_snapshot()
        return payload

    def get_connections_snapshot(self) -> dict:
        if not self._muxes:
            return {
                "udp": [],
                "tcp": [],
                "tun": [],
                "counts": {"udp": 0, "tcp": 0, "tun": 0, "udp_listening": 0, "tcp_listening": 0, "tun_listening": 0},
                "tun_icmp_stage_counts": {},
                "tun_probe_boundary_counts": {},
                "tun_local_reply_stage_counts": {},
                "tun_probe_last_timeout_diag": {},
            }

        udp_rows: list[dict] = []
        tcp_rows: list[dict] = []
        tun_rows: list[dict] = []
        udp_listening = 0
        tcp_listening = 0
        tun_listening = 0
        tun_icmp_stage_counts: dict[str, int] = {}
        tun_probe_boundary_counts: dict[str, int] = {}
        tun_local_reply_stage_counts: dict[str, int] = {}
        tun_probe_last_timeout_diag: dict[str, Any] = {}
        tun_probe_last_timeout_diag_by_transport: dict[str, dict[str, Any]] = {}

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
            for key, value in dict(snap.get("tun_icmp_stage_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_icmp_stage_counts[stage] = int(tun_icmp_stage_counts.get(stage, 0) or 0) + int(value or 0)
            for key, value in dict(snap.get("tun_probe_boundary_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_probe_boundary_counts[stage] = int(tun_probe_boundary_counts.get(stage, 0) or 0) + int(value or 0)
            for key, value in dict(snap.get("tun_local_reply_stage_counts") or {}).items():
                stage = str(key or "")
                if stage:
                    tun_local_reply_stage_counts[stage] = int(tun_local_reply_stage_counts.get(stage, 0) or 0) + int(value or 0)
            timeout_diag = dict(snap.get("tun_probe_last_timeout_diag") or {})
            if timeout_diag:
                session_labels = list(getattr(self, "_session_labels", []) or [])
                label = str(session_labels[idx] if idx < len(session_labels) else f"session-{idx}").strip()
                tun_probe_last_timeout_diag_by_transport[label] = timeout_diag
                captured_at = float(timeout_diag.get("captured_at_unix_ts") or 0.0)
                current_at = float(tun_probe_last_timeout_diag.get("captured_at_unix_ts") or 0.0)
                if captured_at >= current_at:
                    tun_probe_last_timeout_diag = timeout_diag

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
            "tun_icmp_stage_counts": tun_icmp_stage_counts,
            "tun_probe_boundary_counts": tun_probe_boundary_counts,
            "tun_local_reply_stage_counts": tun_local_reply_stage_counts,
            "tun_probe_last_timeout_diag": tun_probe_last_timeout_diag,
            "tun_probe_last_timeout_diag_by_transport": tun_probe_last_timeout_diag_by_transport,
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
            "ws_peer_addresses": "ws_session",
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
                transmit_delay_sample_ms=getattr(session_obj, "transmit_delay_sample_ms", None),
                transmit_delay_est_ms=getattr(session_obj, "transmit_delay_est_ms", None),
                last_rtt_ok_ns=getattr(session_obj, "last_rtt_ok_ns", None),
                inflight=int(session_obj.in_flight()) if hasattr(session_obj, "in_flight") else None,
                max_inflight=getattr(session_obj, "max_in_flight", None),
                waiting_count=int(session_obj.waiting_count()) if hasattr(session_obj, "waiting_count") else None,
                last_ack_peer=getattr(session_obj, "last_ack_peer", None),
                last_sent_ctr=getattr(session_obj, "last_sent_ctr", None),
                expected=getattr(session_obj, "expected", None),
                peer_missed_count=getattr(session_obj, "peer_missed_count", None),
                our_missed_count=len(getattr(session_obj, "missing", [])) if hasattr(session_obj, "missing") else None,
                batch_datagrams_sent=getattr(session_obj, "batch_datagrams_sent", None),
                batch_chunks_sent=getattr(session_obj, "batch_chunks_sent", None),
                batch_datagrams_received=getattr(session_obj, "batch_datagrams_received", None),
                batch_chunks_received=getattr(session_obj, "batch_chunks_received", None),
                malformed_batches=getattr(session_obj, "malformed_batches", None),
                batch_stream_bytes_sent=getattr(session_obj, "batch_stream_bytes_sent", None),
                batch_stream_bytes_received=getattr(session_obj, "batch_stream_bytes_received", None),
                queued_stream_bytes=(session_obj._queued_stream_bytes() if hasattr(session_obj, "_queued_stream_bytes") else None),
                stream_queue_age_ms=(session_obj.stream_queue_age_ms() if hasattr(session_obj, "stream_queue_age_ms") else None),
                retransmitted_chunks=getattr(session_obj, "retransmitted_chunks", None),
                stream_decode_errors=getattr(session_obj, "stream_decode_errors", None),
            )
        except Exception:
            return fallback or SessionMetrics()

    def _session_retransmit_stats(self, session_obj) -> dict:
        hist: dict = {}
        buffered_frames = 0
        budget: dict = {}
        inner = session_obj
        with contextlib.suppress(Exception):
            source = self._unwrap_snapshot_session(session_obj)
            inner = getattr(source, "inner_session", source)
            hist = dict(getattr(inner, "stats_hist", {}) or {})
            waiting_count = getattr(inner, "waiting_count", None)
            if callable(waiting_count):
                buffered_frames = int(waiting_count())
            budget_getter = getattr(source, "get_transport_budget_snapshot", None)
            if callable(budget_getter):
                budget = dict(budget_getter() or {})
        return {
            "buffered_frames": buffered_frames,
            "first_pass": int(hist.get("once", 0)),
            "repeated_once": int(hist.get("twice", 0)),
            "repeated_multiple": int(hist.get("thrice", 0)) + int(hist.get("gt3", 0)),
            "confirmed_total": int(hist.get("confirmed_total", 0)),
            "batch_datagrams_sent": int(getattr(inner, "batch_datagrams_sent", 0) or 0),
            "batch_chunks_sent": int(getattr(inner, "batch_chunks_sent", 0) or 0),
            "batch_datagrams_received": int(getattr(inner, "batch_datagrams_received", 0) or 0),
            "batch_chunks_received": int(getattr(inner, "batch_chunks_received", 0) or 0),
            "malformed_batches": int(getattr(inner, "malformed_batches", 0) or 0),
            "batch_stream_bytes_sent": int(getattr(inner, "batch_stream_bytes_sent", 0) or 0),
            "batch_stream_bytes_received": int(getattr(inner, "batch_stream_bytes_received", 0) or 0),
            "queued_stream_bytes": int(inner._queued_stream_bytes()) if hasattr(inner, "_queued_stream_bytes") else 0,
            "stream_queue_age_ms": float(inner.stream_queue_age_ms()) if hasattr(inner, "stream_queue_age_ms") else 0.0,
            "retransmitted_chunks": int(getattr(inner, "retransmitted_chunks", 0) or 0),
            "stream_decode_errors": int(getattr(inner, "stream_decode_errors", 0) or 0),
            "budget": budget,
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

    def _session_peer_endpoint_for_ui(self, session_obj: Any, transport: Optional[str] = None) -> Optional[object]:
        candidates: list[Any] = []
        for candidate in (session_obj, self._unwrap_snapshot_session(session_obj)):
            if candidate is None:
                continue
            if any(candidate is existing for existing in candidates):
                continue
            candidates.append(candidate)
        for candidate in candidates:
            with contextlib.suppress(Exception):
                peer_proto = getattr(candidate, "peer_proto", None)
                send_port = getattr(peer_proto, "send_port", None)
                peer_addr = getattr(send_port, "peer_addr", None)
                if isinstance(peer_addr, tuple) and len(peer_addr) >= 2 and peer_addr[0] and int(peer_addr[1]) > 0:
                    return {"host": str(peer_addr[0]), "port": int(peer_addr[1])}
            with contextlib.suppress(Exception):
                host = str(getattr(candidate, "_peer_host") or "").strip()
                port = int(getattr(candidate, "_peer_port") or 0)
                if host and port > 0:
                    return {"host": host, "port": port}
            with contextlib.suppress(Exception):
                getter = getattr(candidate, "get_overlay_peers_snapshot", None)
                if callable(getter):
                    for row in list(getter() or []):
                        if bool(row.get("listening")):
                            continue
                        peer_value = RunnerMuxAggregate._peer_label_for_ui(row.get("peer"))
                        if peer_value is not None:
                            return peer_value
        if transport:
            source_args = getattr(session_obj, "_args", None) or self.args
            with contextlib.suppress(Exception):
                real_session = self._unwrap_snapshot_session(session_obj)
                source_args = getattr(real_session, "_args", None) or source_args
            with contextlib.suppress(Exception):
                _, peer_attr, peer_port_attr, _ = _overlay_cli_attrs(str(transport or "myudp").strip().lower())
                host = str(getattr(source_args, peer_attr, "") or "").strip()
                port = int(getattr(source_args, peer_port_attr, 0) or 0)
                if host and port > 0:
                    return {"host": host, "port": port}
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
    def _first_non_null(*values: Any) -> Any:
        for value in values:
            if value is not None:
                return value
        return None

    def _session_connecting_timer_snapshot(self, session: Any) -> dict:
        candidates = []
        for candidate in (session, self._unwrap_snapshot_session(session), getattr(session, "inner_session", None)):
            if candidate is None:
                continue
            if any(candidate is existing for existing in candidates):
                continue
            candidates.append(candidate)
        for candidate in candidates:
            getter = getattr(candidate, "get_connecting_timer_snapshot", None)
            if callable(getter):
                with contextlib.suppress(Exception):
                    snap = dict(getter() or {})
                    if snap:
                        return snap
        return {"next_address_attempt_in_seconds": None}

    def _client_restart_watchdog_timer_snapshot(self, session: Any) -> dict:
        timeout_s = float(getattr(self.args, "client_restart_if_disconnected", 0.0) or 0.0)
        if timeout_s <= 0:
            return {"restart_in_seconds": None}
        if not _has_configured_overlay_peer(self.args):
            return {"restart_in_seconds": None}
        restart_requested = getattr(self, "_restart_requested", None)
        if restart_requested is not None and bool(restart_requested.is_set()):
            return {"restart_in_seconds": None}
        stop_evt = getattr(self, "_stop", None)
        if stop_evt is not None and bool(stop_evt.is_set()):
            return {"restart_in_seconds": None}
        session_obj = getattr(self, "_session_obj", None)
        if session_obj is not None:
            real_session_obj = self._unwrap_snapshot_session(session_obj)
            real_session = self._unwrap_snapshot_session(session)
            if session is not session_obj and real_session is not session_obj and real_session is not real_session_obj:
                return {"restart_in_seconds": None}
        secure_link_status = {}
        get_secure_link_status = getattr(session, "get_secure_link_status_snapshot", None)
        if callable(get_secure_link_status):
            with contextlib.suppress(Exception):
                secure_link_status = dict(get_secure_link_status() or {})
        if (
            str(secure_link_status.get("state") or "").strip().lower() == "failed"
            and str(secure_link_status.get("failure_reason") or "").strip().lower() == "revoked_serial"
        ):
            return {"restart_in_seconds": None}
        disconnected_since = getattr(self, "_last_disconnected_monotonic", None)
        if disconnected_since is None:
            return {"restart_in_seconds": timeout_s}
        remaining = max(0.0, timeout_s - (time.monotonic() - float(disconnected_since)))
        return {"restart_in_seconds": remaining}

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

        def _merge_throttle_summary(current: Optional[dict], candidate: Any) -> Optional[dict]:
            if not isinstance(candidate, dict) or candidate.get("applicable") is False:
                return current
            if current is None:
                return {
                    "applicable": True,
                    "active": bool(candidate.get("active")),
                    "stalled": bool(candidate.get("stalled")),
                    "backpressure_active": bool(candidate.get("backpressure_active")),
                    "disabled": bool(candidate.get("disabled")),
                    "budget_bytes": int(candidate.get("budget_bytes", 0) or 0),
                    "used_bytes": int(candidate.get("used_bytes", 0) or 0),
                    "remaining_bytes": int(candidate.get("remaining_bytes", 0) or 0),
                    "aggregate": dict(candidate.get("aggregate") or {}),
                    "scope": dict(candidate.get("scope") or {}) if isinstance(candidate.get("scope"), dict) else None,
                }
            current["active"] = bool(current.get("active")) or bool(candidate.get("active"))
            current["stalled"] = bool(current.get("stalled")) or bool(candidate.get("stalled"))
            current["backpressure_active"] = bool(current.get("backpressure_active")) or bool(candidate.get("backpressure_active"))
            current["disabled"] = bool(current.get("disabled")) and bool(candidate.get("disabled"))
            current["budget_bytes"] = max(
                int(current.get("budget_bytes", 0) or 0),
                int(candidate.get("budget_bytes", 0) or 0),
            )
            current["used_bytes"] = max(
                int(current.get("used_bytes", 0) or 0),
                int(candidate.get("used_bytes", 0) or 0),
            )
            current["remaining_bytes"] = min(
                int(current.get("remaining_bytes", 0) or 0),
                int(candidate.get("remaining_bytes", 0) or 0),
            )
            current_aggregate = current.get("aggregate") if isinstance(current.get("aggregate"), dict) else {}
            candidate_aggregate = candidate.get("aggregate") if isinstance(candidate.get("aggregate"), dict) else {}
            if not current_aggregate:
                current["aggregate"] = dict(candidate_aggregate)
            elif candidate_aggregate:
                current["aggregate"] = {
                    "scope_id": str(current_aggregate.get("scope_id") or candidate_aggregate.get("scope_id") or ""),
                    "budget_bytes": max(
                        int(current_aggregate.get("budget_bytes", 0) or 0),
                        int(candidate_aggregate.get("budget_bytes", 0) or 0),
                    ),
                    "used_bytes": max(
                        int(current_aggregate.get("used_bytes", 0) or 0),
                        int(candidate_aggregate.get("used_bytes", 0) or 0),
                    ),
                    "remaining_bytes": min(
                        int(current_aggregate.get("remaining_bytes", 0) or 0),
                        int(candidate_aggregate.get("remaining_bytes", 0) or 0),
                    ),
                    "prev_window_bytes": max(
                        int(current_aggregate.get("prev_window_bytes", 0) or 0),
                        int(candidate_aggregate.get("prev_window_bytes", 0) or 0),
                    ),
                    "throttle_drop_count": max(
                        int(current_aggregate.get("throttle_drop_count", 0) or 0),
                        int(candidate_aggregate.get("throttle_drop_count", 0) or 0),
                    ),
                }
            current_scope = current.get("scope") if isinstance(current.get("scope"), dict) else None
            candidate_scope = candidate.get("scope") if isinstance(candidate.get("scope"), dict) else None
            if current_scope is None:
                current["scope"] = dict(candidate_scope) if candidate_scope else None
            elif candidate_scope is not None and int(candidate_scope.get("remaining_bytes", 0) or 0) < int(current_scope.get("remaining_bytes", 0) or 0):
                current["scope"] = dict(candidate_scope)
            return current

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
            if not overlay_rows and real_session is not session:
                with contextlib.suppress(Exception):
                    getter = getattr(real_session, "get_overlay_peers_snapshot", None)
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
                            "peer": RunnerMuxAggregate._peer_label_for_ui(p.get("peer")),
                            "rtt_est_ms": p.get("rtt_est_ms", listener_metrics.rtt_est_ms),
                            "transmit_delay_sample_ms": p.get(
                                "transmit_delay_sample_ms",
                                listener_metrics.transmit_delay_sample_ms,
                            ),
                            "transmit_delay_est_ms": p.get(
                                "transmit_delay_est_ms",
                                listener_metrics.transmit_delay_est_ms,
                            ),
                            "last_incoming_age_seconds": p.get(
                                "last_incoming_age_seconds",
                                self._session_last_incoming_age_seconds(listener_session),
                            ),
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
                    p_throttle: Optional[dict] = None
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
                        p_throttle = _merge_throttle_summary(p_throttle, row.get("throttle"))
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
                        p_throttle = _merge_throttle_summary(p_throttle, row.get("throttle"))
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
                        p_throttle = _merge_throttle_summary(p_throttle, row.get("throttle"))
                    archived = peer_payload_totals.get(int(p.get("peer_id", 0))) or {}
                    p_rx += int(archived.get("rx_bytes", 0) or 0)
                    p_tx += int(archived.get("tx_bytes", 0) or 0)

                    row_connected = bool(p.get("connected", session.is_connected()))
                    row_state = str(p.get("state") or ("connected" if row_connected else "connecting"))
                    secure_link_snapshot = dict(p.get("secure_link") or RunnerMuxAggregate._default_secure_link_snapshot())
                    outer_secure_link = {}
                    get_outer_secure_link = getattr(session, "get_secure_link_status_snapshot", None)
                    if callable(get_outer_secure_link):
                        with contextlib.suppress(Exception):
                            outer_secure_link = dict(get_outer_secure_link() or {})
                    # Transport peer rows do not own SecureLink diagnostics.
                    # Prefer the wrapper's status when the row contains only
                    # the transport-level disabled placeholder.
                    if not bool(secure_link_snapshot.get("enabled")) and bool(outer_secure_link.get("enabled")):
                        secure_link_snapshot = outer_secure_link
                    connected_since_unix_ts = self._first_non_null(
                        p.get("connected_since_unix_ts"),
                        secure_link_snapshot.get("connected_since_unix_ts"),
                        self._session_transport_connected_since_unix_ts(row_session, peer_id=p.get("peer_id")),
                        self._session_transport_connected_since_unix_ts(session, peer_id=p.get("peer_id")),
                    )
                    connecting_timers = self._session_connecting_timer_snapshot(row_session)
                    restart_timer = (
                        self._client_restart_watchdog_timer_snapshot(row_session)
                        if row_state.strip().lower() == "connecting"
                        else {"restart_in_seconds": None}
                    )
                    peers.append({
                        "id": f"{idx}:{p.get('peer_id', 0)}",
                        "transport": label,
                        "state": row_state,
                        "connected": row_connected,
                        "listen": listen_endpoint,
                        "peer": RunnerMuxAggregate._peer_label_for_ui(p.get("peer")),
                        "connection_layers": self._session_connection_layers_snapshot(row_session),
                        "rtt_est_ms": self._first_non_null(p.get("rtt_est_ms"), row_metrics.rtt_est_ms),
                        "transmit_delay_sample_ms": self._first_non_null(
                            p.get("transmit_delay_sample_ms"),
                            row_metrics.transmit_delay_sample_ms,
                        ),
                        "transmit_delay_est_ms": self._first_non_null(
                            p.get("transmit_delay_est_ms"),
                            row_metrics.transmit_delay_est_ms,
                        ),
                        "connected_since_unix_ts": connected_since_unix_ts,
                        "last_incoming_age_seconds": self._first_non_null(
                            p.get("last_incoming_age_seconds"),
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
                        "throttle": p_throttle or {"applicable": False, "active": False, "reason": "no_local_ingress"},
                        "myudp": self._session_retransmit_stats(row_session),
                        "secure_link": secure_link_snapshot,
                        "compress_layer": dict(self._session_compress_layer_snapshot(session, peer_id=p.get("peer_id"))),
                        "next_address_attempt_in_seconds": self._first_non_null(
                            p.get("next_address_attempt_in_seconds"),
                            connecting_timers.get("next_address_attempt_in_seconds"),
                        ),
                        "restart_in_seconds": self._first_non_null(
                            p.get("restart_in_seconds"),
                            restart_timer.get("restart_in_seconds"),
                        ),
                    })
                continue

            rx_bytes = 0
            tx_bytes = 0
            peer_throttle: Optional[dict] = None
            for row in udp_rows + tcp_rows + tun_rows:
                st = row.get("stats", {})
                rx_bytes += int(st.get("rx_bytes", 0) or 0)
                tx_bytes += int(st.get("tx_bytes", 0) or 0)
                peer_throttle = _merge_throttle_summary(peer_throttle, row.get("throttle"))
            for archived in peer_payload_totals.values():
                rx_bytes += int(archived.get("rx_bytes", 0) or 0)
                tx_bytes += int(archived.get("tx_bytes", 0) or 0)
            peer_label = self._session_peer_endpoint_for_ui(session, transport=label)
            decode_errors = 0
            with contextlib.suppress(Exception):
                pp = getattr(real_session, "peer_proto", None) or getattr(session, "peer_proto", None)
                if pp is not None:
                    decode_errors = int(getattr(pp, "unidentified_frames", 0) or 0)
            row_state = "connected" if bool(session.is_connected()) else "connecting"
            connecting_timers = self._session_connecting_timer_snapshot(real_session)
            restart_timer = (
                self._client_restart_watchdog_timer_snapshot(real_session)
                if row_state == "connecting"
                else {"restart_in_seconds": None}
            )
            peers.append({
                "id": idx,
                "transport": label,
                "state": row_state,
                "connected": bool(session.is_connected()),
                "listen": listen_endpoint,
                "peer": peer_label,
                "connection_layers": self._session_connection_layers_snapshot(session),
                "rtt_est_ms": m.rtt_est_ms,
                "transmit_delay_sample_ms": m.transmit_delay_sample_ms,
                "transmit_delay_est_ms": m.transmit_delay_est_ms,
                "connected_since_unix_ts": self._session_transport_connected_since_unix_ts(session),
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
                "throttle": peer_throttle or {"applicable": False, "active": False, "reason": "no_local_ingress"},
                "myudp": self._session_retransmit_stats(session),
                "next_address_attempt_in_seconds": connecting_timers.get("next_address_attempt_in_seconds"),
                "restart_in_seconds": restart_timer.get("restart_in_seconds"),
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
            session_dropped = int(result.get("dropped") or 0)
            dropped += session_dropped
            if session_dropped and normalized_scope in {"local_identity", "all"}:
                mux = self._muxes[idx] if idx < len(self._muxes) else None
                rotate = getattr(mux, "request_connection_rotation", None)
                if callable(rotate):
                    rotation = rotate("secure_link_material_reload")
                    if isinstance(rotation, dict):
                        result["rotation"] = dict(rotation)
                    else:
                        result["rotation"] = {
                            "accepted": bool(getattr(rotation, "accepted", False)),
                            "reason": str(getattr(rotation, "reason", "") or ""),
                            "candidate_cycle": getattr(rotation, "candidate_cycle", None),
                            "restart_required": bool(getattr(rotation, "restart_required", False)),
                        }
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
        for section in sorted(sections.keys()):
            keys = sections.get(section, []) or []
            block = {}
            for key in keys:
                if key in config:
                    block[key] = config[key]
            if block:
                grouped[section] = block
        raw_grouped = getattr(self.args, "_raw_config", None)
        if isinstance(raw_grouped, dict):
            for section in sections:
                raw_block = raw_grouped.get(section)
                if not isinstance(raw_block, dict):
                    continue
                block = grouped.setdefault(section, {})
                for key, value in raw_block.items():
                    if key in block:
                        continue
                    block[key] = value
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
        section_keys = set((getattr(self.args, "_config_sections", {}) or {}).keys())
        normalized_updates: dict[str, Any] = {}
        for key, value in dict(updates).items():
            if key in section_keys and isinstance(value, dict):
                for nested_key, nested_value in value.items():
                    normalized_updates[str(nested_key)] = nested_value
                continue
            normalized_updates[str(key)] = value
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

    def request_shutdown(self, exit_code: Optional[int] = None, reason: str = "") -> None:
        self._shutdown_reason = str(reason or self._shutdown_reason or "unspecified")
        if exit_code is not None:
            self._shutdown_exit_code = int(exit_code)
            self._emit_lifecycle_warning(
                "[RUNNER] shutdown requested rc=%d reason=%s",
                self._shutdown_exit_code,
                self._shutdown_reason,
            )
            self.log.info("[SERVER] Runner shutdown requested rc=%d reason=%s", self._shutdown_exit_code, self._shutdown_reason)
        else:
            self._emit_lifecycle_warning("[RUNNER] shutdown requested reason=%s", self._shutdown_reason)
            self.log.info("[SERVER] Runner shutdown requested reason=%s", self._shutdown_reason)
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

                secure_link_status = {}
                get_secure_link_status = getattr(sess, "get_secure_link_status_snapshot", None)
                if callable(get_secure_link_status):
                    with contextlib.suppress(Exception):
                        secure_link_status = dict(get_secure_link_status() or {})
                if (
                    str(secure_link_status.get("state") or "").strip().lower() == "failed"
                    and str(secure_link_status.get("failure_reason") or "").strip().lower() == "revoked_serial"
                ):
                    continue
                # No disconnect timestamp yet -> initialize defensively
                if self._last_disconnected_monotonic is None:
                    self._last_disconnected_monotonic = time.monotonic()
                    continue

                down_for = time.monotonic() - self._last_disconnected_monotonic
                if down_for < timeout_s:
                    continue
                # A lifecycle event means ChannelMux owns the active outage.
                # This watchdog is only a fallback for sessions that report no
                # lifecycle progress at all.
                if self._last_connection_lifecycle_monotonic is not None:
                    continue

                self.log.warning(
                    "[RUNNER] client disconnected for %.1fs (threshold %.1fs); requesting restart",
                    down_for,
                    timeout_s,
                )
                self.request_restart(reason=f"client_restart_watchdog_missing_lifecycle down_for={down_for:.3f}s timeout={timeout_s:.3f}s")
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

from .bridge_tun_ios import IOSTUNConnectorSettings, IOS_TUN_CONNECTOR_SECTION
from .bridge_proxy_server import (
    ObstacleBridgeProxyProviderSettings,
    ObstacleBridgeProxyServer,
    ObstacleBridgeProxyServerConfig,
    ProxyCredentials,
)
from .bridge_tun_helper_client import TunHelperClient
from .bridge_tun_helper_local_transport import is_local_tcp_endpoint, is_windows_pipe_path
from .bridge_tun_helper_linux import LinuxTunHelperBackend, LinuxTunHelperInMemoryBackend
from .bridge_tun_helper_windows import WindowsTunHelperBackend
from .bridge_tun_helper_settings import (
    DEFAULT_TUN_HELPER_BACKEND,
    TUN_EXECUTION_SECTION,
    TunExecutionSettings,
)
from .bridge_tun_routing import TUN_ROUTING_SECTION, TunRoutingSettings
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
            existing_option_strings = {
                option
                for action in p._actions
                for option in getattr(action, "option_strings", [])
            }
            existing_dests = {getattr(action, "dest", None) for action in p._actions}
            if cli_flag not in existing_option_strings and opt_name not in existing_dests:
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
        raw_grouped = self._raw_config if isinstance(self._raw_config, dict) else {}
        for sec, dests in self._sections.items():
            block = {k: eff[k] for k in dests if k in eff}
            raw_block = raw_grouped.get(sec) if isinstance(raw_grouped.get(sec), dict) else None
            if raw_block:
                for key, value in raw_block.items():
                    if key not in block:
                        block[key] = value
            if block:
                grouped[sec] = block
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
        flat: Dict[str, Any] = {}
        for section in self._sections.keys():
            value = cfg.get(section)
            if not isinstance(value, dict):
                continue
            for kk, vv in value.items():
                # The public tun_execution section uses concise keys, while
                # argparse stores the corresponding CLI destination names.
                if section == TUN_EXECUTION_SECTION:
                    kk = {
                        "mode": "tun_execution_mode",
                        "helper_backend": "tun_helper_backend",
                        "helper_socket": "tun_helper_socket",
                        "helper_apply_network": "tun_helper_apply_network",
                        "helper_log_level": "tun_helper_log_level",
                    }.get(kk, kk)
                flat[kk] = vv
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
        ("admin_web",          AdminWebUI.register_cli),
        ("channel_mux",        ChannelMux.register_cli),
        ("proxy_provider",     ObstacleBridgeProxyProviderSettings.register_cli),
        (IOS_TUN_CONNECTOR_SECTION, IOSTUNConnectorSettings.register_cli),
        (TUN_EXECUTION_SECTION, TunExecutionSettings.register_cli),
        (TUN_ROUTING_SECTION,   TunRoutingSettings.register_cli),
        ("runner",             Runner.register_overlay_cli),
        ("udp_session",        UdpSession.register_cli),
        ("ws_session",         WebSocketSession.register_cli),
        ("quic_session",       QuicSession.register_cli),
        ("tcp_session",        TcpStreamSession.register_cli),
        ("secure_link",        SecureLinkPskSession.register_cli),
        ("compress_layer",     CompressLayerSession.register_cli),
        ("debug_logging",      DebugLoggingConfigurator.register_cli),
        ("stats_board",        StatsBoard.register_cli),
    ]


def _attach_runtime_cli_metadata(args: argparse.Namespace, cli: ConfigAwareCLI) -> argparse.Namespace:
    args._config_sections = {k: sorted(v) for k, v in cli.sections.items()}
    args._config_defaults = dict(cli._baseline_defaults)
    args._config_help = dict(cli._action_help)
    args._config_choices = dict(cli._action_choices)
    args._raw_config = dict(cli._raw_config) if isinstance(cli._raw_config, dict) else {}
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

    def _config_value(doc: Mapping[str, Any], key: str, section: str | None = None) -> Any:
        if section:
            grouped = doc.get(section)
            if isinstance(grouped, Mapping):
                if key in grouped:
                    return grouped.get(key)
        if key in doc:
            return doc.get(key)
        return None

    def _semantic_bootstrap_state(doc: Mapping[str, Any]) -> tuple[bool, str]:
        overlay_transport = str(
            _config_value(doc, "overlay_transport", "runner") or "myudp"
        ).split(",", 1)[0].strip() or "myudp"
        if overlay_transport == "myudp":
            peer_host = _config_value(doc, "udp_peer", "udp_session")
            peer_port = _config_value(doc, "udp_peer_port", "udp_session")
        elif overlay_transport == "tcp":
            peer_host = _config_value(doc, "tcp_peer", "tcp_session")
            peer_port = _config_value(doc, "tcp_peer_port", "tcp_session")
        elif overlay_transport == "ws":
            peer_host = _config_value(doc, "ws_peer", "ws_session")
            peer_port = _config_value(doc, "ws_peer_port", "ws_session")
        else:
            peer_host = None
            peer_port = None
        peer_configured = bool(str(peer_host or "").strip()) and int(peer_port or 0) > 0
        own_servers = _config_value(doc, "own_servers", "channel_mux") or []
        remote_servers = _config_value(doc, "remote_servers", "channel_mux") or []
        first_start_detected = not peer_configured and not own_servers and not remote_servers
        return first_start_detected, ("empty" if first_start_detected else "loaded")

    if config:
        cli._raw_config = dict(config)
        cli._apply_config_defaults_from_json(parser, dict(config))
        cli._first_start_detected, cli._config_file_state = _semantic_bootstrap_state(dict(config))
    else:
        cli._config_file_state = "missing"
        cli._first_start_detected = True
    argv_list = list(argv or [])
    args = parser.parse_args(argv_list)
    persisted_config_path = str(config_path or "")
    args.config = persisted_config_path
    args.dump_config = None
    args.save_config = None
    args.save_format = "json"
    args.force = False
    args._config_file_state = cli._config_file_state
    args._first_start_detected = cli._first_start_detected
    args._config_path = str(pathlib.Path(persisted_config_path).expanduser().resolve()) if persisted_config_path else ""
    _attach_runtime_cli_metadata(args, cli)
    cli._apply_per_section_overrides(args)
    if apply_logging:
        DebugLoggingConfigurator.from_args(args).apply()
    return args


def _signal_name(signum: int) -> str:
    with _process_contextlib.suppress(Exception):
        return _process_signal.Signals(int(signum)).name
    return str(signum)


def _install_process_signal_handlers(runner: Runner, log: logging.Logger) -> list[tuple[int, object]]:
    installed: list[tuple[int, object]] = []

    def _handle_signal(signum: int, _frame: object) -> None:
        exit_code = 128 + int(signum)
        reason = f"signal:{_signal_name(int(signum))}"
        log.warning(
            "[RUNNER] process signal received signum=%d signame=%s exit_code=%d",
            int(signum),
            _signal_name(int(signum)),
            exit_code,
        )
        runner.request_shutdown(exit_code, reason=reason)

    for signum in (_process_signal.SIGINT, _process_signal.SIGTERM):
        with _process_contextlib.suppress(Exception):
            previous = _process_signal.getsignal(signum)
            _process_signal.signal(signum, _handle_signal)
            installed.append((int(signum), previous))
    return installed


def _restore_process_signal_handlers(installed: list[tuple[int, object]]) -> None:
    for signum, previous in installed:
        with _process_contextlib.suppress(Exception):
            _process_signal.signal(signum, previous)


def _configured_local_tun_services(args: argparse.Namespace) -> list[Any]:
    raw_specs = getattr(args, "own_servers", None)
    try:
        specs = ChannelMux._parse_own_servers(raw_specs)
    except Exception:
        return []
    return [spec for spec in specs if str(getattr(spec, "l_proto", "") or "").strip().lower() == "tun"]


def _configured_packetflow_connector_mode(args: argparse.Namespace) -> str:
    return str(getattr(args, "packetflow_connector", "") or "").strip().lower()


def _configured_tun_execution_settings(args: argparse.Namespace) -> TunExecutionSettings:
    return TunExecutionSettings.from_mapping(vars(args))


def _helper_mode_enabled(args: argparse.Namespace) -> bool:
    return str(_configured_tun_execution_settings(args).mode or "").strip().lower() == "helper"


def _needs_linux_tun_elevation(args: argparse.Namespace) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return False
    if int(geteuid()) == 0:
        return False
    if str(os.environ.get("OBSTACLEBRIDGE_LINUX_TUN_ELEVATED", "") or "").strip():
        return False
    if not _configured_local_tun_services(args):
        return False
    if _configured_packetflow_connector_mode(args):
        return False
    if _helper_mode_enabled(args):
        return False
    return True


def _needs_macos_tun_elevation(args: argparse.Namespace) -> bool:
    if not sys.platform.startswith("darwin"):
        return False
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return False
    if int(geteuid()) == 0:
        return False
    if str(os.environ.get("OBSTACLEBRIDGE_MACOS_TUN_ELEVATED", "") or "").strip():
        return False
    if not _configured_local_tun_services(args):
        return False
    if _configured_packetflow_connector_mode(args):
        return False
    if _helper_mode_enabled(args):
        return False
    return True


def _is_windows_admin() -> bool:
    if not sys.platform.startswith("win"):
        return False
    shell32 = getattr(getattr(ctypes, "windll", None), "shell32", None)
    if shell32 is None:
        return False
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def _needs_windows_tun_elevation(args: argparse.Namespace) -> bool:
    if not sys.platform.startswith("win"):
        return False
    if _is_windows_admin():
        return False
    if str(os.environ.get("OBSTACLEBRIDGE_WINDOWS_TUN_ELEVATED", "") or "").strip():
        return False
    if not _configured_local_tun_services(args):
        return False
    if _configured_packetflow_connector_mode(args):
        return False
    return True


def _sudo_tun_elevation_exec_argv(
    argv: Optional[List[str]] = None,
    *,
    elevated_marker_env: str,
) -> list[str]:
    runtime_argv = list(argv) if argv is not None else list(sys.argv[1:])
    preserve_names = [
        elevated_marker_env,
        "OBSTACLEBRIDGE_MACOS_TUN_ELEVATED",
        "OBSTACLEBRIDGE_LINUX_TUN_ELEVATED",
        "PYTHONPATH",
        "VIRTUAL_ENV",
    ]
    preserve_names = list(dict.fromkeys(preserve_names))
    return [
        "sudo",
        "-E",
        f"--preserve-env={','.join(preserve_names)}",
        sys.executable,
        "-m",
        "obstacle_bridge.bridge_runner",
        *runtime_argv,
    ]


def _macos_tun_elevation_exec_argv(argv: Optional[List[str]] = None) -> list[str]:
    return _sudo_tun_elevation_exec_argv(
        argv,
        elevated_marker_env="OBSTACLEBRIDGE_MACOS_TUN_ELEVATED",
    )


def _linux_tun_elevation_exec_argv(argv: Optional[List[str]] = None) -> list[str]:
    return _sudo_tun_elevation_exec_argv(
        argv,
        elevated_marker_env="OBSTACLEBRIDGE_LINUX_TUN_ELEVATED",
    )


def _sudo_tun_helper_exec_argv(module_argv: list[str]) -> list[str]:
    preserve_names = [
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "XDG_RUNTIME_DIR",
    ]
    preserve_names = list(dict.fromkeys(preserve_names))
    return [
        "sudo",
        "-E",
        f"--preserve-env={','.join(preserve_names)}",
        *module_argv,
    ]


_LINUX_CAPABILITY_NAMES = {
    12: "cap_net_admin",
    21: "cap_sys_admin",
}


def _linux_effective_capability_names() -> set[str]:
    if not sys.platform.startswith("linux"):
        return set()
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.startswith("CapEff:"):
                    continue
                raw = line.split(":", 1)[1].strip()
                value = int(raw, 16)
                out: set[str] = set()
                for bit, name in _LINUX_CAPABILITY_NAMES.items():
                    if value & (1 << bit):
                        out.add(name)
                return out
    except Exception:
        return set()
    return set()


def _linux_executable_capability_names(executable: str) -> set[str]:
    path = str(executable or "").strip()
    if not sys.platform.startswith("linux") or not path:
        return set()
    getcap_path = shutil.which("getcap")
    if not getcap_path:
        return set()
    try:
        result = subprocess.run(
            [getcap_path, path],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return set()
    text = str(result.stdout or "").strip().lower()
    out: set[str] = set()
    if "cap_net_admin" in text:
        out.add("cap_net_admin")
    if "cap_sys_admin" in text:
        out.add("cap_sys_admin")
    return out


def _linux_native_tun_helper_can_launch_without_sudo(executable: str) -> bool:
    effective = _linux_effective_capability_names()
    if {"cap_net_admin", "cap_sys_admin"} & effective:
        return True
    file_caps = _linux_executable_capability_names(executable)
    if {"cap_net_admin", "cap_sys_admin"} & file_caps:
        return True
    return False


class _WindowsElevatedHelperProcess:
    def __init__(self, *, pid: int = 0) -> None:
        self.pid = int(pid)
        self.returncode = None
        self._wait_event = asyncio.Event()

    async def wait(self) -> int:
        await self._wait_event.wait()
        return 0 if self.returncode is None else int(self.returncode)

    def request_shutdown(self) -> None:
        if self.returncode is None:
            self.returncode = 0
        self._wait_event.set()

    def terminate(self) -> None:
        self.request_shutdown()

    def kill(self) -> None:
        if self.returncode is None:
            self.returncode = -9
        self._wait_event.set()


def _maybe_reexec_with_sudo_tun_privileges(
    *,
    argv: Optional[List[str]],
    log: logging.Logger,
    notice: str,
    marker_env: str,
    cmd: list[str],
    platform_name: str,
) -> None:
    sudo_path = shutil.which("sudo")
    if not sudo_path:
        raise RuntimeError(
            f"{platform_name} local TUN services require elevated privileges, but sudo is not available. "
            "Install sudo or run the runtime as root."
        )
    env = dict(os.environ)
    env[marker_env] = "1"
    print(notice, file=sys.stderr, flush=True)
    log.warning(
        "[RUNNER] re-executing with elevated privileges for %s local TUN service(s)",
        platform_name,
    )
    os.execvpe(sudo_path, cmd, env)


def _maybe_reexec_with_linux_tun_privileges(
    args: argparse.Namespace,
    *,
    argv: Optional[List[str]],
    log: logging.Logger,
) -> None:
    if not _needs_linux_tun_elevation(args):
        return
    _maybe_reexec_with_sudo_tun_privileges(
        argv=argv,
        log=log,
        notice=(
            "ObstacleBridge needs elevated privileges to create/configure the local Linux TUN device. "
            "sudo may now ask for your password."
        ),
        marker_env="OBSTACLEBRIDGE_LINUX_TUN_ELEVATED",
        cmd=_linux_tun_elevation_exec_argv(argv),
        platform_name="Linux",
    )


def _maybe_reexec_with_macos_tun_privileges(
    args: argparse.Namespace,
    *,
    argv: Optional[List[str]],
    log: logging.Logger,
) -> None:
    if not _needs_macos_tun_elevation(args):
        return
    _maybe_reexec_with_sudo_tun_privileges(
        argv=argv,
        log=log,
        notice=(
            "ObstacleBridge needs elevated privileges to create/configure the local macOS TUN device. "
            "sudo may now ask for your password."
        ),
        marker_env="OBSTACLEBRIDGE_MACOS_TUN_ELEVATED",
        cmd=_macos_tun_elevation_exec_argv(argv),
        platform_name="macOS",
    )


def _windows_tun_elevation_exec_argv(argv: Optional[List[str]] = None) -> list[str]:
    runtime_argv = list(argv) if argv is not None else list(sys.argv[1:])
    return [
        "-m",
        "obstacle_bridge.bridge_runner",
        *runtime_argv,
    ]


def _powershell_single_quoted(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


def _windows_python_shell_execute(
    exec_argv: list[str],
    *,
    env_updates: Optional[Mapping[str, str]] = None,
) -> tuple[str, str]:
    script_lines: list[str] = []
    for key, value in dict(env_updates or {}).items():
        script_lines.append(f"$env:{key} = {_powershell_single_quoted(value)}")
    arg_list = ", ".join(_powershell_single_quoted(part) for part in exec_argv)
    script_lines.append(f"& {_powershell_single_quoted(sys.executable)} @({arg_list})")
    script = "\n".join(script_lines)
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return (
        "powershell.exe",
        f"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
    )


def _windows_tun_elevation_shell_execute(
    argv: Optional[List[str]] = None,
) -> tuple[str, str]:
    exec_argv = _windows_tun_elevation_exec_argv(argv)
    env_updates = {
        "OBSTACLEBRIDGE_WINDOWS_TUN_ELEVATED": "1",
    }
    wintun_dir = str(os.environ.get("WINTUN_DIR", "") or "").strip()
    if wintun_dir:
        env_updates["WINTUN_DIR"] = wintun_dir
    return _windows_python_shell_execute(exec_argv, env_updates=env_updates)


def _windows_tun_helper_shell_execute(
    module_argv: list[str],
    *,
    env_updates: Optional[Mapping[str, str]] = None,
) -> tuple[str, str]:
    merged_env = {
        "OBSTACLEBRIDGE_WINDOWS_TUN_HELPER_ELEVATED": "1",
    }
    merged_env.update({str(key): str(value) for key, value in dict(env_updates or {}).items() if str(value)})
    wintun_dir = str(os.environ.get("WINTUN_DIR", "") or "").strip()
    if wintun_dir and "WINTUN_DIR" not in merged_env:
        merged_env["WINTUN_DIR"] = wintun_dir
    return _windows_python_shell_execute(module_argv, env_updates=merged_env)


def _launch_windows_elevated_helper_process(
    module_argv: list[str],
    *,
    env_updates: Optional[Mapping[str, str]] = None,
) -> _WindowsElevatedHelperProcess:
    shell32 = getattr(getattr(ctypes, "windll", None), "shell32", None)
    if shell32 is None:
        raise RuntimeError(
            "Windows helper mode with the windows-native backend needs Administrator privileges, but shell32 is not available "
            "to request a UAC elevation prompt for the helper subprocess."
        )
    executable, params = _windows_tun_helper_shell_execute(module_argv, env_updates=env_updates)
    rc = int(shell32.ShellExecuteW(None, "runas", executable, params, os.getcwd(), 1))
    if rc <= 32:
        raise RuntimeError(
            "Windows helper mode with the windows-native backend needs Administrator privileges, but the helper elevation request "
            f"failed or was cancelled (ShellExecuteW rc={rc})."
        )
    return _WindowsElevatedHelperProcess()


def _maybe_reexec_with_windows_tun_privileges(
    args: argparse.Namespace,
    *,
    argv: Optional[List[str]],
    log: logging.Logger,
) -> None:
    if not _needs_windows_tun_elevation(args):
        return
    shell32 = getattr(getattr(ctypes, "windll", None), "shell32", None)
    if shell32 is None:
        raise RuntimeError(
            "Windows local TUN services require Administrator privileges, but shell32 is not available "
            "to request a UAC elevation prompt."
        )
    executable, params = _windows_tun_elevation_shell_execute(argv)
    log.warning(
        "[RUNNER] re-executing with elevated privileges for Windows local TUN service(s); "
        "this prompts for UAC so the WinTun adapter can be created in the same Python runtime path"
    )
    rc = int(shell32.ShellExecuteW(None, "runas", executable, params, os.getcwd(), 1))
    if rc <= 32:
        raise RuntimeError(
            "Windows local TUN services require Administrator privileges, but the elevation request "
            f"failed or was cancelled (ShellExecuteW rc={rc})."
        )
    raise SystemExit(0)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_runtime_args(argv, apply_logging=True)
    log = logging.getLogger("runner")
    _maybe_reexec_with_linux_tun_privileges(args, argv=argv, log=log)
    _maybe_reexec_with_macos_tun_privileges(args, argv=argv, log=log)
    _maybe_reexec_with_windows_tun_privileges(args, argv=argv, log=log)
    r = Runner(args)
    installed_signal_handlers = _install_process_signal_handlers(r, log)
    log.info("[RUNNER] process start pid=%s argv=%r", os.getpid(), list(argv) if argv is not None else sys.argv[1:])
    try:
        asyncio.run(r.run())
    except SystemExit as exc:
        log.warning(
            "[RUNNER] process exit via SystemExit code=%r stop_requested=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_rc=%r restart_reason=%r",
            exc.code,
            r._stop_requested,
            r._shutdown_exit_code,
            r._shutdown_reason,
            r._restart_requested_flag,
            r._restart_exit_code,
            r._restart_reason,
        )
        raise
    except KeyboardInterrupt:
        log.warning(
            "[RUNNER] process exit via KeyboardInterrupt stop_requested=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_reason=%r",
            r._stop_requested,
            r._shutdown_exit_code,
            r._shutdown_reason,
            r._restart_requested_flag,
            r._restart_reason,
        )
    except BaseException:
        log.exception(
            "[RUNNER] fatal exception escaped main stop_requested=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_reason=%r",
            r._stop_requested,
            r._shutdown_exit_code,
            r._shutdown_reason,
            r._restart_requested_flag,
            r._restart_reason,
        )
        raise
    finally:
        _restore_process_signal_handlers(installed_signal_handlers)
        log.info(
            "[RUNNER] process leaving stop_requested=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_rc=%r restart_reason=%r",
            r._stop_requested,
            r._shutdown_exit_code,
            r._shutdown_reason,
            r._restart_requested_flag,
            r._restart_exit_code,
            r._restart_reason,
        )

if __name__ == '__main__':
    main()
