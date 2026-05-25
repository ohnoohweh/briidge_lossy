"""Python runtime owner for the iOS IPServer Network Extension."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import traceback
import time
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Mapping, Optional

from obstacle_bridge import bridge_tun_ios
from obstacle_bridge.core import ObstacleBridgeClient

from .app import (
    ObstacleBridgeIOSApp,
    _default_ios_grouped_config,
    _flatten_grouped_runtime_config,
    _load_grouped_runtime_config,
)
from .diagnostics import log_event, log_provider_event, snapshot as diagnostics_snapshot
from .m3_tunnel import network_settings_from_runtime_config
from .profiles import ProfileStore


def _simple_udp_peer_settings(config: Mapping[str, Any] | None) -> dict[str, Any] | None:
    grouped = dict(config) if isinstance(config, Mapping) else {}
    section = grouped.get("ios_experiment")
    experiment = dict(section) if isinstance(section, Mapping) else {}
    flat = dict(grouped)

    def _pick(*keys: str, default: Any = "") -> Any:
        for key in keys:
            if key in os.environ and str(os.environ[key]).strip():
                return os.environ[key]
        for key in keys:
            if key in experiment and experiment.get(key) not in (None, ""):
                return experiment.get(key)
        for key in keys:
            if key in flat and flat.get(key) not in (None, ""):
                return flat.get(key)
        return default

    connector_mode = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR",
            "packetflow_connector",
            "ios_packetflow_connector",
            default="",
        )
        or ""
    ).strip().lower()
    if connector_mode != "simple_udp_peer":
        return None

    peer_host = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST",
            "peer_host",
            "ios_packetflow_peer_host",
            default="",
        )
        or ""
    ).strip()
    peer_port_raw = _pick(
        "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT",
        "peer_port",
        "ios_packetflow_peer_port",
        default=0,
    )
    bind_host = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST",
            "bind_host",
            "ios_packetflow_udp_host",
            default="0.0.0.0",
        )
        or "0.0.0.0"
    ).strip()
    bind_port_raw = _pick(
        "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT",
        "bind_port",
        "ios_packetflow_udp_port",
        default=5555,
    )
    ifname = str(_pick("ifname", "ios_packetflow_ifname", default="ios-utun") or "ios-utun").strip()
    mtu_raw = _pick("mtu", "ios_packetflow_mtu", default=1280)

    peer_port = int(peer_port_raw) if str(peer_port_raw).strip() else 0
    bind_port = int(bind_port_raw) if str(bind_port_raw).strip() else 5555
    mtu = int(mtu_raw) if str(mtu_raw).strip() else 1280
    if not peer_host or peer_port <= 0:
        raise ValueError("simple_udp_peer mode requires peer_host and peer_port")
    return {
        "connector_mode": "simple_udp_peer",
        "peer_host": peer_host,
        "peer_port": peer_port,
        "bind_host": bind_host,
        "bind_port": bind_port,
        "ifname": ifname or "ios-utun",
        "mtu": max(68, int(mtu)),
    }


class _PacketFlowOnlyMux:
    class TunDevice:
        def __init__(self, fd: int, ifname: str, mtu: int, service_key: object | None = None) -> None:
            self.fd = fd
            self.ifname = ifname
            self.mtu = mtu
            self.service_key = service_key
            self.reader_registered = False
            self.chan_id = None

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.log = logging.getLogger("runner")

    def _effective_services_by_id(self) -> dict[object, object]:
        return {}

    def _on_local_tun_packet(self, dev: Any, packet: bytes) -> None:
        self.log.info(
            "[TUN/IOS/EXPERIMENT] unexpected local packet callback if=%s len=%s",
            getattr(dev, "ifname", ""),
            len(packet),
        )


class _SimpleUDPPeerRuntime:
    def __init__(self, documents_root: Path, loop: asyncio.AbstractEventLoop) -> None:
        self.documents_root = Path(documents_root)
        self.loop = loop
        self.mux = _PacketFlowOnlyMux(loop)
        self.dev: Any | None = None
        self.config: dict[str, Any] = {}
        self.settings: dict[str, Any] = {}
        self.started = False
        self.started_unix_ts: float | None = None

    @staticmethod
    def _apply_environment(settings: Mapping[str, Any], documents_root: Path, tunnel_address: str) -> None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR"] = "simple_udp_peer"
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST"] = str(settings.get("bind_host") or "0.0.0.0")
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT"] = str(int(settings.get("bind_port") or 5555))
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST"] = str(settings.get("peer_host") or "")
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT"] = str(int(settings.get("peer_port") or 0))
        os.environ["OBSTACLEBRIDGE_IOS_TUNNEL_ADDRESS"] = str(tunnel_address)
        os.environ["OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT"] = str(Path(documents_root) / "logs")

    async def start(self, config: Mapping[str, Any], *, tunnel_address: str) -> None:
        if self.started:
            return
        settings = _simple_udp_peer_settings(config)
        if settings is None:
            raise ValueError("simple_udp_peer runtime requested without matching settings")
        self.config = dict(config)
        self.settings = dict(settings)
        self._apply_environment(settings, self.documents_root, tunnel_address)
        log_provider_event(
            self.documents_root,
            "python_runtime_simple_udp_peer_starting",
            peer_host=settings["peer_host"],
            peer_port=settings["peer_port"],
            bind_host=settings["bind_host"],
            bind_port=settings["bind_port"],
            ifname=settings["ifname"],
            mtu=settings["mtu"],
        )
        self.dev = bridge_tun_ios.open_tun_device(self.mux, str(settings["ifname"]), int(settings["mtu"]))
        bridge_tun_ios.register_tun_reader(self.mux, self.dev)
        task = getattr(self.dev, "udp_connector_task", None)
        if task is not None:
            await task
        self.started = True
        self.started_unix_ts = time.time()
        log_provider_event(
            self.documents_root,
            "python_runtime_simple_udp_peer_started",
            connector_bind=getattr(self.dev, "udp_connector_bind_addr", None),
            peer_addr=getattr(self.dev, "udp_connector_peer_addr", None),
        )

    async def stop(self) -> None:
        if self.dev is not None:
            bridge_tun_ios.close_tun_device(self.mux, self.dev)
            await asyncio.sleep(0)
        self.dev = None
        self.started = False
        log_provider_event(self.documents_root, "python_runtime_simple_udp_peer_stopped")

    def snapshot(self) -> dict[str, Any]:
        status = {
            "runtime_mode": "simple_udp_peer",
            "peer_addr": [self.settings.get("peer_host"), self.settings.get("peer_port")] if self.settings else None,
            "bind_addr": getattr(self.dev, "udp_connector_bind_addr", None) if self.dev is not None else None,
            "started_unix_ts": self.started_unix_ts,
        }
        if self.dev is not None:
            connector = getattr(self.dev, "udp_connector", None)
            status["counters"] = {
                "to_peer_packets": int(getattr(connector, "tx_packets", 0) or 0),
                "from_peer_packets": int(getattr(connector, "rx_packets", 0) or 0),
            }
        return {
            "started": self.started,
            "status": status,
            "connections": {"tcp": [], "udp": [], "tun": []},
            "config": dict(self.config),
        }


class IPServerRuntimeController:
    EMBEDDED_RESTART_STOP_TIMEOUT_SEC = 20.0

    def __init__(self) -> None:
        self.documents_root = ObstacleBridgeIOSApp.DOCUMENTS_ROOT
        self.config_file = ObstacleBridgeIOSApp.CONFIG_FILE
        self.profiles_dir = ObstacleBridgeIOSApp.PROFILES_DIR
        self.log_file = ObstacleBridgeIOSApp.LOG_FILE
        self.admin_web_dir = ObstacleBridgeIOSApp.ADMIN_WEB_DIR
        self.web_dir = ObstacleBridgeIOSApp.WEB_DIR
        self.client = ObstacleBridgeClient(
            _load_grouped_runtime_config(self.documents_root),
            config_path=str(self.config_file),
            apply_logging=True,
        )
        self.profile_store = ProfileStore(self.profiles_dir)
        self._active_profile_id: Optional[str] = None
        self._runtime_loop: Optional[asyncio.AbstractEventLoop] = None
        self._runtime_loop_thread: Optional[threading.Thread] = None
        self._embedded_restart_future: Optional[Future[Any] | asyncio.Task[Any]] = None
        self._simple_udp_peer_runtime: Optional[_SimpleUDPPeerRuntime] = None
        log_event(self.documents_root, "ipserver_runtime.controller_init")
        self._log_config_diagnostics("controller_init", self.client.config)

    def _config_file_snapshot(self) -> dict[str, Any]:
        path = Path(self.config_file)
        payload: dict[str, Any] = {
            "path": str(path),
            "exists": path.is_file(),
        }
        if not path.is_file():
            return payload
        try:
            raw = path.read_bytes()
            payload["size"] = len(raw)
            payload["sha256"] = hashlib.sha256(raw).hexdigest()
        except Exception as exc:
            payload["read_error"] = f"{type(exc).__name__}: {exc}"
            return payload
        try:
            payload["modified_unix_ts"] = path.stat().st_mtime
        except Exception:
            pass
        try:
            decoded = json.loads(raw.decode("utf-8"))
            if isinstance(decoded, dict):
                payload["top_level_keys"] = sorted(decoded.keys())
                runner = decoded.get("runner")
                udp = decoded.get("udp_session")
                admin_web = decoded.get("admin_web")
                secure_link = decoded.get("secure_link")
                if isinstance(runner, Mapping):
                    payload["runner_overlay_transport"] = runner.get("overlay_transport")
                if isinstance(udp, Mapping):
                    payload["udp_peer"] = udp.get("udp_peer")
                    payload["udp_peer_port"] = udp.get("udp_peer_port")
                if isinstance(admin_web, Mapping):
                    payload["admin_web_bind"] = admin_web.get("admin_web_bind")
                    payload["admin_web_port"] = admin_web.get("admin_web_port")
                if isinstance(secure_link, Mapping):
                    payload["secure_link_mode"] = secure_link.get("secure_link_mode")
        except Exception as exc:
            payload["parse_error"] = f"{type(exc).__name__}: {exc}"
        return payload

    def _probe_foreground_documents_access(self) -> dict[str, Any]:
        shared_config_dir = Path(self.documents_root) / "config"
        hint_path = shared_config_dir / "app-documents-root.json"
        payload: dict[str, Any] = {
            "hint_path": str(hint_path),
            "hint_exists": hint_path.is_file(),
        }
        if not hint_path.is_file():
            return payload
        try:
            hint = json.loads(hint_path.read_text(encoding="utf-8"))
        except Exception as exc:
            payload["hint_read_error"] = f"{type(exc).__name__}: {exc}"
            return payload
        if not isinstance(hint, dict):
            payload["hint_parse_error"] = f"unexpected hint payload type: {type(hint).__name__}"
            return payload
        app_documents_root = str(hint.get("documents_root") or "").strip()
        payload["app_documents_root"] = app_documents_root
        if not app_documents_root:
            payload["hint_parse_error"] = "documents_root missing in hint payload"
            return payload
        target_path = Path(app_documents_root) / "config" / "ObstacleBridge.cfg"
        payload["target_path"] = str(target_path)
        payload["target_exists"] = target_path.exists()
        try:
            raw = target_path.read_bytes()
            payload["target_readable"] = True
            payload["target_size"] = len(raw)
            payload["target_sha256"] = hashlib.sha256(raw).hexdigest()
        except Exception as exc:
            payload["target_readable"] = False
            payload["target_read_error"] = f"{type(exc).__name__}: {exc}"
        return payload

    def _log_config_diagnostics(self, event: str, config: Mapping[str, Any] | None) -> None:
        config_dict = dict(config) if isinstance(config, Mapping) else {}
        log_provider_event(
            self.documents_root,
            f"python_runtime_config_{event}",
            file_snapshot=self._config_file_snapshot(),
            foreground_documents_probe=self._probe_foreground_documents_access(),
            effective_keys=sorted(config_dict.keys()),
            overlay_transport=config_dict.get("overlay_transport"),
            udp_peer=config_dict.get("udp_peer"),
            udp_peer_port=config_dict.get("udp_peer_port"),
            admin_web_bind=config_dict.get("admin_web_bind"),
            admin_web_port=config_dict.get("admin_web_port"),
            secure_link_mode=config_dict.get("secure_link_mode"),
        )

    def _ensure_runtime_loop(self) -> asyncio.AbstractEventLoop:
        loop = self._runtime_loop
        thread = self._runtime_loop_thread
        if loop is not None and thread is not None and thread.is_alive():
            return loop

        log_event(self.documents_root, "ipserver_runtime.runtime_loop_starting")
        ready = threading.Event()

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._runtime_loop = loop
            ready.set()
            try:
                log_event(self.documents_root, "ipserver_runtime.runtime_loop_started")
                loop.run_forever()
            except BaseException as exc:
                log_event(
                    self.documents_root,
                    "ipserver_runtime.runtime_loop_exception",
                    error_type=exc.__class__.__name__,
                    error=str(exc),
                    traceback="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                )
                raise
            finally:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()
                log_event(self.documents_root, "ipserver_runtime.runtime_loop_stopped", pending_tasks=len(pending))

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        ready.wait()
        self._runtime_loop_thread = thread
        if self._runtime_loop is None:
            raise RuntimeError("failed to initialize IPServer runtime loop")
        return self._runtime_loop

    def _run_async_sync(self, awaitable: Any) -> Any:
        loop = self._ensure_runtime_loop()
        future = asyncio.run_coroutine_threadsafe(awaitable, loop)
        return future.result()

    def _attach_embedded_restart_hook(self) -> None:
        if self._simple_udp_peer_runtime is not None:
            return
        runner = self.client.runner
        if runner is not None:
            setattr(runner, "_embedded_restart_callback", self._request_embedded_restart)
            admin_web = getattr(runner, "admin_web", None)
            if admin_web is not None:
                setattr(admin_web, "_embedded_restart_callback", self._request_embedded_restart)

    async def _stop_active_runtime(self) -> None:
        simple_runtime = self._simple_udp_peer_runtime
        if simple_runtime is not None:
            await simple_runtime.stop()
            self._simple_udp_peer_runtime = None
        elif self.client is not None:
            await self.client.stop()

    def _simple_udp_peer_runtime_config(self, config: Mapping[str, Any] | None) -> dict[str, Any] | None:
        settings = _simple_udp_peer_settings(config)
        if settings is None:
            return None
        runtime_cfg = dict(config) if isinstance(config, Mapping) else {}
        runtime_cfg.setdefault("ios_experiment", {})
        if isinstance(runtime_cfg.get("ios_experiment"), Mapping):
            merged = dict(runtime_cfg["ios_experiment"])
            merged.update(
                {
                    "packetflow_connector": "simple_udp_peer",
                    "peer_host": settings["peer_host"],
                    "peer_port": settings["peer_port"],
                    "bind_host": settings["bind_host"],
                    "bind_port": settings["bind_port"],
                    "ifname": settings["ifname"],
                    "mtu": settings["mtu"],
                }
            )
            runtime_cfg["ios_experiment"] = merged
        else:
            runtime_cfg["ios_experiment"] = {
                "packetflow_connector": "simple_udp_peer",
                "peer_host": settings["peer_host"],
                "peer_port": settings["peer_port"],
                "bind_host": settings["bind_host"],
                "bind_port": settings["bind_port"],
                "ifname": settings["ifname"],
                "mtu": settings["mtu"],
            }
        return runtime_cfg

    def _request_embedded_restart(self) -> None:
        future = self._embedded_restart_future
        if future is not None and not future.done():
            log_provider_event(self.documents_root, "python_runtime_restart_requested", status="already_pending")
            return
        loop = self._ensure_runtime_loop()
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        log_provider_event(
            self.documents_root,
            "python_runtime_restart_requested",
            status="scheduled",
            same_loop=bool(running_loop is loop),
        )
        if running_loop is loop:
            future = loop.create_task(self._restart_embedded_runtime())
        else:
            future = asyncio.run_coroutine_threadsafe(self._restart_embedded_runtime(), loop)
        self._embedded_restart_future = future

    async def _restart_embedded_runtime(self) -> None:
        log_provider_event(self.documents_root, "python_runtime_restart_started")
        runner = self.client.runner
        if runner is None:
            log_provider_event(self.documents_root, "python_runtime_restart_skipped", reason="runner_missing")
            self._embedded_restart_future = None
            return
        current_config = _load_grouped_runtime_config(self.documents_root)
        self._log_config_diagnostics("restart_reload", current_config)
        old_client = self.client
        new_client = ObstacleBridgeClient(
            dict(current_config),
            config_path=str(self.config_file),
            apply_logging=True,
        )
        try:
            await asyncio.sleep(0.2)
            log_provider_event(
                self.documents_root,
                "python_runtime_restart_stopping_old_runtime",
                timeout_sec=self.EMBEDDED_RESTART_STOP_TIMEOUT_SEC,
            )
            stop_started = time.monotonic()
            try:
                await asyncio.wait_for(
                    old_client.stop(),
                    timeout=self.EMBEDDED_RESTART_STOP_TIMEOUT_SEC,
                )
            except asyncio.TimeoutError:
                log_provider_event(
                    self.documents_root,
                    "python_runtime_restart_stop_old_runtime_timed_out",
                    timeout_sec=self.EMBEDDED_RESTART_STOP_TIMEOUT_SEC,
                    duration_sec=round(time.monotonic() - stop_started, 3),
                )
                raise
            log_provider_event(
                self.documents_root,
                "python_runtime_restart_stopped_old_runtime",
                duration_sec=round(time.monotonic() - stop_started, 3),
            )
            self.client = new_client
            await new_client.start(config=new_client.config)
            self._attach_embedded_restart_hook()
            self._log_config_diagnostics("restart_started", new_client.config)
            log_provider_event(self.documents_root, "python_runtime_restart_completed")
        except Exception as exc:
            log_provider_event(
                self.documents_root,
                "python_runtime_restart_failed",
                error_type=exc.__class__.__name__,
                error=str(exc),
                traceback="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            )
            raise
        finally:
            self._embedded_restart_future = None

    @staticmethod
    def _runtime_config_from_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
        ob_cfg = profile.get("obstacle_bridge")
        if isinstance(ob_cfg, Mapping):
            runtime_cfg = dict(ob_cfg)
        elif "overlay_transport" in profile:
            runtime_cfg = dict(profile)
        else:
            raise ValueError("profile obstacle_bridge config is required")
        runtime_cfg.setdefault("admin_web", True)
        runtime_cfg.setdefault("admin_web_bind", ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_BIND)
        runtime_cfg.setdefault("admin_web_port", ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PORT)
        runtime_cfg.setdefault("admin_web_path", ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH)
        runtime_cfg.setdefault("admin_web_dir", str(ObstacleBridgeIOSApp.ADMIN_WEB_DIR))
        runtime_cfg.setdefault("ws_static_dir", str(ObstacleBridgeIOSApp.WEB_DIR))
        runtime_cfg.setdefault("log", "DEBUG")
        runtime_cfg.setdefault("file_level", "DEBUG")
        runtime_cfg.setdefault("console_level", "INFO")
        runtime_cfg.setdefault("log_file", str(ObstacleBridgeIOSApp.LOG_FILE))
        runtime_cfg.setdefault("log_file_max_bytes", 1_048_576)
        runtime_cfg.setdefault("log_file_backup_count", 5)
        return runtime_cfg

    @staticmethod
    def _normalize_ios_extension_admin_web(config: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(config)
        if any(isinstance(value, Mapping) for value in normalized.values()):
            admin_web = dict(
                normalized.get("admin_web") if isinstance(normalized.get("admin_web"), Mapping) else {}
            )
            admin_web["admin_web_auth_disable"] = True
            admin_web["admin_web_username"] = ""
            admin_web["admin_web_password"] = ""
            normalized["admin_web"] = admin_web
            debug_logging = dict(
                normalized.get("debug_logging") if isinstance(normalized.get("debug_logging"), Mapping) else {}
            )
            debug_logging["ios_admin_web_auth_policy"] = "disabled_in_extension_runtime"
            normalized["debug_logging"] = debug_logging
            return normalized
        normalized["admin_web_auth_disable"] = True
        normalized["admin_web_username"] = ""
        normalized["admin_web_password"] = ""
        normalized["ios_admin_web_auth_policy"] = "disabled_in_extension_runtime"
        return normalized

    @staticmethod
    def _runtime_config_with_ios_defaults(config: Mapping[str, Any]) -> dict[str, Any]:
        if any(isinstance(value, Mapping) for value in config.values()):
            merged = IPServerRuntimeController._normalize_ios_extension_admin_web(config)
            defaults = _default_ios_grouped_config(ObstacleBridgeIOSApp.DOCUMENTS_ROOT)
            for section, values in defaults.items():
                existing = merged.get(section)
                if isinstance(existing, Mapping):
                    block = dict(values)
                    block.update(dict(existing))
                    merged[section] = block
                else:
                    merged.setdefault(section, dict(values))
            admin_web = dict(merged.get("admin_web") if isinstance(merged.get("admin_web"), Mapping) else {})
            admin_web["admin_web_dir"] = str(ObstacleBridgeIOSApp.ADMIN_WEB_DIR)
            merged["admin_web"] = admin_web
            ws_session = dict(merged.get("ws_session") if isinstance(merged.get("ws_session"), Mapping) else {})
            ws_session["ws_static_dir"] = str(ObstacleBridgeIOSApp.WEB_DIR)
            merged["ws_session"] = ws_session
            debug_logging = dict(
                merged.get("debug_logging") if isinstance(merged.get("debug_logging"), Mapping) else {}
            )
            debug_logging["log_file"] = str(ObstacleBridgeIOSApp.LOG_FILE)
            merged["debug_logging"] = debug_logging
            return merged
        runtime_cfg = IPServerRuntimeController._runtime_config_from_profile(
            {"obstacle_bridge": IPServerRuntimeController._normalize_ios_extension_admin_web(config)}
        )
        runtime_cfg["admin_web_dir"] = str(ObstacleBridgeIOSApp.ADMIN_WEB_DIR)
        runtime_cfg["ws_static_dir"] = str(ObstacleBridgeIOSApp.WEB_DIR)
        runtime_cfg["log_file"] = str(ObstacleBridgeIOSApp.LOG_FILE)
        return runtime_cfg

    def connect_profile(
        self,
        *,
        profile: Optional[Mapping[str, Any]] = None,
        profile_id: Optional[str] = None,
    ) -> dict[str, Any]:
        selected = profile
        if selected is None:
            target_id = str(profile_id or "").strip()
            if not target_id:
                raise ValueError("profile or profile_id is required")
            selected = self.profile_store.load_profile(target_id, include_secrets=True)
        log_event(self.documents_root, "ipserver_runtime.connect_profile_requested", profile_id=profile_id or selected.get("profile_id"))
        runtime_cfg = self._runtime_config_from_profile(selected)
        self._run_async_sync(self._stop_active_runtime())
        self._run_async_sync(self.client.start(config=runtime_cfg))
        self._attach_embedded_restart_hook()
        self._active_profile_id = str(selected.get("profile_id", "") or "").strip() or None
        return self.connection_snapshot()

    def disconnect_profile(self) -> dict[str, Any]:
        log_event(self.documents_root, "ipserver_runtime.disconnect_profile_requested")
        self._run_async_sync(self._stop_active_runtime())
        self._active_profile_id = None
        return self.connection_snapshot()

    def connection_snapshot(self) -> dict[str, Any]:
        simple_runtime = self._simple_udp_peer_runtime
        if simple_runtime is not None:
            snap = dict(simple_runtime.snapshot())
        else:
            snap = dict(self.client.snapshot())
        snap["active_profile_id"] = self._active_profile_id
        runtime_cfg = snap.get("config")
        if isinstance(runtime_cfg, Mapping):
            snap["webadmin_url"] = ObstacleBridgeIOSApp.webadmin_url_from_config(runtime_cfg)
        else:
            grouped_cfg = _load_grouped_runtime_config(self.documents_root)
            snap["config"] = grouped_cfg
            snap["webadmin_url"] = ObstacleBridgeIOSApp.webadmin_url_from_config(
                _flatten_grouped_runtime_config(grouped_cfg)
            )
        return snap

    def start_embedded_webadmin(self, runtime_config: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
        log_provider_event(self.documents_root, "python_runtime_start_requested", runtime_owner="IPServer Network Extension")
        normalized_config = (
            self._runtime_config_with_ios_defaults(runtime_config)
            if isinstance(runtime_config, Mapping)
            else self._runtime_config_with_ios_defaults(_load_grouped_runtime_config(self.documents_root))
        )
        simple_runtime_config = self._simple_udp_peer_runtime_config(normalized_config)
        self.client.config = normalized_config
        tunnel_address = network_settings_from_runtime_config(self.client.config).tunnel_address
        os.environ["OBSTACLEBRIDGE_IOS_TUNNEL_ADDRESS"] = tunnel_address
        connector_mode = str(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "") or "").strip().lower()
        if simple_runtime_config is None:
            if not connector_mode:
                peer_host = str(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", "") or "").strip()
                peer_port = str(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", "") or "").strip()
                if peer_host and peer_port:
                    os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR"] = "simple_udp_peer"
                else:
                    os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR"] = "udp"
        os.environ["OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT"] = str(self.documents_root / "logs")
        log_provider_event(
            self.documents_root,
            "python_runtime_config_prepared",
            config_keys=sorted(self.client.config.keys()) if isinstance(self.client.config, Mapping) else [],
        )
        self._log_config_diagnostics("prepared", self.client.config)
        self._run_async_sync(self._stop_active_runtime())
        if simple_runtime_config is not None:
            self._simple_udp_peer_runtime = _SimpleUDPPeerRuntime(self.documents_root, self._ensure_runtime_loop())
            self._run_async_sync(self._simple_udp_peer_runtime.start(simple_runtime_config, tunnel_address=tunnel_address))
            log_provider_event(self.documents_root, "python_runtime_start_completed", runtime_mode="simple_udp_peer")
        else:
            self.client._args = None
            self._run_async_sync(self.client.start(config=self.client.config))
            self._attach_embedded_restart_hook()
            log_provider_event(self.documents_root, "python_runtime_start_completed", runtime_mode="obstaclebridge")
        return self.connection_snapshot()

    def diagnostics_snapshot(self) -> dict[str, Any]:
        payload = diagnostics_snapshot(self.documents_root)
        payload["connection"] = self.connection_snapshot()
        return payload
