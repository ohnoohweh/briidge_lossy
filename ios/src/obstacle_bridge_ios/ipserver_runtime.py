"""Python runtime owner for the iOS IPServer Network Extension."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import traceback
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Mapping, Optional

from obstacle_bridge.core import ObstacleBridgeClient

from .app import (
    ObstacleBridgeIOSApp,
    _default_ios_grouped_config,
    _flatten_grouped_runtime_config,
    _load_grouped_runtime_config,
)
from .diagnostics import log_event, log_provider_event, snapshot as diagnostics_snapshot
from .profiles import ProfileStore


class IPServerRuntimeController:
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
        self._embedded_restart_future: Optional[Future[Any]] = None
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
        runner = self.client.runner
        if runner is not None:
            setattr(runner, "_embedded_restart_callback", self._request_embedded_restart)

    def _request_embedded_restart(self) -> Future[Any]:
        future = self._embedded_restart_future
        if future is not None and not future.done():
            return future
        loop = self._ensure_runtime_loop()
        future = asyncio.run_coroutine_threadsafe(self._restart_embedded_runtime(), loop)
        self._embedded_restart_future = future
        return future

    async def _restart_embedded_runtime(self) -> None:
        runner = self.client.runner
        if runner is None:
            return
        current_config = runner.get_config_snapshot(include_secrets=True)
        old_client = self.client
        new_client = ObstacleBridgeClient(
            dict(current_config),
            config_path=str(self.config_file),
            apply_logging=True,
        )
        await asyncio.sleep(0.2)
        await old_client.stop()
        self.client = new_client
        await new_client.start(config=new_client.config)
        self._attach_embedded_restart_hook()

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
        self._run_async_sync(self.client.start(config=runtime_cfg))
        self._attach_embedded_restart_hook()
        self._active_profile_id = str(selected.get("profile_id", "") or "").strip() or None
        return self.connection_snapshot()

    def disconnect_profile(self) -> dict[str, Any]:
        log_event(self.documents_root, "ipserver_runtime.disconnect_profile_requested")
        self._run_async_sync(self.client.stop())
        self._active_profile_id = None
        return self.connection_snapshot()

    def connection_snapshot(self) -> dict[str, Any]:
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
        os.environ["OBSTACLEBRIDGE_IOS_TUNNEL_ADDRESS"] = "10.77.0.2"
        self.client.config = (
            self._runtime_config_with_ios_defaults(runtime_config)
            if isinstance(runtime_config, Mapping)
            else self._runtime_config_with_ios_defaults(_load_grouped_runtime_config(self.documents_root))
        )
        log_provider_event(
            self.documents_root,
            "python_runtime_config_prepared",
            config_keys=sorted(self.client.config.keys()) if isinstance(self.client.config, Mapping) else [],
        )
        self._log_config_diagnostics("prepared", self.client.config)
        self.client._args = None
        self._run_async_sync(self.client.start(config=self.client.config))
        self._attach_embedded_restart_hook()
        log_provider_event(self.documents_root, "python_runtime_start_completed")
        return self.connection_snapshot()

    def diagnostics_snapshot(self) -> dict[str, Any]:
        payload = diagnostics_snapshot(self.documents_root)
        payload["connection"] = self.connection_snapshot()
        return payload
