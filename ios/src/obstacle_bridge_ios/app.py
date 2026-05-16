"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import os
import shutil
import sys
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Optional

ConfigAwareCLI: Any = None
from .diagnostics import (
    install_crash_hooks,
    log_event,
    log_provider_event,
    snapshot as diagnostics_snapshot,
)
from .profiles import ProfileStore
from .tunnel_control import harvest_shared_logs, ipserver_tunnel_status, start_ipserver_tunnel

try:
    import toga
except Exception:  # pragma: no cover - exercised in iOS build/runtime, not unit tests.
    toga = None


WEBADMIN_DEFAULT_BIND = "0.0.0.0"
WEBADMIN_DEFAULT_PORT = 18080
WEBADMIN_DEFAULT_PATH = "/"
IPSERVER_TUNNEL_ADDRESS = "10.77.0.2"


def _config_aware_cli_class() -> Any:
    global ConfigAwareCLI
    if ConfigAwareCLI is None:
        from obstacle_bridge.bridge import ConfigAwareCLI as _ConfigAwareCLI

        ConfigAwareCLI = _ConfigAwareCLI
    return ConfigAwareCLI


def _resolve_toga_webview_class() -> Any:
    """Resolve Toga's WebView even when the top-level lazy export is absent."""
    if toga is not None:
        webview_cls = getattr(toga, "WebView", None)
        if webview_cls is not None:
            return webview_cls
    try:
        module = importlib.import_module("toga.widgets.webview")
    except Exception:
        return None
    return getattr(module, "WebView", None)


def _configure_ios_safe_locale() -> None:
    """Ensure Toga's locale bootstrap has a supported default on iOS."""
    os.environ["LC_ALL"] = "C"
    os.environ["LANG"] = "C"
    os.environ["OBSTACLEBRIDGE_ADMIN_UI_PLATFORM"] = "ios"


def _probe_http_ok(url: str, timeout_sec: float = 1.0) -> bool:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            status = int(getattr(response, "status", 0) or 0)
            return 200 <= status < 500
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def _ios_documents_root() -> Path:
    """Return a USB-shareable app Documents root for configs and logs."""
    override = os.environ.get("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT")
    if override:
        root = Path(override)
        root.mkdir(parents=True, exist_ok=True)
        return root

    if sys.platform == "ios":
        root = Path.home() / "Documents"
        root.mkdir(parents=True, exist_ok=True)
        return root

    root = Path.home() / "Documents" / "ObstacleBridge"
    try:
        root.mkdir(parents=True, exist_ok=True)
        return root
    except OSError:
        fallback = Path.cwd() / ".obstaclebridge-ios-documents"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _source_dir_candidates(name: str) -> list[Path]:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / name,
        here.parents[2] / name,
        here.parents[3] / name if len(here.parents) > 3 else here.parents[-1] / name,
        Path.cwd() / name,
    ]
    if name == "admin_web":
        try:
            obstacle_bridge_pkg = importlib.import_module("obstacle_bridge")
            pkg_file = getattr(obstacle_bridge_pkg, "__file__", None)
            if pkg_file:
                candidates.insert(0, Path(pkg_file).resolve().parent / "admin_web")
        except Exception:
            pass
    return candidates


def _copy_document_tree(source_name: str, target: Path) -> bool:
    for candidate in _source_dir_candidates(source_name):
        if candidate.resolve() == target.resolve():
            return target.is_dir()
        if (candidate / "index.html").is_file():
            target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                candidate,
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
            )
            return True
    target.mkdir(parents=True, exist_ok=True)
    return False


def _default_ios_runtime_config(root: Path) -> dict[str, Any]:
    return {
        "admin_web": True,
        "admin_web_bind": WEBADMIN_DEFAULT_BIND,
        "admin_web_port": WEBADMIN_DEFAULT_PORT,
        "admin_web_path": WEBADMIN_DEFAULT_PATH,
        "admin_web_dir": str(root / "admin_web"),
        "ws_static_dir": str(root / "web"),
        "log": "DEBUG",
        "file_level": "DEBUG",
        "console_level": "INFO",
        "log_file": str(root / "logs" / "obstaclebridge.log"),
        "log_file_max_bytes": 1_048_576,
        "log_file_backup_count": 5,
    }


def _default_ios_grouped_config(root: Path) -> dict[str, Any]:
    return {
        "admin_web": {
            "admin_web": True,
            "admin_web_bind": WEBADMIN_DEFAULT_BIND,
            "admin_web_port": WEBADMIN_DEFAULT_PORT,
            "admin_web_path": WEBADMIN_DEFAULT_PATH,
            "admin_web_dir": str(root / "admin_web"),
        },
        "debug_logging": {
            "log": "DEBUG",
            "file_level": "DEBUG",
            "console_level": "INFO",
            "log_file": str(root / "logs" / "obstaclebridge.log"),
            "log_file_max_bytes": 1_048_576,
            "log_file_backup_count": 5,
        },
        "ws_session": {
            "ws_static_dir": str(root / "web"),
        },
    }


def _load_grouped_runtime_config(root: Path) -> dict[str, Any]:
    path = root / "config" / "ObstacleBridge.cfg"
    defaults = _default_ios_grouped_config(root)
    if not path.exists():
        return defaults
    try:
        payload = _config_aware_cli_class()(description="ios-app")._load_json_config(str(path))
    except Exception as exc:
        try:
            raw_payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return defaults
        if not isinstance(raw_payload, dict):
            return defaults
        payload = dict(raw_payload)
        payload.setdefault("debug_logging", {})
        if isinstance(payload["debug_logging"], Mapping):
            debug_logging = dict(payload["debug_logging"])
            debug_logging["config_load_error"] = f"{type(exc).__name__}: {exc}"
            payload["debug_logging"] = debug_logging
        else:
            payload["debug_logging"] = {"config_load_error": f"{type(exc).__name__}: {exc}"}
    if not isinstance(payload, dict):
        return defaults
    merged = dict(payload)
    for section, values in defaults.items():
        existing = merged.get(section)
        if isinstance(existing, Mapping):
            block = dict(values)
            block.update(dict(existing))
            merged[section] = block
        else:
            merged[section] = dict(values)
    return merged


def _flatten_grouped_runtime_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten grouped config sections into Runner-style args."""
    flattened: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, Mapping):
            flattened.update(dict(value))
        else:
            flattened[key] = value
    return flattened


def _write_default_config_file(root: Path) -> Path:
    path = root / "config" / "ObstacleBridge.cfg"
    if not path.exists():
        payload = _default_ios_grouped_config(root)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_startup_artifacts(root: Path | None = None) -> Path:
    """Create USB-visible folders early so Finder/iTunes can expose them."""
    root = _ios_documents_root() if root is None else Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "profiles").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    admin_web_copied = _copy_document_tree("admin_web", root / "admin_web")
    web_copied = _copy_document_tree("web", root / "web")
    _write_default_config_file(root)
    readme = root / "README.txt"
    if not readme.exists():
        readme.write_text(
            "ObstacleBridge iOS shared files.\n"
            "config/: editable runtime configuration\n"
            "profiles/: saved configuration files\n"
            "logs/: runtime and startup logs\n"
            "admin_web/: editable WebAdmin files served by the app runtime\n"
            "web/: editable static web files for websocket/static-file use\n",
            encoding="utf-8",
        )
    manifest = {
        "documents_root": str(root),
        "config_file": str(root / "config" / "ObstacleBridge.cfg"),
        "log_file": str(root / "logs" / "obstaclebridge.log"),
        "diagnostics_file": str(root / "logs" / "ios-diagnostics.jsonl"),
        "admin_web_dir": str(root / "admin_web"),
        "admin_web_files_copied": admin_web_copied,
        "web_dir": str(root / "web"),
        "web_files_copied": web_copied,
    }
    (root / "documents-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return root


def _append_startup_crash_log(exc: BaseException) -> None:
    try:
        root = _write_startup_artifacts()
        path = root / "logs" / "startup-crash.log"
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n=== startup exception ===\n")
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=fh)
    except Exception:
        pass


_EARLY_DOCUMENTS_ROOT = _write_startup_artifacts()


class ObstacleBridgeIOSApp:
    """Thin wrapper that keeps shared runtime/onboarding imports explicit."""

    WEBADMIN_DEFAULT_BIND = WEBADMIN_DEFAULT_BIND
    WEBADMIN_DEFAULT_PORT = WEBADMIN_DEFAULT_PORT
    WEBADMIN_DEFAULT_PATH = WEBADMIN_DEFAULT_PATH
    DOCUMENTS_ROOT = _ios_documents_root()
    CONFIG_DIR = DOCUMENTS_ROOT / "config"
    CONFIG_FILE = CONFIG_DIR / "ObstacleBridge.cfg"
    PROFILES_DIR = DOCUMENTS_ROOT / "profiles"
    LOGS_DIR = DOCUMENTS_ROOT / "logs"
    LOG_FILE = LOGS_DIR / "obstaclebridge.log"
    ADMIN_WEB_DIR = DOCUMENTS_ROOT / "admin_web"
    WEB_DIR = DOCUMENTS_ROOT / "web"

    def __init__(self) -> None:
        _write_startup_artifacts(self.DOCUMENTS_ROOT)
        install_crash_hooks(self.DOCUMENTS_ROOT)
        log_event(self.DOCUMENTS_ROOT, "ios_app.facade_init", runtime_owner="IPServer Network Extension")
        self.profile_store = ProfileStore(self.PROFILES_DIR)
        self._active_profile_id: Optional[str] = None

    def close(self) -> None:
        log_event(self.DOCUMENTS_ROOT, "ios_app.facade_closed")

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup.
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def webadmin_url_from_config(config: Mapping[str, Any]) -> Optional[str]:
        if not isinstance(config, Mapping) or not bool(config.get("admin_web")):
            return None
        bind = str(config.get("admin_web_bind") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_BIND).strip() or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_BIND
        port = int(config.get("admin_web_port") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PORT)
        path = str(config.get("admin_web_path") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH).strip() or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH
        if not path.startswith("/"):
            path = "/" + path
        if bind in {"0.0.0.0", "::", "*", "localhost"}:
            host = IPSERVER_TUNNEL_ADDRESS if sys.platform == "ios" else "127.0.0.1"
        else:
            host = bind
        return f"http://{host}:{port}{path}"

    def save_profile(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        return self.profile_store.save_profile(profile)

    def connection_snapshot(self) -> dict[str, Any]:
        runtime_cfg = _load_grouped_runtime_config(self.DOCUMENTS_ROOT)
        return {
            "started": False,
            "runtime_owner": "IPServer Network Extension",
            "active_profile_id": self._active_profile_id,
            "config": runtime_cfg,
            "webadmin_url": self.webadmin_url_from_config(_flatten_grouped_runtime_config(runtime_cfg)),
        }

    def diagnostics_snapshot(self) -> dict[str, Any]:
        payload = diagnostics_snapshot(self.DOCUMENTS_ROOT)
        payload["connection"] = self.connection_snapshot()
        return payload


def main():
    try:
        if toga is None:
            raise RuntimeError("Toga is required to run the iOS app UI")
        _configure_ios_safe_locale()

        class _TogaObstacleBridgeApp(toga.App):
            def startup(self):
                log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.startup_entered")
                bridge_app = ObstacleBridgeIOSApp()
                safe_pack_keys = {
                    "direction",
                    "padding",
                    "padding_top",
                    "padding_bottom",
                    "padding_left",
                    "padding_right",
                    "width",
                    "height",
                    "flex",
                }

                def _pack(**kwargs):
                    try:
                        return toga.style.Pack(**kwargs)
                    except Exception:
                        return toga.style.Pack(**{key: value for key, value in kwargs.items() if key in safe_pack_keys})

                def _fallback_label(text: str):
                    return toga.Label(
                        text,
                        style=_pack(
                            padding=16,
                            font_size=14,
                            color="#374151",
                        ),
                    )

                def _set_webview_url(widget, url: str) -> bool:
                    if widget is None or not url:
                        return False
                    try:
                        setattr(widget, "url", url)
                        return True
                    except Exception:
                        pass
                    for method_name in ("load_url", "set_url"):
                        method = getattr(widget, method_name, None)
                        if callable(method):
                            try:
                                method(url)
                                return True
                            except Exception:
                                pass
                    return False

                try:
                    root = _write_startup_artifacts()
                    webview_cls = _resolve_toga_webview_class()
                    webadmin_view = None
                    webadmin_view_ready = False
                    if webview_cls is not None:
                        try:
                            webadmin_view = webview_cls(style=_pack(flex=1))
                            webadmin_view_ready = True
                        except Exception:
                            webadmin_view = None
                            webadmin_view_ready = False

                    def _refresh_webadmin() -> bool:
                        try:
                            snap = bridge_app.connection_snapshot()
                            webadmin_url = str(snap.get("webadmin_url") or "").strip()
                            if not webadmin_url or not webadmin_view_ready:
                                return False
                            return _set_webview_url(webadmin_view, webadmin_url)
                        except Exception as exc:
                            _append_startup_crash_log(exc)
                            return False

                    async def _await_and_refresh_webadmin() -> None:
                        deadline = asyncio.get_running_loop().time() + 15.0
                        while asyncio.get_running_loop().time() < deadline:
                            try:
                                snap = bridge_app.connection_snapshot()
                                webadmin_url = str(snap.get("webadmin_url") or "").strip()
                            except Exception:
                                webadmin_url = ""
                            if webadmin_url and await asyncio.to_thread(_probe_http_ok, webadmin_url, 0.75):
                                break
                            await asyncio.sleep(0.25)
                        _refresh_webadmin()

                    def _schedule_webadmin_refresh() -> None:
                        loop = getattr(self, "loop", None)
                        if loop is None:
                            return
                        loop.call_soon_threadsafe(asyncio.create_task, _await_and_refresh_webadmin())

                    root_box = toga.Box(
                        style=_pack(direction="column", flex=1, padding=0, background_color="#ffffff")
                    )
                    if webadmin_view_ready and webadmin_view is not None:
                        root_box.add(webadmin_view)
                    else:
                        fallback_box = toga.Box(
                            style=_pack(direction="column", flex=1, background_color="#ffffff")
                        )
                        fallback_box.add(
                            _fallback_label(
                                f"Embedded WebAdmin is unavailable. Shared files are in {root}."
                            )
                        )
                        root_box.add(fallback_box)

                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.ui_ready_runtime_not_started",
                        runtime_owner="IPServer Network Extension",
                    )
                    harvested_logs = harvest_shared_logs()
                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.ipserver_shared_logs_harvested",
                        result=harvested_logs,
                    )
                    tunnel_start = start_ipserver_tunnel()
                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.ipserver_tunnel_start_requested",
                        result=tunnel_start,
                    )
                    _refresh_webadmin()

                    async def _log_tunnel_status_after_start() -> None:
                        await asyncio.sleep(3.0)
                        log_event(
                            ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                            "toga.ipserver_tunnel_status_after_start",
                            result=ipserver_tunnel_status(),
                        )

                    async def _on_running(app, **kwargs) -> None:
                        log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.on_running")
                        asyncio.create_task(_log_tunnel_status_after_start())
                        _schedule_webadmin_refresh()

                    self.on_running = _on_running
                    async def _on_exit(app, **kwargs) -> bool:
                        log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.on_exit")
                        bridge_app.close()
                        return True

                    async def _on_suspend(app, **kwargs) -> None:
                        log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.on_suspend")

                    async def _on_resume(app, **kwargs) -> None:
                        log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.on_resume")
                        log_event(
                            ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                            "toga.ipserver_tunnel_status",
                            result=ipserver_tunnel_status(),
                        )
                        _schedule_webadmin_refresh()

                    self.on_exit = _on_exit
                    with contextlib.suppress(Exception):
                        self.on_suspend = _on_suspend
                    with contextlib.suppress(Exception):
                        self.on_resume = _on_resume
                    window = toga.MainWindow(title="ObstacleBridge")
                    window.content = root_box
                    self.main_window = window
                    window.show()
                    _schedule_webadmin_refresh()
                except Exception as exc:
                    _append_startup_crash_log(exc)
                    raise

        return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
    except Exception as exc:
        _append_startup_crash_log(exc)
        raise
