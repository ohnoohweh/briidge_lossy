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
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Optional

from obstacle_bridge import bridge_tun_ios
from obstacle_bridge.bridge_tun_routing import (
    DEFAULT_EXCLUDED_ROUTES,
    DEFAULT_EXCLUDED_ROUTES6,
    DEFAULT_INCLUDED_ROUTES,
    DEFAULT_INCLUDED_ROUTES6,
    DEFAULT_TUNNEL_ADDRESS,
    DEFAULT_TUNNEL_ADDRESS6,
    DEFAULT_TUNNEL_GATEWAY,
    DEFAULT_TUNNEL_GATEWAY6,
    DEFAULT_TUNNEL_MTU,
    DEFAULT_TUNNEL_PREFIX,
    DEFAULT_TUNNEL_PREFIX6,
    DEFAULT_TUN_ROUTING_LOG,
)

from .m3_tunnel import network_settings_from_runtime_config

ConfigAwareCLI: Any = None
from .diagnostics import (
    install_crash_hooks,
    log_event,
    log_provider_event,
    snapshot as diagnostics_snapshot,
)
from .profiles import ProfileStore
from .tunnel_control import (
    harvest_runtime_logs,
    prepare_runtime,
    runtime_status,
    start_runtime,
    stop_runtime,
)

try:
    import toga
except Exception:  # pragma: no cover - exercised in iOS build/runtime, not unit tests.
    toga = None


WEBADMIN_DEFAULT_BIND = "127.0.0.1"
WEBADMIN_DEFAULT_PORT = 18080
WEBADMIN_DEFAULT_PATH = "/"
WEBADMIN_REMOTE_DEFAULT_NAME = "WebAdmin iphone"
WEBADMIN_REMOTE_DEFAULT_PORT = 13081


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


def _resolve_toga_switch_class() -> Any:
    """Resolve Toga's native Switch without relying on a lazy top-level export."""
    if toga is not None:
        switch_cls = getattr(toga, "Switch", None)
        if switch_cls is not None:
            return switch_cls
    try:
        module = importlib.import_module("toga.widgets.switch")
    except Exception:
        return None
    return getattr(module, "Switch", None)


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


def _admin_api_request(base_url: str, path: str, *, method: str = "GET", body: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Use the extension's public Admin API, matching the embedded WebAdmin page."""
    target = urllib.parse.urljoin(base_url, path)
    data = json.dumps(dict(body)).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        target,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"ok": False, "error": f"HTTP {exc.code}"}
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"Admin API request failed: {type(exc).__name__}: {exc}"}
    return payload if isinstance(payload, dict) else {"ok": False, "error": "Admin API response was not an object"}


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

    root = Path.home() / "Documents"
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
            try:
                shutil.copytree(
                    candidate,
                    target,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
                )
                return True
            except (OSError, shutil.Error):
                return False
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
            "admin_snapshot_cache_enabled": False,
            "admin_web_remote_publish": True,
            "admin_web_remote_port": WEBADMIN_REMOTE_DEFAULT_PORT,
        },
        "debug_logging": {
            "log": "DEBUG",
            "file_level": "DEBUG",
            "console_level": "INFO",
            "log_file": str(root / "logs" / "obstaclebridge.log"),
            "log_file_max_bytes": 1_048_576,
            "log_file_backup_count": 5,
        },
        "channel_mux": {
            "own_servers": [],
            "remote_servers": [],
        },
        "iOS_TUN_connector": {
            "packetflow_connector": "swift_udp",
            "bind_host": bridge_tun_ios.DEFAULT_IOS_PACKETFLOW_BIND_HOST,
            "bind_port": bridge_tun_ios.DEFAULT_IOS_PACKETFLOW_BIND_PORT,
            "peer_host": bridge_tun_ios.DEFAULT_IOS_SWIFT_UDP_SHIM_HOST,
            "peer_port": bridge_tun_ios.DEFAULT_IOS_PACKETFLOW_BIND_PORT + 1,
            "ifname": bridge_tun_ios.DEFAULT_IOS_PACKETFLOW_IFNAME,
            "mtu": bridge_tun_ios.DEFAULT_IOS_PACKETFLOW_MTU,
        },
        "TUN_routing": {
            "tunnel_address": DEFAULT_TUNNEL_ADDRESS,
            "tunnel_prefix": DEFAULT_TUNNEL_PREFIX,
            "tunnel_gateway": DEFAULT_TUNNEL_GATEWAY,
            "included_routes": list(DEFAULT_INCLUDED_ROUTES),
            "excluded_routes": list(DEFAULT_EXCLUDED_ROUTES),
            "tunnel_address6": DEFAULT_TUNNEL_ADDRESS6,
            "tunnel_prefix6": DEFAULT_TUNNEL_PREFIX6,
            "tunnel_gateway6": DEFAULT_TUNNEL_GATEWAY6,
            "included_routes6": list(DEFAULT_INCLUDED_ROUTES6),
            "excluded_routes6": list(DEFAULT_EXCLUDED_ROUTES6),
            "dns_servers": ["1.1.1.1"],
            "mtu": DEFAULT_TUNNEL_MTU,
            "log_TUN_routing": DEFAULT_TUN_ROUTING_LOG,
        },
        "ws_session": {
            "ws_static_dir": str(root / "web"),
        },
    }


def _webadmin_target_host_from_bind(bind: Any) -> str:
    bind_host = str(bind or WEBADMIN_DEFAULT_BIND).strip() or WEBADMIN_DEFAULT_BIND
    if bind_host in {"0.0.0.0", "::", "*", "localhost"}:
        return "127.0.0.1"
    return bind_host


def _default_ios_remote_admin_server(config: Mapping[str, Any]) -> dict[str, Any] | None:
    admin_section = dict(config.get("admin_web") or {})
    if not bool(admin_section.get("admin_web", True)):
        return None
    if not bool(admin_section.get("admin_web_remote_publish", True)):
        return None
    admin_port = int(admin_section.get("admin_web_port") or WEBADMIN_DEFAULT_PORT)
    remote_port = int(admin_section.get("admin_web_remote_port") or WEBADMIN_REMOTE_DEFAULT_PORT)
    return {
        "name": str(admin_section.get("admin_web_remote_name") or WEBADMIN_REMOTE_DEFAULT_NAME),
        "listen": {
            "protocol": "tcp",
            "bind": "0.0.0.0",
            "port": remote_port,
        },
        "target": {
            "protocol": "tcp",
            "host": _webadmin_target_host_from_bind(admin_section.get("admin_web_bind")),
            "port": admin_port,
        },
    }


def _has_remote_admin_forward(config: Mapping[str, Any], remote_servers: list[Any]) -> bool:
    admin_section = dict(config.get("admin_web") or {})
    admin_port = int(admin_section.get("admin_web_port") or WEBADMIN_DEFAULT_PORT)
    target_host = _webadmin_target_host_from_bind(admin_section.get("admin_web_bind"))
    for spec in remote_servers:
        if not isinstance(spec, Mapping):
            continue
        target = dict(spec.get("target") or {})
        if str(target.get("protocol") or "").strip().lower() != "tcp":
            continue
        if int(target.get("port") or 0) != admin_port:
            continue
        if str(target.get("host") or "").strip() not in {target_host, "127.0.0.1", "localhost"}:
            continue
        return True
    return False


def _apply_ios_remote_admin_defaults(config: dict[str, Any]) -> dict[str, Any]:
    channel_mux = dict(config.get("channel_mux") or {})
    remote_servers = list(channel_mux.get("remote_servers") or [])
    if not _has_remote_admin_forward(config, remote_servers):
        default_server = _default_ios_remote_admin_server(config)
        if default_server is not None:
            remote_servers.append(default_server)
    channel_mux["remote_servers"] = remote_servers
    config["channel_mux"] = channel_mux
    return config


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
    return _apply_ios_remote_admin_defaults(merged)


def _flatten_grouped_runtime_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten grouped config sections into Runner-style args."""
    flattened: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, Mapping):
            flattened.update(dict(value))
        else:
            flattened[key] = value
    return flattened


def _runtime_mode_from_grouped_config(config: Mapping[str, Any]) -> str:
    mode = bridge_tun_ios.packetflow_connector_mode_from_config(config)
    return mode or "swift_udp"


def _runtime_owner_from_mode(mode: str) -> str:
    if mode == "swift_host_runner":
        return "ObstacleBridgeApp swift_host_runner"
    return "IPServer Network Extension"


def _write_default_config_file(root: Path) -> Path:
    path = root / "config" / "ObstacleBridge.cfg"
    if sys.platform == "ios":
        return path
    if not path.exists():
        payload = _default_ios_grouped_config(root)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_startup_artifacts(root: Path | None = None) -> Path:
    """Create USB-visible folders early so Finder/iTunes can expose them."""
    explicit_root = root is not None
    root = _ios_documents_root() if root is None else Path(root)
    try:
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
    except OSError:
        if explicit_root or sys.platform == "ios" or os.environ.get("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT"):
            raise
        fallback = Path.cwd() / ".obstaclebridge-ios-documents"
        if fallback.resolve() == root.resolve():
            raise
        return _write_startup_artifacts(fallback)


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
    DOCUMENTS_ROOT = _EARLY_DOCUMENTS_ROOT
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
        runtime_cfg = _load_grouped_runtime_config(self.DOCUMENTS_ROOT)
        runtime_mode = _runtime_mode_from_grouped_config(runtime_cfg)
        log_event(
            self.DOCUMENTS_ROOT,
            "ios_app.facade_init",
            runtime_mode=runtime_mode,
            runtime_owner=_runtime_owner_from_mode(runtime_mode),
        )
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
        # The embedded app and Safari use the same extension-owned Admin API.
        port = int(config.get("admin_web_port") or WEBADMIN_DEFAULT_PORT)
        path = str(config.get("admin_web_path") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH).strip() or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH
        if not path.startswith("/"):
            path = "/" + path
        return f"http://127.0.0.1:{port}{path}"

    def save_profile(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        return self.profile_store.save_profile(profile)

    def connection_snapshot(self) -> dict[str, Any]:
        runtime_cfg = _load_grouped_runtime_config(self.DOCUMENTS_ROOT)
        runtime_mode = _runtime_mode_from_grouped_config(runtime_cfg)
        return {
            "started": False,
            "runtime_mode": runtime_mode,
            "runtime_owner": _runtime_owner_from_mode(runtime_mode),
            "active_profile_id": self._active_profile_id,
            "config": runtime_cfg,
            "webadmin_url": self.webadmin_url_from_config(_flatten_grouped_runtime_config(runtime_cfg)),
        }

    def diagnostics_snapshot(self) -> dict[str, Any]:
        payload = diagnostics_snapshot(self.DOCUMENTS_ROOT)
        payload["connection"] = self.connection_snapshot()
        return payload


def _run_probe_mode(argv: list[str]) -> int | None:
    probe_flags = {
        "--host-websocket-probe",
        "--ws-udp-echo-probe",
        "--ws-secure-link-probe",
        "--runtime-config",
        "--embedded-webadmin-probe",
        "--webadmin-http-probe",
    }
    if not any(flag in argv for flag in probe_flags):
        return None

    from obstacle_bridge_ios_e2e.__main__ import main as e2e_main

    return int(e2e_main(argv))


def main(argv: list[str] | None = None):
    args = list(sys.argv[1:] if argv is None else argv)
    probe_exit_code = _run_probe_mode(args)
    if probe_exit_code is not None:
        return probe_exit_code
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
                    switch_cls = _resolve_toga_switch_class()
                    webadmin_view = None
                    webadmin_view_ready = False
                    if webview_cls is not None:
                        try:
                            webadmin_view = webview_cls(style=_pack(flex=1))
                            webadmin_view_ready = True
                        except Exception:
                            webadmin_view = None
                            webadmin_view_ready = False

                    control_state = {"updating": False}

                    def _extension_state(payload: Mapping[str, Any]) -> str:
                        status = str(payload.get("status") or "").lower()
                        if status in {
                            "connected",
                            "connecting",
                            "reasserting",
                        }:
                            return "active"
                        if status in {"disconnected", "disconnecting", "invalid", "stopped"}:
                            return "inactive"
                        return "unknown"

                    def _set_switch_value(widget: Any, value: bool) -> None:
                        if widget is None:
                            return
                        control_state["updating"] = True
                        try:
                            widget.value = value
                        except Exception:
                            pass
                        finally:
                            control_state["updating"] = False

                    def _refresh_webadmin(extension: Mapping[str, Any] | None = None) -> bool:
                        try:
                            snap = bridge_app.connection_snapshot()
                            webadmin_url = str(snap.get("webadmin_url") or "").strip()
                            if not webadmin_url or not webadmin_view_ready:
                                return False
                            extension_state = _extension_state(extension or runtime_status())
                            if extension_state == "inactive":
                                return _set_webview_url(webadmin_view, "about:blank")
                            if extension_state == "unknown":
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

                    controls_box = toga.Box(
                        style=_pack(
                            direction="column",
                            padding_top=12,
                            padding_bottom=12,
                            padding_left=16,
                            padding_right=16,
                            background_color="#15233b",
                        )
                    )
                    vpn_switch = None
                    tun_switch = None

                    def _schedule_native_task(coroutine) -> None:
                        loop = getattr(self, "loop", None)
                        if loop is not None:
                            loop.call_soon_threadsafe(asyncio.create_task, coroutine)

                    async def _refresh_native_controls() -> None:
                        extension = await asyncio.to_thread(runtime_status)
                        snapshot = bridge_app.connection_snapshot()
                        webadmin_url = str(snapshot.get("webadmin_url") or "")
                        tun = (
                            await asyncio.to_thread(_admin_api_request, webadmin_url, "/api/tun-routing/status")
                            if extension_state == "active" and webadmin_url
                            else {"enabled": bool(snapshot.get("config", {}).get("TUN_routing", {}).get("enabled_on_startup", True))}
                        )
                        extension_state = _extension_state(extension)
                        extension_active = extension_state == "active"
                        _set_switch_value(vpn_switch, extension_active)
                        _set_switch_value(tun_switch, bool(tun.get("enabled") or tun.get("active")))
                        try:
                            tun_switch.enabled = extension_active
                        except Exception:
                            pass
                        _set_operational_surface(extension_state)
                        _refresh_webadmin(extension)

                    async def _refresh_native_controls_until_settled() -> None:
                        for delay in (0.0, 1.0, 3.0):
                            if delay:
                                await asyncio.sleep(delay)
                            await _refresh_native_controls()

                    async def _change_extension(enabled: bool) -> None:
                        result = await asyncio.to_thread(start_runtime if enabled else stop_runtime)
                        log_event(
                            ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                            "toga.network_extension_control_requested",
                            enabled=enabled,
                            result=result,
                        )
                        await _refresh_native_controls_until_settled()
                        if enabled:
                            _schedule_webadmin_refresh()

                    async def _change_tun(enabled: bool) -> None:
                        webadmin_url = str(bridge_app.connection_snapshot().get("webadmin_url") or "")
                        result = await asyncio.to_thread(
                            _admin_api_request,
                            webadmin_url,
                            "/api/tun-routing/control",
                            method="POST",
                            body={"enabled": enabled},
                        ) if webadmin_url else {"ok": False, "error": "Network Extension Admin API is unavailable"}
                        log_event(
                            ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                            "toga.network_tunneling_control_requested",
                            enabled=enabled,
                            result=result,
                        )
                        await _refresh_native_controls_until_settled()

                    def _on_vpn_switch_change(widget: Any) -> None:
                        if not control_state["updating"]:
                            _schedule_native_task(_change_extension(bool(getattr(widget, "value", False))))

                    def _on_tun_switch_change(widget: Any) -> None:
                        if not control_state["updating"]:
                            _schedule_native_task(_change_tun(bool(getattr(widget, "value", False))))

                    def _add_native_control(label: str, handler) -> Any:
                        row = toga.Box(style=_pack(direction="row", padding_top=8, padding_bottom=8))
                        row.add(toga.Label(label, style=_pack(flex=1, font_size=14, color="#e6edf7")))
                        if switch_cls is None:
                            row.add(_fallback_label("Unavailable"))
                            controls_box.add(row)
                            return None
                        try:
                            switch = switch_cls("", value=False, on_change=handler)
                        except TypeError:
                            switch = switch_cls("")
                            switch.value = False
                            switch.on_change = handler
                        row.add(switch)
                        controls_box.add(row)
                        return switch

                    vpn_switch = _add_native_control("Network extension active", _on_vpn_switch_change)
                    tun_switch = _add_native_control("Network tunneling active", _on_tun_switch_change)

                    operational_box = toga.Box(
                        style=_pack(direction="column", flex=1, background_color="#0a1220")
                    )
                    extension_off_box = toga.Box(
                        style=_pack(
                            direction="column",
                            flex=1,
                            padding=16,
                            background_color="#0a1220",
                        )
                    )
                    extension_off_card = toga.Box(
                        style=_pack(direction="column", padding=18, background_color="#15233b")
                    )
                    extension_off_badge = toga.Box(
                        style=_pack(direction="row", height=24, padding_bottom=10)
                    )
                    extension_off_badge.add(
                        toga.Box(style=_pack(width=8, height=8, background_color="#ef4444"))
                    )
                    extension_off_badge.add(
                        toga.Label(
                            "OFFLINE",
                            style=_pack(font_size=12, color="#fca5a5", padding_left=8),
                        )
                    )
                    extension_off_title = toga.Label(
                        "Checking Network Extension status...",
                        style=_pack(font_size=16, color="#e6edf7", padding_bottom=6),
                    )
                    extension_off_message = toga.Label(
                        "Waiting for the Network Extension status.",
                        style=_pack(font_size=13, color="#8ba0bd"),
                    )
                    extension_off_card.add(extension_off_badge)
                    extension_off_card.add(extension_off_title)
                    extension_off_card.add(extension_off_message)
                    extension_off_box.add(extension_off_card)
                    operational_surface = {"widget": None}

                    def _set_operational_surface(extension_state: str) -> None:
                        if extension_state == "active":
                            target = webadmin_view if webadmin_view_ready and webadmin_view is not None else fallback_box
                        else:
                            target = extension_off_box
                            if extension_state == "inactive":
                                extension_off_title.text = "Turn on Network Extension"
                                extension_off_message.text = (
                                    "Use the switch above to enable ObstacleBridge."
                                )
                            else:
                                extension_off_title.text = "Checking Network Extension status..."
                                extension_off_message.text = "Waiting for the Network Extension status."
                        if operational_surface["widget"] is target:
                            return
                        operational_box.clear()
                        operational_box.add(target)
                        operational_surface["widget"] = target

                    root_box = toga.Box(
                        style=_pack(direction="column", flex=1, padding=0, background_color="#0a1220")
                    )
                    root_box.add(controls_box)
                    fallback_box = toga.Box(
                        style=_pack(direction="column", flex=1, background_color="#0a1220")
                    )
                    fallback_box.add(
                        _fallback_label(
                            f"Embedded WebAdmin is unavailable. Shared files are in {root}."
                        )
                    )
                    _set_operational_surface("unknown")
                    root_box.add(operational_box)

                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.ui_ready_runtime_not_started",
                        runtime_mode=bridge_app.connection_snapshot().get("runtime_mode", ""),
                        runtime_owner=bridge_app.connection_snapshot().get("runtime_owner", ""),
                    )
                    harvested_logs = harvest_runtime_logs()
                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.runtime_logs_harvested",
                        result=harvested_logs,
                    )
                    tunnel_prepare = prepare_runtime()
                    log_event(
                        ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                        "toga.runtime_prepare_requested",
                        result=tunnel_prepare,
                    )
                    _refresh_webadmin()
                    _schedule_native_task(_refresh_native_controls_until_settled())

                    async def _log_tunnel_status_after_prepare() -> None:
                        await asyncio.sleep(3.0)
                        log_event(
                            ObstacleBridgeIOSApp.DOCUMENTS_ROOT,
                            "toga.runtime_status_after_prepare",
                            result=runtime_status(),
                        )

                    async def _on_running(app, **kwargs) -> None:
                        log_event(ObstacleBridgeIOSApp.DOCUMENTS_ROOT, "toga.on_running")
                        asyncio.create_task(_log_tunnel_status_after_prepare())
                        _schedule_native_task(_refresh_native_controls_until_settled())
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
                            "toga.runtime_status",
                            result=runtime_status(),
                        )
                        _schedule_native_task(_refresh_native_controls_until_settled())
                        _schedule_webadmin_refresh()

                    self.on_exit = _on_exit
                    with contextlib.suppress(Exception):
                        self.on_suspend = _on_suspend
                    with contextlib.suppress(Exception):
                        self.on_resume = _on_resume
                    window = toga.MainWindow(title="")
                    window.content = root_box
                    self.main_window = window
                    window.show()
                    _schedule_webadmin_refresh()
                except Exception as exc:
                    _append_startup_crash_log(exc)
                    raise

        # Toga requires a non-empty formal name even though the iOS window has no title.
        return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
    except Exception as exc:
        _append_startup_crash_log(exc)
        raise
