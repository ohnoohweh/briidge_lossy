"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Optional

from obstacle_bridge.core import ObstacleBridgeClient

from .dependency_spike import (
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)
from .m25_ui import M25Config, profile_from_m25_config, tcp_status_probe
from .m3_tunnel import M3NetworkSettings, m3_vpn_profile_from_profile
from .onboarding import preview_import_text
from .profiles import ProfileStore

try:
    import toga
except Exception:  # pragma: no cover - exercised in iOS build/runtime, not unit tests.
    toga = None


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


def _probe_http_ok(url: str, timeout_sec: float = 1.0) -> bool:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            status = int(getattr(response, "status", 0) or 0)
            return 200 <= status < 500
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


class ObstacleBridgeIOSApp:
    """Thin wrapper that keeps shared runtime/onboarding imports explicit."""

    WEBADMIN_DEFAULT_BIND = "127.0.0.1"
    WEBADMIN_DEFAULT_PORT = 18080
    WEBADMIN_DEFAULT_PATH = "/"

    def __init__(self) -> None:
        self.client = ObstacleBridgeClient(
            {
                "admin_web": True,
                "admin_web_bind": self.WEBADMIN_DEFAULT_BIND,
                "admin_web_port": self.WEBADMIN_DEFAULT_PORT,
                "admin_web_path": self.WEBADMIN_DEFAULT_PATH,
            }
        )
        self.profile_store = ProfileStore(Path.home() / ".obstaclebridge-ios" / "profiles")
        self._active_profile_id: Optional[str] = None
        self._runtime_loop: Optional[asyncio.AbstractEventLoop] = None
        self._runtime_loop_thread: Optional[threading.Thread] = None

    def _ensure_runtime_loop(self) -> asyncio.AbstractEventLoop:
        loop = self._runtime_loop
        thread = self._runtime_loop_thread
        if loop is not None and thread is not None and thread.is_alive():
            return loop

        ready = threading.Event()

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._runtime_loop = loop
            ready.set()
            loop.run_forever()
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        ready.wait()
        self._runtime_loop_thread = thread
        if self._runtime_loop is None:  # pragma: no cover - defensive guard.
            raise RuntimeError("failed to initialize embedded runtime loop")
        return self._runtime_loop

    def _run_async_sync(self, awaitable: Any) -> Any:
        """Run an awaitable on the persistent embedded runtime loop."""
        loop = self._ensure_runtime_loop()
        future = asyncio.run_coroutine_threadsafe(awaitable, loop)
        return future.result()

    def close(self) -> None:
        loop = self._runtime_loop
        thread = self._runtime_loop_thread
        if loop is None or thread is None:
            return
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=2.0)
        self._runtime_loop = None
        self._runtime_loop_thread = None

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup.
        try:
            self.close()
        except Exception:
            pass

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
        return runtime_cfg

    @staticmethod
    def webadmin_url_from_config(config: Mapping[str, Any]) -> Optional[str]:
        if not isinstance(config, Mapping) or not bool(config.get("admin_web")):
            return None
        bind = str(config.get("admin_web_bind") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_BIND).strip() or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_BIND
        port = int(config.get("admin_web_port") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PORT)
        path = str(config.get("admin_web_path") or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH).strip() or ObstacleBridgeIOSApp.WEBADMIN_DEFAULT_PATH
        if not path.startswith("/"):
            path = "/" + path
        host = "127.0.0.1" if bind in {"0.0.0.0", "::", "*", "localhost"} else bind
        return f"http://{host}:{port}{path}"

    def preview_import(self, text: str) -> dict:
        return preview_import_text(text)

    def save_profile(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        return self.profile_store.save_profile(profile)

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
        runtime_cfg = self._runtime_config_from_profile(selected)
        self._run_async_sync(self.client.start(config=runtime_cfg))
        self._active_profile_id = str(selected.get("profile_id", "") or "").strip() or None
        return self.connection_snapshot()

    def disconnect_profile(self) -> dict[str, Any]:
        self._run_async_sync(self.client.stop())
        self._active_profile_id = None
        return self.connection_snapshot()

    def connection_snapshot(self) -> dict[str, Any]:
        snap = dict(self.client.snapshot())
        snap["active_profile_id"] = self._active_profile_id
        runtime_cfg = snap.get("config")
        snap["webadmin_url"] = self.webadmin_url_from_config(runtime_cfg) if isinstance(runtime_cfg, Mapping) else None
        return snap

    def start_embedded_webadmin(self) -> dict[str, Any]:
        self._run_async_sync(
            self.client.start(
                config={
                    "admin_web": True,
                    "admin_web_bind": self.WEBADMIN_DEFAULT_BIND,
                    "admin_web_port": self.WEBADMIN_DEFAULT_PORT,
                    "admin_web_path": self.WEBADMIN_DEFAULT_PATH,
                }
            )
        )
        return self.connection_snapshot()

    def import_and_store_profile(
        self,
        import_text: str,
        *,
        profile_id: str,
        display_name: str,
    ) -> dict[str, Any]:
        preview = self.preview_import(import_text)
        updates = preview.get("suggested_updates")
        if not isinstance(updates, dict):
            raise ValueError("import preview did not produce suggested_updates")
        profile = {
            "profile_id": str(profile_id),
            "display_name": str(display_name),
            "obstacle_bridge": dict(updates),
        }
        return self.save_profile(profile)

    def run_m2_dependency_spike(self) -> dict[str, Any]:
        return run_m2_dependency_spike_sync()

    def run_m2_dependency_spike_and_store_report(self) -> Path:
        report = self.run_m2_dependency_spike()
        return write_m2_dependency_spike_report(report)

    def build_profile_from_m25_config(self, cfg: M25Config) -> dict[str, Any]:
        return profile_from_m25_config(cfg)

    def tcp_status_probe(self, host: str, port: int, timeout_sec: float = 2.0) -> dict[str, Any]:
        return tcp_status_probe(host, port, timeout_sec=timeout_sec)

    def build_m3_vpn_profile(
        self,
        profile: Mapping[str, Any],
        *,
        provider_bundle_identifier: str,
        network: Optional[M3NetworkSettings] = None,
    ) -> dict[str, Any]:
        return m3_vpn_profile_from_profile(
            profile,
            provider_bundle_identifier=provider_bundle_identifier,
            network=network,
        )


def main():
    if toga is None:
        raise RuntimeError("Toga is required to run the iOS app UI")
    _configure_ios_safe_locale()

    class _TogaObstacleBridgeApp(toga.App):
        def startup(self):
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
                for attr in ("url",):
                    try:
                        setattr(widget, attr, url)
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
                    print(f"Embedded WebAdmin load failed: {type(exc).__name__}: {exc}")
                    return False

            async def _await_and_refresh_webadmin() -> None:
                deadline = asyncio.get_running_loop().time() + 15.0
                webadmin_url = ""
                while asyncio.get_running_loop().time() < deadline:
                    try:
                        snap = bridge_app.connection_snapshot()
                    except Exception:
                        await asyncio.sleep(0.25)
                        continue
                    webadmin_url = str(snap.get("webadmin_url") or "").strip()
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
                        "Embedded WebAdmin is unavailable in this runtime build."
                    )
                )
                root_box.add(fallback_box)

            try:
                bridge_app.start_embedded_webadmin()
                _refresh_webadmin()
            except Exception as exc:
                print(f"Embedded runtime start failed: {type(exc).__name__}: {exc}")

            async def _on_running(app, **kwargs) -> None:
                _schedule_webadmin_refresh()

            self.on_running = _on_running
            window = toga.MainWindow(title="")
            window.content = root_box
            window.show()
            _schedule_webadmin_refresh()

    return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
