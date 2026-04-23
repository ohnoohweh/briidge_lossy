"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import asyncio
import json
import os
import threading
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


def _configure_ios_safe_locale() -> None:
    """Ensure Toga's locale bootstrap has a supported default on iOS."""
    os.environ["LC_ALL"] = "C"
    os.environ["LANG"] = "C"


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

    def _run_async_sync(self, awaitable: Any) -> Any:
        """Run an awaitable from sync UI callbacks."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(awaitable)

        result: dict[str, Any] = {"value": None}
        error: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result["value"] = asyncio.run(awaitable)
            except BaseException as exc:  # pragma: no cover - defensive path.
                error["exc"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()
        if "exc" in error:
            raise error["exc"]
        return result["value"]

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

            def _label(text: str, *, role: str = "body", padding_top: int = 0, padding_bottom: int = 0):
                style_map = {
                    "hero": {"font_size": 26, "font_weight": "bold", "color": "#111827"},
                    "title": {"font_size": 18, "font_weight": "bold", "color": "#111827"},
                    "eyebrow": {"font_size": 11, "color": "#2563eb"},
                    "body": {"font_size": 14, "color": "#374151"},
                    "muted": {"font_size": 12, "color": "#6b7280"},
                    "success": {"font_size": 13, "font_weight": "bold", "color": "#047857"},
                    "warning": {"font_size": 13, "font_weight": "bold", "color": "#b45309"},
                }
                return toga.Label(
                    text,
                    style=_pack(
                        padding_top=padding_top,
                        padding_bottom=padding_bottom,
                        **style_map.get(role, style_map["body"]),
                    ),
                )

            def _section(title: str, subtitle: Optional[str] = None):
                box = toga.Box(
                    style=_pack(
                        direction="column",
                        padding=14,
                        padding_bottom=10,
                        background_color="#ffffff",
                    )
                )
                box.add(_label(title, role="title", padding_bottom=4))
                if subtitle:
                    box.add(_label(subtitle, role="muted", padding_bottom=8))
                return box

            def _field(parent, label_text: str, widget, help_text: Optional[str] = None) -> None:
                parent.add(_label(label_text, role="muted", padding_top=6, padding_bottom=2))
                parent.add(widget)
                if help_text:
                    parent.add(_label(help_text, role="muted", padding_top=2))

            def _scrollable(content):
                scroll_cls = getattr(toga, "ScrollContainer", None)
                if scroll_cls is None:
                    return content
                try:
                    return scroll_cls(content=content, style=_pack(flex=1))
                except TypeError:
                    scroll = scroll_cls(style=_pack(flex=1))
                    scroll.content = content
                    return scroll

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

            cfg_status = _label("Ready for a demo profile.", role="muted", padding_top=8)
            status_label = _label("Run a reachability check when the host peer is listening.", role="muted", padding_top=8)
            connect_label = _label("Overlay session is idle.", role="muted", padding_top=8)
            snapshot_label = _label("Snapshot pending.", role="muted", padding_top=8)
            route_status = _label("System tunnel: POC source ready, entitlement/device validation pending.", role="warning")
            webadmin_label = _label("WebAdmin appears inside the app after connect.", role="muted", padding_top=8)
            webadmin_status_label = _label("Connect the overlay to open WebAdmin here.", role="muted", padding_top=8)
            webadmin_url_label = _label("WebAdmin URL unavailable.", role="muted", padding_top=6)
            webview_cls = getattr(toga, "WebView", None)
            webadmin_view = None
            webadmin_view_ready = False
            if webview_cls is not None:
                try:
                    webadmin_view = webview_cls(style=_pack(flex=1))
                    webadmin_view_ready = True
                except Exception:
                    webadmin_view = None
                    webadmin_view_ready = False

            profile_id_input = toga.TextInput(value="ios-m25-default")
            display_name_input = toga.TextInput(value="Demo Client")
            transport_select = toga.Selection(items=["ws", "tcp", "myudp", "quic"], value="ws")
            peer_host_input = toga.TextInput(value="127.0.0.1")
            peer_port_input = toga.NumberInput(min=1, max=65535, value=8080)
            local_tcp_input = toga.NumberInput(min=1, max=65535, value=18080)
            local_udp_input = toga.NumberInput(min=1, max=65535, value=18081)
            target_host_input = toga.TextInput(value="127.0.0.1")
            target_tcp_input = toga.NumberInput(min=1, max=65535, value=8080)
            target_udp_input = toga.NumberInput(min=1, max=65535, value=8081)

            def _num(value: Any, fallback: int) -> int:
                try:
                    return int(value)
                except Exception:
                    return int(fallback)

            def _save_config(widget) -> None:
                try:
                    cfg = M25Config(
                        profile_id=str(profile_id_input.value or "").strip(),
                        display_name=str(display_name_input.value or "").strip(),
                        transport=str(transport_select.value or "ws"),
                        peer_host=str(peer_host_input.value or "").strip(),
                        peer_port=_num(peer_port_input.value, 443),
                        local_tcp_port=_num(local_tcp_input.value, 18080),
                        local_udp_port=_num(local_udp_input.value, 18081),
                        target_host=str(target_host_input.value or "127.0.0.1").strip() or "127.0.0.1",
                        target_tcp_port=_num(target_tcp_input.value, 8080),
                        target_udp_port=_num(target_udp_input.value, 8081),
                    )
                    profile = bridge_app.build_profile_from_m25_config(cfg)
                    bridge_app.save_profile(profile)
                    cfg_status.text = f"Saved '{cfg.display_name or cfg.profile_id}' for {cfg.transport.upper()} at {cfg.peer_host}:{cfg.peer_port}."
                except Exception as exc:
                    cfg_status.text = f"Needs attention: {exc}"

            def _check_status(widget) -> None:
                result = bridge_app.tcp_status_probe(
                    str(peer_host_input.value or "").strip(),
                    _num(peer_port_input.value, 8080),
                    timeout_sec=2.0,
                )
                if bool(result.get("ok")):
                    status_label.text = f"Online: host answered in {int(result.get('latency_ms', 0))} ms."
                else:
                    status_label.text = "Offline: start the macOS host peer, then try again."

            def _format_snapshot() -> str:
                snap = bridge_app.connection_snapshot()
                started = bool(snap.get("started"))
                active_profile_id = str(snap.get("active_profile_id") or "-")
                runtime_cfg = snap.get("config") if isinstance(snap.get("config"), Mapping) else {}
                transport = str(runtime_cfg.get("overlay_transport") or "-")
                webadmin_url = str(snap.get("webadmin_url") or "-")

                peer_host = "-"
                peer_port = "-"
                for prefix in ("ws", "tcp", "udp", "quic"):
                    host_key = f"{prefix}_peer"
                    port_key = f"{prefix}_peer_port"
                    if runtime_cfg.get(host_key):
                        peer_host = str(runtime_cfg.get(host_key))
                        peer_port = str(runtime_cfg.get(port_key) or "-")
                        break

                connections = snap.get("connections")
                if isinstance(connections, list):
                    connection_count = len(connections)
                elif isinstance(connections, Mapping):
                    if isinstance(connections.get("channels"), list):
                        connection_count = len(connections.get("channels"))
                    elif isinstance(connections.get("items"), list):
                        connection_count = len(connections.get("items"))
                    else:
                        connection_count = len(connections)
                else:
                    connection_count = 0

                brief = (
                    f"started={started} | profile={active_profile_id} | transport={transport} | "
                    f"peer={peer_host}:{peer_port} | connections={connection_count} | webadmin={webadmin_url}"
                )
                return f"{brief}\n{json.dumps(snap, indent=2, sort_keys=True)}"

            def _refresh_snapshot(widget=None) -> None:
                try:
                    snap = bridge_app.connection_snapshot()
                    webadmin_url = str(snap.get("webadmin_url") or "").strip()
                    if webadmin_url:
                        webadmin_label.text = "WebAdmin is available inside this app session."
                        webadmin_url_label.text = f"Runtime URL: {webadmin_url}"
                        if webadmin_view_ready and _set_webview_url(webadmin_view, webadmin_url):
                            webadmin_status_label.text = "WebAdmin loaded in the embedded view."
                        elif webadmin_view_ready:
                            webadmin_status_label.text = "WebAdmin URL is ready, but the embedded view could not navigate yet."
                        else:
                            webadmin_status_label.text = "This runtime has WebAdmin enabled, but this build does not expose a native WebView widget."
                    else:
                        webadmin_label.text = "WebAdmin is disabled for the current runtime config."
                        webadmin_url_label.text = "WebAdmin URL unavailable."
                        webadmin_status_label.text = "Connect the overlay to open WebAdmin here."
                    snapshot_label.text = _format_snapshot()
                except Exception as exc:
                    webadmin_label.text = "WebAdmin URL unavailable."
                    webadmin_url_label.text = "WebAdmin URL unavailable."
                    webadmin_status_label.text = f"WebAdmin refresh failed: {type(exc).__name__}: {exc}"
                    snapshot_label.text = f"Snapshot failed: {type(exc).__name__}: {exc}"

            def _connect_overlay(widget) -> None:
                try:
                    cfg = M25Config(
                        profile_id=str(profile_id_input.value or "").strip(),
                        display_name=str(display_name_input.value or "").strip(),
                        transport=str(transport_select.value or "ws"),
                        peer_host=str(peer_host_input.value or "").strip(),
                        peer_port=_num(peer_port_input.value, 443),
                        local_tcp_port=_num(local_tcp_input.value, 18080),
                        local_udp_port=_num(local_udp_input.value, 18081),
                        target_host=str(target_host_input.value or "127.0.0.1").strip() or "127.0.0.1",
                        target_tcp_port=_num(target_tcp_input.value, 8080),
                        target_udp_port=_num(target_udp_input.value, 8081),
                    )
                    profile = bridge_app.build_profile_from_m25_config(cfg)
                    stored = bridge_app.save_profile(profile)
                    snap = bridge_app.connect_profile(profile=stored)
                    if snap.get("started"):
                        connect_label.text = f"Connected: {cfg.transport.upper()} {cfg.peer_host}:{cfg.peer_port}"
                    else:
                        connect_label.text = "Connect requested, but runtime is not started."
                    _refresh_snapshot()
                except Exception as exc:
                    connect_label.text = f"Connect failed: {type(exc).__name__}: {exc}"
                    _refresh_snapshot()

            def _disconnect_overlay(widget) -> None:
                try:
                    snap = bridge_app.disconnect_profile()
                    if snap.get("started"):
                        connect_label.text = "Disconnect requested, but runtime still reports active."
                    else:
                        connect_label.text = "Disconnected."
                    _refresh_snapshot()
                except Exception as exc:
                    connect_label.text = f"Disconnect failed: {type(exc).__name__}: {exc}"
                    _refresh_snapshot()

            def _load_demo(widget) -> None:
                profile_id_input.value = "ios-demo-client"
                display_name_input.value = "Conference Demo"
                transport_select.value = "ws"
                peer_host_input.value = "127.0.0.1"
                peer_port_input.value = 8080
                local_tcp_input.value = 18080
                local_udp_input.value = 18081
                target_host_input.value = "127.0.0.1"
                target_tcp_input.value = 8080
                target_udp_input.value = 8081
                cfg_status.text = "Demo preset loaded. Save it, then check host reachability."

            config_box = toga.Box(
                style=_pack(direction="column", padding=16, background_color="#f3f6fb")
            )
            config_box.add(_label("OBSTACLEBRIDGE IOS", role="eyebrow", padding_bottom=4))
            config_box.add(_label("Private bridge, pocket sized.", role="hero", padding_bottom=6))
            config_box.add(
                _label(
                    "Prepare a demo profile, connect to a host peer, and keep the system-tunnel work visible without burying the story in raw config.",
                    role="body",
                    padding_bottom=12,
                )
            )
            config_box.add(toga.Button("Use demo preset", on_press=_load_demo, style=_pack(padding_bottom=8)))

            profile_section = _section("Profile", "A friendly name for the customer-facing setup.")
            _field(profile_section, "Display name", display_name_input)
            _field(profile_section, "Profile ID", profile_id_input)
            config_box.add(profile_section)

            peer_section = _section("Host peer", "The macOS or Linux peer this iOS demo will reach.")
            _field(peer_section, "Transport", transport_select)
            _field(peer_section, "Host", peer_host_input)
            _field(peer_section, "Port", peer_port_input)
            config_box.add(peer_section)

            preview_section = _section("Local preview", "These ports describe the app-side service intent before the packet tunnel is enabled.")
            _field(preview_section, "Local TCP port", local_tcp_input)
            _field(preview_section, "Local UDP port", local_udp_input)
            _field(preview_section, "Target host", target_host_input)
            _field(preview_section, "Target TCP port", target_tcp_input)
            _field(preview_section, "Target UDP port", target_udp_input)
            config_box.add(preview_section)

            action_section = _section("Ready")
            action_section.add(toga.Button("Save profile", on_press=_save_config, style=_pack(padding_bottom=8)))
            action_section.add(cfg_status)
            config_box.add(action_section)

            status_box = toga.Box(
                style=_pack(direction="column", padding=16, background_color="#f8fafc")
            )
            status_box.add(_label("LIVE STATUS", role="eyebrow", padding_bottom=4))
            status_box.add(_label("Demo health check", role="hero", padding_bottom=6))
            status_box.add(
                _label(
                    "Use this during the system demo to show that the simulator app can reach the host peer.",
                    role="body",
                    padding_bottom=12,
                )
            )

            runtime_section = _section("Runtime", "Shared code is packaged into the iOS app.")
            runtime_section.add(_label(f"Loaded: {bridge_app.client.__class__.__name__}", role="success"))
            runtime_section.add(route_status)
            runtime_section.add(webadmin_label)
            status_box.add(runtime_section)

            connection_section = _section("Host connection", "Checks the configured host and port from the app facade.")
            connection_section.add(toga.Button("Connect overlay", on_press=_connect_overlay, style=_pack(padding_bottom=6)))
            connection_section.add(toga.Button("Disconnect overlay", on_press=_disconnect_overlay, style=_pack(padding_bottom=8)))
            connection_section.add(connect_label)
            connection_section.add(toga.Button("Check host", on_press=_check_status, style=_pack(padding_bottom=8)))
            connection_section.add(status_label)
            status_box.add(connection_section)

            snapshot_section = _section("Runtime snapshot", "Live facade/runtime state for the current app session.")
            snapshot_section.add(toga.Button("Refresh snapshot", on_press=_refresh_snapshot, style=_pack(padding_bottom=8)))
            snapshot_section.add(snapshot_label)
            status_box.add(snapshot_section)

            story_section = _section("What is real today", "A clear demo boundary keeps trust high.")
            story_section.add(_label("Profile storage, invite preview, dependency checks, and host reachability are live.", role="body"))
            story_section.add(
                _label(
                    "Full system traffic needs the Network Extension entitlement and device validation.",
                    role="muted",
                    padding_top=6,
                )
            )
            status_box.add(story_section)

            webadmin_box = toga.Box(
                style=_pack(direction="column", padding=16, background_color="#f5f7fb")
            )
            webadmin_box.add(_label("WEBADMIN", role="eyebrow", padding_bottom=4))
            webadmin_box.add(_label("Embedded operator view", role="hero", padding_bottom=6))
            webadmin_box.add(
                _label(
                    "This loads the runtime's WebAdmin inside the app instead of assuming the macOS host browser can reach simulator localhost.",
                    role="body",
                    padding_bottom=12,
                )
            )

            webadmin_runtime_section = _section("WebAdmin session", "Start the overlay runtime first, then refresh this view if needed.")
            webadmin_runtime_section.add(toga.Button("Refresh WebAdmin", on_press=_refresh_snapshot, style=_pack(padding_bottom=8)))
            webadmin_runtime_section.add(webadmin_label)
            webadmin_runtime_section.add(webadmin_status_label)
            webadmin_runtime_section.add(webadmin_url_label)
            webadmin_box.add(webadmin_runtime_section)

            webadmin_view_section = _section("Live view", "The embedded browser is the intended access path for the simulator app.")
            if webadmin_view_ready and webadmin_view is not None:
                webadmin_view_section.add(webadmin_view)
            else:
                webadmin_view_section.add(
                    _label(
                        "WebView is not available in this runtime build. The runtime URL is still shown above for diagnostics.",
                        role="warning",
                    )
                )
            webadmin_box.add(webadmin_view_section)

            tabs = toga.OptionContainer(style=_pack(flex=1))
            tabs.content.append("Connect", _scrollable(config_box))
            tabs.content.append("Health", _scrollable(status_box))
            tabs.content.append("WebAdmin", _scrollable(webadmin_box))
            _refresh_snapshot()

            window = toga.MainWindow(title=self.formal_name)
            window.content = tabs
            window.show()

    return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
