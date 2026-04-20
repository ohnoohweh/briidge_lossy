"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import os
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

    def __init__(self) -> None:
        self.client = ObstacleBridgeClient({"admin_web": False})
        self.profile_store = ProfileStore(Path.home() / ".obstaclebridge-ios" / "profiles")

    def preview_import(self, text: str) -> dict:
        return preview_import_text(text)

    def save_profile(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        return self.profile_store.save_profile(profile)

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

            cfg_status = _label("Ready for a demo profile.", role="muted", padding_top=8)
            status_label = _label("Run a reachability check when the host peer is listening.", role="muted", padding_top=8)
            route_status = _label("System tunnel: POC source ready, entitlement/device validation pending.", role="warning")

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
            status_box.add(runtime_section)

            connection_section = _section("Host connection", "Checks the configured host and port from the app facade.")
            connection_section.add(toga.Button("Check host", on_press=_check_status, style=_pack(padding_bottom=8)))
            connection_section.add(status_label)
            status_box.add(connection_section)

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

            tabs = toga.OptionContainer(style=_pack(flex=1))
            tabs.content.append("Connect", _scrollable(config_box))
            tabs.content.append("Health", _scrollable(status_box))

            window = toga.MainWindow(title=self.formal_name)
            window.content = tabs
            window.show()

    return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
