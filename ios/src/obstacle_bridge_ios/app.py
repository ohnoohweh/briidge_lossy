"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from obstacle_bridge.core import ObstacleBridgeClient

from .dependency_spike import (
    run_m2_dependency_spike_sync,
    write_m2_dependency_spike_report,
)
from .m25_ui import M25Config, profile_from_m25_config, tcp_status_probe
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


def main():
    if toga is None:
        raise RuntimeError("Toga is required to run the iOS app UI")
    _configure_ios_safe_locale()

    class _TogaObstacleBridgeApp(toga.App):
        def startup(self):
            bridge_app = ObstacleBridgeIOSApp()
            cfg_status = toga.Label("", style=toga.style.Pack(padding_top=8))
            status_label = toga.Label("Not checked yet", style=toga.style.Pack(padding_top=8))

            profile_id_input = toga.TextInput(value="ios-m25-default")
            display_name_input = toga.TextInput(value="iOS M2.5 Profile")
            transport_select = toga.Selection(items=["ws", "tcp", "myudp", "quic"], value="ws")
            peer_host_input = toga.TextInput(value="127.0.0.1")
            peer_port_input = toga.NumberInput(min=1, max=65535, value=443)
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
                    cfg_status.text = f"Saved profile '{cfg.profile_id}' with localhost TCP/UDP exposure settings."
                except Exception as exc:
                    cfg_status.text = f"Save failed: {type(exc).__name__}: {exc}"

            def _check_status(widget) -> None:
                result = bridge_app.tcp_status_probe(
                    str(peer_host_input.value or "").strip(),
                    _num(peer_port_input.value, 443),
                    timeout_sec=2.0,
                )
                icon = "Connected" if bool(result.get("ok")) else "Failed"
                status_label.text = f"{icon}: {result.get('detail')} (latency={int(result.get('latency_ms', 0))}ms)"

            config_box = toga.Box(style=toga.style.Pack(direction="column", padding=12))
            config_box.add(toga.Label("ObstacleBridge iOS M2.5 - Configuration", style=toga.style.Pack(padding_bottom=8)))
            config_box.add(toga.Label("Profile ID"))
            config_box.add(profile_id_input)
            config_box.add(toga.Label("Display Name", style=toga.style.Pack(padding_top=6)))
            config_box.add(display_name_input)
            config_box.add(toga.Label("Overlay Transport", style=toga.style.Pack(padding_top=6)))
            config_box.add(transport_select)
            config_box.add(toga.Label("Peer Host", style=toga.style.Pack(padding_top=6)))
            config_box.add(peer_host_input)
            config_box.add(toga.Label("Peer Port", style=toga.style.Pack(padding_top=6)))
            config_box.add(peer_port_input)
            config_box.add(toga.Label("Localhost TCP Port", style=toga.style.Pack(padding_top=6)))
            config_box.add(local_tcp_input)
            config_box.add(toga.Label("Localhost UDP Port", style=toga.style.Pack(padding_top=6)))
            config_box.add(local_udp_input)
            config_box.add(toga.Label("Target Host", style=toga.style.Pack(padding_top=6)))
            config_box.add(target_host_input)
            config_box.add(toga.Label("Target TCP Port", style=toga.style.Pack(padding_top=6)))
            config_box.add(target_tcp_input)
            config_box.add(toga.Label("Target UDP Port", style=toga.style.Pack(padding_top=6)))
            config_box.add(target_udp_input)
            config_box.add(toga.Button("Save M2.5 Profile", on_press=_save_config, style=toga.style.Pack(padding_top=8)))
            config_box.add(cfg_status)
            config_box.add(
                toga.Label(
                    "Note: system-wide Safari/app traffic interception requires M3 packet tunnel work.",
                    style=toga.style.Pack(padding_top=8),
                )
            )

            status_box = toga.Box(style=toga.style.Pack(direction="column", padding=12))
            status_box.add(toga.Label("Connection Status", style=toga.style.Pack(padding_bottom=8)))
            status_box.add(
                toga.Label(
                    f"Shared runtime loaded: {bridge_app.client.__class__.__name__}",
                    style=toga.style.Pack(padding_bottom=6),
                )
            )
            status_box.add(toga.Button("Check TCP Reachability", on_press=_check_status))
            status_box.add(status_label)

            tabs = toga.OptionContainer(style=toga.style.Pack(flex=1))
            tabs.content.append("Configuration", config_box)
            tabs.content.append("Status", status_box)

            window = toga.MainWindow(title=self.formal_name)
            window.content = tabs
            window.show()

    return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
