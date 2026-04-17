"""BeeWare app entrypoint for the iOS M1 prototype."""

from __future__ import annotations

import os
from pathlib import Path

from obstacle_bridge.core import ObstacleBridgeClient

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


def main():
    if toga is None:
        raise RuntimeError("Toga is required to run the iOS app UI")
    _configure_ios_safe_locale()

    class _TogaObstacleBridgeApp(toga.App):
        def startup(self):
            bridge_app = ObstacleBridgeIOSApp()
            box = toga.Box(style=toga.style.Pack(direction="column", padding=16))
            box.add(toga.Label("ObstacleBridge iOS prototype (M1)", style=toga.style.Pack(padding_bottom=8)))
            box.add(
                toga.Label(
                    f"Shared runtime loaded: {bridge_app.client.__class__.__name__}",
                    style=toga.style.Pack(padding_bottom=4),
                )
            )
            box.add(toga.Label("Import preview and profile storage scaffolding is ready."))
            window = toga.MainWindow(title=self.formal_name)
            window.content = box
            window.show()

    return _TogaObstacleBridgeApp("ObstacleBridge", "com.obstaclebridge")
