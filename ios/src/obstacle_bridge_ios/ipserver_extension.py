"""Python bridge entrypoints for the iOS IPServer extension target."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .app import ObstacleBridgeIOSApp, _write_startup_artifacts

_CONTROLLER: ObstacleBridgeIOSApp | None = None


def _controller() -> ObstacleBridgeIOSApp:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = ObstacleBridgeIOSApp()
    return _CONTROLLER


def _decode_message(message: Any) -> dict[str, Any]:
    if message is None:
        return {}
    if isinstance(message, Mapping):
        return dict(message)
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    if isinstance(message, str):
        text = message.strip()
        if not text:
            return {}
        payload = json.loads(text)
        if not isinstance(payload, Mapping):
            raise ValueError("message JSON must decode to an object")
        return dict(payload)
    raise TypeError(f"unsupported message type: {type(message)!r}")


def handle_message(message: Any = None) -> dict[str, Any]:
    payload = _decode_message(message)
    command = str(payload.get("command") or "snapshot").strip() or "snapshot"
    controller = _controller()

    try:
        if command in {"start_embedded_webadmin", "start_webadmin", "start"}:
            result = controller.start_embedded_webadmin()
        elif command == "connect_profile":
            result = controller.connect_profile(
                profile=payload.get("profile"),
                profile_id=payload.get("profile_id"),
            )
        elif command in {"disconnect_profile", "stop"}:
            result = controller.disconnect_profile()
        elif command in {"snapshot", "status"}:
            result = controller.connection_snapshot()
        elif command == "write_startup_artifacts":
            root = _write_startup_artifacts()
            result = {"documents_root": str(root)}
        else:
            raise ValueError(f"unsupported command: {command}")
        return {"ok": True, "command": command, "result": result}
    except Exception as exc:
        return {
            "ok": False,
            "command": command,
            "error_type": exc.__class__.__name__,
            "error": str(exc),
        }


def handle_message_json(message: Any = None) -> str:
    return json.dumps(handle_message(message), sort_keys=True)
