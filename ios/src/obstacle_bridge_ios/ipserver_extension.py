"""Python bridge entrypoints for the iOS IPServer extension target."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .app import ObstacleBridgeIOSApp, _write_startup_artifacts
from .diagnostics import install_crash_hooks, log_event, log_provider_event

_CONTROLLER: ObstacleBridgeIOSApp | None = None


def _controller() -> ObstacleBridgeIOSApp:
    global _CONTROLLER
    if _CONTROLLER is None:
        root = _write_startup_artifacts()
        install_crash_hooks(root)
        log_event(root, "ipserver_extension.controller_init")
        log_provider_event(root, "python_controller_init")
        _CONTROLLER = ObstacleBridgeIOSApp(owns_runtime=True)
        log_provider_event(root, "python_controller_ready", owns_runtime=True)
    return _CONTROLLER


def _runtime_config_from_provider_configuration(provider_configuration: Any) -> dict[str, Any] | None:
    if not isinstance(provider_configuration, Mapping):
        return None
    runtime_config = provider_configuration.get("runtime_config")
    if isinstance(runtime_config, Mapping):
        return dict(runtime_config)
    obstacle_bridge = provider_configuration.get("obstacle_bridge")
    if isinstance(obstacle_bridge, Mapping):
        return dict(obstacle_bridge)
    return None


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
    root = _write_startup_artifacts()
    log_provider_event(root, "python_handle_message_entered", command=command)

    try:
        if command in {"start_embedded_webadmin", "start_webadmin", "start"}:
            runtime_config = _runtime_config_from_provider_configuration(payload.get("provider_configuration"))
            log_provider_event(
                root,
                "python_start_embedded_webadmin_requested",
                command=command,
                runtime_config_keys=sorted(runtime_config.keys()) if isinstance(runtime_config, Mapping) else [],
            )
            result = controller.start_embedded_webadmin(
                runtime_config
            )
        elif command == "connect_profile":
            result = controller.connect_profile(
                profile=payload.get("profile"),
                profile_id=payload.get("profile_id"),
            )
        elif command in {"disconnect_profile", "stop"}:
            result = controller.disconnect_profile()
        elif command in {"snapshot", "status"}:
            result = controller.connection_snapshot()
        elif command in {"diagnostics", "diagnostics_snapshot"}:
            result = controller.diagnostics_snapshot()
        elif command == "diagnostic_event":
            root = _write_startup_artifacts()
            event = str(payload.get("event") or "ipserver_extension.native_event")
            fields = payload.get("fields")
            log_event(root, event, **(dict(fields) if isinstance(fields, Mapping) else {}))
            result = {"logged": True}
        elif command == "write_startup_artifacts":
            root = _write_startup_artifacts()
            result = {"documents_root": str(root)}
        else:
            raise ValueError(f"unsupported command: {command}")
        log_provider_event(
            root,
            "python_handle_message_completed",
            command=command,
            result_keys=sorted(result.keys()) if isinstance(result, Mapping) else [],
        )
        return {"ok": True, "command": command, "result": result}
    except Exception as exc:
        log_provider_event(
            root,
            "python_handle_message_failed",
            command=command,
            error_type=exc.__class__.__name__,
            error=str(exc),
        )
        return {
            "ok": False,
            "command": command,
            "error_type": exc.__class__.__name__,
            "error": str(exc),
        }


def handle_message_json(message: Any = None) -> str:
    return json.dumps(handle_message(message), sort_keys=True)
