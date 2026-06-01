"""Rubicon bridge for starting the iOS IPServer Network Extension."""

from __future__ import annotations

import json
from typing import Any

_LAST_ERROR = ""


def _load_bridge() -> Any:
    global _LAST_ERROR
    try:
        from rubicon.objc import ObjCClass
    except Exception as exc:
        _LAST_ERROR = f"rubicon import failed: {type(exc).__name__}: {exc}"
        return None
    try:
        bridge = ObjCClass("ObstacleBridgeTunnelControl")
    except Exception as exc:
        _LAST_ERROR = f"Objective-C class lookup failed: {type(exc).__name__}: {exc}"
        return None
    _LAST_ERROR = ""
    return bridge


def _decode_response(value: Any) -> dict[str, Any]:
    try:
        text = str(value)
        payload = json.loads(text)
    except Exception as exc:
        return {"ok": False, "error": f"invalid native tunnel-control response: {type(exc).__name__}: {exc}"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "native tunnel-control response was not an object"}
    return payload


def start_ipserver_tunnel() -> dict[str, Any]:
    bridge = _load_bridge()
    if bridge is None:
        return {"ok": False, "error": _LAST_ERROR}
    try:
        return _decode_response(bridge.startIPServerTunnel())
    except Exception as exc:
        return {"ok": False, "error": f"startIPServerTunnel failed: {type(exc).__name__}: {exc}"}


def start_runtime() -> dict[str, Any]:
    return start_ipserver_tunnel()


def prepare_ipserver_tunnel() -> dict[str, Any]:
    bridge = _load_bridge()
    if bridge is None:
        return {"ok": False, "error": _LAST_ERROR}
    try:
        return _decode_response(bridge.prepareIPServerTunnel())
    except Exception as exc:
        return {"ok": False, "error": f"prepareIPServerTunnel failed: {type(exc).__name__}: {exc}"}


def prepare_runtime() -> dict[str, Any]:
    return prepare_ipserver_tunnel()


def harvest_shared_logs() -> dict[str, Any]:
    bridge = _load_bridge()
    if bridge is None:
        return {"ok": False, "error": _LAST_ERROR}
    try:
        return _decode_response(bridge.harvestSharedLogs())
    except Exception as exc:
        return {"ok": False, "error": f"harvestSharedLogs failed: {type(exc).__name__}: {exc}"}


def harvest_runtime_logs() -> dict[str, Any]:
    return harvest_shared_logs()


def ipserver_tunnel_status() -> dict[str, Any]:
    bridge = _load_bridge()
    if bridge is None:
        return {"ok": False, "error": _LAST_ERROR}
    try:
        return _decode_response(bridge.status())
    except Exception as exc:
        return {"ok": False, "error": f"status failed: {type(exc).__name__}: {exc}"}


def runtime_status() -> dict[str, Any]:
    return ipserver_tunnel_status()
