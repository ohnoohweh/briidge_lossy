"""Packet Tunnel extension-hosted ObstacleBridge runtime.

This module is imported by the native Network Extension process. It starts the
same Python runtime stack used by the app facade, but with configuration passed
through NETunnelProviderProtocol.providerConfiguration.
"""

from __future__ import annotations

import asyncio
import json
import threading
import traceback
from pathlib import Path
from typing import Any

from obstacle_bridge.core import ObstacleBridgeClient


_lock = threading.RLock()
_loop: asyncio.AbstractEventLoop | None = None
_thread: threading.Thread | None = None
_client: ObstacleBridgeClient | None = None
_status: dict[str, Any] = {"started": False, "source": "packet-tunnel-extension-python"}


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _loop, _thread
    with _lock:
        if _loop is not None and _thread is not None and _thread.is_alive():
            return _loop
        ready = threading.Event()

        def run() -> None:
            global _loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            _loop = loop
            ready.set()
            loop.run_forever()

        _thread = threading.Thread(target=run, name="ObstacleBridgeExtensionRuntime", daemon=True)
        _thread.start()
        ready.wait(timeout=10.0)
        if _loop is None:
            raise RuntimeError("extension runtime event loop did not start")
        return _loop


def _run_sync(coro: Any) -> Any:
    loop = _ensure_loop()
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=30.0)


def _extension_root(parent_bundle_path: str) -> Path:
    root = Path(parent_bundle_path).resolve().parent / "Documents" / "ObstacleBridgeExtension"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except Exception:
        root = Path("/tmp") / "ObstacleBridgeExtension"
        root.mkdir(parents=True, exist_ok=True)
    return root


def _runtime_config(provider_configuration: dict[str, Any], parent_bundle_path: str) -> dict[str, Any]:
    root = _extension_root(parent_bundle_path)
    config = dict(provider_configuration.get("obstacle_bridge_config") or {})
    config.setdefault("admin_web", True)
    config.setdefault("admin_web_bind", "127.0.0.1")
    config.setdefault("admin_web_port", 18080)
    config.setdefault("admin_web_path", "/")
    config.setdefault("admin_web_dir", str(Path(parent_bundle_path) / "app" / "obstacle_bridge" / "admin_web"))
    config.setdefault("ws_static_dir", str(Path(parent_bundle_path) / "app" / "web"))
    config.setdefault("log", "DEBUG")
    config.setdefault("file_level", "DEBUG")
    config.setdefault("console_level", "INFO")
    config.setdefault("log_file", str(root / "obstaclebridge-extension.log"))
    config.setdefault("log_file_max_bytes", 1_048_576)
    config.setdefault("log_file_backup_count", 5)
    config["_ios_extension_provider_configuration"] = provider_configuration
    config["_ios_extension_root"] = str(root)
    return config


def start(provider_configuration_json: str, parent_bundle_path: str) -> str:
    """Start the extension-hosted Python runtime and return JSON status."""

    global _client, _status
    try:
        provider_configuration = json.loads(provider_configuration_json or "{}")
        config = _runtime_config(provider_configuration, parent_bundle_path)
        with _lock:
            if _client is None:
                _client = ObstacleBridgeClient(config=config, apply_logging=True)
                _run_sync(_client.start())
            _status = {
                "started": True,
                "source": "packet-tunnel-extension-python",
                "runtime_owner": "packet-tunnel-extension",
                "runtime_layers": list((provider_configuration.get("runtime") or {}).get("layers") or []),
                "webadmin_url": f"http://{config.get('admin_web_bind', '127.0.0.1')}:{config.get('admin_web_port', 18080)}/"
                if config.get("admin_web")
                else None,
                "config": {
                    "admin_web": bool(config.get("admin_web")),
                    "admin_web_bind": config.get("admin_web_bind"),
                    "admin_web_port": config.get("admin_web_port"),
                    "overlay_transport": config.get("overlay_transport"),
                    "secure_link_mode": config.get("secure_link_mode"),
                    "compress_layer": config.get("compress_layer"),
                },
            }
        return json.dumps(_status, sort_keys=True)
    except Exception as exc:
        _status = {
            "started": False,
            "source": "packet-tunnel-extension-python",
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }
        return json.dumps(_status, sort_keys=True)


def stop() -> str:
    """Stop the extension-hosted Python runtime and return JSON status."""

    global _client, _status
    with _lock:
        client = _client
        _client = None
    if client is not None:
        try:
            _run_sync(client.stop())
        except Exception as exc:
            _status = {
                "started": False,
                "source": "packet-tunnel-extension-python",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
            return json.dumps(_status, sort_keys=True)
    _status = {"started": False, "source": "packet-tunnel-extension-python"}
    return json.dumps(_status, sort_keys=True)


def status() -> str:
    """Return JSON status for native handleAppMessage/WebAdmin callers."""

    with _lock:
        client = _client
    if client is None:
        return json.dumps(_status, sort_keys=True)
    try:
        snap = client.snapshot()
        payload = {
            "started": bool(snap.get("started")),
            "source": "packet-tunnel-extension-python",
            "runtime_owner": "packet-tunnel-extension",
            "status": snap.get("status"),
            "connections": snap.get("connections"),
            "config": snap.get("config"),
        }
        return json.dumps(payload, sort_keys=True)
    except Exception:
        return json.dumps(_status, sort_keys=True)
