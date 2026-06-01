"""Python-side stand-in for the iOS packet-tunnel extension used in E2E tests.

It runs the shared ObstacleBridge runtime on a background asyncio loop so the
integration suite can exercise the extension-style config/runtime contract
without a physical device.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from typing import Any

from obstacle_bridge.core import ObstacleBridgeClient

from . import ipserver_runtime

_CONTROLLER: "_RuntimeController | None" = None


def _runtime_config_from_provider_configuration(provider_configuration: dict[str, Any]) -> dict[str, Any]:
    runtime_config = dict(provider_configuration.get("runtime_config") or {})
    network = dict(provider_configuration.get("network_settings") or {})
    if network:
        routing = dict(runtime_config.get("TUN_routing") or {})
        if network.get("tunnel_address") is not None:
            routing["tunnel_address"] = network.get("tunnel_address")
        if network.get("tunnel_prefix") is not None:
            routing["tunnel_prefix"] = network.get("tunnel_prefix")
        if network.get("included_routes") is not None:
            routing["included_routes"] = list(network.get("included_routes") or [])
        if network.get("excluded_routes") is not None:
            routing["excluded_routes"] = list(network.get("excluded_routes") or [])
        if network.get("tunnel_address6") is not None:
            routing["tunnel_address6"] = network.get("tunnel_address6")
        if network.get("tunnel_prefix6") is not None:
            routing["tunnel_prefix6"] = network.get("tunnel_prefix6")
        if network.get("included_routes6") is not None:
            routing["included_routes6"] = list(network.get("included_routes6") or [])
        if network.get("excluded_routes6") is not None:
            routing["excluded_routes6"] = list(network.get("excluded_routes6") or [])
        if network.get("dns_servers") is not None:
            routing["dns_servers"] = list(network.get("dns_servers") or [])
        if network.get("mtu") is not None:
            routing["mtu"] = network.get("mtu")
        runtime_config["TUN_routing"] = routing
    return runtime_config


def _publish_packetflow_env(runtime_config: dict[str, Any]) -> None:
    import os

    section = dict(runtime_config.get("iOS_TUN_connector") or {})
    if section.get("packetflow_connector") is not None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR"] = str(section.get("packetflow_connector") or "")
    if section.get("bind_host") is not None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_BIND_HOST"] = str(section.get("bind_host") or "")
    if section.get("bind_port") is not None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_BIND_PORT"] = str(int(section.get("bind_port") or 0))
    if section.get("peer_host") is not None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST"] = str(section.get("peer_host") or "")
    if section.get("peer_port") is not None:
        os.environ["OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT"] = str(int(section.get("peer_port") or 0))


class _RuntimeController:
    def __init__(self, runtime_config: dict[str, Any]) -> None:
        self.runtime_config = runtime_config
        self.client = ObstacleBridgeClient(runtime_config)
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        loop.run_forever()
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._thread_main, name="ipserver-extension-e2e", daemon=True)
            self._thread.start()
            self._ready.wait(timeout=5.0)
        fut = self._submit(self.client.start())
        fut.result(timeout=20.0)

    def stop(self) -> None:
        if self._loop is None:
            return
        try:
            self._submit(self.client.stop()).result(timeout=10.0)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5.0)
            self._thread = None
            self._loop = None
            self._ready.clear()

    def snapshot(self) -> dict[str, Any]:
        return dict(self.client.snapshot() or {})

    def _submit(self, coro: Any) -> Future[Any]:
        if self._loop is None:
            raise RuntimeError("controller loop not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)


def handle_message(message: dict[str, Any]) -> dict[str, Any]:
    global _CONTROLLER
    command = str(message.get("command") or "").strip()

    if command == "start_embedded_webadmin":
        provider_configuration = dict(message.get("provider_configuration") or {})
        runtime_config = _runtime_config_from_provider_configuration(provider_configuration)
        ipserver_runtime.LAST_PROVIDER_CONFIGURATION = provider_configuration
        _publish_packetflow_env(runtime_config)
        if _CONTROLLER is not None:
            _CONTROLLER.stop()
        _CONTROLLER = _RuntimeController(runtime_config)
        _CONTROLLER.start()
        return {"ok": True, "result": _CONTROLLER.snapshot()}

    if command == "snapshot":
        return {"ok": True, "result": {} if _CONTROLLER is None else _CONTROLLER.snapshot()}

    if command == "disconnect_profile":
        if _CONTROLLER is not None:
            _CONTROLLER.stop()
            _CONTROLLER = None
        return {"ok": True, "result": {"started": False}}

    return {"ok": False, "error": f"unsupported command: {command}"}

