from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import pathlib
import subprocess
import sys
import time
from typing import Any, Awaitable, Callable, Optional

from . import bridge_tun_macos
from .bridge_tun_routing import TUN_ROUTING_SECTION, TunRoutingSettings


class _HelperLog:
    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _HelperMux:
    log = _HelperLog()


class DarwinTunHelperBackend:
    """macOS helper backend that owns a real Darwin utun descriptor."""

    def __init__(self, *, read_poll_interval_s: float = 0.01) -> None:
        self._packet_sink: Optional[Callable[[bytes], Awaitable[None] | None]] = None
        self._fd: Optional[int] = None
        self._opened = False
        self._ifname = ""
        self._mtu = 0
        self._packets_from_runtime = 0
        self._packets_to_runtime = 0
        self._stopped = False
        self._reader_task: Optional[asyncio.Task] = None
        self._read_poll_interval_s = float(read_poll_interval_s)
        self._network_applied = False
        self._apply_calls = 0
        self._remove_calls = 0
        self._last_apply_payload: dict[str, Any] = {}
        self._last_remove_payload: dict[str, Any] = {}
        self._last_failure: dict[str, Any] = {}
        self._last_hook_argv: list[str] = []
        self._last_hook_env: dict[str, str] = {}
        self._last_hook_action = ""

    def set_packet_sink(self, sink: Callable[[bytes], Awaitable[None] | None]) -> None:
        self._packet_sink = sink
        if self._opened and self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_loop())

    @staticmethod
    def _require_macos_tun_support() -> None:
        if not sys.platform.startswith("darwin"):
            raise RuntimeError("Darwin native TUN helper backend is supported only on macOS")
        bridge_tun_macos.require_tun_support(_HelperMux())

    @staticmethod
    def _repo_root() -> pathlib.Path:
        return pathlib.Path(__file__).resolve().parents[2]

    @classmethod
    def _default_hook_path(cls, *, server_side: bool) -> str:
        script = "server-tun-hook-macos.sh" if server_side else "client-tun-hook-macos.sh"
        return str(cls._repo_root() / "scripts" / script)

    @staticmethod
    def _routing_settings(payload: dict[str, Any]) -> TunRoutingSettings:
        tun_routing = payload.get("tun_routing")
        values = tun_routing if isinstance(tun_routing, dict) else {}
        return TunRoutingSettings.from_mapping({TUN_ROUTING_SECTION: values})

    @staticmethod
    def _service_is_server_side(payload: dict[str, Any]) -> bool:
        catalog = str(payload.get("service_catalog") or "").strip().lower()
        service_key = payload.get("service_key")
        first = ""
        if isinstance(service_key, list) and service_key:
            first = str(service_key[0] or "").strip().lower()
        return catalog == "remote_servers" or first == "peer"

    def _hook_env(self, payload: dict[str, Any], *, server_side: bool) -> dict[str, str]:
        settings = self._routing_settings(payload)
        env = settings.remote_hook_env() if server_side else settings.local_hook_env()
        listener_env = payload.get("listener_hook_env")
        if isinstance(listener_env, dict):
            for key, value in listener_env.items():
                text_key = str(key or "").strip()
                if text_key:
                    env[text_key] = str(value or "")
        env["MTU"] = str(int(payload.get("mtu") or self._mtu or env.get("MTU") or settings.mtu))
        return env

    @staticmethod
    def _run_hook(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        merged_env = dict(os.environ)
        merged_env.update(env)
        merged_env["PATH"] = "/usr/sbin:/sbin:/usr/bin:/bin:" + str(merged_env.get("PATH") or "")
        return subprocess.run(
            argv,
            check=True,
            capture_output=True,
            text=True,
            env=merged_env,
        )

    def _record_failure(self, *, operation: str, stage: str, exc: BaseException) -> None:
        self._last_failure = {
            "operation": str(operation or ""),
            "stage": str(stage or ""),
            "error_type": type(exc).__name__,
            "detail": str(exc),
            "unix_ts": float(time.time()),
        }

    def _clear_last_failure(self) -> None:
        self._last_failure = {}

    async def open_tun(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._opened and self._fd is not None:
            return self.local_snapshot()
        self._require_macos_tun_support()
        requested_ifname = str(payload.get("ifname") or "utun")
        requested_mtu = int(payload.get("mtu") or 1600)
        sock = bridge_tun_macos.socket.socket(
            bridge_tun_macos.PF_SYSTEM,
            bridge_tun_macos.socket.SOCK_DGRAM,
            bridge_tun_macos.SYSPROTO_CONTROL,
        )
        try:
            control_id = bridge_tun_macos._lookup_utun_control_id(sock.fileno())
            bridge_tun_macos._connect_utun(sock.fileno(), control_id)
            actual = bridge_tun_macos._query_utun_ifname(sock, requested_ifname)
            fd = sock.detach()
            os.set_blocking(fd, False)
            bridge_tun_macos._set_iface_mtu_and_up(_HelperMux(), actual, requested_mtu)
            self._fd = fd
            self._opened = True
            self._ifname = actual
            self._mtu = requested_mtu
            self._stopped = False
            if self._packet_sink is not None and self._reader_task is None:
                self._reader_task = asyncio.create_task(self._read_loop())
            return self.local_snapshot()
        except Exception:
            with contextlib.suppress(Exception):
                sock.close()
            raise

    async def write_packet(self, packet: bytes) -> dict[str, Any]:
        if self._fd is None:
            raise RuntimeError("Darwin native TUN helper backend is not opened")
        frame = bridge_tun_macos._family_prefix_for_packet(bytes(packet)) + bytes(packet)
        os.write(self._fd, frame)
        self._packets_from_runtime += 1
        return {"accepted": True, "len": len(packet)}

    async def snapshot(self) -> dict[str, Any]:
        return self.local_snapshot()

    def local_snapshot(self) -> dict[str, Any]:
        return {
            "backend": "darwin-native",
            "opened": self._opened,
            "ifname": self._ifname,
            "mtu": self._mtu,
            "packets_from_runtime": self._packets_from_runtime,
            "packets_to_runtime": self._packets_to_runtime,
            "network_applied": self._network_applied,
            "apply_calls": self._apply_calls,
            "remove_calls": self._remove_calls,
            "last_apply_payload": dict(self._last_apply_payload),
            "last_remove_payload": dict(self._last_remove_payload),
            "last_hook_argv": list(self._last_hook_argv),
            "last_hook_env": dict(self._last_hook_env),
            "last_hook_action": self._last_hook_action,
            "last_failure": dict(self._last_failure),
            "stopped": self._stopped,
        }

    async def apply_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._apply_calls += 1
        self._network_applied = True
        self._last_apply_payload = dict(payload or {})
        self._clear_last_failure()
        ifname = str(self._ifname or payload.get("ifname") or "utun")
        server_side = self._service_is_server_side(payload)
        hook_path = self._default_hook_path(server_side=server_side)
        env = self._hook_env(payload, server_side=server_side)
        argv = [hook_path, "up", ifname]
        try:
            self._run_hook(argv, env)
        except Exception as exc:
            self._network_applied = False
            self._record_failure(operation="apply_network", stage="hook_up", exc=exc)
            raise
        self._last_hook_argv = list(argv)
        self._last_hook_env = dict(env)
        self._last_hook_action = "up"
        snapshot = self.local_snapshot()
        snapshot.update({
            "applied": True,
            "backend": "darwin-native",
            "ifname": ifname,
            "apply_calls": self._apply_calls,
            "hook_argv": list(argv),
            "hook_env": dict(env),
            "last_failure": dict(self._last_failure),
        })
        return snapshot

    async def remove_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._remove_calls += 1
        self._network_applied = False
        self._last_remove_payload = dict(payload or {})
        self._clear_last_failure()
        ifname = str(self._ifname or payload.get("ifname") or "utun")
        server_side = self._service_is_server_side(payload)
        hook_path = self._default_hook_path(server_side=server_side)
        env = self._hook_env(payload, server_side=server_side)
        argv = [hook_path, "down", ifname]
        try:
            self._run_hook(argv, env)
        except Exception as exc:
            self._record_failure(operation="remove_network", stage="hook_down", exc=exc)
            raise
        self._last_hook_argv = list(argv)
        self._last_hook_env = dict(env)
        self._last_hook_action = "down"
        snapshot = self.local_snapshot()
        snapshot.update({
            "removed": True,
            "backend": "darwin-native",
            "ifname": ifname,
            "remove_calls": self._remove_calls,
            "hook_argv": list(argv),
            "hook_env": dict(env),
            "last_failure": dict(self._last_failure),
        })
        return snapshot

    async def stop(self) -> None:
        self._stopped = True
        if self._network_applied and self._ifname:
            with contextlib.suppress(Exception):
                await self.remove_network(self._last_apply_payload or {"ifname": self._ifname})
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
            self._reader_task = None
        if self._fd is not None:
            with contextlib.suppress(Exception):
                os.close(self._fd)
            self._fd = None
        self._opened = False

    async def _read_loop(self) -> None:
        while True:
            fd = self._fd
            if fd is None:
                return
            try:
                frame = os.read(fd, max(72, int(self._mtu or 1600) + 4))
                if frame:
                    packet = bridge_tun_macos._packet_from_utun_frame(bytes(frame))
                    if packet:
                        self._packets_to_runtime += 1
                        if self._packet_sink is not None:
                            result = self._packet_sink(bytes(packet))
                            if inspect.isawaitable(result):
                                await result
                    continue
            except BlockingIOError:
                pass
            except OSError as exc:
                if getattr(exc, "errno", None) not in (11,):
                    raise
            await asyncio.sleep(self._read_poll_interval_s)
