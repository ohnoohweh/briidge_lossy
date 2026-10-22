"""Private process ownership for the Python explicit proxy provider.

The connected inherited socket is the capability; credentials travel only in
its bounded startup frame, never in the command line or environment.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import ipaddress
import json
import logging
import os
import shutil
import socket
import struct
import sys
from typing import Any

from .bridge_proxy_server import ObstacleBridgeProxyServer, ObstacleBridgeProxyServerConfig, ProxyCredentials

MAX_FRAME = 64 * 1024
_PROTOCOLS = {"http", "http-connect", "socks5", "socks5-connect"}
_AUTH_MODES = {"none", "basic", "token", "password"}


class ProxyWorkerStartupError(ValueError):
    """A credential-free startup outcome exposed by the local supervisor."""

    def __init__(self, code: str) -> None:
        super().__init__(f"proxy worker startup failed: {code}")
        self.code = code


def resolve_native_proxy_worker_executable(explicit: str | None = None) -> str:
    """Return the one native worker executable selected for a desktop owner.

    An explicit configuration wins.  A packaged launcher can then supply its
    adjacent worker through the deployment override without depending on a
    mutable process ``PATH``.  The final ``PATH`` lookup preserves the
    development invocation.  Every result is validated before the private
    control socket is created, so a bad package cannot trigger an in-process
    fallback.
    """
    executable = explicit or os.environ.get("OBSTACLEBRIDGE_NATIVE_PROXY_WORKER") or shutil.which("ObstacleBridgeProxyWorker")
    if not executable or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise ValueError("native proxy worker executable is unavailable")
    return executable


def worker_capabilities(implementation: str) -> dict[str, Any]:
    """Redacted, versioned declaration of the selected worker surface."""
    if implementation == "native":
        bind_families, egress_modes = ["ipv4", "ipv6"], ["direct", "system"]
    else:
        bind_families, egress_modes = ["ipv4", "ipv6"], ["direct", "system"]
    return {
        "contract_version": 1,
        "bind_families": bind_families,
        "protocols": ["http-connect", "socks5-connect"],
        "auth_modes": ["none", "basic", "token", "password"],
        "egress_modes": egress_modes,
        "destination_policy": {"enforced": True, "requires_unrestricted": False},
    }


def validate_worker_policy(config: dict[str, Any]) -> None:
    """Accept only the policy shape both selected workers enforce."""
    policy = config.get("policy")
    if (not isinstance(policy, dict) or set(policy) != {"allow_private_destinations", "blocked_host_patterns"}
            or not isinstance(policy.get("allow_private_destinations"), bool)
            or not isinstance(policy.get("blocked_host_patterns"), list)
            or any(not isinstance(pattern, str) or not pattern.strip() for pattern in policy["blocked_host_patterns"])):
        raise ValueError("proxy worker destination policy is invalid")


def validate_worker_config(config: dict[str, Any], implementation: str) -> None:
    """Reject unsupported startup values before they can be silently ignored.

    This is the contract-v1 configuration corpus boundary.  The native
    implementation intentionally has a narrower selectable surface; its
    capability declaration advertises that difference.
    """
    if implementation not in {"python", "native"} or not isinstance(config, dict):
        raise ValueError("invalid proxy worker configuration")
    validate_worker_policy(config)
    protocols = config.get("protocols")
    if not isinstance(protocols, list) or not protocols or not all(isinstance(item, str) for item in protocols):
        raise ValueError("proxy worker protocols must be a non-empty list")
    if not set(protocols).issubset(_PROTOCOLS):
        raise ValueError("proxy worker protocol is unsupported")
    for key in ("http_port", "socks5_port"):
        value = config.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
            raise ValueError("proxy worker listener port is invalid")
    bind = config.get("bind")
    try:
        bind_address = ipaddress.ip_address(bind)
    except (TypeError, ValueError):
        raise ValueError("proxy worker bind host is invalid") from None
    if not bind_address.is_loopback or bind_address.version not in {4, 6}:
        raise ValueError("proxy worker bind family is unsupported")
    egress = config.get("egress")
    if (not isinstance(egress, dict) or not set(egress).issubset({"mode", "address_families"})
            or not isinstance(egress.get("mode"), str)):
        raise ValueError("proxy worker egress configuration is invalid")
    if "address_families" in egress and (not isinstance(egress["address_families"], list)
                                         or not all(isinstance(item, str) for item in egress["address_families"])
                                         or sorted(egress["address_families"]) != ["ipv4", "ipv6"]):
        raise ValueError("proxy worker egress address families are invalid")
    mode = egress["mode"].lower()
    if mode not in {"direct", "system"}:
        raise ValueError("proxy worker egress mode is unsupported")
    auth = config.get("auth")
    if not isinstance(auth, dict) or not set(auth).issubset({"mode", "username", "token", "password"}):
        raise ValueError("proxy worker authentication configuration is invalid")
    auth_mode = auth.get("mode", "none")
    if not isinstance(auth_mode, str) or auth_mode.lower() not in _AUTH_MODES:
        raise ValueError("proxy worker authentication mode is unsupported")
    if auth_mode.lower() == "none":
        if any(value not in (None, "") for key, value in auth.items() if key != "mode"):
            raise ValueError("proxy worker credentials require an authentication mode")
        return
    username, token, password = auth.get("username"), auth.get("token"), auth.get("password")
    if not isinstance(username, str) or not username.strip() or (token is not None and not isinstance(token, str)) or (password is not None and not isinstance(password, str)):
        raise ValueError("proxy worker credentials are invalid")
    if not ((token or "").strip() or (password or "").strip()):
        raise ValueError("proxy worker credentials are incomplete")


async def _read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if size == 0 or size > MAX_FRAME:
        raise ValueError("invalid proxy worker frame size")
    message = json.loads((await reader.readexactly(size)).decode("utf-8"))
    if not isinstance(message, dict) or message.get("v") != 1:
        raise ValueError("invalid proxy worker frame")
    return message


async def _write_frame(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not encoded or len(encoded) > MAX_FRAME:
        raise ValueError("invalid proxy worker frame size")
    writer.write(struct.pack("!I", len(encoded)) + encoded)
    await asyncio.wait_for(writer.drain(), timeout=1.0)


def _snapshot(servers: dict[str, ObstacleBridgeProxyServer]) -> dict[str, Any]:
    result = {}
    for name, server in servers.items():
        entry = server.snapshot()
        sockets = server._server.sockets if server._server else []
        entry["bound_port"] = sockets[0].getsockname()[1] if sockets else 0
        result[name] = entry
    return result


async def _serve(data_fd: int, log_fd: int | None = None) -> None:
    data = socket.socket(fileno=data_fd)
    if data.family != socket.AF_UNIX or data.type != socket.SOCK_STREAM:
        data.close()
        raise ValueError("invalid proxy worker control socket")
    data.setblocking(False)
    reader, writer = await asyncio.open_connection(sock=data)
    servers: dict[str, ObstacleBridgeProxyServer] = {}
    command = None
    log_socket = None
    try:
        init = await asyncio.wait_for(_read_frame(reader), timeout=5.0)
        generation = init.get("generation")
        if (init.get("kind") != "proxy.start" or not isinstance(init.get("config"), dict)
                or isinstance(generation, bool) or not isinstance(generation, int) or generation < 1):
            raise ValueError("invalid proxy worker start")
        if log_fd is not None:
            from .bridge_logging_worker import install_child_log_handler
            log_socket = install_child_log_handler(log_fd, int(init.get("log_root_level", logging.WARNING)),
                                                   init.get("log_levels", {}))
        cfg = init["config"]
        validate_worker_config(cfg, "python")
        protocols = set(cfg.get("protocols") or [])
        specs = []
        if {"http", "http-connect"} & protocols:
            specs.append(("http", int(cfg["http_port"]), True, False))
        if {"socks5", "socks5-connect"} & protocols:
            specs.append(("socks5", int(cfg["socks5_port"]), False, True))
        if not specs:
            raise ValueError("no supported proxy protocols")
        auth = cfg.get("auth") or {}
        mode = str(auth.get("mode") or "none").strip().lower()
        credentials = None
        if mode not in {"", "none", "off", "disabled"}:
            username = str(auth.get("username") or "").strip()
            password = str(auth.get("token") or auth.get("password") or "").strip()
            if not username or not password:
                raise ValueError("incomplete proxy credentials")
            credentials = ProxyCredentials(username, password)
        for name, port, http, socks in specs:
            server = ObstacleBridgeProxyServer(ObstacleBridgeProxyServerConfig(
                bind_host=str(cfg["bind"]), port=port, credentials=credentials,
                allow_http=http, allow_socks5=socks, egress=cfg.get("egress"),
                policy=cfg.get("policy"),
            ))
            await server.start()
            servers[name] = server
        await _write_frame(writer, {"v": 1, "kind": "proxy.ready", "implementation": "python", "generation": generation,
                                    "capabilities": worker_capabilities("python"), "listeners": _snapshot(servers)})
        command = asyncio.create_task(_read_frame(reader))
        while True:
            done, _ = await asyncio.wait({command}, timeout=0.25)
            if done:
                request = command.result()
                if request.get("kind") != "proxy.stop":
                    raise ValueError("invalid proxy worker command")
                break
            await _write_frame(writer, {"v": 1, "kind": "proxy.snapshot", "generation": generation,
                                        "listeners": _snapshot(servers)})
    except (ValueError, KeyError, TypeError):
        # This is deliberately a stable, redacted startup outcome.  Detailed
        # configuration values can contain credentials and never cross back.
        with contextlib.suppress(Exception):
            await _write_frame(writer, {"v": 1, "kind": "proxy.error", "code": "invalid_configuration"})
    except OSError:
        with contextlib.suppress(Exception):
            await _write_frame(writer, {"v": 1, "kind": "proxy.error", "code": "startup_failed"})
    except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
        pass  # Owner loss revokes the worker's capability.
    finally:
        if command is not None:
            if not command.done():
                command.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await command
        for server in servers.values():
            with contextlib.suppress(Exception):
                await server.stop()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        if log_socket is not None:
            log_socket.close()


class ProxyWorker:
    """Async supervisor for one independently owned proxy process."""

    def __init__(self, implementation: str = "python", native_executable: str | None = None, *, supervised: bool = False) -> None:
        if implementation not in {"python", "native"}:
            raise ValueError("unsupported proxy worker implementation")
        self.implementation = implementation
        self.native_executable = native_executable
        self.process = None
        self.writer = None
        self._reader_task = None
        self.listeners: dict[str, Any] = {}
        self.last_error = ""
        self._stopping = False
        self._log_relay = None
        self._supervised = supervised
        self._monitor = None
        self._restart_config = None
        self.generation = 0
        self.restarts = 0
        self.failed_starts = 0
        self.capabilities: dict[str, Any] = {}

    async def start(self, config: dict[str, Any]) -> None:
        if self.process is not None or self._monitor is not None:
            raise RuntimeError("proxy worker already started")
        self._stopping = False
        self._restart_config = copy.deepcopy(config)
        try:
            await self._start_child(self._restart_config)
        except BaseException:
            self._restart_config = None
            raise
        if self._supervised:
            self._monitor = asyncio.create_task(self._supervise(), name="proxy-worker-supervisor")

    async def _start_child(self, config: dict[str, Any]) -> None:
        if os.name != "posix":
            raise RuntimeError("proxy workers require Unix socket pairs")
        try:
            validate_worker_config(config, self.implementation)
        except ValueError as exc:
            raise ProxyWorkerStartupError("invalid_configuration") from exc
        if self.implementation == "native":
            executable = resolve_native_proxy_worker_executable(self.native_executable)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            command = ([sys.executable, "-m", "obstacle_bridge.bridge_proxy_worker"] if self.implementation == "python" else [executable])
            inherited = [child.fileno()]
            from .bridge_logging_worker import open_child_log_relay
            self._log_relay = open_child_log_relay()
            if self._log_relay is not None:
                log_fd = self._log_relay.sender.fileno()
                command.extend(["--log-fd", str(log_fd)])
                inherited.append(log_fd)
            self.process = await asyncio.create_subprocess_exec(
                *command, "--control-fd", str(child.fileno()),
                stdin=asyncio.subprocess.DEVNULL, pass_fds=tuple(inherited),
            )
            child.close()
            if self._log_relay is not None:
                self._log_relay.sender.close()
            parent.setblocking(False)
            reader, self.writer = await asyncio.open_connection(sock=parent)
            expected_generation = self.generation + 1
            await _write_frame(self.writer, {"v": 1, "kind": "proxy.start", "generation": expected_generation, "config": config,
                                             "log_root_level": logging.getLogger().level,
                                             "log_levels": {"proxy_provider": logging.getLogger("proxy_provider").level}})
            response = await asyncio.wait_for(_read_frame(reader), timeout=5.0)
            if response.get("kind") == "proxy.error" and response.get("code") in {"invalid_configuration", "startup_failed"}:
                raise ProxyWorkerStartupError(response["code"])
            if (response.get("kind") != "proxy.ready" or response.get("implementation") != self.implementation
                    or response.get("generation") != expected_generation
                    or not isinstance(response.get("capabilities"), dict) or not isinstance(response.get("listeners"), dict)):
                raise ValueError("invalid proxy worker readiness")
            self.listeners = response["listeners"]
            self.capabilities = response["capabilities"]
            self.generation = expected_generation
            self._reader_task = asyncio.create_task(self._receive(reader, expected_generation))
            for name in ("http", "socks5"):
                key = f"{name}_port"
                if int(config.get(key) or 0) == 0 and name in self.listeners:
                    port = int(self.listeners[name].get("bound_port") or 0)
                    if port > 0:
                        config[key] = port
            self.last_error = ""
        except BaseException:
            parent.close()
            child.close()
            await self._stop_child()
            raise

    async def _supervise(self) -> None:
        while not self._stopping:
            waiter = asyncio.create_task(self.process.wait())
            try:
                await asyncio.wait((waiter, self._reader_task), return_when=asyncio.FIRST_COMPLETED)
            finally:
                if not waiter.done():
                    waiter.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await waiter
            if self._stopping:
                return
            self.listeners = {}
            self.last_error = "unavailable"
            await self._stop_child()
            delay = 0.25
            while not self._stopping:
                await asyncio.sleep(delay)
                try:
                    await self._start_child(self._restart_config)
                except ProxyWorkerStartupError as exc:
                    self.failed_starts += 1
                    self.last_error = exc.code
                    delay = min(delay * 2, 5.0)
                except Exception:
                    self.failed_starts += 1
                    self.last_error = "startup_failed"
                    delay = min(delay * 2, 5.0)
                else:
                    self.restarts += 1
                    break

    async def _receive(self, reader: asyncio.StreamReader, expected_generation: int) -> None:
        try:
            while True:
                event = await _read_frame(reader)
                if (event.get("kind") != "proxy.snapshot" or event.get("generation") != expected_generation
                        or not isinstance(event.get("listeners"), dict)):
                    raise ValueError("invalid proxy worker snapshot")
                if self.generation == expected_generation:
                    self.listeners = event["listeners"]
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError, UnicodeError, json.JSONDecodeError):
            if not self._stopping and self.generation == expected_generation:
                self.listeners = {}
                self.last_error = "unavailable"

    async def stop(self) -> None:
        self._stopping = True
        if self._monitor is not None:
            self._monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor
            self._monitor = None
        await self._stop_child()
        self._restart_config = None

    async def _stop_child(self) -> None:
        if self.writer is not None:
            with contextlib.suppress(Exception):
                await _write_frame(self.writer, {"v": 1, "kind": "proxy.stop"})
            self.writer.close()
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()
            self.writer = None
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
            self._reader_task = None
        if self.process is not None:
            try:
                await asyncio.wait_for(self.process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self.process.kill()
                await self.process.wait()
        if self._log_relay is not None:
            await asyncio.to_thread(self._log_relay.close)
            self._log_relay = None
        self.listeners = {}
        self.capabilities = {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--log-fd", type=int)
    args = parser.parse_args()
    try:
        asyncio.run(_serve(args.control_fd, args.log_fd))
    except Exception:
        # Never log the startup frame, which can contain credentials.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
