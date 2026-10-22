"""Private process ownership for one outbound desktop peer stack.

The inherited connected Unix stream is the capability. Bootstrap credentials
are never placed on the command line, and every control frame is bounded and
fenced by the peer identity and worker generation.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import shutil
import socket
import struct
import sys
import uuid
from typing import Any

MAX_FRAME = 1024 * 1024


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate peer worker field")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("invalid peer worker number")


async def _read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("invalid peer worker frame size")
    value = json.loads((await reader.readexactly(size)).decode("utf-8"),
                       object_pairs_hook=_json_object, parse_constant=_invalid_constant)
    if not isinstance(value, dict) or type(value.get("v")) is not int or value["v"] != 1:
        raise ValueError("invalid peer worker frame")
    return value


async def _write_frame(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 0 < len(body) <= MAX_FRAME:
        raise ValueError("invalid peer worker frame size")
    writer.write(struct.pack("!I", len(body)) + body)
    await asyncio.wait_for(writer.drain(), 1.0)


def _validate_peer_services(args: Any) -> None:
    from .bridge import ChannelMux

    services = (ChannelMux._parse_own_servers(getattr(args, "own_servers", None))
                + ChannelMux._parse_remote_servers(getattr(args, "remote_servers", None)))
    if any(service.l_proto == "tun" or service.r_proto == "tun" for service in services):
        raise ValueError("peer worker cannot own shared TUN services")


def _peer_args(config: dict[str, Any]):
    # Import the public module first; bridge_runner is intentionally loaded
    # through bridge's compatibility export and cannot be imported first.
    from .bridge import build_runtime_args_from_config
    from .bridge_runner import _has_configured_overlay_peer

    args = build_runtime_args_from_config(config)
    if str(args.overlay_transport).strip().lower() != "tcp" or not _has_configured_overlay_peer(args, transport="tcp"):
        raise ValueError("peer worker requires exactly one outbound TCP peer")
    routing = config.get("TUN_routing") if isinstance(config.get("TUN_routing"), dict) else {}
    tun_requested = routing.get("enabled_on_startup", config.get("enabled_on_startup"))
    if ((tun_requested is not None and tun_requested is not False)
            or str(getattr(args, "tun_execution_mode", "inline")) != "inline"
            or bool(getattr(args, "proxy_provider_enabled", False))
            or bool(getattr(args, "telemetry_enabled", False))
            or bool(getattr(args, "telemetry_collector_enabled", False))):
        raise ValueError("peer worker cannot own shared desktop services")
    _validate_peer_services(args)
    # Admin, shared TUN, proxy and telemetry belong to other owners. The
    # runtime defaults enable Admin, TUN and terminal status, so explicitly
    # disable those defaults in this narrowly scoped peer process.
    args.admin_web = False
    args.admin_web_worker = "off"
    args.peer_stack_worker = "off"
    args._peer_worker_forbid_tun = True
    args.enabled_on_startup = False
    args.status = False
    return args


async def _serve(control_fd: int, log_fd: int | None = None) -> None:
    from .bridge import Runner

    control = socket.socket(fileno=control_fd)
    if control.family != socket.AF_UNIX or control.type != socket.SOCK_STREAM or log_fd == control_fd:
        control.close()
        raise ValueError("invalid peer worker control socket")
    control.getpeername()
    control.setblocking(False)
    reader, writer = await asyncio.open_connection(sock=control)
    runner = None
    log_socket = None
    try:
        start = await asyncio.wait_for(_read_frame(reader), 5.0)
        peer_id, generation, config = start.get("peer_id"), start.get("generation"), start.get("config")
        if (start.get("kind") != "peer.start" or not isinstance(peer_id, str) or not 1 <= len(peer_id) <= 128
                or type(generation) is not int or generation < 1 or not isinstance(config, dict)):
            raise ValueError("invalid peer worker bootstrap")
        args = _peer_args(config)
        if log_fd is not None:
            from .bridge_logging_worker import install_child_log_handler
            log_socket = install_child_log_handler(log_fd, int(start.get("log_root_level", logging.WARNING)),
                                                   start.get("log_levels", {}))
        else:
            logging.basicConfig(level=int(start.get("log_root_level", logging.WARNING)))
            for name, level in start.get("log_levels", {}).items():
                logging.getLogger(name).setLevel(level)
        runner = Runner(args)
        # Watch the capability while starting: owner loss or premature input
        # cancels startup instead of leaving an orphaned stack behind.
        startup = asyncio.create_task(runner.start())
        owner_input = asyncio.create_task(reader.read(1))
        try:
            done, _ = await asyncio.wait({startup, owner_input}, timeout=15.0, return_when=asyncio.FIRST_COMPLETED)
            if startup not in done or owner_input in done:
                raise ConnectionError("peer owner lost during startup")
            startup.result()
        finally:
            for task in (startup, owner_input):
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        identity = {"v": 1, "peer_id": peer_id, "generation": generation}
        await _write_frame(writer, {**identity, "kind": "peer.ready", "implementation": "python"})
        while True:
            request = await _read_frame(reader)
            if (request.get("peer_id") != peer_id or type(request.get("generation")) is not int
                    or request["generation"] != generation):
                raise ValueError("stale peer worker generation")
            request_id = request.get("id")
            if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
                raise ValueError("invalid peer worker request")
            if request.get("kind") == "peer.stop":
                await _write_frame(writer, {**identity, "kind": "peer.stopping", "id": request_id})
                break
            if request.get("kind") == "peer.control":
                operation = request.get("operation")
                target = request.get("target_peer_id")
                if target is not None and (not isinstance(target, str) or len(target) > 128):
                    raise ValueError("invalid peer control target")
                if operation == "reconnect":
                    result = runner.request_overlay_reconnect(target_peer_id=target)
                elif operation == "rekey":
                    result = runner.request_secure_link_rekey(target_peer_id=target)
                elif operation == "reload" and request.get("scope") in {"all", "revocation", "local_identity"}:
                    result = runner.request_secure_link_reload(scope=request["scope"], target_peer_id=target)
                else:
                    raise ValueError("invalid peer control operation")
                await _write_frame(writer, {**identity, "kind": "peer.control.reply", "id": request_id, "result": result})
                continue
            if request.get("kind") != "peer.snapshot":
                raise ValueError("unsupported peer worker request")
            await _write_frame(writer, {**identity, "kind": "peer.snapshot.reply", "id": request_id,
                                        "status": runner.get_status_snapshot(),
                                        "connections": runner.get_connections_snapshot(),
                                        "peers": runner.get_peer_connections_snapshot()})
    except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
        pass
    except Exception:
        # Errors can contain credentials or peer data; send only a category.
        with contextlib.suppress(Exception):
            await _write_frame(writer, {"v": 1, "kind": "peer.error", "error": "peer worker failed"})
    finally:
        if runner is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(runner.stop(reason="peer-worker-stop"), 12.0)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        if log_socket is not None:
            log_socket.close()


class PeerStackWorker:
    """Python supervisor for a single outbound TCP peer stack."""

    def __init__(self, peer_id: str | None = None, *, implementation: str = "python", native_executable: str | None = None) -> None:
        self.peer_id = peer_id or uuid.uuid4().hex
        if not 1 <= len(self.peer_id) <= 128:
            raise ValueError("invalid peer identity")
        self.generation = 0
        if implementation not in {"python", "native"}:
            raise ValueError("unsupported peer worker implementation")
        self.implementation = implementation
        self.native_executable = native_executable
        self.process: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._log_relay = None
        self._lock = asyncio.Lock()

    async def start(self, config: dict[str, Any]) -> None:
        if self.process is not None:
            raise RuntimeError("peer worker already started")
        if sys.platform not in {"darwin", "linux"}:
            raise RuntimeError("peer workers require macOS or Linux")
        if self.implementation == "native" and sys.platform not in {"darwin", "linux"}:
            raise RuntimeError("native peer worker is not available on this platform")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        process = None
        try:
            # Both Python and native peer children receive the same
            # producer-only descriptor.  In particular, a native macOS child
            # must not fall back to inherited stderr when a managed collector
            # is selected by its Python supervisor.
            from .bridge_logging_worker import open_child_log_relay
            self._log_relay = open_child_log_relay()
            if self.implementation == "python":
                command = [sys.executable, "-m", "obstacle_bridge.bridge_peer_worker", "--control-fd", str(child.fileno())]
            else:
                default_executable = "ObstacleBridgeHostRunner" if sys.platform == "darwin" else "ObstacleBridgeLinux"
                executable = self.native_executable or os.environ.get("OBSTACLEBRIDGE_NATIVE_PEER_WORKER") or shutil.which(default_executable)
                if not executable or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
                    raise RuntimeError("native peer worker executable is unavailable")
                command = [executable, "--peer-worker-control-fd", str(child.fileno())]
            inherited = [child.fileno()]
            if self._log_relay is not None:
                log_fd = self._log_relay.sender.fileno()
                command.extend(["--log-fd", str(log_fd)])
                inherited.append(log_fd)
            environment = os.environ.copy()
            # The supervisor owns the runtime-health file; the peer must not
            # concurrently write the same durable state through an inherited
            # path override.
            environment.pop("OBSTACLEBRIDGE_RUNTIME_HEALTH_PATH", None)
            process = await asyncio.create_subprocess_exec(
                *command, pass_fds=tuple(inherited), env=environment,
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL if self._log_relay is not None else None,
            )
            child.close()
            if self._log_relay is not None:
                self._log_relay.sender.close()
            parent.setblocking(False)
            self._reader, self._writer = await asyncio.open_connection(sock=parent)
            self.process = process
            generation = self.generation + 1
            names = ("runner", "tcp_session", "peer_address_protocol", "secure_link", "compress_layer", "channel_mux")
            await _write_frame(self._writer, {"v": 1, "kind": "peer.start", "peer_id": self.peer_id,
                                             "generation": generation, "config": config,
                                             "log_root_level": logging.getLogger().level,
                                             "log_levels": {name: logging.getLogger(name).level for name in names}})
            ready = await asyncio.wait_for(_read_frame(self._reader), 20.0)
            if (ready.get("kind") != "peer.ready" or ready.get("implementation") != self.implementation
                    or ready.get("peer_id") != self.peer_id or type(ready.get("generation")) is not int
                    or ready["generation"] != generation):
                raise RuntimeError("peer worker startup failed")
            self.generation = generation
        except BaseException:
            child.close()
            parent.close()
            await self._retire()
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            raise

    async def _request(self, kind: str, expected: str, **fields: Any) -> dict[str, Any]:
        async with self._lock:
            if self.process is None or self.process.returncode is not None or self._reader is None or self._writer is None:
                raise RuntimeError("peer worker unavailable")
            request_id = uuid.uuid4().hex
            try:
                await _write_frame(self._writer, {"v": 1, "kind": kind, "peer_id": self.peer_id,
                                                  "generation": self.generation, "id": request_id, **fields})
                reply = await asyncio.wait_for(_read_frame(self._reader), 2.0)
                if (reply.get("kind") != expected or reply.get("id") != request_id
                        or reply.get("peer_id") != self.peer_id or type(reply.get("generation")) is not int
                        or reply["generation"] != self.generation):
                    raise ValueError("invalid peer worker response")
                return reply
            except asyncio.CancelledError:
                # A caller deadline must not wait through graceful shutdown of
                # a hung child, or leave a partially consumed stream reusable.
                await self._retire(force=True)
                raise
            except BaseException:
                # Never reuse a stream after a partial or timed-out response.
                await self._retire()
                raise

    async def snapshot_bundle(self) -> dict[str, Any]:
        reply = await self._request("peer.snapshot", "peer.snapshot.reply")
        if any(not isinstance(reply.get(key), dict) for key in ("status", "connections", "peers")):
            await self._retire()
            raise ValueError("invalid peer worker snapshot")
        return {key: reply[key] for key in ("status", "connections", "peers")}

    async def snapshot(self) -> dict[str, Any]:
        return (await self.snapshot_bundle())["status"]

    async def control(self, operation: str, target_peer_id: str | None = None, scope: str | None = None) -> dict[str, Any]:
        if operation not in {"reconnect", "rekey", "reload"}:
            raise ValueError("invalid peer control operation")
        if target_peer_id is not None and (not isinstance(target_peer_id, str) or len(target_peer_id) > 128):
            raise ValueError("invalid peer control target")
        if operation == "reload" and scope not in {"all", "revocation", "local_identity"}:
            raise ValueError("invalid peer reload scope")
        reply = await self._request("peer.control", "peer.control.reply", operation=operation,
                                    target_peer_id=target_peer_id, scope=scope)
        if not isinstance(reply.get("result"), dict):
            await self._retire()
            raise ValueError("invalid peer control response")
        return reply["result"]

    async def stop(self) -> None:
        if self.process is not None and self.process.returncode is None:
            with contextlib.suppress(Exception):
                await self._request("peer.stop", "peer.stopping")
        await self._retire()

    async def _retire(self, *, force: bool = False) -> None:
        process, writer, relay = self.process, self._writer, self._log_relay
        self.process = None
        self._writer = None
        self._reader = None
        self._log_relay = None
        try:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            if process is not None and process.returncode is None:
                if force:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                try:
                    await asyncio.wait_for(process.wait(), 12.0)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
        except BaseException:
            # Retirement may itself be cancelled by an Admin deadline or
            # supervisor shutdown after ownership was cleared above.
            if process is not None and process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await asyncio.shield(process.wait())
            raise
        finally:
            if relay is not None:
                relay.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--log-fd", type=int)
    args = parser.parse_args()
    asyncio.run(_serve(args.control_fd, args.log_fd))


if __name__ == "__main__":
    main()
