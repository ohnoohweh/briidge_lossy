"""Private, supervised desktop log workers using inherited local sockets.

The anonymous socket pair is the capability: no path, port or bearer token is
published. The separate lifetime socket lets the worker observe parent death.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Optional

from .bridge_logging_ipc import LOG_WIRE_VERSION, NonBlockingUdpLogHandler, UdpLogReceiver, swap_admin_log_query_client

PRIVATE_MAX_DATAGRAM = 8 * 1024


def serve_private_receiver(data_fd: int, lifetime_fd: int) -> int:
    """Serve records until the owner closes its inherited lifetime socket."""
    with socket.socket(fileno=data_fd) as data, socket.socket(fileno=lifetime_fd) as lifetime:
        if data.family != socket.AF_UNIX or data.type != socket.SOCK_DGRAM or lifetime.family != socket.AF_UNIX or lifetime.type != socket.SOCK_STREAM:
            raise ValueError("invalid private logging sockets")
        receiver = UdpLogReceiver("", PRIVATE_MAX_DATAGRAM, connected_socket=data)
        data.send(json.dumps({"v": LOG_WIRE_VERSION, "kind": "worker.ready", "role": "logging", "implementation": "python"}).encode("utf-8"))
        while True:
            readable, _, _ = select.select([data, lifetime], [], [])
            if lifetime in readable:
                # No commands are defined on this socket; EOF or unexpected
                # input both revoke the worker's authority to keep running.
                lifetime.recv(1)
                return 0
            if data in readable:
                packet = data.recv(PRIVATE_MAX_DATAGRAM + 1)
                if len(packet) <= PRIVATE_MAX_DATAGRAM:
                    receiver.handle_datagram(packet)


class _PrivateLogHandler(NonBlockingUdpLogHandler):
    def __init__(self, data: socket.socket):
        logging.Handler.__init__(self)
        self._socket = data
        self.max_datagram_bytes = PRIVATE_MAX_DATAGRAM
        self.dropped_records = 0

    def close(self) -> None:
        # The worker owns this shared socket; queries may still be in flight.
        logging.Handler.close(self)


class ManagedLoggingWorker:
    """Launch a selected Python/native log worker and own its private channels."""

    def __init__(self, implementation: str, *, native_executable: Optional[str] = None, stdout: Any = None):
        if implementation not in {"python", "native"}:
            raise ValueError("logging worker must be python or native")
        if os.name != "posix":
            raise RuntimeError("private logging workers require Unix socket pairs")
        if implementation == "native" and not native_executable:
            raise ValueError("native logging worker executable is required")
        self.implementation = implementation
        self._query_lock = threading.Lock()
        self._data, child_data = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self._lifetime, child_lifetime = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except BaseException:
            self._data.close()
            child_data.close()
            raise
        self._data.setblocking(False)
        self.process: Optional[subprocess.Popen] = None
        self.handler = _PrivateLogHandler(self._data)
        try:
            # Darwin defaults AF_UNIX datagram send buffers to 2 KiB. Set
            # both directions explicitly so the shared 8 KiB wire limit is
            # usable for records and replies on both supported hosts.
            for endpoint in (self._data, child_data):
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
            fds = [str(child_data.fileno()), str(child_lifetime.fileno())]
            command = ([sys.executable, "-m", "obstacle_bridge.bridge_logging_ipc"] if implementation == "python" else [str(native_executable)]) + ["--private-fds", *fds]
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, pass_fds=(child_data.fileno(), child_lifetime.fileno()))
            child_data.close()
            child_lifetime.close()
            readable, _, _ = select.select([self._data], [], [], 5.0)
            if not readable:
                raise RuntimeError("logging worker startup timed out")
            ready = json.loads(self._data.recv(PRIVATE_MAX_DATAGRAM).decode("utf-8"))
            if ready != {"v": LOG_WIRE_VERSION, "kind": "worker.ready", "role": "logging", "implementation": implementation}:
                raise RuntimeError("invalid logging worker startup response")
        except BaseException:
            child_data.close()
            child_lifetime.close()
            self.close()
            raise

    def fetch(self, limit: int) -> dict[str, Any]:
        unavailable = {"available": False, "lines": [], "error": "logger unavailable"}
        request_id = uuid.uuid4().hex
        request = json.dumps({"v": LOG_WIRE_VERSION, "kind": "logs.query", "limit": max(1, min(int(limit), 1000)), "request_id": request_id}, separators=(",", ":")).encode("utf-8")
        deadline = time.monotonic() + 0.15
        if not self._query_lock.acquire(timeout=0.15):
            return unavailable
        try:
            try:
                self._data.send(request)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([self._data], [], [], remaining)[0]:
                        return unavailable
                    payload = json.loads(self._data.recv(PRIVATE_MAX_DATAGRAM).decode("utf-8"))
                    if not isinstance(payload, dict) or payload.get("request_id") != request_id:
                        continue
                    if payload.get("v") != LOG_WIRE_VERSION or payload.get("kind") != "logs.reply" or payload.get("ok") is not True or not isinstance(payload.get("lines"), list):
                        return unavailable
                    return {"available": True, "lines": [str(line) for line in payload["lines"]], "error": ""}
            except (OSError, ValueError, TypeError):
                return unavailable
        finally:
            self._query_lock.release()

    def close(self) -> None:
        self.handler.close()
        self._lifetime.close()
        self._data.close()
        if self.process is not None:
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1.0)


class _SupervisedLogHandler(NonBlockingUdpLogHandler):
    """Stable producer handler; the monitor can replace its child independently."""

    def __init__(self, supervisor):
        logging.Handler.__init__(self)
        self._supervisor = supervisor
        self.max_datagram_bytes = PRIVATE_MAX_DATAGRAM
        self.dropped_records = 0

    def emit(self, record):
        child = self._supervisor._active
        if child is None or self._supervisor._stop.is_set():
            self.dropped_records += 1
            return
        self._socket = child._data
        super().emit(record)

    def close(self):
        logging.Handler.close(self)


class SupervisedLoggingWorker:
    """Restart the chosen implementation without blocking producers or queries."""

    def __init__(self, implementation: str, *, native_executable: Optional[str] = None, stdout: Any = None):
        self.implementation = implementation
        self.native_executable = native_executable
        self.stdout = stdout
        self._stop = threading.Event()
        self._active: Optional[ManagedLoggingWorker] = ManagedLoggingWorker(
            implementation, native_executable=native_executable, stdout=stdout
        )
        self._last_process = self._active.process
        self._generation = 1
        self._restart_count = 0
        self._failed_starts = 0
        self.handler = _SupervisedLogHandler(self)
        self._thread = threading.Thread(target=self._monitor, name="logging-worker-supervisor", daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._active.close()
            self.handler.close()
            raise

    @property
    def process(self):
        child = self._active
        return child.process if child is not None else self._last_process

    def status(self):
        child = self._active
        state = "stopped" if self._stop.is_set() else (
            "running" if child is not None and child.process.poll() is None else "restarting"
        )
        try:
            pid = int(child.process.pid) if child is not None and child.process.poll() is None else 0
        except (TypeError, ValueError):
            pid = 0
        return {
            "state": state,
            "implementation": self.implementation,
            "pid": pid,
            "generation": self._generation,
            "restarts": self._restart_count,
            "failed_starts": self._failed_starts,
            "dropped_records": self.handler.dropped_records,
        }

    def fetch(self, limit: int) -> dict[str, Any]:
        child = self._active
        result = child.fetch(limit) if child is not None and not self._stop.is_set() else {
            "available": False, "lines": [], "error": "logger unavailable"
        }
        if self._stop.is_set() or child is not self._active or (child is not None and child.process.poll() is not None):
            result = {"available": False, "lines": [], "error": "logger unavailable"}
        result["worker_status"] = self.status()
        return result

    def forward_record(self, packet: bytes) -> None:
        """Best-effort child record delivery to the current collector generation."""
        child = self._active
        if child is None or self._stop.is_set() or child.process.poll() is not None:
            self.handler.dropped_records += 1
            return
        try:
            child._data.send(packet)
        except OSError:
            self.handler.dropped_records += 1

    def _monitor(self):
        try:
            self._monitor_loop()
        finally:
            child = self._active
            self._active = None
            if child is not None:
                child.close()

    def _monitor_loop(self):
        delay = 0.25
        started_at = time.monotonic()
        while not self._stop.wait(0.1):
            child = self._active
            if child is not None and child.process.poll() is None:
                if time.monotonic() - started_at >= 5:
                    delay = 0.25
                continue
            self._active = None
            if child is not None:
                child.close()
            if self._stop.wait(delay):
                break
            try:
                replacement = ManagedLoggingWorker(
                    self.implementation, native_executable=self.native_executable, stdout=self.stdout
                )
            except Exception:
                self._failed_starts += 1
                delay = min(delay * 2, 5.0)
                continue
            if self._stop.is_set():
                replacement.close()
                break
            self._last_process = replacement.process
            self._generation += 1
            self._restart_count += 1
            self._active = replacement
            started_at = time.monotonic()
            delay = min(delay * 2, 5.0)

    def close(self):
        self._stop.set()
        self._thread.join(timeout=9.0)
        self.handler.close()


class ChildLogRelay:
    """A record-only inherited capability, distinct from collector queries.

    One draining thread per child keeps parsing and collector sends away from
    both the child and the runner event loops. The stable parent endpoint
    follows collector replacement; stale workers cannot read query replies.
    """

    def __init__(self, supervisor: SupervisedLoggingWorker):
        self.supervisor = supervisor
        self._stop = threading.Event()
        self.receiver, self.sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            for endpoint in (self.receiver, self.sender):
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
            self.receiver.settimeout(0.2)
            self.sender.setblocking(False)
            self._thread = threading.Thread(target=self._run, name="child-log-relay", daemon=True)
            self._thread.start()
        except BaseException:
            self.receiver.close()
            self.sender.close()
            raise

    def _run(self):
        while not self._stop.is_set():
            try:
                packet = self.receiver.recv(PRIVATE_MAX_DATAGRAM + 1)
            except socket.timeout:
                continue
            except OSError:
                return
            if not packet or len(packet) > PRIVATE_MAX_DATAGRAM:
                continue
            try:
                record = json.loads(packet.decode("utf-8"))
                if not isinstance(record, dict) or record.get("v") != LOG_WIRE_VERSION or "kind" in record:
                    continue
            except (UnicodeError, ValueError):
                continue
            self.supervisor.forward_record(packet)

    def close(self):
        self._stop.set()
        self.sender.close()
        self.receiver.close()
        self._thread.join(timeout=0.4)


def open_child_log_relay() -> Optional[ChildLogRelay]:
    """Return a producer-only capability when private logging is active."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, _SupervisedLogHandler) and not handler._supervisor._stop.is_set():
            try:
                return ChildLogRelay(handler._supervisor)
            except (OSError, RuntimeError):
                # Logging is optional observability: inability to allocate a
                # child producer channel must not prevent service startup.
                handler.dropped_records += 1
                return None
    return None


def managed_logging_status() -> dict[str, Any]:
    """Return the selected collector's redacted Admin status, if any."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, _SupervisedLogHandler):
            return handler._supervisor.status()
    return {"state": "off", "implementation": "", "pid": 0, "generation": 0,
            "restarts": 0, "failed_starts": 0, "dropped_records": 0}


def install_child_log_handler(fd: int, root_level: int, logger_levels: dict[str, int]) -> socket.socket:
    """Replace child sinks with its inherited nonblocking record-only socket."""
    sock = socket.socket(fileno=fd)
    if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_DGRAM:
        sock.close()
        raise ValueError("invalid child logging socket")
    sock.setblocking(False)
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(root_level)
    for name, level in logger_levels.items():
        logging.getLogger(name).setLevel(level)
    root.addHandler(_PrivateLogHandler(sock))
    return sock


def validate_managed_logging_args(args):
    """Reject unsupported combinations before applying file/sink configuration."""
    implementation = str(getattr(args, "log_worker", "off") or "off")
    if implementation == "off":
        return implementation
    if getattr(args, "log_file", None):
        raise ValueError("private logging worker does not yet support --log-file")
    if any(getattr(args, name, None) for name in ("log_udp_target", "log_admin_udp_target", "log_udp_only", "debug_stderr")):
        raise ValueError("private logging worker cannot be combined with UDP log sinks or --debug-stderr")
    return implementation


@contextlib.contextmanager
def activate_managed_logging(args):
    """Use the selected worker for process logs and Admin queries until exit."""
    implementation = validate_managed_logging_args(args)
    if implementation == "off":
        yield None
        return
    executable = getattr(args, "log_worker_native_executable", None) or shutil.which("ObstacleBridgeLogCollector")
    worker = SupervisedLoggingWorker(implementation, native_executable=executable)
    setattr(args, "_admin_logging_worker_status", worker.status)
    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_query = swap_admin_log_query_client(worker)
    try:
        for handler in previous_handlers:
            root.removeHandler(handler)
        root.addHandler(worker.handler)
        yield worker
    finally:
        root.removeHandler(worker.handler)
        for handler in previous_handlers:
            root.addHandler(handler)
        swap_admin_log_query_client(previous_query)
        setattr(args, "_admin_logging_worker_status", None)
        worker.close()
