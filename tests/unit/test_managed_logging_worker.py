from __future__ import annotations

import asyncio
import logging
import os
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from obstacle_bridge.bridge_logging_ipc import fetch_remote_log_lines
from obstacle_bridge.bridge_logging_worker import ChildLogRelay, ManagedLoggingWorker, SupervisedLoggingWorker, _PrivateLogHandler, activate_managed_logging
from obstacle_bridge.bridge_proxy_worker import ProxyWorker
from obstacle_bridge.bridge import AdminWebUI

SOURCE = Path(__file__).resolve().parents[2] / "swift/Sources/ObstacleBridgeLogCollector/main.swift"
pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="private workers require desktop Unix sockets")


@pytest.fixture(scope="module")
def native_collector(tmp_path_factory):
    swiftc = shutil.which("swiftc")
    if not swiftc or sys.platform not in {"darwin", "linux"}:
        pytest.skip("native collector requires swiftc on macOS or Linux")
    binary = tmp_path_factory.mktemp("private-log-collector") / "collector"
    subprocess.run([swiftc, str(SOURCE), "-o", str(binary)], check=True, capture_output=True, text=True)
    return binary


@pytest.fixture(params=["python", "native"])
def worker(request):
    binary = request.getfixturevalue("native_collector") if request.param == "native" else None
    instance = ManagedLoggingWorker(request.param, native_executable=str(binary) if binary else None, stdout=subprocess.DEVNULL)
    yield instance
    instance.close()


def test_private_worker_records_queries_and_rejects_bad_input(worker):
    assert worker.process.pid != os.getpid()
    assert worker._data.family == socket.AF_UNIX
    worker._data.send(b"not-json")
    worker._data.send(b"x" * 8193)
    worker.handler.emit(logging.LogRecord("private.test", logging.WARNING, __file__, 1, "worker message", (), None))
    result = worker.fetch(10)
    assert result["available"]
    assert any("private.test: worker message" in line for line in result["lines"])
    for index in range(4):
        worker.handler.emit(logging.LogRecord("private.test", logging.INFO, __file__, 1, f"{index}:" + "x" * 1000, (), None))
        result = worker.fetch(10)
        assert result["available"]
    assert sum(len(line) for line in result["lines"]) > 4000
    assert worker.process.poll() is None


def test_private_worker_exits_when_owner_lifetime_closes(worker):
    worker._lifetime.close()
    assert worker.process.wait(timeout=3) == 0
    worker.handler.emit(logging.LogRecord("private.test", logging.WARNING, __file__, 1, "after loss", (), None))
    assert worker.handler.dropped_records == 1
    assert worker.fetch(10)["available"] is False


def test_private_query_lock_has_a_bounded_wait(worker):
    worker._query_lock.acquire()
    try:
        started = time.monotonic()
        assert worker.fetch(10)["available"] is False
        assert time.monotonic() - started < 0.5
    finally:
        worker._query_lock.release()


def test_python_runner_admin_queries_managed_worker_and_restores_sinks():
    args = SimpleNamespace(log_worker="python", log_file=None)
    root = logging.getLogger()
    before = list(root.handlers)
    ui = AdminWebUI(args, mock.Mock())
    ui._send_json = mock.AsyncMock()
    ui._log_api_response = mock.Mock()
    ui._call_runner = mock.Mock()
    with activate_managed_logging(args) as worker:
        worker.handler.emit(logging.LogRecord("private.test", logging.WARNING, __file__, 1, "admin message", (), None))
        asyncio.run(ui._handle_logs(mock.Mock(), "/api/logs?limit=10"))
        result = ui._send_json.await_args.args[2]
        assert result["source"] == "private_worker"
        assert result["logger_available"]
        assert result["logger_worker"]["state"] == "running"
        assert result["logger_worker"]["generation"] == 1
        assert any("admin message" in line for line in result["lines"])
        ui._call_runner.assert_not_called()
    assert root.handlers == before
    assert worker.process.poll() is not None
    assert fetch_remote_log_lines(10) is None


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_child_record_relay_survives_collector_restart_and_rejects_queries(implementation, request):
    binary = request.getfixturevalue("native_collector") if implementation == "native" else None
    supervisor = SupervisedLoggingWorker(implementation, native_executable=str(binary) if binary else None, stdout=subprocess.DEVNULL)
    relay = ChildLogRelay(supervisor)
    producer = _PrivateLogHandler(relay.sender)
    try:
        relay.sender.send(b'{"v":1,"kind":"logs.query","request_id":"child"}')
        producer.emit(logging.LogRecord("child.test", logging.WARNING, __file__, 1, "first generation", (), None))
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = supervisor.fetch(10)
            if any("first generation" in line for line in result["lines"]):
                break
            time.sleep(0.02)
        assert result["available"] and any("first generation" in line for line in result["lines"])
        with pytest.raises(BlockingIOError):
            relay.sender.recv(8192)
        supervisor.process.kill()
        end = time.monotonic() + 5
        while time.monotonic() < end and supervisor.status()["generation"] < 2:
            time.sleep(0.05)
        assert supervisor.status()["generation"] >= 2
        producer.emit(logging.LogRecord("child.test", logging.WARNING, __file__, 1, "replacement generation", (), None))
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = supervisor.fetch(10)
            if any("replacement generation" in line for line in result["lines"]):
                break
            time.sleep(0.02)
        assert result["available"] and any("replacement generation" in line for line in result["lines"])
    finally:
        producer.close()
        relay.close()
        supervisor.close()


@pytest.mark.parametrize("proxy_implementation", ["python", "native"])
@pytest.mark.parametrize("logger_implementation", ["python", "native"])
def test_proxy_child_sends_logs_to_selected_collector(monkeypatch, request, proxy_implementation, logger_implementation):
    native_log = request.getfixturevalue("native_collector") if logger_implementation == "native" else None
    native_proxy = request.getfixturevalue("native_proxy_worker_executable") if proxy_implementation == "native" else None
    args = SimpleNamespace(log_worker=logger_implementation, log_worker_native_executable=str(native_log) if native_log else None, log_file=None)
    monkeypatch.setattr(logging.getLogger(), "level", logging.INFO)
    with activate_managed_logging(args) as logs:
        async def exercise():
            worker = ProxyWorker(proxy_implementation, native_executable=native_proxy, supervised=True)
            await worker.start({"bind": "127.0.0.1", "http_port": 0, "socks5_port": 0,
                                "protocols": ["http-connect"], "auth": {"mode": "basic", "username": "user", "token": "secret-not-logged"},
                                "egress": {"mode": "direct"},
                                "policy": {"allow_private_destinations": True, "blocked_host_patterns": []}})
            try:
                for _ in range(30):
                    data = await asyncio.to_thread(logs.fetch, 100)
                    if any("[PROXY] listener started" in line for line in data["lines"]):
                        break
                    await asyncio.sleep(0.05)
                assert any("[PROXY] listener started" in line for line in data["lines"])
                assert "secret-not-logged" not in repr(data)
                old = worker.process
                old.kill()
                for _ in range(160):
                    if worker.generation >= 2 and worker.process.returncode is None:
                        break
                    await asyncio.sleep(0.05)
                assert worker.generation >= 2 and old.returncode is not None
                for _ in range(60):
                    data = await asyncio.to_thread(logs.fetch, 100)
                    if sum("[PROXY] listener started" in line for line in data["lines"]) >= 2:
                        break
                    await asyncio.sleep(0.05)
                assert sum("[PROXY] listener started" in line for line in data["lines"]) >= 2
                assert "secret-not-logged" not in repr(data)
            finally:
                await worker.stop()
        asyncio.run(exercise())


def test_failed_relay_allocation_does_not_prevent_proxy_start(monkeypatch):
    args = SimpleNamespace(log_worker="python", log_file=None)
    with activate_managed_logging(args) as logs:
        with mock.patch("obstacle_bridge.bridge_logging_worker.ChildLogRelay", side_effect=OSError("unavailable")):
            async def exercise():
                worker = ProxyWorker("python")
                await worker.start({"bind": "127.0.0.1", "http_port": 0, "socks5_port": 0,
                                    "protocols": ["http-connect"], "auth": {"mode": "none"},
                                    "egress": {"mode": "direct"},
                                    "policy": {"allow_private_destinations": True, "blocked_host_patterns": []}})
                try:
                    assert worker.listeners["http"]["bound_port"] > 0
                    assert logs.status()["dropped_records"] >= 1
                finally:
                    await worker.stop()
            asyncio.run(exercise())


def test_child_producer_drops_records_when_relay_is_stalled():
    entered = threading.Event()
    release = threading.Event()

    class StalledSupervisor:
        def forward_record(self, _packet):
            entered.set()
            release.wait(5)

    relay = ChildLogRelay(StalledSupervisor())
    producer = _PrivateLogHandler(relay.sender)
    record = logging.LogRecord("child.test", logging.WARNING, __file__, 1, "x" * 2048, (), None)
    try:
        producer.emit(record)
        assert entered.wait(2)
        started = time.monotonic()
        for _ in range(500):
            producer.emit(record)
        assert time.monotonic() - started < 3
        assert producer.dropped_records > 0
    finally:
        release.set()
        producer.close()
        relay.close()


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_supervisor_restarts_selected_worker_after_crash(implementation, request):
    binary = request.getfixturevalue("native_collector") if implementation == "native" else None
    supervisor = SupervisedLoggingWorker(implementation, native_executable=str(binary) if binary else None, stdout=subprocess.DEVNULL)
    original = supervisor.process
    try:
        original.kill()
        original.wait(timeout=3)
        deadline = time.monotonic() + 5
        while supervisor.status()["state"] != "restarting" and time.monotonic() < deadline:
            time.sleep(0.01)
        assert supervisor.status()["state"] == "restarting"
        started = time.monotonic()
        supervisor.handler.emit(logging.LogRecord("recovery", logging.WARNING, __file__, 1, "during outage", (), None))
        assert supervisor.fetch(10)["available"] is False
        assert time.monotonic() - started < 0.5
        assert supervisor.handler.dropped_records >= 1
        while supervisor.status()["generation"] < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert supervisor.status()["state"] == "running"
        assert supervisor.status()["restarts"] == 1
        assert supervisor.process.pid != original.pid
        supervisor.handler.emit(logging.LogRecord("recovery", logging.WARNING, __file__, 1, "after restart", (), None))
        result = supervisor.fetch(10)
        assert result["available"]
        assert any("after restart" in line for line in result["lines"])
        assert not any("during outage" in line for line in result["lines"])
    finally:
        supervisor.close()
    assert supervisor.process.poll() is not None
    assert not supervisor._thread.is_alive()


def test_supervisor_retries_failed_restart_without_fallback():
    supervisor = SupervisedLoggingWorker("python", stdout=subprocess.DEVNULL)
    original = supervisor.process
    attempts = []

    def restart(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise FileNotFoundError("collector temporarily unavailable")
        return ManagedLoggingWorker(*args, **kwargs)

    try:
        with mock.patch("obstacle_bridge.bridge_logging_worker.ManagedLoggingWorker", side_effect=restart):
            original.kill()
            original.wait(timeout=3)
            deadline = time.monotonic() + 6
            while supervisor.status()["generation"] < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
        status = supervisor.status()
        assert status["failed_starts"] == 1
        assert status["restarts"] == 1
        assert status["implementation"] == "python"
        assert status["state"] == "running"
    finally:
        supervisor.close()


def test_supervisor_discards_reply_from_retired_generation():
    supervisor = object.__new__(SupervisedLoggingWorker)
    supervisor._stop = threading.Event()
    supervisor._generation = 2
    supervisor._restart_count = 1
    supervisor._failed_starts = 0
    supervisor.implementation = "python"
    supervisor.handler = mock.Mock(dropped_records=0)
    original = mock.Mock()
    supervisor._active = original
    replacement = mock.Mock()
    replacement.process.poll.return_value = None

    def old_reply(_limit):
        supervisor._active = replacement
        return {"available": True, "lines": ["stale"], "error": ""}

    original.fetch.side_effect = old_reply
    result = supervisor.fetch(10)
    assert result["available"] is False
    assert result["lines"] == []


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_supervisor_drops_records_when_collector_is_stalled(implementation, request):
    binary = request.getfixturevalue("native_collector") if implementation == "native" else None
    supervisor = SupervisedLoggingWorker(implementation, native_executable=str(binary) if binary else None, stdout=subprocess.DEVNULL)
    process = supervisor.process
    try:
        os.kill(process.pid, signal.SIGSTOP)
        started = time.monotonic()
        for _ in range(500):
            supervisor.handler.emit(logging.LogRecord("saturation", logging.WARNING, __file__, 1, "x" * 4000, (), None))
        result = supervisor.fetch(10)
        assert time.monotonic() - started < 2
        assert result["available"] is False
        assert supervisor.status()["dropped_records"] > 0
    finally:
        os.kill(process.pid, signal.SIGCONT)
        supervisor.close()


@pytest.mark.parametrize("extra", [{"log_file": "unused.log"}, {"log_udp_target": "127.0.0.1:15140"}, {"debug_stderr": True}])
def test_private_worker_rejects_unsupported_sinks(extra):
    with pytest.raises(ValueError):
        with activate_managed_logging(SimpleNamespace(log_worker="python", **extra)):
            pytest.fail("unsupported logging configuration started")


def test_private_native_worker_start_failure_does_not_replace_handlers():
    root = logging.getLogger()
    before = list(root.handlers)
    args = SimpleNamespace(log_worker="native", log_worker_native_executable="/nonexistent/collector")
    with pytest.raises(FileNotFoundError):
        with activate_managed_logging(args):
            pytest.fail("missing native collector started")
    assert root.handlers == before


def test_runner_main_activates_private_worker_around_runtime():
    from obstacle_bridge import bridge_runner

    args = SimpleNamespace(log_worker="python")

    def run_runtime(runtime_args, argv, log):
        assert runtime_args is args
        log.warning("runner lifecycle message")
        result = fetch_remote_log_lines(10)
        assert result["available"]
        assert any("runner lifecycle message" in line for line in result["lines"])

    with mock.patch.object(bridge_runner, "parse_runtime_args", return_value=args), \
         mock.patch.object(bridge_runner, "_maybe_reexec_with_linux_tun_privileges"), \
         mock.patch.object(bridge_runner, "_maybe_reexec_with_macos_tun_privileges"), \
         mock.patch.object(bridge_runner, "_maybe_reexec_with_windows_tun_privileges"), \
         mock.patch.object(bridge_runner, "_run_configured_main", side_effect=run_runtime):
        bridge_runner.main(["--log-worker", "python"])


def test_unsupported_file_is_rejected_before_logging_configuration(tmp_path):
    from obstacle_bridge.bridge_runner import parse_runtime_args

    log_path = tmp_path / "must-not-be-created.log"
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="--log-file"):
        parse_runtime_args(["--config", str(config_path), "--log-worker", "python", "--log-file", str(log_path)])
    assert not log_path.exists()
