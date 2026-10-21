from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys

import pytest

from obstacle_bridge.bridge_proxy_worker import worker_capabilities

pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix workers")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def native_supervisor(tmp_path_factory):
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("Swift compiler required")
    binary = tmp_path_factory.mktemp("proxy-supervisor") / "supervisor"
    subprocess.run([swiftc, str(ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeLogWorkerSupervisor.swift"),
                    str(ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeProxyWorkerSupervisor.swift"),
                    str(ROOT / "tests/fixtures/native_proxy_supervisor_runner.swift"), "-o", str(binary)], check=True)
    return str(binary)


@pytest.fixture(scope="module")
def native_collector(tmp_path_factory):
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("Swift compiler required")
    binary = tmp_path_factory.mktemp("proxy-log-collector") / "collector"
    subprocess.run([swiftc, str(ROOT / "swift/Sources/ObstacleBridgeLogCollector/main.swift"), "-o", str(binary)], check=True)
    return str(binary)


def _config():
    return {"bind": "127.0.0.1", "http_port": 0, "socks5_port": 0, "protocols": ["http-connect"],
            "auth": {"mode": "basic", "username": "user", "token": "secret-not-in-process-arguments"},
            "egress": {"mode": "direct"}, "policy": {"allow_private_destinations": True, "blocked_host_patterns": []}}


@pytest.mark.parametrize("implementation", ["python", "native"], ids=lambda value: f"{sys.platform}-native-supervisor-{value}-worker")
def test_swift_supervisor_owns_python_or_native_proxy(native_supervisor, native_proxy_worker_executable, implementation):
    async def exercise():
        async def echo(reader, writer):
            writer.write(await reader.read(4096))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        executable = sys.executable if implementation == "python" else native_proxy_worker_executable
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        try:
            host.stdin.write((json.dumps({"implementation": implementation, "executable": executable, "config": _config()}) + "\n").encode())
            await host.stdin.drain()
            ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
            assert set(ready) == {"worker", "listeners", "last_error"}
            assert {"implementation", "state", "generation", "restarts", "failed_starts", "capabilities"} <= set(ready["worker"])
            assert ready["worker"]["state"] == "running"
            assert ready["worker"]["pid"] > 1 and ready["worker"]["pid"] != host.pid
            assert ready["worker"]["capabilities"] == worker_capabilities(implementation)
            assert "capabilities" not in ready
            assert ready["last_error"] == ""
            port = ready["listeners"]["http"]["bound_port"]
            command = subprocess.check_output(["ps", "-p", str(ready["worker"]["pid"]), "-o", "command="], text=True)
            assert "secret-not-in-process-arguments" not in command
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            auth = base64.b64encode(b"user:secret-not-in-process-arguments").decode()
            target = server.sockets[0].getsockname()[1]
            writer.write(f"CONNECT 127.0.0.1:{target} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
            await writer.drain()
            assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)).startswith(b"HTTP/1.1 200")
            writer.write(b"mixed-process")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(13), 5) == b"mixed-process"
            writer.close()
            await writer.wait_closed()
            os.kill(ready["worker"]["pid"], signal.SIGKILL)
            for _ in range(140):
                host.stdin.write(b"status\n")
                await host.stdin.drain()
                status = json.loads(await asyncio.wait_for(host.stdout.readline(), 5))
                assert status["worker"]["restarts"] == max(0, status["worker"]["generation"] - 1)
                if status["worker"]["state"] == "running" and status["worker"]["generation"] > ready["worker"]["generation"]:
                    break
                await asyncio.sleep(0.05)
            assert status["worker"]["state"] == "running" and status["worker"]["restarts"] >= 1
            assert status["worker"]["pid"] != ready["worker"]["pid"]
            assert status["listeners"]["http"]["bound_port"] == port
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT 127.0.0.1:{target} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
            await writer.drain()
            assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)).startswith(b"HTTP/1.1 200")
            writer.write(b"recovered")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(9), 5) == b"recovered"
            writer.close()
            await writer.wait_closed()
        finally:
            host.stdin.write(b"stop\n")
            await host.stdin.drain()
            await asyncio.wait_for(host.wait(), 5)
            server.close()
            await server.wait_closed()
    asyncio.run(exercise())


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_owner_loss_closes_proxy_listener(native_supervisor, native_proxy_worker_executable, implementation):
    async def exercise():
        executable = sys.executable if implementation == "python" else native_proxy_worker_executable
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        host.stdin.write((json.dumps({"implementation": implementation, "executable": executable, "config": _config()}) + "\n").encode())
        await host.stdin.drain()
        ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
        port = ready["listeners"]["http"]["bound_port"]
        host.kill()
        await asyncio.wait_for(host.wait(), 5)
        for _ in range(100):
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
            except OSError:
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("proxy listener survived supervisor loss")
    asyncio.run(exercise())


@pytest.mark.parametrize("implementation", ["python", "native"])
@pytest.mark.parametrize("stop_during_backoff", [False, True])
def test_native_proxy_supervisor_retries_occupied_port(native_supervisor, native_proxy_worker_executable, implementation, stop_during_backoff):
    async def exercise():
        executable = sys.executable if implementation == "python" else native_proxy_worker_executable
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        reserved = socket.socket()
        reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        async def status():
            host.stdin.write(b"status\n")
            await host.stdin.drain()
            current = json.loads(await asyncio.wait_for(host.stdout.readline(), 5))
            assert current["worker"]["restarts"] == max(0, current["worker"]["generation"] - 1)
            return current

        try:
            host.stdin.write((json.dumps({"implementation": implementation, "executable": executable, "config": _config()}) + "\n").encode())
            await host.stdin.drain()
            ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
            port = ready["listeners"]["http"]["bound_port"]
            assert ready["worker"]["pid"] > 1 and ready["worker"]["pid"] != host.pid
            os.kill(ready["worker"]["pid"], signal.SIGKILL)
            for _ in range(100):
                try:
                    reserved.bind(("127.0.0.1", port))
                    reserved.listen()
                    break
                except OSError:
                    await asyncio.sleep(0.01)
            else:
                pytest.fail("could not reserve the retired listener")
            for _ in range(160):
                current = await status()
                if current["worker"]["failed_starts"] >= 1:
                    break
                await asyncio.sleep(0.05)
            assert current["worker"]["failed_starts"] >= 1
            assert current["worker"]["state"] == "unavailable" and current["listeners"] == {}
            assert "secret-not-in-process-arguments" not in json.dumps(current)
            if stop_during_backoff:
                host.stdin.write(b"stop\n")
                await host.stdin.drain()
                await asyncio.wait_for(host.wait(), 8)
                reserved.close()
                await asyncio.sleep(0.6)
                with pytest.raises(OSError):
                    await asyncio.open_connection("127.0.0.1", port)
                return
            reserved.close()
            for _ in range(160):
                current = await status()
                if current["worker"]["state"] == "running" and current["worker"]["generation"] >= 2:
                    break
                await asyncio.sleep(0.05)
            assert current["worker"]["state"] == "running"
            assert current["listeners"]["http"]["bound_port"] == port
            assert current["worker"]["restarts"] >= 1
        finally:
            reserved.close()
            if host.returncode is None:
                host.stdin.write(b"stop\n")
                await host.stdin.drain()
                await asyncio.wait_for(host.wait(), 8)
    asyncio.run(exercise())


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_native_proxy_supervisor_replaces_stalled_child(native_supervisor, native_proxy_worker_executable, implementation):
    async def exercise():
        executable = sys.executable if implementation == "python" else native_proxy_worker_executable
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        child_pid = None
        try:
            host.stdin.write((json.dumps({"implementation": implementation, "executable": executable, "config": _config()}) + "\n").encode())
            await host.stdin.drain()
            ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
            child_pid = ready["worker"]["pid"]
            assert child_pid > 1 and child_pid != host.pid
            os.kill(child_pid, signal.SIGSTOP)
            for _ in range(240):
                host.stdin.write(b"status\n")
                await host.stdin.drain()
                current = json.loads(await asyncio.wait_for(host.stdout.readline(), 5))
                assert current["worker"]["restarts"] == max(0, current["worker"]["generation"] - 1)
                if current["worker"]["state"] == "running" and current["worker"]["generation"] >= 2:
                    break
                await asyncio.sleep(0.05)
            assert current["worker"]["state"] == "running" and current["worker"]["generation"] >= 2
            assert current["worker"]["pid"] != child_pid
            assert current["listeners"]["http"]["bound_port"] == ready["listeners"]["http"]["bound_port"]
            child_pid = None
        finally:
            if child_pid is not None:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child_pid, signal.SIGCONT)
            if host.returncode is None:
                host.stdin.write(b"stop\n")
                await host.stdin.drain()
                await asyncio.wait_for(host.wait(), 10)
    asyncio.run(exercise())


@pytest.mark.parametrize("proxy_implementation", ["python", "native"])
@pytest.mark.parametrize("log_implementation", ["python", "native"])
def test_native_proxy_child_logs_follow_collector_and_proxy_restarts(native_supervisor, native_proxy_worker_executable, native_collector, proxy_implementation, log_implementation):
    async def exercise():
        proxy_executable = sys.executable if proxy_implementation == "python" else native_proxy_worker_executable
        log_executable = sys.executable if log_implementation == "python" else native_collector
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

        async def command(value):
            host.stdin.write((value + "\n").encode())
            await host.stdin.drain()
            return json.loads(await asyncio.wait_for(host.stdout.readline(), 8))

        try:
            host.stdin.write((json.dumps({"implementation": proxy_implementation, "executable": proxy_executable, "config": _config(),
                                          "logging": {"implementation": log_implementation, "executable": log_executable}}) + "\n").encode())
            await host.stdin.drain()
            proxy = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
            assert proxy["worker"]["state"] == "running"
            for _ in range(100):
                result = await command("logs")
                if any("[PROXY] listener started" in line for line in result.get("lines", [])):
                    break
                await asyncio.sleep(0.05)
            assert result["available"] and any("[PROXY] listener started" in line for line in result["lines"])
            assert "secret-not-in-process-arguments" not in repr(result)
            assert not (await command("producer-probe"))["producer_received_reply"]
            for _ in range(100):
                result = await command("logs")
                if any("relay marker" in line for line in result.get("lines", [])):
                    break
                await asyncio.sleep(0.05)
            assert any("relay marker" in line for line in result["lines"])
            log_status = await command("log-status")
            assert log_status["pid"] > 1 and log_status["pid"] != host.pid
            os.kill(log_status["pid"], signal.SIGKILL)
            for _ in range(160):
                current = await command("log-status")
                if current["state"] == "running" and current["generation"] > log_status["generation"]:
                    break
                await asyncio.sleep(0.05)
            assert current["state"] == "running" and current["generation"] > log_status["generation"]
            assert (await command("status"))["worker"]["pid"] == proxy["worker"]["pid"]
            assert proxy["worker"]["pid"] > 1 and proxy["worker"]["pid"] != host.pid
            os.kill(proxy["worker"]["pid"], signal.SIGKILL)
            for _ in range(160):
                current = await command("status")
                if current["worker"]["state"] == "running" and current["worker"]["generation"] > proxy["worker"]["generation"]:
                    break
                await asyncio.sleep(0.05)
            assert current["worker"]["state"] == "running" and current["worker"]["generation"] > proxy["worker"]["generation"]
            for _ in range(100):
                result = await command("logs")
                if any("[PROXY] listener started" in line for line in result.get("lines", [])):
                    break
                await asyncio.sleep(0.05)
            assert result["available"] and any("[PROXY] listener started" in line for line in result["lines"])
            assert "secret-not-in-process-arguments" not in repr(result)
        finally:
            if host.returncode is None:
                host.stdin.write(b"stop\n")
                await host.stdin.drain()
                await asyncio.wait_for(host.wait(), 10)
    asyncio.run(exercise())


@pytest.mark.parametrize("proxy_implementation", ["python", "native"])
@pytest.mark.parametrize("log_implementation", ["python", "native"])
@pytest.mark.parametrize("level", ["INFO", "WARNING"])
def test_native_proxy_child_honors_component_log_level(native_supervisor, native_proxy_worker_executable, native_collector, proxy_implementation, log_implementation, level):
    async def exercise():
        proxy_executable = sys.executable if proxy_implementation == "python" else native_proxy_worker_executable
        log_executable = sys.executable if log_implementation == "python" else native_collector
        host = await asyncio.create_subprocess_exec(native_supervisor, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

        async def command(value):
            host.stdin.write((value + "\n").encode())
            await host.stdin.drain()
            return json.loads(await asyncio.wait_for(host.stdout.readline(), 8))

        try:
            host.stdin.write((json.dumps({"implementation": proxy_implementation, "executable": proxy_executable, "config": _config(),
                                          "logging": {"implementation": log_implementation, "executable": log_executable,
                                                      "configuration": {"proxy_provider": {"log_proxy_provider": level}}}}) + "\n").encode())
            await host.stdin.drain()
            proxy = json.loads(await asyncio.wait_for(host.stdout.readline(), 10))
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy["listeners"]["http"]["bound_port"])
            writer.write(b"invalid-request\r\n\r\n")
            await writer.drain()
            writer.write_eof()
            await asyncio.wait_for(reader.read(4096), 5)
            writer.close()
            await writer.wait_closed()
            for _ in range(100):
                logs = await command("logs")
                if any("[PROXY] client failed" in line for line in logs.get("lines", [])):
                    break
                await asyncio.sleep(0.05)
            assert logs["available"] and any("[PROXY] client failed" in line for line in logs["lines"])
            assert any("[PROXY] listener started" in line for line in logs["lines"]) == (level == "INFO")
            assert "secret-not-in-process-arguments" not in repr(logs)
        finally:
            if host.returncode is None:
                host.stdin.write(b"stop\n")
                await host.stdin.drain()
                await asyncio.wait_for(host.wait(), 10)
    asyncio.run(exercise())


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_restricted_policy_starts_with_enforcement(native_supervisor, native_proxy_worker_executable, implementation):
    config = _config()
    config["policy"]["allow_private_destinations"] = False
    executable = sys.executable if implementation == "python" else native_proxy_worker_executable
    result = subprocess.run([native_supervisor], input=json.dumps({"implementation": implementation, "executable": executable, "config": config}) + "\n", text=True, capture_output=True, timeout=10)
    assert result.returncode == 0
    snapshot = json.loads(result.stdout)
    assert snapshot["worker"]["capabilities"]["destination_policy"] == {"enforced": True, "requires_unrestricted": False}
    assert snapshot["listeners"]["http"]["destination_policy_enforced"] is True
    assert "secret-not-in-process-arguments" not in result.stderr
