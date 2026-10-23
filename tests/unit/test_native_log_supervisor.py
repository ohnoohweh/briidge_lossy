from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix workers")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def native_log_binaries(tmp_path_factory):
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("Swift compiler required")
    directory = tmp_path_factory.mktemp("log-supervisor")
    owner = directory / "supervisor"
    collector = directory / "collector"
    shared = ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeWorkerIPC.swift"
    subprocess.run([swiftc, str(shared), str(ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeLogWorkerSupervisor.swift"),
                    str(ROOT / "tests/fixtures/native_log_supervisor_runner.swift"), "-o", str(owner)], check=True)
    subprocess.run([swiftc, str(shared), str(ROOT / "swift/Sources/ObstacleBridgeLogCollector/main.swift"), "-o", str(collector)], check=True)
    return str(owner), str(collector)


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_swift_host_logging_records_queries_and_restarts(native_log_binaries, implementation):
    async def exercise():
        owner, collector = native_log_binaries
        executable = sys.executable if implementation == "python" else collector
        host = await asyncio.create_subprocess_exec(owner, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

        async def command(value):
            host.stdin.write((value + "\n").encode())
            await host.stdin.drain()
            return json.loads(await asyncio.wait_for(host.stdout.readline(), 8))

        try:
            host.stdin.write((json.dumps({"implementation": implementation, "executable": executable}) + "\n").encode())
            await host.stdin.drain()
            ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 8))
            assert ready["state"] == "running" and ready["generation"] == 1
            assert ready["pid"] > 1 and ready["pid"] != host.pid
            host.stdin.write(b"record\n")
            await host.stdin.drain()
            for _ in range(60):
                result = await command("fetch")
                if any("desktop.test: private worker record" in line for line in result["lines"]):
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("native supervisor could not query the child log record")
            os.kill(ready["pid"], signal.SIGKILL)
            for _ in range(120):
                status = await command("status")
                if status["state"] == "running" and status["generation"] > 1:
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("selected logging implementation was not restarted")
            assert status["implementation"] == implementation
            assert status["restarts"] >= 1
            assert status["pid"] != ready["pid"]
            host.stdin.write(b"record\n")
            await host.stdin.drain()
            for _ in range(60):
                result = await command("fetch")
                if any("desktop.test: private worker record" in line for line in result["lines"]):
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("replacement collector did not receive records")
        finally:
            host.stdin.write(b"stop\n")
            await host.stdin.drain()
            await asyncio.wait_for(host.wait(), 8)
    asyncio.run(exercise())


@pytest.mark.parametrize(("configuration", "expected"), [
    ({}, "off"),
    ({"debug_logging": {"log_worker": " OFF "}}, "off"),
    ({"log_worker": "native"}, "enabled"),
    ({"debug_logging": {"log_worker": "python", "log_file": "/tmp/log"}}, "invalid"),
    ({"log_worker": "native", "log_udp_target": "127.0.0.1:1234"}, "invalid"),
    ({"log_worker": "native", "debug_stderr": True}, "invalid"),
    ({"log_worker": "other"}, "invalid"),
    ({"log_worker": 7}, "invalid"),
])
def test_swift_host_logging_configuration_fails_closed(native_log_binaries, configuration, expected):
    owner, _ = native_log_binaries
    completed = subprocess.run([owner], input=json.dumps({"configuration": configuration}) + "\n", text=True, capture_output=True, check=True, timeout=5)
    assert json.loads(completed.stdout)["selection"] == expected


@pytest.mark.parametrize(("configuration", "level"), [
    ({"log_worker": "native"}, 0),
    ({"log_worker": "native", "log_proxy_provider": "warning"}, 30),
    ({"log_worker": "native", "proxy_provider": {"log_proxy_provider": "DEBUG"}}, 10),
    ({"log_worker": "native", "proxy_provider": {"log_proxy_provider": "NOTSET"}}, 0),
    ({"log_worker": "native", "proxy_provider": {"log_proxy_provider": "invalid"}}, 0),
    ({"log_worker": "native", "proxy_provider": {"log_proxy_provider": None}}, 0),
])
def test_swift_host_proxy_log_level_configuration(native_log_binaries, configuration, level):
    owner, _ = native_log_binaries
    completed = subprocess.run([owner], input=json.dumps({"configuration": configuration}) + "\n", text=True, capture_output=True, check=True, timeout=5)
    assert json.loads(completed.stdout)["proxy_log_level"] == level


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_swift_host_logging_drops_when_collector_stalls(native_log_binaries, implementation):
    async def exercise():
        owner, collector = native_log_binaries
        executable = sys.executable if implementation == "python" else collector
        host = await asyncio.create_subprocess_exec(owner, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        child_pid = None
        try:
            host.stdin.write((json.dumps({"implementation": implementation, "executable": executable}) + "\n").encode())
            await host.stdin.drain()
            ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 8))
            child_pid = ready["pid"]
            assert child_pid > 1 and child_pid != host.pid
            os.kill(child_pid, signal.SIGSTOP)
            host.stdin.write(b"burst\n")
            await host.stdin.drain()
            burst = json.loads(await asyncio.wait_for(host.stdout.readline(), 8))
            assert burst["elapsed_ms"] < 5000
            assert burst["status"]["dropped_records"] > 0
            os.kill(child_pid, signal.SIGCONT)
            child_pid = None
        finally:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGCONT)
            host.stdin.write(b"stop\n")
            await host.stdin.drain()
            await asyncio.wait_for(host.wait(), 8)
    asyncio.run(exercise())


@pytest.mark.parametrize("implementation", ["python", "native"])
def test_swift_logging_child_exits_on_owner_loss(native_log_binaries, implementation):
    async def exercise():
        owner, collector = native_log_binaries
        executable = sys.executable if implementation == "python" else collector
        host = await asyncio.create_subprocess_exec(owner, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        host.stdin.write((json.dumps({"implementation": implementation, "executable": executable}) + "\n").encode())
        await host.stdin.drain()
        ready = json.loads(await asyncio.wait_for(host.stdout.readline(), 8))
        child_pid = ready["pid"]
        assert child_pid > 1 and child_pid != host.pid
        host.kill()
        await asyncio.wait_for(host.wait(), 8)
        for _ in range(120):
            state = subprocess.run(["ps", "-p", str(child_pid), "-o", "stat="], text=True, capture_output=True).stdout.strip()
            if not state or state.startswith("Z"):
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("logging child survived supervisor loss")
    asyncio.run(exercise())
