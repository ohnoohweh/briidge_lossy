from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix workers")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def native_supervisor(tmp_path_factory):
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("Swift compiler required")
    binary = tmp_path_factory.mktemp("proxy-supervisor") / "supervisor"
    subprocess.run([swiftc, str(ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeProxyWorkerSupervisor.swift"),
                    str(ROOT / "tests/fixtures/native_proxy_supervisor_runner.swift"), "-o", str(binary)], check=True)
    return str(binary)


def _config():
    return {"bind": "127.0.0.1", "http_port": 0, "socks5_port": 0, "protocols": ["http-connect"],
            "auth": {"mode": "basic", "username": "user", "token": "secret-not-in-process-arguments"},
            "egress": {"mode": "direct"}, "policy": {"allow_private_destinations": True, "blocked_host_patterns": []}}


@pytest.mark.parametrize("implementation", ["python", "native"])
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
            assert ready["worker"]["state"] == "running"
            assert ready["worker"]["pid"] != host.pid
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
            for _ in range(60):
                host.stdin.write(b"status\n")
                await host.stdin.drain()
                status = json.loads(await asyncio.wait_for(host.stdout.readline(), 5))
                if status["worker"]["state"] == "unavailable":
                    break
                await asyncio.sleep(0.05)
            assert status["worker"]["state"] == "unavailable"
            assert status["listeners"] == {}
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
def test_restricted_policy_fails_closed(native_supervisor, native_proxy_worker_executable, implementation):
    config = _config()
    config["policy"]["allow_private_destinations"] = False
    executable = sys.executable if implementation == "python" else native_proxy_worker_executable
    result = subprocess.run([native_supervisor], input=json.dumps({"implementation": implementation, "executable": executable, "config": config}) + "\n", text=True, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert json.loads(result.stdout) == {"error": "worker startup failed"}
    assert "secret-not-in-process-arguments" not in result.stderr
