from __future__ import annotations

import asyncio
import json
import logging
import os
import argparse
import socket
import struct
import subprocess
import sys

import pytest
import websockets

from obstacle_bridge.bridge import Runner, build_runtime_args_from_config
from obstacle_bridge.bridge_admin_worker import AdminWorker, MAX_FRAME, _read_frame, _RemoteRunner
from obstacle_bridge.bridge_logging_worker import activate_managed_logging

pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix worker")


def _runner(auth=False):
    args = build_runtime_args_from_config({"admin_web": {
        "admin_web": True, "admin_web_bind": "127.0.0.1", "admin_web_port": 0,
        "admin_web_worker": "python", "admin_web_auth_disable": not auth,
        "admin_web_username": "operator" if auth else "",
        "admin_web_password": "secret-not-on-command-line" if auth else "",
    }})
    return Runner(args)


async def _request(port, path, updates=None):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        body = json.dumps({"updates": updates}).encode() if updates is not None else b""
        method = "POST" if updates is not None else "GET"
        writer.write(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 4)
        head, body = response.split(b"\r\n\r\n", 1)
        return int(head.split()[1]), json.loads(body)
    finally:
        writer.close()
        await writer.wait_closed()


def test_python_admin_worker_serves_runner_config_and_authenticates():
    async def exercise():
        runner = _runner()
        worker = AdminWorker(runner, runner.args)
        await worker.start()
        try:
            assert worker.process.pid != os.getpid()
            status, payload = await _request(worker.port, "/api/config")
            assert status == 200
            assert payload["ok"] and payload["config"]["admin_web_worker"] == "python"
            assert payload["schema"]
        finally:
            await worker.stop()
        assert worker.process.returncode == 0
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", worker.port)

        runner = _runner(auth=True)
        worker = AdminWorker(runner, runner.args)
        await worker.start()
        try:
            command = subprocess.check_output(["ps", "-p", str(worker.process.pid), "-o", "command="], text=True)
            assert "secret-not-on-command-line" not in command
            status, payload = await _request(worker.port, "/api/config")
            assert status == 401 and not payload["authenticated"]
        finally:
            await worker.stop()
    asyncio.run(exercise())


def test_python_admin_worker_updates_runner_and_serves_concurrent_requests(monkeypatch):
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    async def exercise():
        runner = _runner()
        runner.save_runtime_config = lambda: (True, "")
        worker = AdminWorker(runner, runner.args)
        runner.admin_web = worker
        await worker.start()
        try:
            status, result = await _request(worker.port, "/api/config", {"admin_web_name": "Updated Node"})
            assert status == 200 and result["ok"]
            assert runner.args.admin_web_name == "Updated Node"
            responses = await asyncio.gather(*[_request(worker.port, "/api/config") for _ in range(4)])
            assert all(status == 200 and data["config"]["admin_web_name"] == "Updated Node" for status, data in responses)
            status, data = await _request(worker.port, "/api/status")
            assert status == 200 and data["admin_web_worker"] == {
                "implementation": "python", "state": "running", "generation": 1, "restarts": 0, "failed_starts": 0,
            }
            status, data = await _request(worker.port, "/api/logs")
            assert status == 200 and data["ok"] and data["source"] == "local"
            async with websockets.connect(f"ws://127.0.0.1:{worker.port}/api/live") as ws:
                await ws.send(json.dumps({"subscribe": ["status"], "request": ["status"]}))
                for _ in range(5):
                    message = json.loads(await asyncio.wait_for(ws.recv(), 3))
                    if message.get("type") == "status":
                        break
                assert message["type"] == "status"
        finally:
            await worker.stop()
    asyncio.run(exercise())


def test_admin_worker_exits_on_owner_loss_and_reports_child_loss():
    async def exercise():
        runner = _runner()
        worker = AdminWorker(runner, runner.args)
        runner.admin_web = worker
        await worker.start()
        worker.lifetime.close()
        assert await asyncio.wait_for(worker.process.wait(), 3) == 0
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", worker.port)
        await worker.stop()

        worker = AdminWorker(runner, runner.args)
        await worker.start()
        worker.process.kill()
        await worker.process.wait()
        for _ in range(30):
            if worker.last_error:
                break
            await asyncio.sleep(0.05)
        assert worker.last_error == "Admin worker unavailable"
        assert runner.get_status_snapshot()["admin_web_worker"]["state"] == "unavailable"
        await worker.stop()
    asyncio.run(exercise())


@pytest.mark.parametrize("loss", ["process", "control"])
def test_supervised_admin_recovers_at_same_port_with_authentication(loss):
    async def exercise():
        runner = _runner(auth=True)
        worker = AdminWorker(runner, runner.args, supervised=True)
        runner.admin_web = worker
        await worker.start()
        old = worker.process
        original_port = worker.port
        try:
            if loss == "process":
                old.kill()
            else:
                worker.writer.close()
            for _ in range(150):
                if worker.generation >= 2 and worker.process.returncode is None:
                    break
                await asyncio.sleep(0.05)
            assert worker.generation >= 2 and worker.restarts >= 1
            assert worker.process.pid != old.pid and old.returncode is not None
            assert worker.port == original_port
            status, payload = await _request(original_port, "/api/config")
            assert status == 401 and not payload["authenticated"]
            snapshot = runner.get_status_snapshot()["admin_web_worker"]
            assert snapshot["state"] == "running" and snapshot["generation"] >= 2 and snapshot["restarts"] >= 1
        finally:
            await worker.stop()
        assert worker.process.returncode is not None
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", original_port)
    asyncio.run(exercise())


def test_supervised_admin_retries_failed_bind_and_stops_without_orphans():
    async def exercise():
        runner = _runner()
        worker = AdminWorker(runner, runner.args, supervised=True)
        await worker.start()
        port = worker.port
        old = worker.process
        reserved = socket.socket()
        reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            old.kill()
            await old.wait()
            reserved.bind(("127.0.0.1", port))
            reserved.listen()
            for _ in range(120):
                if worker.failed_starts:
                    break
                await asyncio.sleep(0.05)
            assert worker.failed_starts >= 1 and worker.generation == 1
            reserved.close()
            for _ in range(160):
                if worker.generation >= 2 and worker.process.returncode is None:
                    break
                await asyncio.sleep(0.05)
            assert worker.generation >= 2 and worker.port == port
            status, _ = await _request(port, "/api/config")
            assert status == 200
        finally:
            reserved.close()
            await worker.stop()
        assert worker.process.returncode is not None
    asyncio.run(exercise())


def test_supervised_admin_stop_cancels_pending_restart(monkeypatch):
    async def exercise():
        runner = _runner()
        worker = AdminWorker(runner, runner.args, supervised=True)
        await worker.start()
        old = worker.process
        entered = asyncio.Event()

        async def stalled_restart():
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(worker, "_start_child", stalled_restart)
        try:
            old.kill()
            await asyncio.wait_for(entered.wait(), 5)
            await asyncio.wait_for(worker.stop(), 2)
            assert old.returncode is not None and worker._monitor is None
            assert worker.generation == 1 and worker.restarts == 0
        finally:
            await worker.stop()
    asyncio.run(exercise())


def test_admin_worker_rejects_oversized_frame_before_body():
    async def exercise():
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", MAX_FRAME + 1))
        with pytest.raises(ValueError, match="frame size"):
            await asyncio.wait_for(_read_frame(reader), 0.2)
    asyncio.run(exercise())


def test_admin_worker_rejects_embedded_restart_callback():
    async def exercise():
        runner = _runner()
        runner._embedded_restart_callback = lambda *_: None
        worker = AdminWorker(runner, runner.args)
        with pytest.raises(ValueError, match="embedded restart"):
            await worker.start()
        assert worker.process is None
    asyncio.run(exercise())


def test_admin_worker_timeout_fences_late_reply():
    client, server = socket.socketpair()
    try:
        proxy = _RemoteRunner(client, argparse.Namespace())
        with pytest.raises(TimeoutError):
            proxy.get_status_snapshot()
        with pytest.raises(TimeoutError, match="unavailable"):
            proxy.get_connections_snapshot()
        assert proxy._failed
    finally:
        client.close()
        server.close()


def test_admin_worker_failed_listener_start_leaves_no_child():
    async def exercise():
        runner = _runner()
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            reserved.listen()
            runner.args.admin_web_port = reserved.getsockname()[1]
            worker = AdminWorker(runner, runner.args)
            with pytest.raises(Exception):
                await worker.start()
            assert worker.process.returncode is not None
    asyncio.run(exercise())


def test_runner_selects_and_stops_admin_worker(monkeypatch, tmp_path):
    monkeypatch.setenv("OBSTACLEBRIDGE_RUNTIME_HEALTH_PATH", str(tmp_path / "health.json"))
    monkeypatch.setattr(Runner, "build_sessions_from_overlay", staticmethod(lambda _args: []))

    async def exercise():
        runner = _runner()
        runner.args.status = False
        runner.stats.bind_session = lambda _session: None
        try:
            await runner.start()
            worker = runner.admin_web
            assert isinstance(worker, AdminWorker)
            status, data = await _request(worker.port, "/api/config")
            assert status == 200 and data["config"]["admin_web_worker"] == "python"
            old = worker.process
            port = worker.port
            old.kill()
            for _ in range(150):
                if worker.generation >= 2 and worker.process.returncode is None:
                    break
                await asyncio.sleep(0.05)
            assert worker.generation >= 2 and old.returncode is not None and worker.port == port
            status, data = await _request(port, "/api/status")
            assert status == 200 and data["admin_web_worker"]["restarts"] >= 1
        finally:
            await runner.stop()
        assert worker.process.returncode is not None
        assert runner.admin_web is None
    asyncio.run(exercise())


def test_admin_child_queries_python_logging_child(monkeypatch):
    runner = _runner()
    runner.args.log_worker = "python"
    runner.args.log_file = None
    runner.args.proxy_provider_auth = {"mode": "basic", "username": "user", "token": "config-token-must-not-be-logged"}
    monkeypatch.setattr(logging.getLogger(), "level", logging.INFO)
    with activate_managed_logging(runner.args) as logs:
        logs.handler.emit(logging.LogRecord("admin.ipc.test", logging.WARNING, __file__, 1, "child query marker", (), None))

        async def exercise():
            worker = AdminWorker(runner, runner.args)
            await worker.start()
            try:
                status, data = await _request(worker.port, "/api/logs")
                assert status == 200 and data["available"]
                assert data["source"] == "managed"
                assert data["logging_worker"]["state"] == "running"
                assert any("child query marker" in line for line in data["lines"])
                await _request(worker.port, "/api/config")
                await _request(worker.port, "/api/auth/state")
                for _ in range(30):
                    data = await asyncio.to_thread(logs.fetch, 100)
                    if any("ADMIN REQUEST method=GET path=/api/auth/state" in line for line in data["lines"]):
                        break
                    await asyncio.sleep(0.05)
                assert any("ADMIN REQUEST method=GET path=/api/auth/state" in line for line in data["lines"])
                responses = [line for line in data["lines"] if "ADMIN RESPONSE path=/api/logs" in line]
                assert responses and all("child query marker" not in line for line in responses)
                assert "config-token-must-not-be-logged" not in repr(data["lines"])
                logs.process.kill()
                for _ in range(100):
                    if logs.status()["generation"] >= 2 and logs.status()["state"] == "running":
                        break
                    await asyncio.sleep(0.05)
                assert logs.status()["generation"] >= 2
                await _request(worker.port, "/api/auth/state")
                for _ in range(30):
                    data = await asyncio.to_thread(logs.fetch, 100)
                    if any("ADMIN REQUEST method=GET path=/api/auth/state" in line for line in data["lines"]):
                        break
                    await asyncio.sleep(0.05)
                assert any("ADMIN REQUEST method=GET path=/api/auth/state" in line for line in data["lines"])
            finally:
                await worker.stop()
        asyncio.run(exercise())
