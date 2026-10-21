from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys

import pytest

from obstacle_bridge.bridge import Runner, build_runtime_args_from_config
from obstacle_bridge.bridge_peer_worker import PeerStackWorker, _read_frame, _write_frame


pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix worker")


def _reserved_ports() -> tuple[int, int]:
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        return first.getsockname()[1], second.getsockname()[1]


@pytest.mark.parametrize("ending", ["owner-loss", "stale-generation", "explicit-restart"])
def test_python_peer_worker_carries_secure_mux_traffic_and_owner_loss(ending):
    async def exercise():
        async def echo(reader, writer):
            try:
                data = await reader.read(4096)
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        overlay_port, service_port = _reserved_ports()
        secret = "peer-worker-secret-not-in-process-arguments"
        secure = {"secure_link": True, "secure_link_mode": "psk", "secure_link_psk": secret}
        listener_args = build_runtime_args_from_config({
            "runner": {"overlay_transport": "tcp"},
            "tcp_session": {"tcp_bind": "127.0.0.1", "tcp_own_port": overlay_port},
            "secure_link": secure, "TUN_routing": {"enabled_on_startup": False},
        })
        listener_args.admin_web = False
        listener_args.status = False
        listener = Runner(listener_args)
        worker = PeerStackWorker("peer-test")
        try:
            await listener.start()
            configuration = {
                "runner": {"overlay_transport": "tcp"},
                "tcp_session": {"tcp_peer": "127.0.0.1", "tcp_peer_port": overlay_port},
                "secure_link": secure,
                "channel_mux": {"own_servers": [{"name": "peer-worker-echo",
                    "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": service_port},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": target_port}}]},
            }
            await worker.start(configuration)
            child = worker.process
            assert child is not None and child.pid > 1 and child.pid != os.getpid()
            command = subprocess.check_output(["ps", "-p", str(child.pid), "-o", "command="], text=True)
            assert secret not in command
            for _ in range(120):
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", service_port), 1)
                    writer.write(b"peer-process-secure-traffic")
                    await writer.drain()
                    result = await asyncio.wait_for(reader.readexactly(27), 2)
                    writer.close()
                    await writer.wait_closed()
                    if result == b"peer-process-secure-traffic":
                        break
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    await asyncio.sleep(0.1)
            else:
                pytest.fail("isolated peer did not forward secure ChannelMux traffic")
            status = await worker.snapshot()
            assert secret not in json.dumps(status)
            layers = next(item["layers"] for item in status["connection_layers"] if item.get("transport") == "tcp")
            assert any(layer.get("layer") == "secure_link" and layer.get("app_ready") for layer in layers), layers
            assert any(layer.get("layer") == "compression" and layer.get("app_ready") for layer in layers), layers
            assert worker._writer is not None and worker._reader is not None
            if ending == "owner-loss":
                worker._writer.close()
                await worker._writer.wait_closed()
                assert await asyncio.wait_for(child.wait(), 15) == 0
            elif ending == "stale-generation":
                await _write_frame(worker._writer, {"v": 1, "kind": "peer.snapshot", "peer_id": worker.peer_id,
                                                   "generation": worker.generation + 1, "id": "stale"})
                response = await asyncio.wait_for(_read_frame(worker._reader), 3)
                assert response == {"v": 1, "kind": "peer.error", "error": "peer worker failed"}
                assert await asyncio.wait_for(child.wait(), 15) == 0
            else:
                await worker.stop()
                assert child.returncode == 0
                await worker.start(configuration)
                assert worker.generation == 2 and worker.process.pid != child.pid
                assert secret not in json.dumps(await worker.snapshot())
        finally:
            await worker.stop()
            await listener.stop(reason="peer-worker-test")
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())


@pytest.mark.parametrize("failure_signal", [signal.SIGKILL, signal.SIGSTOP], ids=["killed", "unresponsive"])
def test_python_runner_supervises_peer_worker_and_recovers_secure_service(failure_signal):
    async def exercise():
        async def echo(reader, writer):
            try:
                data = await reader.read(4096)
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        overlay_port, service_port = _reserved_ports()
        admin_port = 0
        while admin_port in {0, overlay_port, service_port, target_port}:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                admin_port = reservation.getsockname()[1]
        secret = "peer-supervisor-secret-not-in-status"
        secure = {"secure_link": True, "secure_link_mode": "psk", "secure_link_psk": secret}
        common = {"secure_link": secure, "TUN_routing": {"enabled_on_startup": False}}
        listener_args = build_runtime_args_from_config({**common,
            "runner": {"overlay_transport": "tcp"},
            "tcp_session": {"tcp_bind": "127.0.0.1", "tcp_own_port": overlay_port}})
        client_args = build_runtime_args_from_config({**common,
            "runner": {"overlay_transport": "tcp", "peer_stack_worker": "python"},
            "admin_web": {"admin_web_bind": "127.0.0.1", "admin_web_port": admin_port,
                          "admin_web_auth_disable": True},
            "tcp_session": {"tcp_peer": "127.0.0.1", "tcp_peer_port": overlay_port},
            "channel_mux": {"own_servers": [{"name": "supervised-echo",
                "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": service_port},
                "target": {"protocol": "tcp", "host": "127.0.0.1", "port": target_port}}]}})
        listener_args.admin_web = False
        listener_args.status = client_args.status = False
        listener, client = Runner(listener_args), Runner(client_args)

        async def exchange():
            for _ in range(120):
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", service_port), 1)
                    try:
                        writer.write(b"supervised-peer-traffic")
                        await writer.drain()
                        if await asyncio.wait_for(reader.readexactly(23), 2) == b"supervised-peer-traffic":
                            return
                    finally:
                        writer.close()
                        await writer.wait_closed()
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    await asyncio.sleep(0.1)
            pytest.fail("supervised peer did not forward traffic")

        async def admin_json(path):
            reader, writer = await asyncio.open_connection("127.0.0.1", admin_port)
            try:
                writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 5)
                head, body = response.split(b"\r\n\r\n", 1)
                assert head.startswith(b"HTTP/1.1 200"), head
                return json.loads(body)
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            await listener.start()
            await client.start()
            await exchange()
            status = client.get_status_snapshot()
            initial = status["peer_stack_worker"]
            assert initial["state"] == "running" and initial["generation"] == 1
            assert initial["pid"] > 1 and initial["pid"] != os.getpid()
            assert secret not in json.dumps(status)
            assert (await admin_json("/api/status"))["peer_stack_worker"]["generation"] == 1
            assert "tcp" in await admin_json("/api/connections")
            assert "peers" in await admin_json("/api/peers")
            assert client.request_overlay_reconnect()["reason"] == "peer_worker_control_not_supported"
            assert client.request_secure_link_rekey()["error"] == "peer_worker_control_not_supported"
            assert client.request_secure_link_reload("all")["reason"] == "peer_worker_control_not_supported"
            ok, message = client.update_config({"tcp_session": {"tcp_peer": "192.0.2.1"}})
            assert not ok and "restarting" in message and client.args.tcp_peer == "127.0.0.1"
            os.kill(initial["pid"], failure_signal)
            unavailable = False
            for _ in range(500):
                status = client.get_status_snapshot()
                current = status["peer_stack_worker"]
                unavailable |= current["state"] == "unavailable"
                if current["state"] == "running" and current["generation"] > initial["generation"]:
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("peer supervisor did not replace its failed child")
            assert current["pid"] != initial["pid"] and current["restarts"] >= 1
            if failure_signal == signal.SIGSTOP:
                assert unavailable, "timed-out peer snapshots must be fenced before replacement"
            await exchange()
            assert secret not in json.dumps(client.get_status_snapshot())
            assert (await admin_json("/api/status"))["peer_stack_worker"]["generation"] == current["generation"]
        finally:
            await client.stop(reason="peer-supervisor-test")
            await listener.stop(reason="peer-supervisor-test")
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())


def test_python_peer_worker_exits_when_supervisor_is_killed():
    async def exercise():
        program = (
            "import asyncio,json,sys\n"
            "from obstacle_bridge.bridge_peer_worker import PeerStackWorker\n"
            "async def run():\n"
            " w=PeerStackWorker('owner-loss'); await w.start(json.loads(sys.stdin.readline()))\n"
            " print(w.process.pid,flush=True); await asyncio.Event().wait()\n"
            "asyncio.run(run())\n"
        )
        owner = await asyncio.create_subprocess_exec(sys.executable, "-c", program, stdin=asyncio.subprocess.PIPE,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        child_pid = None
        try:
            owner.stdin.write((json.dumps({"runner": {"overlay_transport": "tcp"},
                                           "tcp_session": {"tcp_peer": "127.0.0.1", "tcp_peer_port": 9}}) + "\n").encode())
            await owner.stdin.drain()
            child_pid = int(await asyncio.wait_for(owner.stdout.readline(), 20))
            assert child_pid > 1 and child_pid not in {owner.pid, os.getpid()}
            owner.kill()
            await asyncio.wait_for(owner.wait(), 5)
            for _ in range(150):
                state = subprocess.run(["ps", "-p", str(child_pid), "-o", "stat="], text=True, capture_output=True).stdout.strip()
                if not state or state.startswith("Z"):
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("peer child survived supervisor loss")
            child_pid = None
        finally:
            if owner.returncode is None:
                owner.kill()
                await owner.wait()
            if child_pid is not None:
                command = subprocess.run(["ps", "-p", str(child_pid), "-o", "command="], text=True, capture_output=True).stdout
                if "obstacle_bridge.bridge_peer_worker" in command:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(child_pid, signal.SIGKILL)
    asyncio.run(exercise())


@pytest.mark.parametrize("admin_worker", ["off", "python"])
def test_module_entrypoint_supervises_peer_worker(tmp_path, admin_worker):
    async def exercise():
        async def echo(reader, writer):
            try:
                writer.write(await reader.read(4096))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        overlay_port, service_port = _reserved_ports()
        admin_port = 0
        while admin_port in {0, overlay_port, service_port, target_port}:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                admin_port = reservation.getsockname()[1]
        secret = "entrypoint-peer-secret-not-in-status"
        secure = {"secure_link": True, "secure_link_mode": "psk", "secure_link_psk": secret}
        listener_args = build_runtime_args_from_config({"runner": {"overlay_transport": "tcp"},
            "tcp_session": {"tcp_bind": "127.0.0.1", "tcp_own_port": overlay_port},
            "secure_link": secure, "TUN_routing": {"enabled_on_startup": False}})
        listener_args.admin_web = listener_args.status = False
        listener = Runner(listener_args)
        config_path = tmp_path / "peer-worker.json"
        config_path.write_text(json.dumps({"runner": {"overlay_transport": "tcp", "peer_stack_worker": "python"},
            "tcp_session": {"tcp_peer": "127.0.0.1", "tcp_peer_port": overlay_port},
            "secure_link": secure, "TUN_routing": {"enabled_on_startup": False},
            "admin_web": {"admin_web_bind": "127.0.0.1", "admin_web_port": admin_port, "admin_web_auth_disable": True,
                          "admin_web_worker": admin_worker},
            "stats_board": {"status": False},
            "channel_mux": {"own_servers": [{"name": "entrypoint-echo",
                "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": service_port},
                "target": {"protocol": "tcp", "host": "127.0.0.1", "port": target_port}}]}}), encoding="utf-8")
        launcher = None

        async def request(path, payload=None):
            reader, writer = await asyncio.open_connection("127.0.0.1", admin_port)
            try:
                body = json.dumps(payload).encode() if payload is not None else b""
                method = "POST" if payload is not None else "GET"
                writer.write(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 5)
                head, body = response.split(b"\r\n\r\n", 1)
                return int(head.split()[1]), json.loads(body)
            finally:
                writer.close()
                await writer.wait_closed()

        async def status():
            code, payload = await request("/api/status")
            assert code == 200
            return payload

        async def authenticated_peer(previous_session=0):
            for _ in range(200):
                code, payload = await request("/api/peers")
                assert code == 200
                for row in payload.get("peers", []):
                    session = int((row.get("secure_link") or {}).get("session_id") or 0)
                    if row.get("id") and session and session != previous_session:
                        return str(row["id"]), session
                await asyncio.sleep(0.05)
            pytest.fail("isolated peer did not authenticate a new SecureLink session")

        async def wait_generation(after):
            for _ in range(200):
                try:
                    payload = await status()
                    worker = payload.get("peer_stack_worker", {})
                    if worker.get("state") == "running" and worker.get("generation", 0) > after:
                        assert secret not in json.dumps(payload)
                        return worker
                except (OSError, asyncio.TimeoutError, ValueError):
                    pass
                await asyncio.sleep(0.05)
            pytest.fail("module entrypoint did not publish the peer worker")

        async def exchange():
            for _ in range(120):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", service_port)
                    try:
                        writer.write(b"module-peer-traffic")
                        await writer.drain()
                        if await asyncio.wait_for(reader.readexactly(19), 2) == b"module-peer-traffic":
                            return
                    finally:
                        writer.close()
                        await writer.wait_closed()
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    await asyncio.sleep(0.1)
            pytest.fail("module entrypoint peer did not forward traffic")

        try:
            await listener.start()
            launcher = await asyncio.create_subprocess_exec(sys.executable, "-m", "obstacle_bridge", "--config", str(config_path),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True)
            initial = await wait_generation(0)
            await exchange()
            peer_id, session = await authenticated_peer()
            code, payload = await request("/api/secure-link/rekey", {"peer_id": peer_id})
            assert code == 200 and payload.get("ok") is True and payload.get("requested") == 1, payload
            await authenticated_peer(session)
            await exchange()
            code, payload = await request("/api/secure-link/reload", {"scope": "all", "peer_id": peer_id})
            assert code == 409 and payload.get("requested") == 1 and payload.get("failed") == 1, payload
            assert payload["results"][0]["reason"] == "secure_link_cert_mode_required"
            code, payload = await request("/api/secure-link/reload", {"scope": "all", "peer_id": peer_id + "-missing"})
            assert code == 409 and payload.get("reason") == "unknown_peer_id", payload
            code, payload = await request("/api/reconnect", {"peer_id": peer_id + "-missing"})
            assert code == 404 and payload.get("reason") == "unknown_peer_id", payload
            code, payload = await request("/api/reconnect", {"peer_id": peer_id})
            assert code == 200 and payload.get("ok") is True and payload.get("requested") == 1, payload
            await exchange()
            assert initial["pid"] > 1 and initial["pid"] not in {os.getpid(), launcher.pid}
            os.kill(initial["pid"], signal.SIGKILL)
            current = await wait_generation(initial["generation"])
            assert current["pid"] != initial["pid"] and current["restarts"] >= 1
            await exchange()
        finally:
            if launcher is not None and launcher.returncode is None:
                os.killpg(launcher.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(launcher.wait(), 8)
                except asyncio.TimeoutError:
                    os.killpg(launcher.pid, signal.SIGKILL)
                    await launcher.wait()
            await listener.stop(reason="module-peer-test")
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())
