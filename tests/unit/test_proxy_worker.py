from __future__ import annotations

import asyncio
import base64
import os
import socket
import struct
import subprocess
import sys

import pytest

from obstacle_bridge.bridge import Runner, build_runtime_args_from_config
from obstacle_bridge.bridge_proxy_worker import MAX_FRAME, ProxyWorker, _read_frame

pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="proxy worker requires desktop Unix sockets")


@pytest.fixture(params=["python", "native"])
def backend(request):
    return request.param, request.getfixturevalue("native_proxy_worker_executable") if request.param == "native" else None


def _config(**overrides):
    cfg = {"enabled": True, "bind": "127.0.0.1", "http_port": 0, "socks5_port": 0,
           "protocols": ["http-connect", "socks5-connect"],
           "auth": {"mode": "basic", "username": "user", "token": "private-token"},
           "egress": {"mode": "direct"}, "policy": {"allow_private_destinations": True, "blocked_host_patterns": []}}
    cfg.update(overrides)
    return cfg


async def _echo(reader, writer):
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def _http_tunnel(proxy_port, target_port, authorized):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    token = base64.b64encode(b"user:private-token").decode()
    auth = f"Proxy-Authorization: bAsIc {token}\r\n" if authorized else ""
    writer.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n".encode())
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
    if authorized:
        assert response.startswith(b"HTTP/1.1 200")
        writer.write(b"http-data")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(9), 3) == b"http-data"
    else:
        assert response.startswith(b"HTTP/1.1 407")
    writer.close()
    await writer.wait_closed()


async def _socks_tunnel(proxy_port, target_port):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x02"
    for byte in b"\x01\x04user\x0dprivate-token":
        writer.write(bytes([byte]))
        await writer.drain()
    assert await reader.readexactly(2) == b"\x01\x00"
    writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
    await writer.drain()
    assert (await reader.readexactly(10))[:2] == b"\x05\x00"
    writer.write(b"socks-data")
    await writer.drain()
    assert await reader.readexactly(10) == b"socks-data"
    writer.close()
    await writer.wait_closed()


def test_runner_proxy_child_owns_http_socks_and_snapshots(backend):
    async def exercise():
        args = build_runtime_args_from_config({"proxy_provider": {
            "proxy_provider_enabled": True, "proxy_provider_worker": backend[0], "proxy_provider_bind": "127.0.0.1",
            "proxy_provider_worker_native_executable": backend[1],
            "proxy_provider_http_port": 0, "proxy_provider_socks5_port": 0,
            "proxy_provider_protocols": ["http-connect", "socks5-connect"],
            "proxy_provider_auth": {"mode": "basic", "username": "user", "token": "private-token"},
            "proxy_provider_egress": {"mode": "direct"},
            "proxy_provider_policy": {"allow_private_destinations": True, "blocked_host_patterns": []},
        }})
        runner = Runner(args)
        target = await asyncio.start_server(_echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        await runner._start_proxy_provider()
        worker = runner._proxy_provider_worker
        try:
            assert worker.process.pid != os.getpid()
            command = subprocess.check_output(["ps", "-p", str(worker.process.pid), "-o", "command="], text=True)
            assert "private-token" not in command
            snap = runner._proxy_provider_snapshot()
            assert snap["worker"] == {"implementation": backend[0], "state": "running"}
            http = snap["listeners"]["http"]["bound_port"]
            socks = snap["listeners"]["socks5"]["bound_port"]
            await _http_tunnel(http, target_port, False)
            await _http_tunnel(http, target_port, True)
            await _socks_tunnel(socks, target_port)
            for _ in range(30):
                snap = runner._proxy_provider_snapshot()
                if snap["listeners"]["http"]["accepted_connections"] >= 2 and snap["listeners"]["socks5"]["accepted_connections"] >= 1:
                    break
                await asyncio.sleep(0.05)
            assert snap["listeners"]["http"]["accepted_connections"] == 2
            assert snap["listeners"]["socks5"]["accepted_connections"] == 1
            assert "private-token" not in repr(snap["listeners"])
        finally:
            await runner._stop_proxy_provider()
            target.close()
            await target.wait_closed()
        assert worker.process.returncode == 0
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", http)
    asyncio.run(exercise())


def test_proxy_worker_owner_loss_closes_listeners(backend):
    async def exercise():
        worker = ProxyWorker(*backend)
        await worker.start(_config())
        port = worker.listeners["http"]["bound_port"]
        worker.writer.close()
        await worker.writer.wait_closed()
        assert await asyncio.wait_for(worker.process.wait(), 3) == 0
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", port)
        await worker.stop()
    asyncio.run(exercise())


def test_proxy_worker_failed_start_cleans_up_and_never_uses_incomplete_auth(backend):
    async def exercise():
        worker = ProxyWorker(*backend)
        with pytest.raises(Exception):
            await worker.start(_config(auth={"mode": "basic", "username": "user", "token": ""}))
        assert worker.process.returncode is not None
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            reserved.listen()
            worker = ProxyWorker(*backend)
            with pytest.raises(Exception):
                await worker.start(_config(socks5_port=reserved.getsockname()[1]))
            assert worker.process.returncode is not None
    asyncio.run(exercise())


def test_runner_reports_lost_proxy_worker_without_in_process_fallback(backend):
    async def exercise():
        args = build_runtime_args_from_config({"proxy_provider": {"proxy_provider_enabled": True,
            "proxy_provider_worker": backend[0], "proxy_provider_bind": "127.0.0.1",
            "proxy_provider_worker_native_executable": backend[1], "proxy_provider_egress": {"mode": "direct"},
            "proxy_provider_http_port": 0, "proxy_provider_protocols": ["http-connect"],
            "proxy_provider_policy": {"allow_private_destinations": True, "blocked_host_patterns": []}}})
        runner = Runner(args)
        await runner._start_proxy_provider()
        worker = runner._proxy_provider_worker
        try:
            worker.process.kill()
            await worker.process.wait()
            for _ in range(30):
                if worker.last_error:
                    break
                await asyncio.sleep(0.05)
            snapshot = runner._proxy_provider_snapshot()
            assert snapshot["worker"]["state"] == "unavailable"
            assert snapshot["last_error"] == "proxy worker unavailable"
            assert snapshot["listeners"] == {}
            assert runner._proxy_provider_servers == {}
        finally:
            await runner._stop_proxy_provider()
    asyncio.run(exercise())


def test_proxy_control_rejects_oversize_header_without_waiting_for_body():
    async def exercise():
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", MAX_FRAME + 1))
        with pytest.raises(ValueError, match="frame size"):
            await asyncio.wait_for(_read_frame(reader), timeout=0.1)
    asyncio.run(exercise())


def test_runner_rejects_unknown_proxy_worker_selection():
    async def exercise():
        args = build_runtime_args_from_config({})
        args.proxy_provider_worker = "unknown"
        runner = Runner(args)
        with pytest.raises(ValueError, match="unsupported proxy worker"):
            await runner._start_proxy_provider()
        assert runner._proxy_provider_servers == {}
    asyncio.run(exercise())


def test_proxy_worker_fails_closed_on_unimplemented_destination_restrictions(backend):
    async def exercise():
        for policy in ({}, {"allow_private_destinations": False, "blocked_host_patterns": []},
                       {"allow_private_destinations": True, "blocked_host_patterns": ["*.example"]},
                       {"allow_private_destinations": True, "blocked_host_patterns": [], "future_rule": True}):
            worker = ProxyWorker(*backend)
            with pytest.raises(ValueError, match="policy"):
                await worker.start(_config(policy=policy))
            assert worker.process is None
        args = build_runtime_args_from_config({"proxy_provider": {"proxy_provider_enabled": True,
            "proxy_provider_worker": "python", "proxy_provider_protocols": ["http-connect"]}})
        runner = Runner(args)
        with pytest.raises(ValueError, match="policy"):
            await runner._start_proxy_provider()
        assert runner._proxy_provider_snapshot()["last_error"] == "proxy worker destination policy unsupported"
        assert runner._proxy_provider_servers == {}
    asyncio.run(exercise())


def test_native_proxy_worker_rejects_unimplemented_egress_and_bind(native_proxy_worker_executable):
    async def exercise():
        for changes in ({"egress": {"mode": "system"}}, {"bind": "0.0.0.0"},
                        {"egress": {"mode": "direct", "address_families": ["ipv4"]}},
                        {"egress": {"mode": "direct", "proxy_host": "host"}}):
            worker = ProxyWorker("native", native_proxy_worker_executable)
            with pytest.raises(ValueError, match="loopback bind and unrestricted direct egress"):
                await worker.start(_config(**changes))
            assert worker.process is None
    asyncio.run(exercise())


def test_proxy_worker_ipv6_socks_and_password_fallback(backend):
    async def exercise():
        try:
            target = await asyncio.start_server(_echo, "::1", 0)
        except OSError:
            pytest.skip("IPv6 loopback unavailable")
        worker = ProxyWorker(*backend)
        try:
            await worker.start(_config(auth={"mode": "basic", "username": "user", "token": "", "password": "private-token"}))
            reader, writer = await asyncio.open_connection("127.0.0.1", worker.listeners["socks5"]["bound_port"])
            writer.write(b"\x05\x01\x02\x01\x04user\x0dprivate-token")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(4), 3) == b"\x05\x02\x01\x00"
            port = target.sockets[0].getsockname()[1]
            writer.write(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + port.to_bytes(2, "big"))
            await writer.drain()
            assert (await asyncio.wait_for(reader.readexactly(10), 3))[:2] == b"\x05\x00"
            payload = b"ipv6-stream" * 30_000
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(len(payload)), 10) == payload
            writer.close()
            await writer.wait_closed()
        finally:
            await worker.stop()
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())


def test_native_proxy_concurrent_half_close_with_large_replies(native_proxy_worker_executable):
    async def exercise():
        reply = b"large-response" * 20_000

        async def target_handler(reader, writer):
            try:
                request = await reader.read()
                assert request == b"request-after-connect"
                writer.write(reply)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        target = await asyncio.start_server(target_handler, "127.0.0.1", 0)
        worker = ProxyWorker("native", native_proxy_worker_executable)
        await worker.start(_config())
        try:
            async def client():
                reader, writer = await asyncio.open_connection("127.0.0.1", worker.listeners["http"]["bound_port"])
                try:
                    auth = base64.b64encode(b"user:private-token").decode()
                    port = target.sockets[0].getsockname()[1]
                    writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
                    await writer.drain()
                    assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)).startswith(b"HTTP/1.1 200")
                    writer.write(b"request-after-connect")
                    await writer.drain()
                    writer.write_eof()
                    assert await asyncio.wait_for(reader.readexactly(len(reply)), 20) == reply
                    assert await asyncio.wait_for(reader.read(), 10) == b""
                finally:
                    writer.close()
                    await writer.wait_closed()
            await asyncio.gather(*(client() for _ in range(24)))
        finally:
            await worker.stop()
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())


def test_native_proxy_idle_clients_do_not_starve_new_connections(native_proxy_worker_executable):
    async def exercise():
        target = await asyncio.start_server(_echo, "127.0.0.1", 0)
        worker = ProxyWorker("native", native_proxy_worker_executable)
        await worker.start(_config())
        idle = []
        try:
            port = worker.listeners["http"]["bound_port"]
            for _ in range(24):
                idle.append(await asyncio.open_connection("127.0.0.1", port))
            await asyncio.sleep(0.2)
            await asyncio.wait_for(_http_tunnel(port, target.sockets[0].getsockname()[1], True), 10)
        finally:
            for _, writer in idle:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for _, writer in idle))
            await worker.stop()
            target.close()
            await target.wait_closed()
    asyncio.run(exercise())
