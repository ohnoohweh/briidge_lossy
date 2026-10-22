from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import struct
import sys
from types import SimpleNamespace

import pytest

from obstacle_bridge.bridge_peer_worker import MAX_FRAME, PeerStackWorker, _peer_args, _read_frame, _serve, _write_frame


pytestmark = pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="desktop Unix worker")


def _config():
    return {"runner": {"overlay_transport": "tcp"},
            "tcp_session": {"tcp_peer": "127.0.0.1", "tcp_peer_port": 45678}}


def test_peer_worker_restricts_shared_services_and_non_client_modes():
    args = _peer_args(_config())
    assert args.admin_web is False and args.enabled_on_startup is False and args.status is False
    assert args._peer_worker_forbid_tun is True
    for extra in (
        {"runner": {"overlay_transport": "ws"}},
        {"tcp_session": {"tcp_peer": None}},
        {"TUN_routing": {"enabled_on_startup": True}},
        {"tun_execution": {"tun_execution_mode": "helper"}},
        {"proxy_provider": {"proxy_provider_enabled": True}},
        {"telemetry_client": {"telemetry_enabled": True}},
        {"channel_mux": {"own_servers": [{"listen": {"protocol": "tun", "bind": "obtun0", "port": 0},
                                            "target": {"protocol": "tun", "host": "obtun1", "port": 0}}]}},
    ):
        config = {**_config(), **extra}
        with pytest.raises(ValueError):
            _peer_args(config)


def test_peer_worker_rejects_remote_tun_before_install_or_hooks(monkeypatch):
    from obstacle_bridge.bridge import ChannelMux

    mux = ChannelMux.__new__(ChannelMux)
    mux.args = SimpleNamespace(_peer_worker_forbid_tun=True)
    mux.log = __import__("logging").getLogger(__name__)
    service = SimpleNamespace(l_proto="tun", r_proto="tun")
    monkeypatch.setattr(mux, "_decode_remote_services_set_v2", lambda _payload: (1, 1, [service]))
    assert mux._on_remote_services_payload(b"catalog", 1) is False
    monkeypatch.setattr(mux, "_rx_tun_open", lambda *_args, **_kwargs: pytest.fail("TUN OPEN was dispatched"))
    mux._rx_tun(1, ChannelMux.MType.OPEN, b"remote-open", peer_id=1)


def test_peer_worker_rejects_oversized_and_noncanonical_frames():
    async def exercise():
        for prefix, body in (
            (struct.pack("!I", 0), b""),
            (struct.pack("!I", MAX_FRAME + 1), b""),
            (struct.pack("!I", 10), b'{"v":true}'),
            (struct.pack("!I", 13), b'{"v":1,"v":1}'),
            (struct.pack("!I", 15), b'{"v":1,"x":NaN}'),
        ):
            reader = asyncio.StreamReader()
            reader.feed_data(prefix + body)
            reader.feed_eof()
            with pytest.raises(ValueError):
                await _read_frame(reader)
    asyncio.run(exercise())


def test_peer_worker_invalid_start_is_reaped_without_exposing_configuration():
    async def exercise():
        worker = PeerStackWorker("peer-test")
        secret = "secret-not-in-worker-diagnostics"
        with pytest.raises(RuntimeError) as error:
            await worker.start({"runner": {"overlay_transport": "tcp"}, "secure_link": {"secure_link_psk": secret}})
        assert secret not in str(error.value)
        assert worker.process is None and worker.generation == 0
    asyncio.run(exercise())


def test_native_peer_worker_is_rejected_off_macos(monkeypatch):
    async def exercise():
        monkeypatch.setattr(sys, "platform", "win32")
        worker = PeerStackWorker("native-platform-test", implementation="native")
        with pytest.raises(RuntimeError, match="require macOS or Linux"):
            await worker.start(_config())
        assert worker.process is None and worker.generation == 0
    asyncio.run(exercise())


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-native peer qualification requires Linux")
def test_linux_native_peer_worker_negotiates_common_ipc_and_stops():
    executable = os.environ.get("OBSTACLEBRIDGE_TEST_LINUX_PEER_WORKER", "")
    if not executable or not os.path.isfile(executable):
        pytest.skip("Linux-native peer executable is not available")

    async def exercise():
        worker = PeerStackWorker("linux-native-peer-test", implementation="native", native_executable=executable)
        try:
            await worker.start(_config())
            assert worker.generation == 1
            snapshot = await worker.snapshot()
            assert isinstance(snapshot, dict)
        finally:
            await worker.stop()

    asyncio.run(exercise())


def test_peer_worker_inherits_stderr_without_managed_collector(monkeypatch, capfd):
    async def exercise():
        worker = PeerStackWorker("stderr-test")
        try:
            await worker.start(_config())
        finally:
            await worker.stop()

    monkeypatch.setattr(logging.getLogger(), "level", logging.INFO)
    asyncio.run(exercise())
    assert "[SERVER] ObstacleBridge build=" in capfd.readouterr().err


def test_cancelled_peer_retirement_kills_and_reaps_child():
    async def exercise():
        class Process:
            returncode = None

            def __init__(self):
                self.waiting = asyncio.Event()
                self.stopped = asyncio.Event()
                self.killed = False

            async def wait(self):
                self.waiting.set()
                await self.stopped.wait()
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9
                self.stopped.set()

        worker = PeerStackWorker("cancel-test")
        process = Process()
        worker.process = process
        task = asyncio.create_task(worker._retire())
        await asyncio.wait_for(process.waiting.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert process.killed and process.returncode == -9 and worker.process is None
    asyncio.run(exercise())


def test_peer_control_deadline_kills_and_reaps_unresponsive_child():
    async def exercise():
        worker = PeerStackWorker("deadline-test")
        await worker.start(_config())
        child = worker.process
        try:
            os.kill(child.pid, signal.SIGSTOP)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(worker.control("reconnect"), 0.25)
            await asyncio.wait_for(child.wait(), 2)
            assert child.returncode is not None and worker.process is None
        finally:
            await worker.stop()
    asyncio.run(exercise())


def test_peer_control_lost_reply_reports_unknown_without_retry():
    async def exercise():
        from obstacle_bridge.bridge import Runner

        class LostReply:
            calls = 0

            async def control(self, operation, target_peer_id=None, scope=None):
                self.calls += 1
                raise asyncio.TimeoutError()

        runner = Runner.__new__(Runner)
        runner._peer_stack_worker = LostReply()
        result = await runner._peer_stack_control("rekey", "0:0")
        assert result["ok"] is False and result["reason"] == "peer_worker_unavailable_or_outcome_unknown"
        assert result["target_peer_id"] == "0:0" and runner._peer_stack_worker.calls == 1
    asyncio.run(exercise())


def test_peer_worker_aborts_inflight_start_when_owner_disappears(monkeypatch):
    async def exercise():
        import obstacle_bridge.bridge as bridge
        import obstacle_bridge.bridge_peer_worker as peer_module

        started, stopped = asyncio.Event(), asyncio.Event()

        class SlowRunner:
            def __init__(self, _args):
                pass

            async def start(self):
                started.set()
                await asyncio.Event().wait()

            async def stop(self, reason):
                stopped.set()

        monkeypatch.setattr(bridge, "Runner", SlowRunner)
        monkeypatch.setattr(peer_module, "_peer_args", lambda _config: object())
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=parent)
        task = asyncio.create_task(_serve(child.detach()))
        await _write_frame(writer, {"v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["peer.control"], "generation": 1})
        assert await _read_frame(reader) == {"v": 1, "kind": "worker.hello", "role": "peer", "capabilities": ["peer.control"], "generation": 1}
        await _write_frame(writer, {"v": 1, "kind": "peer.start", "peer_id": "test", "generation": 1, "config": {}})
        await asyncio.wait_for(started.wait(), 2)
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(task, 2)
        assert stopped.is_set()
    asyncio.run(exercise())
