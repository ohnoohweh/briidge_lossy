from __future__ import annotations

import asyncio
import logging
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
        _reader, writer = await asyncio.open_connection(sock=parent)
        task = asyncio.create_task(_serve(child.detach()))
        await _write_frame(writer, {"v": 1, "kind": "peer.start", "peer_id": "test", "generation": 1, "config": {}})
        await asyncio.wait_for(started.wait(), 2)
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(task, 2)
        assert stopped.is_set()
    asyncio.run(exercise())
