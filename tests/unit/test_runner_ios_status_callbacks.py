from __future__ import annotations

import asyncio
import argparse
from types import SimpleNamespace

import obstacle_bridge.bridge as bridge
import obstacle_bridge.bridge_runner as bridge_runner


class _FakeSession:
    def __init__(self) -> None:
        self.on_state_change = None
        self.on_peer_rx = None
        self.on_peer_tx = None
        self.on_peer_set = None
        self.on_transport_epoch_change = None
        self.started = False

    def set_on_state_change(self, cb):
        self.on_state_change = cb

    def set_on_peer_rx(self, cb):
        self.on_peer_rx = cb

    def set_on_peer_tx(self, cb):
        self.on_peer_tx = cb

    def set_on_peer_set(self, cb):
        self.on_peer_set = cb

    def set_on_transport_epoch_change(self, cb):
        self.on_transport_epoch_change = cb

    async def start(self):
        self.started = True

    async def stop(self):
        return None

    def is_connected(self):
        return False

    def get_metrics(self):
        return bridge_runner.SessionMetrics()


class _FakeMux:
    def __init__(self, on_local_rx_bytes, on_local_tx_bytes) -> None:
        self.on_local_rx_bytes = on_local_rx_bytes
        self.on_local_tx_bytes = on_local_tx_bytes
        self.started = False

    async def start(self):
        self.started = True

    async def stop(self):
        return None

    def udp_open_count(self):
        return 0

    def tcp_open_count(self):
        return 0

    def tun_open_count(self):
        return 0


def _base_args() -> argparse.Namespace:
    return SimpleNamespace(
        admin_web=False,
        status=False,
        no_dashboard=True,
        overlay_transport="myudp",
        udp_bind="::",
        udp_own_port=4433,
        max_inflight=32,
    )


def test_runner_keeps_status_callbacks_wired_on_ios(monkeypatch):
    async def _run() -> None:
        session = _FakeSession()
        mux_holder: dict[str, _FakeMux] = {}

        monkeypatch.setattr(bridge_runner, "_admin_ui_platform", lambda: "ios")
        monkeypatch.setattr(
            bridge_runner.Runner,
            "build_sessions_from_overlay",
            staticmethod(lambda args: [("myudp", session)]),
        )

        def _fake_from_args(session_obj, loop, args, on_local_rx_bytes=None, on_local_tx_bytes=None):
            mux = _FakeMux(on_local_rx_bytes, on_local_tx_bytes)
            mux_holder["mux"] = mux
            return mux

        monkeypatch.setattr(
            bridge_runner.ChannelMux,
            "from_args",
            staticmethod(_fake_from_args),
        )

        runner = bridge_runner.Runner(_base_args())
        await runner.start()

        assert session.started is True
        assert session.on_peer_rx == runner.stats.on_peer_rx_bytes
        assert session.on_peer_tx == runner.stats.on_peer_tx_bytes
        assert session.on_peer_set == runner.stats.on_peer_set
        assert mux_holder["mux"].on_local_rx_bytes == runner.stats.on_app_rx_bytes
        assert mux_holder["mux"].on_local_tx_bytes == runner.stats.on_app_tx_bytes

    asyncio.run(_run())
