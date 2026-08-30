from __future__ import annotations

import asyncio
import logging
import time
import unittest

from obstacle_bridge.bridge import SecureLinkPskSession
from obstacle_bridge.bridge import SessionMetrics
from test_secure_link_psk import FakeInnerSession, _args


async def _run_rekey_with_diagnostics() -> list[str]:
    client_inner = FakeInnerSession()
    server_inner = FakeInnerSession()
    client_inner.connect_peer(server_inner)
    server_inner.connect_peer(client_inner)
    client = SecureLinkPskSession(
        client_inner,
        _args(tcp_peer="127.0.0.1", secure_link_rekey_after_frames=1),
        "tcp",
    )
    server = SecureLinkPskSession(server_inner, _args(), "tcp")
    await client.start()
    await server.start()
    try:
        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        with unittest.TestCase().assertLogs("secure_link", logging.INFO) as captured:
            client.send_app(b"diagnostic-rekey")
            for _ in range(8):
                await asyncio.sleep(0)
        return captured.output
    finally:
        await client.stop()
        await server.stop()


def test_rekey_diagnostics_log_each_protocol_leg_without_payload_material() -> None:
    lines = asyncio.run(_run_rekey_with_diagnostics())
    output = "\n".join(lines)

    for phase in (
        "phase=request direction=tx",
        "phase=hello direction=rx",
        "phase=reply direction=tx",
        "phase=reply direction=rx",
        "phase=commit direction=tx",
        "phase=commit direction=rx",
        "phase=done direction=tx",
        "phase=done direction=rx",
    ):
        assert phase in output
    assert "active_session_id=" in output
    assert "pending_session_id=" in output
    assert "tx_counter=" in output
    assert "rx_counter=" in output
    assert "transmit_delay_est_ms=" in output
    assert "rekey_transfer_budget_ms=120000.000" in output
    assert "transmit_delay_exceeds_rekey_budget=False" in output
    assert "diagnostic-rekey" not in output


async def _run_rekey_timeout_with_diagnostics() -> list[str]:
    client_inner = FakeInnerSession()
    server_inner = FakeInnerSession()
    client_inner.connect_peer(server_inner)
    server_inner.connect_peer(client_inner)
    client = SecureLinkPskSession(client_inner, _args(tcp_peer="127.0.0.1"), "tcp")
    server = SecureLinkPskSession(server_inner, _args(), "tcp")
    await client.start()
    await server.start()
    try:
        server_inner.emit_state(True)
        client_inner.emit_state(True)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        state = client._peer_states[0]
        client_inner._peer = None
        client_inner.get_metrics = lambda: SessionMetrics(transmit_delay_est_ms=120001.0)
        client._start_client_rekey(state, trigger="operator")
        state.pending_started_unix_ts = time.time() - client._HANDSHAKE_TIMEOUT_S
        with unittest.TestCase().assertLogs("secure_link", logging.WARNING) as captured:
            client._expire_stale_handshakes()
        return captured.output
    finally:
        await client.stop()
        await server.stop()


def test_rekey_diagnostics_log_timeout_with_pending_session_context() -> None:
    output = "\n".join(asyncio.run(_run_rekey_timeout_with_diagnostics()))

    assert "[SECURE-LINK/REKEY] phase=timeout direction=local" in output
    assert "pending_session_id=" in output
    assert "pending_age_ms=" in output
    assert "transmit_delay_est_ms=" in output
    assert "rekey_transfer_budget_ms=120000.000" in output
    assert "transmit_delay_est_ms=120001.000" in output
    assert "transmit_delay_exceeds_rekey_budget=True" in output
    assert "[SECURE-LINK] auth failure" in output
    assert "detail=secure-link re-authentication timed out" in output
