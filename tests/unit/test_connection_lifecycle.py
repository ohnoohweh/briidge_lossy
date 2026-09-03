from __future__ import annotations

import argparse
import types
import unittest
from unittest.mock import patch

from obstacle_bridge.bridge_connection_lifecycle import (
    ConnectionLifecycleEvent,
    ConnectionRotationResult,
    ConnectionState,
)
from obstacle_bridge.bridge import UdpSession


class ConnectionLifecycleContractTests(unittest.TestCase):
    def test_event_snapshot_round_trip_preserves_state_epoch_and_reason(self) -> None:
        event = ConnectionLifecycleEvent(
            state=ConnectionState.CONNECTED,
            epoch=7,
            reason="transport_recovered",
            changed_at_unix_ts=1234.5,
        )

        restored = ConnectionLifecycleEvent.from_snapshot(event.as_snapshot())

        self.assertEqual(restored, event)
        self.assertTrue(restored.connected)

    def test_event_normalizes_legacy_connected_snapshot(self) -> None:
        event = ConnectionLifecycleEvent.from_snapshot({"connected": True, "epoch": 2})

        self.assertEqual(event.state, ConnectionState.CONNECTED)
        self.assertEqual(event.epoch, 2)

    def test_event_rejects_negative_epoch(self) -> None:
        with self.assertRaises(ValueError):
            ConnectionLifecycleEvent(state=ConnectionState.DISCONNECTED, epoch=-1)

    def test_rotation_result_exposes_transport_policy_metadata(self) -> None:
        result = ConnectionRotationResult(
            accepted=True,
            reason="next_candidate",
            next_epoch=4,
            candidate_index=1,
            candidate_cycle=2,
            restart_required=False,
        )

        self.assertEqual(
            result.as_snapshot(),
            {
                "accepted": True,
                "reason": "next_candidate",
                "next_epoch": 4,
                "candidate_index": 1,
                "candidate_cycle": 2,
                "restart_required": False,
            },
        )

    def test_myudp_emits_ordered_lifecycle_events_with_one_epoch(self) -> None:
        session = UdpSession(argparse.Namespace(max_inflight=200))
        events = []
        session.set_on_connection_lifecycle(events.append)

        session._on_state_change(True)
        session._on_state_change(False)

        self.assertEqual(
            [(event.state, event.epoch) for event in events],
            [(ConnectionState.CONNECTED, 1), (ConnectionState.DISCONNECTED, 1)],
        )
        self.assertEqual(session.get_connection_lifecycle_snapshot()["epoch"], 1)

    def test_myudp_rotation_advances_epoch_until_recovery_or_cycle_exhaustion(self) -> None:
        session = UdpSession(argparse.Namespace(max_inflight=200))
        events = []
        session.set_on_connection_lifecycle(events.append)
        session._peer_candidates = [
            ("192.0.2.10", 4433, 2),
            ("2001:db8::10", 4433, 10),
        ]
        session._peer_candidate_index = 0
        session.inner_session = types.SimpleNamespace(reset_transport_epoch=lambda: None)
        peer_port = types.SimpleNamespace(set_peer=lambda _peer: None)
        proto_runtime = types.SimpleNamespace(
            _conn_evt=types.SimpleNamespace(clear=lambda: None),
            _conn_state=True,
            _next_probe_due_ns=1,
            _send_idle_probe=lambda initial: None,
        )
        session._proto = types.SimpleNamespace(send_port=peer_port, _proto_rt=proto_runtime)
        session._publish_connection_lifecycle(True)

        result = session.request_connection_rotation("channelmux_disconnected")

        self.assertTrue(result.accepted)
        self.assertEqual(result.candidate_index, 1)
        self.assertEqual(result.candidate_cycle, 0)
        self.assertEqual(result.next_epoch, 2)
        second_result = session.request_connection_rotation("channelmux_disconnected")

        self.assertTrue(second_result.accepted)
        self.assertEqual(second_result.candidate_index, 0)
        self.assertEqual(second_result.candidate_cycle, 1)
        self.assertEqual(second_result.next_epoch, 3)
        session._on_state_change(True)
        self.assertEqual(session._peer_candidate_cycle, 1)
        session.reset_connection_rotation_cycles()
        self.assertEqual(session._peer_candidate_cycle, 0)

        session._peer_candidates = [("192.0.2.10", 4433, 2)]
        single_candidate_result = session.request_connection_rotation("channelmux_disconnected")

        self.assertTrue(single_candidate_result.accepted)
        self.assertEqual(single_candidate_result.candidate_index, 0)
        self.assertEqual(single_candidate_result.candidate_cycle, 1)
        for expected_cycle in (2, 3):
            single_candidate_result = session.request_connection_rotation("channelmux_disconnected")
            self.assertEqual(single_candidate_result.candidate_cycle, expected_cycle)
        self.assertTrue(single_candidate_result.restart_required)
        self.assertEqual(
            [(event.state, event.epoch) for event in events],
            [
                (ConnectionState.CONNECTED, 1),
                (ConnectionState.DISCONNECTED, 2),
                (ConnectionState.DISCONNECTED, 3),
                (ConnectionState.CONNECTED, 4),
                (ConnectionState.DISCONNECTED, 5),
                (ConnectionState.DISCONNECTED, 6),
                (ConnectionState.DISCONNECTED, 7),
            ],
        )

    def test_listener_peer_without_completed_app_payload_has_bounded_deadline(self) -> None:
        session = UdpSession(argparse.Namespace(max_inflight=200))
        first_seen = 1_000_000_000
        ctx = {
            "first_seen_wall_ns": first_seen,
            "last_incoming_wall_ns": first_seen,
            "last_completed_app_payload_wall_ns": 0,
        }

        deadline = session._listener_peer_app_payload_deadline_ns(ctx)

        self.assertEqual(deadline, first_seen + int(session._LISTENER_PREAUTH_APP_PAYLOAD_TIMEOUT_S * 1e9))
        session._server_peers[7] = ctx
        with patch("obstacle_bridge.bridge_transport_udp.now_ns", return_value=first_seen + 1):
            session._on_complete_for_peer(7, b"secure-link-hello")
        self.assertEqual(session._listener_peer_app_payload_deadline_ns(ctx), 0)
