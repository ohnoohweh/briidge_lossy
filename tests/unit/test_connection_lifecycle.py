from __future__ import annotations

import unittest

from obstacle_bridge.bridge_connection_lifecycle import (
    ConnectionLifecycleEvent,
    ConnectionRotationResult,
    ConnectionState,
)


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
        )

        self.assertEqual(
            result.as_snapshot(),
            {
                "accepted": True,
                "reason": "next_candidate",
                "next_epoch": 4,
                "candidate_index": 1,
                "candidate_cycle": 2,
            },
        )
