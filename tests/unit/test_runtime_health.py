import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner
from obstacle_bridge.runtime_health import RuntimeHealthRecord, RuntimeHealthRing, RuntimeHealthStore


class RuntimeHealthTests(unittest.TestCase):
    def test_record_uses_portable_redacted_schema(self):
        record = RuntimeHealthRecord(
            sequence=7,
            timestamp_unix_milliseconds=1_700_000_000_123,
            event="heartbeat",
            process_footprint_bytes=32_768,
            packet_pump_running=True,
            overlay_state="connected",
            securelink_state="authenticated",
            transport_epoch=4,
            incoming_queued_packets=3,
            outgoing_queued_packets=2,
            outgoing_inflight_writes=1,
            incoming_dropped_packets=5,
            slow_writes=6,
            packets_from_system=7,
            packets_to_system=8,
        )

        self.assertEqual(json.loads(json.dumps(record.as_payload())), {
            "schema_version": 1,
            "sequence": 7,
            "timestamp_unix_milliseconds": 1_700_000_000_123,
            "event": "heartbeat",
            "controlled_stop": False,
            "process_resident_bytes": None,
            "process_footprint_bytes": 32_768,
            "heartbeat_age_milliseconds": None,
            "packet_pump_running": True,
            "overlay_state": "connected",
            "securelink_state": "authenticated",
            "transport_epoch": 4,
            "incoming_queued_packets": 3,
            "outgoing_queued_packets": 2,
            "outgoing_inflight_writes": 1,
            "incoming_dropped_packets": 5,
            "outgoing_dropped_packets": None,
            "slow_writes": 6,
            "packets_from_system": 7,
            "packets_to_system": 8,
        })

    def test_ring_is_bounded_and_classifies_only_the_last_lifecycle_marker(self):
        ring = RuntimeHealthRing(capacity=2)
        self.assertIsNone(ring.previous_lifetime_ended_cleanly)
        ring.append(RuntimeHealthRecord(sequence=1, timestamp_unix_milliseconds=1, event="start"))
        ring.append(RuntimeHealthRecord(sequence=2, timestamp_unix_milliseconds=2, event="stop", controlled_stop=True))
        self.assertTrue(ring.previous_lifetime_ended_cleanly)
        ring.append(RuntimeHealthRecord(sequence=3, timestamp_unix_milliseconds=3, event="start"))
        self.assertEqual([record.sequence for record in ring.records], [2, 3])
        self.assertFalse(ring.previous_lifetime_ended_cleanly)

    def test_ring_rejects_nonpositive_capacity(self):
        with self.assertRaises(ValueError):
            RuntimeHealthRing(capacity=0)

    def test_store_recovers_last_stop_marker_and_writes_a_bounded_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime-health.json"
            store = RuntimeHealthStore(path, capacity=2)
            self.assertIsNone(store.begin_lifetime())
            store.append(RuntimeHealthRecord(sequence=1, timestamp_unix_milliseconds=1, event="stop", controlled_stop=True))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            restarted = RuntimeHealthStore(path, capacity=2)
            self.assertTrue(restarted.begin_lifetime())
            restarted.append(RuntimeHealthRecord(sequence=2, timestamp_unix_milliseconds=2, event="start"))
            restarted.append(RuntimeHealthRecord(sequence=3, timestamp_unix_milliseconds=3, event="heartbeat"))
            self.assertEqual([record.sequence for record in restarted.ring.records], [2, 3])

    def test_runner_lifecycle_persists_and_reports_redacted_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime-health.json"
            args = type("Args", (), {
                "no_dashboard": True,
                "udp_bind": "0.0.0.0",
                "udp_own_port": 4433,
                "overlay_transport": "tcp",
                "status": False,
                "config": "",
                "_config_path": "",
            })()
            with mock.patch.dict("os.environ", {"OBSTACLEBRIDGE_RUNTIME_HEALTH_PATH": str(path)}):
                first = Runner(args)
                first._begin_runtime_health_lifetime()
                first._record_runtime_health("runner_stopped", controlled_stop=True)
                self.assertEqual(first._runtime_health_status_fields()["runtime_health_record_count"], 2)

                restarted = Runner(args)
                restarted._begin_runtime_health_lifetime()
                fields = restarted._runtime_health_status_fields()
                self.assertTrue(fields["previous_runtime_lifetime_ended_cleanly"])
                self.assertNotIn("packet_contents", fields)
