import json
import unittest

from obstacle_bridge.runtime_health import RuntimeHealthRecord, RuntimeHealthRing


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
