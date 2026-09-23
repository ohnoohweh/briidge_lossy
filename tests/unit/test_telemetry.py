import json
from pathlib import Path

import pytest

from obstacle_bridge.bridge_telemetry import (
    TelemetryEmitter,
    TelemetrySpool,
    TelemetryValidationError,
    decode_event,
    encode_batch,
    encode_event,
)


VECTORS = json.loads((Path(__file__).parents[2] / "docs" / "TELEMETRY_V1_VECTORS.json").read_text(encoding="utf-8"))


def test_v1_vector_round_trips_canonically():
    encoded = encode_event(VECTORS["event"])
    assert decode_event(encoded) == VECTORS["event"]


@pytest.mark.parametrize("field", ["payload", "secure_key", "peer_address", "token"])
def test_schema_rejects_payload_and_secret_bearing_fields(field):
    event = dict(VECTORS["event"])
    event["fields"] = {field: "forbidden"}
    with pytest.raises(TelemetryValidationError):
        encode_event(event)


def test_schema_rejects_unknown_event_members_and_invalid_sequence():
    event = dict(VECTORS["event"])
    event["extra"] = True
    with pytest.raises(TelemetryValidationError):
        encode_event(event)
    event = dict(VECTORS["event"])
    event["sequence"] = 0
    with pytest.raises(TelemetryValidationError):
        encode_event(event)


def test_emitter_drops_full_low_priority_queue_but_admits_critical_by_evicting_low():
    emitter = TelemetryEmitter("install-01", "session-01", capacity=1)
    assert emitter.emit_load(queue_depth=1, dropped=0)
    assert not emitter.emit_load(queue_depth=2, dropped=1)
    assert emitter.emit_lifecycle("stopping", "watchdog")
    event = emitter.drain()[0]
    assert event["event"] == "runtime.lifecycle"
    assert emitter.dropped["queue_full"] == 1
    assert emitter.dropped["evicted_low"] == 1


def test_batch_rejects_empty_and_encodes_valid_events():
    with pytest.raises(TelemetryValidationError):
        encode_batch([])
    payload = encode_batch([VECTORS["event"]])
    assert b"telemetry.batch" in payload


def test_spool_recovers_atomic_events_and_acknowledges_them(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool"))
    assert spool.append(VECTORS["event"])
    assert spool.recover() == [VECTORS["event"]]
    assert spool.acknowledge_through(1) == 1
    assert spool.recover() == []


def test_spool_ignores_partial_write_and_quarantines_corrupt_segment(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool"))
    (spool.directory / ".event-00000000000000000001.tmp").write_bytes(b"partial")
    (spool.directory / "event-00000000000000000001-low.json").write_bytes(b"not-json")
    assert spool.recover() == []
    assert spool.dropped["corrupt_segment"] == 1
    assert list(spool.directory.glob("*.corrupt"))


def test_spool_evicts_low_priority_before_rejecting_critical_event(tmp_path):
    low = dict(VECTORS["event"])
    low.update({"sequence": 1, "priority": "low", "event": "runtime.load"})
    critical = dict(VECTORS["event"])
    critical.update({"sequence": 2, "priority": "critical"})
    spool = TelemetrySpool(str(tmp_path / "spool"), max_files=1)
    assert spool.append(low)
    assert spool.append(critical)
    assert spool.recover() == [critical]
    assert spool.dropped["evicted_low"] == 1
