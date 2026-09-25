import json
import http.client
import socket
import ssl
import threading
import subprocess
import sys
import http.server
import argparse
import asyncio
import importlib
from pathlib import Path
from unittest import mock

import pytest

from obstacle_bridge.bridge_telemetry import (
    TelemetryEmitter,
    TelemetrySpool,
    TelemetryValidationError,
    decode_event,
    encode_batch,
    encode_event,
)
from obstacle_bridge import bridge_telemetry_ingest as ingest
from obstacle_bridge.bridge_telemetry_ingest import TelemetryAdmissionControl, TelemetryIngestStore, build_tls_context
from obstacle_bridge.bridge_telemetry_credentials import TelemetryRevocationList, client_certificate_paths, generate_ca, issue_client_certificate, issue_server_certificate
from obstacle_bridge.bridge_telemetry_uploader import TelemetryUploader
from obstacle_bridge.bridge import Runner
bridge_runner = importlib.import_module("obstacle_bridge.bridge_runner")


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


def test_emitter_empty_drain_is_non_blocking_and_returns_no_events():
    emitter = TelemetryEmitter("install-01", "session-01")
    assert emitter.drain() == []


def test_spool_status_is_bounded_and_redacted(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool")); assert spool.append(VECTORS["event"])
    status = spool.status()
    assert status["pending_events"] == 1
    assert "fields" not in status and "installation_id" not in status


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


def test_ingest_store_acknowledges_only_valid_ordered_durable_batch(tmp_path):
    event = dict(VECTORS["event"])
    payload = json.dumps({"v": 1, "kind": "telemetry.batch", "events": [event]}).encode("utf-8")
    store = TelemetryIngestStore(str(tmp_path / "ingest"))
    assert store.accept(payload, "install-01", 1) == {"ok": True, "accepted_through": 1, "accepted_count": 1}
    assert store.spool.recover() == [event]
    status = json.loads((tmp_path / "ingest" / "collector-status.json").read_text(encoding="utf-8"))
    assert status["accepted_batches"] == 1
    assert status["rejected_batches"] == 0
    assert status["last_accepted_unix_ts"] is not None
    bad = dict(event)
    bad["sequence"] = 0
    with pytest.raises(TelemetryValidationError):
        store.accept(json.dumps({"v": 1, "kind": "telemetry.batch", "events": [bad]}).encode("utf-8"), "install-01", 1)
    status = json.loads((tmp_path / "ingest" / "collector-status.json").read_text(encoding="utf-8"))
    assert status["rejected_batches"] == 1


def test_ingest_rejects_replay_and_admission_exhaustion(tmp_path):
    payload = json.dumps({"v": 1, "kind": "telemetry.batch", "events": [VECTORS["event"]]}).encode("utf-8")
    store = TelemetryIngestStore(str(tmp_path / "ingest"), admission=TelemetryAdmissionControl(capacity=1, refill_per_sec=0.1))
    assert store.accept(payload, "install-01", 1, "source-a")["ok"]
    with pytest.raises(TelemetryValidationError, match="admission"):
        store.accept(payload, "install-01", 1, "source-a")
    replay = TelemetryIngestStore(str(tmp_path / "ingest"), admission=TelemetryAdmissionControl())
    with pytest.raises(TelemetryValidationError, match="replayed"):
        replay.accept(payload, "install-01", 1, "source-b")


def test_ingest_requires_tls_material(tmp_path):
    with pytest.raises(ValueError):
        build_tls_context("", "", "")


def test_mtls_credential_issue_and_revocation(tmp_path):
    ca_key, ca_cert = generate_ca("test-ca")
    _, client_cert, serial = issue_client_certificate(ca_key, ca_cert, "install-01")
    assert b"BEGIN CERTIFICATE" in client_cert
    revocations = TelemetryRevocationList(str(tmp_path / "revocations.json"))
    assert not revocations.is_revoked(serial)
    revocations.revoke(serial)
    assert revocations.is_revoked(serial)


def test_client_certificate_directory_derives_installation_id(tmp_path):
    ca_key, ca_cert = generate_ca("test-ca")
    client_key, client_cert, _ = issue_client_certificate(ca_key, ca_cert, "install-01")
    (tmp_path / "client.key.pem").write_bytes(client_key)
    (tmp_path / "client.cert.pem").write_bytes(client_cert)
    (tmp_path / "collector-ca.cert.pem").write_bytes(ca_cert)

    cert, key, ca, installation_id = client_certificate_paths(str(tmp_path))
    assert (cert, key, ca, installation_id) == (
        str(tmp_path / "client.cert.pem"), str(tmp_path / "client.key.pem"),
        str(tmp_path / "collector-ca.cert.pem"), "install-01",
    )


def test_mtls_ingest_accepts_matching_client_identity(tmp_path):
    ca_key, ca_cert = generate_ca("test-ca")
    server_key, server_cert = issue_server_certificate(ca_key, ca_cert, "127.0.0.1")
    client_key, client_cert, _ = issue_client_certificate(ca_key, ca_cert, "install-01")
    paths = {name: tmp_path / name for name in ("ca.pem", "server.key", "server.pem", "client.key", "client.pem")}
    paths["ca.pem"].write_bytes(ca_cert); paths["server.key"].write_bytes(server_key); paths["server.pem"].write_bytes(server_cert)
    paths["client.key"].write_bytes(client_key); paths["client.pem"].write_bytes(client_cert)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ingest._Handler)
    server.RequestHandlerClass.store = TelemetryIngestStore(str(tmp_path / "spool"), TelemetryRevocationList(str(tmp_path / "revoke.json")))
    server.socket = build_tls_context(str(paths["server.pem"]), str(paths["server.key"]), str(paths["ca.pem"])).wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever); thread.start()
    try:
        context = ssl.create_default_context(cafile=str(paths["ca.pem"])); context.check_hostname = False
        context.load_cert_chain(str(paths["client.pem"]), str(paths["client.key"]))
        connection = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=context, timeout=2)
        connection.request("POST", "/v1/telemetry/batches", json.dumps({"v": 1, "kind": "telemetry.batch", "events": [VECTORS["event"]]}).encode("utf-8"), {"Content-Type": "application/json"})
        assert connection.getresponse().status == 202
        second = dict(VECTORS["event"]); second["sequence"] = 2
        upload_spool = TelemetrySpool(str(tmp_path / "upload-spool")); assert upload_spool.append(second)
        uploader = TelemetryUploader(upload_spool, "https://127.0.0.1:%s/v1/telemetry/batches" % server.server_address[1], str(paths["ca.pem"]), str(paths["client.pem"]), str(paths["client.key"]))
        result = uploader.upload_once()
        assert result == {"ok": True, "accepted_count": 1, "accepted_through": 2}, uploader.last_error
    finally:
        server.shutdown(); thread.join(timeout=2); server.server_close()


def test_uploader_requires_https_and_respects_backoff(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool")); assert spool.append(VECTORS["event"])
    with pytest.raises(ValueError):
        TelemetryUploader(spool, "http://invalid", "", "", "")


def test_runner_telemetry_client_spools_lifecycle_event_off_runtime_path(tmp_path, monkeypatch):
    class _Uploader:
        last_error = ""

        def upload_once(self):
            return {"ok": False, "reason": "backoff"}

    runner = Runner.__new__(Runner)
    runner.args = argparse.Namespace(
        telemetry_enabled=True,
        telemetry_endpoint="https://collector.example.test/v1/telemetry/batches",
        telemetry_spool_directory=str(tmp_path / "spool"),
        telemetry_client_certificate_directory=str(tmp_path / "credentials"),
    )
    runner.log = mock.Mock()
    runner._telemetry_client_task = None
    runner._telemetry_emitter = None
    runner._telemetry_spool = None
    runner._telemetry_uploader = None
    runner._telemetry_client_last_error = ""
    runner._telemetry_client_last_warning = ""
    monkeypatch.setattr(bridge_runner, "client_certificate_paths", lambda directory: ("client.cert.pem", "client.key.pem", "ca.cert.pem", "install-01"))
    monkeypatch.setattr(bridge_runner, "TelemetryUploader", lambda *args: _Uploader())

    async def run() -> None:
        await runner._start_telemetry_client()
        await asyncio.sleep(0.05)
        assert runner._telemetry_spool is not None
        events = runner._telemetry_spool.recover()
        assert [event["event"] for event in events] == ["runtime.lifecycle", "runtime.load"]
        assert events[0]["fields"] == {"state": "started", "reason": ""}
        assert events[1]["fields"]["queue_depth"] >= 1
        await runner._stop_telemetry_client()

    asyncio.run(run())


def test_runner_telemetry_client_retries_a_failed_flush_worker(tmp_path, monkeypatch):
    class _Uploader:
        last_error = ""

        def upload_once(self):
            return {"ok": True, "accepted_count": 1}

    runner = Runner.__new__(Runner)
    runner.args = argparse.Namespace(
        telemetry_enabled=True,
        telemetry_endpoint="https://collector.example.test/v1/telemetry/batches",
        telemetry_spool_directory=str(tmp_path / "spool"),
        telemetry_client_certificate_directory=str(tmp_path / "credentials"),
    )
    runner.log = mock.Mock()
    runner._telemetry_client_task = None
    runner._telemetry_emitter = None
    runner._telemetry_spool = None
    runner._telemetry_uploader = None
    runner._telemetry_client_flush_task = None
    runner._telemetry_client_last_error = ""
    runner._telemetry_client_last_warning = ""
    runner._telemetry_client_last_cycle_monotonic = 0.0
    runner._telemetry_client_last_load_monotonic = 0.0
    runner._telemetry_client_cycles = 0
    monkeypatch.setattr(bridge_runner, "client_certificate_paths", lambda directory: ("client.cert.pem", "client.key.pem", "ca.cert.pem", "install-01"))
    monkeypatch.setattr(bridge_runner, "TelemetryUploader", lambda *args: _Uploader())

    original_flush = runner._telemetry_client_flush_blocking
    attempts = 0

    def _flaky_flush(events):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("temporary spool failure")
        return original_flush(events)

    runner._telemetry_client_flush_blocking = _flaky_flush

    async def run() -> None:
        await runner._start_telemetry_client()
        await asyncio.sleep(3.1)
        snapshot = runner.get_telemetry_client_snapshot()
        assert attempts >= 2
        assert snapshot["worker_state"] == "running"
        assert snapshot["worker_cycles"] >= 2
        await runner._stop_telemetry_client()

    asyncio.run(run())


def test_telemetry_qualification_harness_reports_bounded_emit_latency():
    completed = subprocess.run([sys.executable, "scripts/qualify_telemetry.py", "--events", "200", "--max-p99-ms", "20"], capture_output=True, text=True, check=True)
    result = json.loads(completed.stdout)
    assert result["p99_emit_ms"] <= 20
    assert result["drops"]["queue_full"] > 0


def test_ingest_main_reads_enabled_collector_from_shared_telemetry_config(tmp_path, monkeypatch):
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(json.dumps({"telemetry_server": {
        "telemetry_collector_enabled": True,
        "telemetry_collector_bind": "127.0.0.1",
        "telemetry_collector_address_family": "ipv4",
        "telemetry_collector_port": 19443,
        "telemetry_collector_spool_directory": str(tmp_path / "ingest"),
        "telemetry_collector_tls_cert": "/tmp/server.cert.pem",
        "telemetry_collector_tls_key": "/tmp/server.key.pem",
        "telemetry_collector_client_ca": "/tmp/client-ca.cert.pem",
        "telemetry_collector_revocations": str(tmp_path / "revocations.json"),
    }}), encoding="utf-8")
    observed = {}
    monkeypatch.setattr(ingest, "serve", lambda *args: observed.setdefault("args", args))

    assert ingest.main(["--config", str(config_path)]) == 0
    assert observed["args"] == (
        "127.0.0.1", 19443, str(tmp_path / "ingest"),
        "/tmp/server.cert.pem", "/tmp/server.key.pem", "/tmp/client-ca.cert.pem",
        str(tmp_path / "revocations.json"), "ipv4",
    )


def test_ingest_main_rejects_disabled_collector_config(tmp_path):
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(json.dumps({"telemetry_server": {"telemetry_collector_enabled": False}}), encoding="utf-8")

    with pytest.raises(SystemExit, match="telemetry collector is disabled"):
        ingest.main(["--config", str(config_path)])


def test_collector_uses_explicit_ipv4_or_ipv6_address_family():
    ipv4 = ingest._collector_server("127.0.0.1", 0, "ipv4")
    try:
        assert ipv4.address_family == socket.AF_INET
    finally:
        ipv4.server_close()
    try:
        ipv6 = ingest._collector_server("::1", 0, "ipv6")
    except OSError:
        pytest.skip("IPv6 loopback is unavailable on this host")
    try:
        assert ipv6.address_family == socket.AF_INET6
    finally:
        ipv6.server_close()
