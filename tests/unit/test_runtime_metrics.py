import unittest
import asyncio
import threading
from types import SimpleNamespace

from obstacle_bridge.bridge import Runner
from obstacle_bridge.runtime_metrics import (
    DurationHistogram,
    NANOSECONDS_PER_MILLISECOND,
    NANOSECONDS_PER_SECOND,
    RollingDurationHistogram,
    RuntimeMetricAccumulator,
)


class FakeClock:
    def __init__(self, now_ns=0):
        self.now_ns = now_ns

    def monotonic_ns(self):
        return self.now_ns


def _runner_for_metrics_tests():
    runner = Runner.__new__(Runner)
    runner._runtime_metrics_task = None
    runner._runtime_metrics_last_sample_monotonic_ns = None
    runner._runtime_metrics_last_sample_cpu_ns = None
    runner._runtime_metrics_last_cpu_cores = None
    runner._runtime_metrics_sample_count = 0
    runner._runtime_metrics_last_loop_lag_ns = None
    runner._runtime_metrics_max_loop_lag_ns = 0
    runner._runtime_metrics_lag_probe_count = 0
    runner._runtime_metrics = RuntimeMetricAccumulator((
        "channelmux_callback", "tun_callback", "overlay_receive", "overlay_send",
        "overlay_receive_prepare", "overlay_receive_data", "overlay_receive_idle",
        "overlay_receive_control", "securelink", "compression", "control_tick",
        "compression_encode", "compression_decode", "compression_frame",
        "apple_transport_owner_queue", "securelink_worker",
        "apple_transport_parse_dispatch", "apple_transport_egress",
        "apple_transport_payload_route", "apple_transport_lifecycle",
        "apple_transport_securelink_route", "apple_transport_delivered_payload",
        "apple_transport_mux_dispatch", "apple_transport_tun_payload",
        "apple_transport_tcp_payload", "apple_transport_udp_payload",
        "apple_transport_tcp_server_data", "apple_transport_tcp_client_open",
        "apple_transport_tcp_client_data", "apple_transport_tcp_write_enqueue",
        "apple_transport_tcp_close",
        "apple_transport_tcp_client_open_core", "apple_transport_tcp_client_open_publication",
        "apple_transport_tcp_connection_start", "apple_transport_tcp_receive_registration",
        "retransmit_tick", "retransmit_reported_missing", "retransmit_unconfirmed",
        "status_stats", "status_session_summaries", "status_worker_state",
        "status_telemetry_state", "status_tun_helper_state", "status_peer_stack_state",
        "runtime_metrics_projection", "connections_snapshot", "peers_snapshot",
        "build_info", "security_advisor", "logging",
    ))
    runner._runtime_metrics_started = {}
    runner._runtime_metrics_cpu_peaks = []
    runner._runtime_metrics_cpu_peak_overall = None
    runner._runtime_metrics_cpu_peak_overall_contributor = None
    runner._runtime_metrics_cpu_interval_by_category = {}
    runner._async_diag_lock = threading.Lock()
    runner._sync_diag = {"last_started_name": "", "last_started_kind": "", "last_started_monotonic": None,
                        "last_finished_name": "", "last_finished_kind": "", "last_finished_monotonic": None,
                        "last_failed_name": "", "last_failed_kind": "", "last_failed_monotonic": None, "last_failed_error": ""}
    return runner


def test_histogram_reports_bounded_percentiles_and_no_samples():
    histogram = DurationHistogram((1 * NANOSECONDS_PER_MILLISECOND, 4 * NANOSECONDS_PER_MILLISECOND))
    assert histogram.summary().as_payload() == {
        "count": 0,
        "total_ms": 0.0,
        "max_ms": None,
        "p50_ms": None,
        "p95_ms": None,
        "p99_ms": None,
    }

    histogram.record(500_000)
    histogram.record(2 * NANOSECONDS_PER_MILLISECOND)
    histogram.record(9 * NANOSECONDS_PER_MILLISECOND)
    summary = histogram.summary()
    assert summary.count == 3
    assert summary.total_ms == 11.5
    assert summary.max_ms == 9.0
    assert summary.p50_ms == 4.0
    assert summary.p95_ms == 9.0
    assert summary.p99_ms == 9.0


def test_rolling_histogram_expires_old_slots_without_retaining_samples():
    histogram = RollingDurationHistogram(slot_count=3, slot_duration_ns=NANOSECONDS_PER_SECOND)
    histogram.record(3 * NANOSECONDS_PER_MILLISECOND, completed_at_ns=0)
    histogram.record(7 * NANOSECONDS_PER_MILLISECOND, completed_at_ns=NANOSECONDS_PER_SECOND)
    assert histogram.summary(now_ns=NANOSECONDS_PER_SECOND).count == 2

    assert histogram.summary(now_ns=4 * NANOSECONDS_PER_SECOND).count == 0
    assert histogram.summary(now_ns=4 * NANOSECONDS_PER_SECOND).max_ms is None


def test_rolling_histogram_reads_only_the_active_window_epochs():
    histogram = RollingDurationHistogram(slot_count=60, slot_duration_ns=NANOSECONDS_PER_SECOND)
    histogram.record(3 * NANOSECONDS_PER_MILLISECOND, completed_at_ns=57 * NANOSECONDS_PER_SECOND)
    histogram.record(5 * NANOSECONDS_PER_MILLISECOND, completed_at_ns=58 * NANOSECONDS_PER_SECOND)
    histogram.record(7 * NANOSECONDS_PER_MILLISECOND, completed_at_ns=59 * NANOSECONDS_PER_SECOND)

    summary = histogram.summary(now_ns=59 * NANOSECONDS_PER_SECOND, window_ns=2 * NANOSECONDS_PER_SECOND)
    assert summary.count == 2
    assert summary.total_ms == 12.0
    assert summary.max_ms == 7.0


def test_accumulator_bounds_categories_and_uses_injected_clock():
    clock = FakeClock(5 * NANOSECONDS_PER_SECOND)
    metrics = RuntimeMetricAccumulator(("overlay_receive", "admin_snapshot"), clock=clock)
    assert metrics.record("overlay_receive", 3 * NANOSECONDS_PER_MILLISECOND)
    assert not metrics.record("peer-203.0.113.1", 1)
    assert metrics.unknown_category_drops == 1

    snapshot = {item.category: item for item in metrics.snapshot()}
    assert snapshot["overlay_receive"].lifetime.count == 1
    assert snapshot["overlay_receive"].recent.max_ms == 3.0
    assert snapshot["admin_snapshot"].lifetime.count == 0


def test_accumulator_rejects_unbounded_category_definitions():
    with unittest.TestCase().assertRaises(ValueError):
        RuntimeMetricAccumulator(())
    with unittest.TestCase().assertRaises(ValueError):
        RuntimeMetricAccumulator(("x" * 65,))
    with unittest.TestCase().assertRaises(ValueError):
        RuntimeMetricAccumulator(tuple(str(index) for index in range(57)))


def test_runner_cpu_sampler_uses_process_delta_over_monotonic_wall_delta():
    runner = _runner_for_metrics_tests()
    assert runner._sample_runtime_cpu(monotonic_ns=10, process_cpu_ns=5) is None
    assert runner._sample_runtime_cpu(monotonic_ns=110, process_cpu_ns=55) == 0.5
    assert runner._runtime_metrics_last_cpu_cores == 0.5
    assert runner._runtime_metrics_sample_count == 1
    assert runner._record_runtime_loop_lag(deadline_ns=200, actual_ns=243) == 43
    assert runner._runtime_metrics_last_loop_lag_ns == 43
    assert runner._runtime_metrics_max_loop_lag_ns == 43


def test_runner_cpu_peak_keeps_largest_callback_occupancy_estimate():
    runner = _runner_for_metrics_tests()
    assert runner._sample_runtime_cpu(monotonic_ns=0, process_cpu_ns=0) is None
    runner._runtime_metrics_cpu_interval_by_category = {"channelmux_callback": 50, "tun_callback": 10}
    assert runner._sample_runtime_cpu(monotonic_ns=100, process_cpu_ns=80) == 0.8
    payload = runner._runtime_metrics_status_fields()["cpu_cores_max"]
    assert payload["overall_contributor"] == {"category": "channelmux_callback", "observed_cores": 0.5}
    assert payload["last_2_seconds_contributor"] == {"category": "channelmux_callback", "observed_cores": 0.5}


def test_runner_monitor_is_one_owned_task_and_cancels_cleanly():
    async def exercise():
        runner = _runner_for_metrics_tests()
        runner._start_runtime_metrics_monitor()
        task = runner._runtime_metrics_task
        assert task is not None
        runner._start_runtime_metrics_monitor()
        assert runner._runtime_metrics_task is task
        await asyncio.sleep(0)
        await runner._stop_runtime_metrics_monitor()
        assert runner._runtime_metrics_task is None
        assert task.cancelled()

    asyncio.run(exercise())


def test_runner_runtime_metrics_status_is_bounded_and_redacted():
    runner = _runner_for_metrics_tests()
    runner.record_sync_activity("channelmux.dispatch", phase="started")
    runner.record_sync_activity("channelmux.dispatch", phase="finished")
    payload = runner._runtime_metrics_status_fields()
    assert set(payload) == {"cpu_cores_max", "work_slice_ms_max", "event_loop_lag_ms", "categories", "longest_uninterrupted_category", "longest_uninterrupted_last_2_seconds_category"}
    assert payload["longest_uninterrupted_category"] == "channelmux_callback"
    assert payload["longest_uninterrupted_last_2_seconds_category"] == "channelmux_callback"
    assert all("payload" not in row and "address" not in row for row in payload["categories"])


def test_runner_records_completed_runtime_scope_without_retaining_individual_events():
    runner = _runner_for_metrics_tests()
    runner.record_runtime_duration("securelink", 3 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("unapproved_source", 5 * NANOSECONDS_PER_MILLISECOND)
    rows = {item["category"]: item for item in runner._runtime_metrics_status_fields()["categories"]}
    assert rows["securelink"]["count"] == 1
    assert rows["securelink"]["max_ms"] == 3.0
    assert runner._runtime_metrics.unknown_category_drops == 0


def test_runner_keeps_webadmin_snapshot_components_separate():
    runner = _runner_for_metrics_tests()
    runner.record_runtime_duration("status_stats", 3 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("status_session_summaries", 5 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("status_telemetry_state", 6 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("overlay_receive_data", 4 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("retransmit_unconfirmed", 2 * NANOSECONDS_PER_MILLISECOND)
    runner.record_runtime_duration("connections_snapshot", 7 * NANOSECONDS_PER_MILLISECOND)
    rows = {item["category"]: item for item in runner._runtime_metrics_status_fields()["categories"]}
    assert rows["status_stats"]["max_ms"] == 3.0
    assert rows["status_session_summaries"]["max_ms"] == 5.0
    assert rows["status_telemetry_state"]["max_ms"] == 6.0
    assert rows["overlay_receive_data"]["max_ms"] == 4.0
    assert rows["retransmit_unconfirmed"]["max_ms"] == 2.0
    assert rows["connections_snapshot"]["max_ms"] == 7.0
    assert rows["peers_snapshot"]["count"] == 0


def test_disabled_collector_status_skips_spool_filesystem_snapshot(monkeypatch):
    runner = Runner.__new__(Runner)
    runner.args = SimpleNamespace(
        telemetry_collector_enabled=False,
        telemetry_collector_spool_directory="/must-not-be-read",
    )
    runner._telemetry_collector_process = None
    runner._telemetry_collector_last_error = ""

    def unexpected_spool(*args, **kwargs):
        raise AssertionError("disabled collector must not inspect its spool")

    monkeypatch.setattr("obstacle_bridge.bridge_runner.TelemetrySpool", unexpected_spool)
    assert runner.get_telemetry_collector_snapshot() == {
        "enabled": False,
        "runtime_state": "disabled",
        "pid": None,
        "last_error": None,
        "spool": {},
        "accepted_batches": 0,
        "rejected_batches": 0,
        "last_accepted_unix_ts": None,
        "last_rejected_unix_ts": None,
        "ingest_last_error": None,
    }


def test_linux_local_runtime_metrics_smoke_lifecycle():
    """Socket/TUN-free local smoke coverage for the monitor/status lifecycle."""
    async def exercise():
        runner = _runner_for_metrics_tests()
        runner._start_runtime_metrics_monitor()
        await asyncio.sleep(0)
        runner._record_runtime_loop_lag(deadline_ns=10, actual_ns=20)
        payload = runner._runtime_metrics_status_fields()
        assert payload["event_loop_lag_ms"]["last"] == 0.00001
        assert isinstance(payload["categories"], list)
        await runner._stop_runtime_metrics_monitor()
        assert runner._runtime_metrics_task is None

    asyncio.run(exercise())
