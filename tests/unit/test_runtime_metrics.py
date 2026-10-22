import unittest
import asyncio
import threading

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
    runner._runtime_metrics = RuntimeMetricAccumulator(("channelmux_callback", "tun_callback", "admin_snapshot"))
    runner._runtime_metrics_started = {}
    runner._runtime_metrics_cpu_peaks = []
    runner._runtime_metrics_cpu_peak_overall = None
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
        RuntimeMetricAccumulator(tuple(str(index) for index in range(33)))


def test_runner_cpu_sampler_uses_process_delta_over_monotonic_wall_delta():
    runner = _runner_for_metrics_tests()
    assert runner._sample_runtime_cpu(monotonic_ns=10, process_cpu_ns=5) is None
    assert runner._sample_runtime_cpu(monotonic_ns=110, process_cpu_ns=55) == 0.5
    assert runner._runtime_metrics_last_cpu_cores == 0.5
    assert runner._runtime_metrics_sample_count == 1
    assert runner._record_runtime_loop_lag(deadline_ns=200, actual_ns=243) == 43
    assert runner._runtime_metrics_last_loop_lag_ns == 43
    assert runner._runtime_metrics_max_loop_lag_ns == 43


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
    assert set(payload) == {"cpu_cores_max", "work_slice_ms_max", "event_loop_lag_ms", "categories", "most_timed_category", "longest_uninterrupted_category"}
    assert payload["most_timed_category"] == "channelmux_callback"
    assert all("payload" not in row and "address" not in row for row in payload["categories"])
