import unittest

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
