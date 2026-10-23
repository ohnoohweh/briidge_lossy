"""Bounded, dependency-free in-process runtime timing primitives.

This module intentionally does not start timers, inspect a process, or expose
an HTTP API. Runtime owners supply clock readings and choose their bounded set
of categories; later integration layers own sampling and status projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import math
import time
from typing import Callable, Dict, Iterable, Iterator, Optional, Protocol, Sequence, Tuple


NANOSECONDS_PER_MILLISECOND = 1_000_000
NANOSECONDS_PER_SECOND = 1_000_000_000
DEFAULT_DURATION_BUCKETS_NS: Tuple[int, ...] = tuple(
    int(milliseconds * NANOSECONDS_PER_MILLISECOND)
    for milliseconds in (0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512)
)


class RuntimeClock(Protocol):
    """Injectable monotonic clock contract used by runtime metric owners."""

    def monotonic_ns(self) -> int:
        """Return a monotonic timestamp in nanoseconds."""


class SystemRuntimeClock:
    """Default monotonic clock; process CPU accounting belongs to an adapter."""

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


@contextmanager
def bounded_runtime_scope(
    callback: Optional[Callable[[str, int], None]], category: str
) -> Iterator[None]:
    """Measure one synchronous scope and retain only its aggregate duration.

    The callback is intentionally optional so the production data path does
    not need a monitoring dependency.  The scope never changes an operation's
    result or exception behaviour.
    """
    if not callable(callback):
        yield
        return
    started_ns = time.monotonic_ns()
    try:
        yield
    finally:
        try:
            callback(str(category), max(0, time.monotonic_ns() - started_ns))
        except Exception:
            pass


@dataclass(frozen=True)
class DurationSummary:
    """A redacted, aggregate duration distribution in milliseconds."""

    count: int
    total_ms: float
    max_ms: Optional[float]
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    p99_ms: Optional[float]

    @classmethod
    def empty(cls) -> "DurationSummary":
        return cls(count=0, total_ms=0.0, max_ms=None, p50_ms=None, p95_ms=None, p99_ms=None)

    def as_payload(self) -> dict:
        return {
            "count": self.count,
            "total_ms": self.total_ms,
            "max_ms": self.max_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
        }


class DurationHistogram:
    """Fixed-bucket duration distribution with no retained individual samples."""

    def __init__(self, buckets_ns: Sequence[int] = DEFAULT_DURATION_BUCKETS_NS) -> None:
        normalized = tuple(int(value) for value in buckets_ns)
        if not normalized or any(value <= 0 for value in normalized):
            raise ValueError("duration histogram buckets must be positive")
        if tuple(sorted(set(normalized))) != normalized:
            raise ValueError("duration histogram buckets must be strictly increasing")
        self.buckets_ns = normalized
        self.counts = [0] * (len(normalized) + 1)
        self.count = 0
        self.total_ns = 0
        self.max_ns = 0

    def record(self, duration_ns: int) -> None:
        duration = int(duration_ns)
        if duration < 0:
            raise ValueError("duration must not be negative")
        index = len(self.buckets_ns)
        for candidate, ceiling in enumerate(self.buckets_ns):
            if duration <= ceiling:
                index = candidate
                break
        self.counts[index] += 1
        self.count += 1
        self.total_ns += duration
        self.max_ns = max(self.max_ns, duration)

    def merge(self, other: "DurationHistogram") -> None:
        if self.buckets_ns != other.buckets_ns:
            raise ValueError("duration histogram bucket mismatch")
        self.counts = [left + right for left, right in zip(self.counts, other.counts)]
        self.count += other.count
        self.total_ns += other.total_ns
        self.max_ns = max(self.max_ns, other.max_ns)

    def summary(self) -> DurationSummary:
        if not self.count:
            return DurationSummary.empty()
        return DurationSummary(
            count=self.count,
            total_ms=self.total_ns / NANOSECONDS_PER_MILLISECOND,
            max_ms=self.max_ns / NANOSECONDS_PER_MILLISECOND,
            p50_ms=self._percentile_ms(0.50),
            p95_ms=self._percentile_ms(0.95),
            p99_ms=self._percentile_ms(0.99),
        )

    def _percentile_ms(self, quantile: float) -> float:
        rank = max(1, int(math.ceil(self.count * quantile)))
        observed = 0
        for index, bucket_count in enumerate(self.counts):
            observed += bucket_count
            if observed >= rank:
                if index < len(self.buckets_ns):
                    return self.buckets_ns[index] / NANOSECONDS_PER_MILLISECOND
                return self.max_ns / NANOSECONDS_PER_MILLISECOND
        return self.max_ns / NANOSECONDS_PER_MILLISECOND


class RollingDurationHistogram:
    """Fixed slot ring that bounds rolling histogram memory and work."""

    def __init__(
        self,
        *,
        slot_count: int = 60,
        slot_duration_ns: int = NANOSECONDS_PER_SECOND,
        buckets_ns: Sequence[int] = DEFAULT_DURATION_BUCKETS_NS,
    ) -> None:
        if slot_count <= 0:
            raise ValueError("rolling histogram slot_count must be positive")
        if slot_duration_ns <= 0:
            raise ValueError("rolling histogram slot duration must be positive")
        self.slot_count = int(slot_count)
        self.slot_duration_ns = int(slot_duration_ns)
        self.buckets_ns = tuple(int(value) for value in buckets_ns)
        self._epochs: list[Optional[int]] = [None] * self.slot_count
        self._slots = [DurationHistogram(self.buckets_ns) for _ in range(self.slot_count)]

    @property
    def capacity_ns(self) -> int:
        return self.slot_count * self.slot_duration_ns

    def record(self, duration_ns: int, *, completed_at_ns: int) -> None:
        epoch = int(completed_at_ns) // self.slot_duration_ns
        index = epoch % self.slot_count
        if self._epochs[index] != epoch:
            self._epochs[index] = epoch
            self._slots[index] = DurationHistogram(self.buckets_ns)
        self._slots[index].record(duration_ns)

    def summary(self, *, now_ns: int, window_ns: Optional[int] = None) -> DurationSummary:
        window = self.capacity_ns if window_ns is None else int(window_ns)
        if window <= 0 or window > self.capacity_ns:
            raise ValueError("rolling histogram window must fit its configured capacity")
        now_epoch = int(now_ns) // self.slot_duration_ns
        # Slots are complete, fixed intervals. Treat the rolling lower bound as
        # exclusive so a sample exactly one full window old does not survive
        # merely because it shares a coarse slot boundary.
        window_slots = int(math.ceil(window / self.slot_duration_ns))
        earliest_epoch = now_epoch - window_slots + 1
        aggregate = DurationHistogram(self.buckets_ns)
        # The ring index is derived from the epoch, so inspecting every ring
        # slot is unnecessary for a short status window.  In particular, the
        # Runtime Analysis two-second projection visits only its two relevant
        # slots per category rather than all sixty retained slots.
        for epoch in range(earliest_epoch, now_epoch + 1):
            index = epoch % self.slot_count
            if self._epochs[index] == epoch:
                aggregate.merge(self._slots[index])
        return aggregate.summary()


@dataclass(frozen=True)
class CategorySnapshot:
    """Lifetime and rolling aggregates for one approved metric category."""

    category: str
    lifetime: DurationSummary
    recent: DurationSummary

    def as_payload(self) -> dict:
        return {
            "category": self.category,
            "lifetime": self.lifetime.as_payload(),
            "recent": self.recent.as_payload(),
        }


class RuntimeMetricAccumulator:
    """Bounded multi-category timing accumulator for a runtime owner."""

    def __init__(
        self,
        categories: Iterable[str],
        *,
        clock: Optional[RuntimeClock] = None,
        max_categories: int = 56,
        rolling_slot_count: int = 60,
        rolling_slot_duration_ns: int = NANOSECONDS_PER_SECOND,
        buckets_ns: Sequence[int] = DEFAULT_DURATION_BUCKETS_NS,
    ) -> None:
        approved = tuple(dict.fromkeys(str(category) for category in categories))
        if not approved:
            raise ValueError("runtime metric categories must not be empty")
        if len(approved) > max_categories:
            raise ValueError("runtime metric categories exceed bounded capacity")
        if any(not category or len(category) > 64 for category in approved):
            raise ValueError("runtime metric categories must be non-empty and bounded")
        self.clock = clock or SystemRuntimeClock()
        self._categories = approved
        self._lifetime: Dict[str, DurationHistogram] = {
            category: DurationHistogram(buckets_ns) for category in approved
        }
        self._rolling: Dict[str, RollingDurationHistogram] = {
            category: RollingDurationHistogram(
                slot_count=rolling_slot_count,
                slot_duration_ns=rolling_slot_duration_ns,
                buckets_ns=buckets_ns,
            )
            for category in approved
        }
        self.unknown_category_drops = 0

    @property
    def categories(self) -> Tuple[str, ...]:
        return self._categories

    def record(self, category: str, duration_ns: int, *, completed_at_ns: Optional[int] = None) -> bool:
        key = str(category)
        lifetime = self._lifetime.get(key)
        rolling = self._rolling.get(key)
        if lifetime is None or rolling is None:
            self.unknown_category_drops += 1
            return False
        completed = self.clock.monotonic_ns() if completed_at_ns is None else int(completed_at_ns)
        lifetime.record(duration_ns)
        rolling.record(duration_ns, completed_at_ns=completed)
        return True

    def snapshot(self, *, now_ns: Optional[int] = None, window_ns: Optional[int] = None) -> Tuple[CategorySnapshot, ...]:
        now = self.clock.monotonic_ns() if now_ns is None else int(now_ns)
        return tuple(
            CategorySnapshot(
                category=category,
                lifetime=self._lifetime[category].summary(),
                recent=self._rolling[category].summary(now_ns=now, window_ns=window_ns),
            )
            for category in self._categories
        )
