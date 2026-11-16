"""Bounded, dependency-free process-memory monitoring for runtime owners."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import sys
from typing import Callable, Deque, Optional

from .runtime_metrics import NANOSECONDS_PER_SECOND


MEMORY_MEASUREMENT_RESIDENT = "resident"
MEMORY_MEASUREMENT_UNAVAILABLE = "unavailable"
RECENT_MEMORY_WINDOW_NS = 2 * NANOSECONDS_PER_SECOND
# The Runner samples once per second. Three values cover the inclusive
# two-second window while keeping retention fixed even if a caller samples
# more often during tests or a future cadence change.
RECENT_MEMORY_SAMPLE_CAPACITY = 3


def sample_process_resident_memory_bytes(
    *,
    status_reader: Optional[Callable[[], str]] = None,
) -> Optional[int]:
    """Return current Linux process RSS in bytes, or ``None`` if unavailable.

    ``/proc/self/status`` provides a current process-local measurement.  This
    deliberately does not use ``ru_maxrss``, which is a platform-dependent
    high-water value rather than a current resident-memory reading.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        if status_reader is not None:
            text = status_reader()
        else:
            with open("/proc/self/status", "r", encoding="utf-8") as status_file:
                text = status_file.read()
    except (OSError, UnicodeError):
        return None
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if key != "VmRSS" or not separator:
            continue
        fields = value.split()
        if len(fields) != 2 or fields[1] != "kB":
            return None
        try:
            kibibytes = int(fields[0])
        except ValueError:
            return None
        return kibibytes * 1024 if kibibytes >= 0 else None
    return None


@dataclass(frozen=True)
class MemorySample:
    timestamp_ns: int
    bytes: int


class RuntimeMemoryMetrics:
    """Fixed-size current/peak memory projection for one process lifetime."""

    def __init__(self, *, warning_limit_bytes: Optional[int] = None) -> None:
        if warning_limit_bytes is not None and int(warning_limit_bytes) < 0:
            raise ValueError("memory warning limit must be non-negative")
        self.warning_limit_bytes = (
            None if warning_limit_bytes is None else int(warning_limit_bytes)
        )
        self.current_bytes: Optional[int] = None
        self.overall_peak_bytes: Optional[int] = None
        self._recent: Deque[MemorySample] = deque(maxlen=RECENT_MEMORY_SAMPLE_CAPACITY)

    def record(self, value: Optional[int], *, timestamp_ns: int) -> bool:
        """Store one valid reading and retain no data when the sampler fails."""
        if value is None:
            return False
        try:
            bytes_value = int(value)
        except (TypeError, ValueError, OverflowError):
            return False
        if bytes_value < 0:
            return False
        sample = MemorySample(timestamp_ns=int(timestamp_ns), bytes=bytes_value)
        self.current_bytes = bytes_value
        self.overall_peak_bytes = max(self.overall_peak_bytes or 0, bytes_value)
        self._recent.append(sample)
        return True

    def as_payload(self, *, now_ns: int) -> dict:
        if self.current_bytes is None:
            return {
                "current": None,
                "overall_peak": None,
                "last_2_seconds_peak": None,
                "warning_limit": self.warning_limit_bytes,
                "warning_active": False,
                "measurement_kind": MEMORY_MEASUREMENT_UNAVAILABLE,
            }
        recent_peak = max(
            (
                sample.bytes
                for sample in self._recent
                if 0 <= int(now_ns) - sample.timestamp_ns <= RECENT_MEMORY_WINDOW_NS
            ),
            default=None,
        )
        return {
            "current": self.current_bytes,
            "overall_peak": self.overall_peak_bytes,
            "last_2_seconds_peak": recent_peak,
            "warning_limit": self.warning_limit_bytes,
            "warning_active": bool(
                self.warning_limit_bytes is not None
                and self.current_bytes >= self.warning_limit_bytes
            ),
            "measurement_kind": MEMORY_MEASUREMENT_RESIDENT,
        }
