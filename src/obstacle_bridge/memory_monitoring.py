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


def _sample_windows_process_resident_memory_bytes() -> Optional[int]:
    """Return the current process working set via the Windows PSAPI.

    ``WorkingSetSize`` is the Windows counterpart of Linux's current RSS.
    Keep the ctypes imports local: this module must remain importable on every
    supported platform without an optional monitoring dependency.
    """
    try:
        import ctypes

        class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            process, ctypes.byref(counters), counters.cb
        )
        value = int(counters.WorkingSetSize) if ok else -1
        return value if value >= 0 else None
    except (AttributeError, OSError, ValueError):
        return None


def _sample_darwin_process_resident_memory_bytes() -> Optional[int]:
    """Return current process resident bytes through the Mach task API."""
    try:
        import ctypes

        class TimeValue(ctypes.Structure):
            _fields_ = [("seconds", ctypes.c_int32), ("microseconds", ctypes.c_int32)]

        class MachTaskBasicInfo(ctypes.Structure):
            _fields_ = [
                ("virtual_size", ctypes.c_uint64),
                ("resident_size", ctypes.c_uint64),
                ("user_time", TimeValue),
                ("system_time", TimeValue),
                ("policy", ctypes.c_int32),
                ("suspend_count", ctypes.c_int32),
            ]

        libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        libsystem.mach_task_self.restype = ctypes.c_uint
        libsystem.task_info.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_uint),
        ]
        libsystem.task_info.restype = ctypes.c_int
        info = MachTaskBasicInfo()
        count = ctypes.c_uint(ctypes.sizeof(info) // ctypes.sizeof(ctypes.c_int))
        result = libsystem.task_info(
            libsystem.mach_task_self(),
            20,  # MACH_TASK_BASIC_INFO
            ctypes.cast(ctypes.byref(info), ctypes.POINTER(ctypes.c_int)),
            ctypes.byref(count),
        )
        value = int(info.resident_size) if result == 0 else -1
        return value if value >= 0 else None
    except (AttributeError, OSError, ValueError):
        return None


def sample_process_resident_memory_bytes(
    *,
    status_reader: Optional[Callable[[], str]] = None,
) -> Optional[int]:
    """Return current process RSS/working-set bytes, or ``None`` if unavailable.

    ``/proc/self/status`` provides a current process-local measurement.  This
    deliberately does not use ``ru_maxrss``, which is a platform-dependent
    high-water value rather than a current resident-memory reading.
    """
    if sys.platform.startswith("win"):
        return _sample_windows_process_resident_memory_bytes()
    if sys.platform == "darwin":
        return _sample_darwin_process_resident_memory_bytes()
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
