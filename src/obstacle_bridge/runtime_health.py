"""Portable, redacted runtime-health evidence shared by platform owners."""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import tempfile
from typing import Optional


@dataclass(frozen=True)
class RuntimeHealthRecord:
    """One bounded diagnostic observation; never carries payload or secrets."""

    schema_version: int = 1
    sequence: int = 0
    timestamp_unix_milliseconds: int = 0
    event: str = ""
    controlled_stop: bool = False
    process_resident_bytes: Optional[int] = None
    process_footprint_bytes: Optional[int] = None
    heartbeat_age_milliseconds: Optional[int] = None
    packet_pump_running: Optional[bool] = None
    overlay_state: Optional[str] = None
    securelink_state: Optional[str] = None
    transport_epoch: Optional[int] = None
    incoming_queued_packets: Optional[int] = None
    outgoing_queued_packets: Optional[int] = None
    outgoing_inflight_writes: Optional[int] = None
    incoming_dropped_packets: Optional[int] = None
    outgoing_dropped_packets: Optional[int] = None
    slow_writes: Optional[int] = None
    packets_from_system: Optional[int] = None
    packets_to_system: Optional[int] = None

    def as_payload(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: object) -> "RuntimeHealthRecord":
        if not isinstance(payload, dict):
            raise ValueError("runtime health record must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"runtime health record has unknown fields: {sorted(unknown)!r}")
        if int(payload.get("schema_version", 1)) != 1:
            raise ValueError("unsupported runtime health record schema")
        return cls(**payload)


class RuntimeHealthRing:
    """Fixed-capacity health records; persistence is adapter-owned."""

    def __init__(self, capacity: int = 128, records: tuple[RuntimeHealthRecord, ...] = ()) -> None:
        if capacity <= 0:
            raise ValueError("runtime health ring capacity must be positive")
        self.capacity = capacity
        self._records = list(records[-capacity:])

    @property
    def records(self) -> tuple[RuntimeHealthRecord, ...]:
        return tuple(self._records)

    def append(self, record: RuntimeHealthRecord) -> None:
        if len(self._records) == self.capacity:
            del self._records[0]
        self._records.append(record)

    def as_payload(self) -> dict[str, object]:
        return {
            "capacity": self.capacity,
            "records": [record.as_payload() for record in self._records],
        }

    @classmethod
    def from_payload(cls, payload: object) -> "RuntimeHealthRing":
        if not isinstance(payload, dict):
            raise ValueError("runtime health ring must be an object")
        capacity = payload.get("capacity")
        records = payload.get("records")
        if not isinstance(capacity, int) or isinstance(capacity, bool):
            raise ValueError("runtime health ring capacity must be an integer")
        if not isinstance(records, list):
            raise ValueError("runtime health ring records must be a list")
        return cls(capacity=capacity, records=tuple(RuntimeHealthRecord.from_payload(item) for item in records))

    @property
    def previous_lifetime_ended_cleanly(self) -> Optional[bool]:
        if not self._records:
            return None
        return self._records[-1].controlled_stop


class RuntimeHealthStore:
    """Crash-safe local storage for a runtime-owned health ring."""

    def __init__(self, path: str | Path, capacity: int = 128) -> None:
        self.path = Path(path)
        self.capacity = capacity
        if capacity <= 0:
            raise ValueError("runtime health ring capacity must be positive")
        self.ring = RuntimeHealthRing(capacity=capacity)

    def begin_lifetime(self) -> Optional[bool]:
        prior = self.load()
        previous = prior.previous_lifetime_ended_cleanly if prior is not None else None
        # Preserve bounded observations from the preceding lifetime. A fresh
        # start marker below is the lifetime boundary; discarding the old ring
        # here would erase the only local evidence of an abrupt termination.
        self.ring = prior if prior is not None else RuntimeHealthRing(capacity=self.capacity)
        return previous

    def append(self, record: RuntimeHealthRecord) -> None:
        self.ring.append(record)
        self.save()

    def load(self) -> Optional[RuntimeHealthRing]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return RuntimeHealthRing.from_payload(payload)
        except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.ring.as_payload(), sort_keys=True, separators=(",", ":"))
        fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_name)
            raise
