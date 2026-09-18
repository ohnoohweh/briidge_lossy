"""Portable, redacted runtime-health evidence shared by platform owners."""

from __future__ import annotations

from dataclasses import asdict, dataclass
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

    @property
    def previous_lifetime_ended_cleanly(self) -> Optional[bool]:
        if not self._records:
            return None
        return self._records[-1].controlled_stop
