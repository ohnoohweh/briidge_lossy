"""Shared connection lifecycle contract for overlay sessions and wrappers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import time
from typing import Any, Mapping, Optional


class ConnectionState(str, Enum):
    """The only externally propagated overlay lifecycle states."""

    DISCONNECTED = "disconnected"
    CONNECTED = "connected"


@dataclass(frozen=True)
class ConnectionLifecycleEvent:
    """A state transition emitted by one layer of an overlay session stack."""

    state: ConnectionState
    epoch: int
    reason: str = ""
    changed_at_unix_ts: float = 0.0

    def __post_init__(self) -> None:
        if int(self.epoch) < 0:
            raise ValueError("connection lifecycle epoch must be non-negative")
        if float(self.changed_at_unix_ts) <= 0.0:
            object.__setattr__(self, "changed_at_unix_ts", time.time())

    @property
    def connected(self) -> bool:
        return self.state is ConnectionState.CONNECTED

    def as_snapshot(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "connected": self.connected,
            "epoch": int(self.epoch),
            "reason": str(self.reason or ""),
            "changed_at_unix_ts": float(self.changed_at_unix_ts),
        }

    @classmethod
    def from_snapshot(cls, value: Mapping[str, Any]) -> "ConnectionLifecycleEvent":
        raw_state = str(value.get("state") or "").strip().lower()
        connected = bool(value.get("connected"))
        state = ConnectionState.CONNECTED if raw_state == ConnectionState.CONNECTED.value or connected else ConnectionState.DISCONNECTED
        return cls(
            state=state,
            epoch=max(0, int(value.get("epoch") or 0)),
            reason=str(value.get("reason") or ""),
            changed_at_unix_ts=float(value.get("changed_at_unix_ts") or 0.0),
        )


@dataclass(frozen=True)
class ConnectionRotationResult:
    """The result returned while a rotation request travels down the stack."""

    accepted: bool
    reason: str = ""
    next_epoch: Optional[int] = None
    candidate_index: Optional[int] = None
    candidate_cycle: Optional[int] = None

    def as_snapshot(self) -> dict[str, Any]:
        return {
            "accepted": bool(self.accepted),
            "reason": str(self.reason or ""),
            "next_epoch": self.next_epoch,
            "candidate_index": self.candidate_index,
            "candidate_cycle": self.candidate_cycle,
        }
