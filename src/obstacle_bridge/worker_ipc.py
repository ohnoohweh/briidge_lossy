"""Versioned private-desktop worker IPC framing.

The inherited Unix socket is the authentication capability.  This module
provides the common, bounded frame contract used when a desktop supervisor and
worker exchange control messages or binary data; it never opens a listener.
"""
from __future__ import annotations

import enum
import json
import struct
from dataclasses import dataclass
from typing import Any


WORKER_IPC_VERSION = 1
WORKER_IPC_MAX_FRAME_BYTES = 1_048_576
_MAGIC = b"OBIP"
_HEADER = struct.Struct("!4sBBHQI")


class WorkerIPCFrameKind(enum.IntEnum):
    HELLO = 1
    READY = 2
    REQUEST = 3
    RESPONSE = 4
    EVENT = 5
    DATA = 6
    ERROR = 7
    GOODBYE = 8


@dataclass(frozen=True)
class WorkerIPCFrame:
    kind: WorkerIPCFrameKind
    generation: int
    payload: bytes


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate worker IPC JSON field")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise ValueError("invalid worker IPC JSON number")


def _validate_generation(generation: int) -> int:
    if type(generation) is not int or not 0 < generation <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("invalid worker IPC generation")
    return generation


def encode_frame(kind: WorkerIPCFrameKind, generation: int, payload: bytes = b"") -> bytes:
    try:
        frame_kind = WorkerIPCFrameKind(kind)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid worker IPC frame kind") from exc
    body = bytes(payload)
    if len(body) > WORKER_IPC_MAX_FRAME_BYTES:
        raise ValueError("worker IPC frame exceeds maximum payload size")
    return _HEADER.pack(_MAGIC, WORKER_IPC_VERSION, int(frame_kind), 0, _validate_generation(generation), len(body)) + body


def try_decode_frame(data: bytes) -> tuple[WorkerIPCFrame, bytes] | None:
    raw = bytes(data)
    size = frame_size(raw)
    if size is None:
        return None
    magic, version, raw_kind, flags, generation, _ = _HEADER.unpack(raw[:_HEADER.size])
    if magic != _MAGIC or version != WORKER_IPC_VERSION or flags != 0:
        raise ValueError("invalid worker IPC frame header")
    try:
        kind = WorkerIPCFrameKind(raw_kind)
    except ValueError as exc:
        raise ValueError("invalid worker IPC frame kind") from exc
    _validate_generation(generation)
    if size > WORKER_IPC_MAX_FRAME_BYTES:
        raise ValueError("worker IPC frame exceeds maximum payload size")
    total = _HEADER.size + size
    if len(raw) < total:
        return None
    return WorkerIPCFrame(kind=kind, generation=generation, payload=raw[_HEADER.size:total]), raw[total:]


def frame_size(data: bytes) -> int | None:
    """Return a validated body size once the fixed header is available."""
    raw = bytes(data)
    if len(raw) < _HEADER.size:
        return None
    magic, version, raw_kind, flags, generation, size = _HEADER.unpack(raw[:_HEADER.size])
    if magic != _MAGIC or version != WORKER_IPC_VERSION or flags != 0:
        raise ValueError("invalid worker IPC frame header")
    try:
        WorkerIPCFrameKind(raw_kind)
    except ValueError as exc:
        raise ValueError("invalid worker IPC frame kind") from exc
    _validate_generation(generation)
    if size > WORKER_IPC_MAX_FRAME_BYTES:
        raise ValueError("worker IPC frame exceeds maximum payload size")
    return size


def encode_control(kind: WorkerIPCFrameKind, generation: int, value: dict[str, Any]) -> bytes:
    if kind == WorkerIPCFrameKind.DATA or not isinstance(value, dict):
        raise ValueError("worker IPC control payload must be an object")
    try:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid worker IPC control payload") from exc
    return encode_frame(kind, generation, payload)


def decode_control(frame: WorkerIPCFrame) -> dict[str, Any]:
    if frame.kind == WorkerIPCFrameKind.DATA:
        raise ValueError("worker IPC data frame has no control payload")
    try:
        value = json.loads(frame.payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_object, parse_constant=_reject_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid worker IPC control payload") from exc
    if not isinstance(value, dict):
        raise ValueError("worker IPC control payload must be an object")
    return value


def hello(generation: int, role: str, capabilities: list[str] | tuple[str, ...] | set[str]) -> bytes:
    if not isinstance(role, str) or not role or len(role) > 64:
        raise ValueError("invalid worker IPC role")
    names = sorted(set(capabilities))
    if any(not isinstance(name, str) or not name or len(name) > 64 for name in names):
        raise ValueError("invalid worker IPC capability")
    return encode_control(WorkerIPCFrameKind.HELLO, generation, {"capabilities": names, "role": role})


def negotiated_capabilities(frame: WorkerIPCFrame, supported: set[str]) -> tuple[str, tuple[str, ...]]:
    if frame.kind != WorkerIPCFrameKind.HELLO:
        raise ValueError("worker IPC capability negotiation requires hello")
    value = decode_control(frame)
    role, advertised = value.get("role"), value.get("capabilities")
    if not isinstance(role, str) or not role or len(role) > 64 or not isinstance(advertised, list):
        raise ValueError("invalid worker IPC hello")
    if any(not isinstance(name, str) or not name or len(name) > 64 for name in advertised) or len(set(advertised)) != len(advertised):
        raise ValueError("invalid worker IPC capability")
    return role, tuple(sorted(set(advertised).intersection(supported)))
