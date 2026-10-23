"""Common ``OBIP`` framing for the local privileged TUN-helper boundary.

The connected local socket and one-time token remain the authentication
capabilities. This module deliberately reuses the desktop worker frame ABI
instead of retaining the former helper-specific five-byte header.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional

from .worker_ipc import (
    WORKER_IPC_MAX_FRAME_BYTES,
    WorkerIPCFrame,
    WorkerIPCFrameKind,
    decode_control,
    encode_control,
    encode_frame as _encode_frame,
    hello as _hello,
    negotiated_capabilities,
    try_decode_frame as _try_decode_frame,
)


TUN_HELPER_PROTOCOL_VERSION = 1
TUN_HELPER_MAX_FRAME_BYTES = WORKER_IPC_MAX_FRAME_BYTES
TUN_HELPER_MAX_OPERATION_CHARS = 64
TUN_HELPER_CLIENT_ROLE = "tun-helper-client"
TUN_HELPER_SERVER_ROLE = "tun-helper"
TUN_HELPER_CAPABILITIES = frozenset({"tun.control", "tun.packet", "tun.event"})


class TunHelperFrameKind(enum.IntEnum):
    HELLO = WorkerIPCFrameKind.HELLO
    READY = WorkerIPCFrameKind.READY
    REQUEST = WorkerIPCFrameKind.REQUEST
    RESPONSE = WorkerIPCFrameKind.RESPONSE
    EVENT = WorkerIPCFrameKind.EVENT
    DATA = WorkerIPCFrameKind.DATA
    ERROR = WorkerIPCFrameKind.ERROR
    GOODBYE = WorkerIPCFrameKind.GOODBYE


@dataclass(frozen=True)
class TunHelperFrame:
    kind: TunHelperFrameKind
    generation: int
    payload: bytes


@dataclass(frozen=True)
class TunHelperControlMessage:
    op: str
    payload: dict[str, Any] = field(default_factory=dict)
    version: int = TUN_HELPER_PROTOCOL_VERSION


def _normalise_operation(value: Any) -> str:
    if not isinstance(value, str) or not (operation := value.strip()) or len(operation) > TUN_HELPER_MAX_OPERATION_CHARS:
        raise ValueError("TUN helper control payload is missing op")
    return operation


def encode_frame(kind: TunHelperFrameKind, generation: int, payload: bytes = b"") -> bytes:
    try:
        return _encode_frame(WorkerIPCFrameKind(kind), generation, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid TUN helper frame") from exc


def try_decode_frame(data: bytes) -> Optional[tuple[TunHelperFrame, bytes]]:
    try:
        decoded = _try_decode_frame(data)
    except ValueError as exc:
        raise ValueError("invalid TUN helper frame") from exc
    if decoded is None:
        return None
    frame, remainder = decoded
    return TunHelperFrame(TunHelperFrameKind(frame.kind), frame.generation, frame.payload), remainder


def encode_control_frame(kind: TunHelperFrameKind, generation: int, message: TunHelperControlMessage) -> bytes:
    if kind not in {TunHelperFrameKind.REQUEST, TunHelperFrameKind.RESPONSE, TunHelperFrameKind.EVENT, TunHelperFrameKind.ERROR, TunHelperFrameKind.READY}:
        raise ValueError(f"control frames require a common control kind, got {kind!r}")
    operation = _normalise_operation(message.op)
    try:
        return encode_control(WorkerIPCFrameKind(kind), generation, {"op": operation, "payload": dict(message.payload)})
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid TUN helper control payload") from exc


def decode_control_payload(payload: bytes) -> TunHelperControlMessage:
    frame = WorkerIPCFrame(kind=WorkerIPCFrameKind.RESPONSE, generation=1, payload=bytes(payload))
    try:
        doc = decode_control(frame)
    except ValueError as exc:
        raise ValueError("invalid TUN helper control payload") from exc
    op = _normalise_operation(doc.get("op"))
    raw_payload = doc.get("payload")
    if raw_payload is None:
        payload_map: dict[str, Any] = {}
    elif isinstance(raw_payload, dict):
        payload_map = dict(raw_payload)
    else:
        raise ValueError("TUN helper control payload field must be an object when present")
    return TunHelperControlMessage(op=op, payload=payload_map)


def encode_hello(generation: int, *, role: str = TUN_HELPER_CLIENT_ROLE) -> bytes:
    return _hello(generation, role, TUN_HELPER_CAPABILITIES)


def negotiated_hello(frame: TunHelperFrame, *, supported: set[str] | frozenset[str] = TUN_HELPER_CAPABILITIES) -> tuple[str, tuple[str, ...]]:
    return negotiated_capabilities(
        WorkerIPCFrame(WorkerIPCFrameKind(frame.kind), frame.generation, frame.payload),
        set(supported),
    )
