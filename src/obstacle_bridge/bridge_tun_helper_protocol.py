from __future__ import annotations

import enum
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional


TUN_HELPER_PROTOCOL_VERSION = 1
_FRAME_HEADER = struct.Struct(">BI")


class TunHelperFrameKind(enum.IntEnum):
    CONTROL_REQUEST = 1
    CONTROL_RESPONSE = 2
    PACKET_FROM_HELPER = 3
    PACKET_TO_HELPER = 4
    EVENT = 5


@dataclass(frozen=True)
class TunHelperControlMessage:
    op: str
    payload: dict[str, Any] = field(default_factory=dict)
    version: int = TUN_HELPER_PROTOCOL_VERSION


def encode_frame(kind: TunHelperFrameKind, payload: bytes) -> bytes:
    body = bytes(payload)
    return _FRAME_HEADER.pack(int(kind), len(body)) + body


def try_decode_frame(data: bytes) -> Optional[tuple[TunHelperFrameKind, bytes, bytes]]:
    if len(data) < _FRAME_HEADER.size:
        return None
    kind_raw, length = _FRAME_HEADER.unpack(data[: _FRAME_HEADER.size])
    try:
        kind = TunHelperFrameKind(kind_raw)
    except ValueError as exc:
        raise ValueError(f"unknown TUN helper frame kind: {kind_raw}") from exc
    frame_total = _FRAME_HEADER.size + int(length)
    if len(data) < frame_total:
        return None
    payload = data[_FRAME_HEADER.size : frame_total]
    remainder = data[frame_total:]
    return kind, payload, remainder


def encode_control_frame(kind: TunHelperFrameKind, message: TunHelperControlMessage) -> bytes:
    if kind not in {TunHelperFrameKind.CONTROL_REQUEST, TunHelperFrameKind.CONTROL_RESPONSE}:
        raise ValueError(f"control frames require request/response kinds, got {kind!r}")
    encoded = json.dumps(
        {
            "version": int(message.version),
            "op": str(message.op),
            "payload": dict(message.payload),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encode_frame(kind, encoded)


def decode_control_payload(payload: bytes) -> TunHelperControlMessage:
    try:
        doc = json.loads(bytes(payload).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid TUN helper control payload: {exc}") from exc
    version = int(doc.get("version", 0) or 0)
    if version != TUN_HELPER_PROTOCOL_VERSION:
        raise ValueError(
            f"unsupported TUN helper protocol version: {version} != {TUN_HELPER_PROTOCOL_VERSION}"
        )
    op = str(doc.get("op") or "").strip()
    if not op:
        raise ValueError("TUN helper control payload is missing op")
    raw_payload = doc.get("payload")
    if raw_payload is None:
        payload_map: dict[str, Any] = {}
    elif isinstance(raw_payload, dict):
        payload_map = dict(raw_payload)
    else:
        raise ValueError("TUN helper control payload field must be an object when present")
    return TunHelperControlMessage(op=op, payload=payload_map, version=version)
