from __future__ import annotations

import json
from pathlib import Path

import pytest

from obstacle_bridge.bridge import BatchDecodeError, MyUDP2BatchCodec, Protocol, StreamChunk
from obstacle_bridge.bridge import BaseFrameV2


_VECTORS = json.loads(
    (Path(__file__).parents[2] / "docs" / "MYUDP2_WIRE_VECTORS.json").read_text(encoding="utf-8")
)


def test_batch_codec_decodes_and_reencodes_frozen_data_vector() -> None:
    vector = next(item for item in _VECTORS["valid_frames"] if item["name"] == "data_batch_two_chunks")
    frame = bytes.fromhex(vector["hex"])
    parsed = Protocol(BaseFrameV2).parse_frame_with_times(frame)
    assert parsed is not None
    ptype, payload, tx_ns, echo_ns = parsed

    chunks = MyUDP2BatchCodec.decode_batch(payload)

    assert (ptype, tx_ns, echo_ns) == (1, 1000, 500)
    assert [(chunk.counter, chunk.data.hex()) for chunk in chunks] == [
        (item["counter"], item["data_hex"]) for item in vector["chunks"]
    ]
    assert MyUDP2BatchCodec.encode_batch(chunks) == payload.tobytes()


@pytest.mark.parametrize("vector", _VECTORS["invalid_frames"], ids=lambda item: item["name"])
def test_batch_codec_rejects_frozen_invalid_vectors(vector: dict) -> None:
    parsed = Protocol(BaseFrameV2).parse_frame_with_times(bytes.fromhex(vector["hex"]))
    assert parsed is not None

    with pytest.raises(BatchDecodeError):
        MyUDP2BatchCodec.decode_batch(parsed[1])


def test_batch_codec_fills_the_exact_frozen_payload_budget() -> None:
    payload = MyUDP2BatchCodec.encode_batch([StreamChunk(1, b"x" * 1425)])

    assert len(payload) == 1433
    assert MyUDP2BatchCodec.decode_batch(payload)[0].data == b"x" * 1425
