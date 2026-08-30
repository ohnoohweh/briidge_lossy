from __future__ import annotations

import pytest

from obstacle_bridge.bridge import (
    MAX_STREAM_RECORD_BYTES,
    StreamDecodeError,
    StreamDeserializer,
    StreamSerializer,
)


def test_stream_deserializer_accepts_every_split_of_length_prefix_and_body() -> None:
    encoded = StreamSerializer().encode(b"payload")

    for split in range(len(encoded) + 1):
        decoder = StreamDeserializer()
        first = decoder.feed(encoded[:split])
        second = decoder.feed(encoded[split:])
        assert first + second == [b"payload"]
        assert decoder.buffered_bytes == 0


def test_stream_deserializer_emits_adjacent_records_and_empty_payload() -> None:
    serializer = StreamSerializer()
    decoder = StreamDeserializer()

    stream = serializer.encode(b"one") + serializer.encode(b"") + serializer.encode(b"three")

    assert decoder.feed(stream) == [b"one", b"", b"three"]


def test_stream_deserializer_rejects_oversized_record_without_leaking_partial_bytes() -> None:
    decoder = StreamDeserializer(max_record_bytes=8)

    with pytest.raises(StreamDecodeError):
        decoder.feed((9).to_bytes(4, "big") + b"partial")

    assert decoder.buffered_bytes == 0
    assert decoder.feed(StreamSerializer(max_record_bytes=8).encode(b"ok")) == [b"ok"]


def test_stream_serializer_rejects_records_above_wire_limit() -> None:
    with pytest.raises(ValueError):
        StreamSerializer().encode(b"x" * (MAX_STREAM_RECORD_BYTES + 1))
