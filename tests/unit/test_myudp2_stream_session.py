from __future__ import annotations

import asyncio

from obstacle_bridge.bridge import BaseFrameV2, MyUDP2BatchCodec, MyUDP2Session, Protocol, StreamChunk


class _Transport:
    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def sendto(self, frame: bytes) -> None:
        self.frames.append(frame)


def _chunks(frame: bytes) -> list[StreamChunk]:
    parsed = Protocol(BaseFrameV2).parse_frame_with_times(frame)
    assert parsed is not None
    return MyUDP2BatchCodec.decode_batch(parsed[1])


def test_myudp2_session_coalesces_small_stream_records_in_one_datagram() -> None:
    async def scenario() -> tuple[MyUDP2Session, _Transport]:
        session = MyUDP2Session(proto=Protocol(BaseFrameV2))
        transport = _Transport()
        assert session.send_application_payload(b"one", transport) == 1
        assert session.send_application_payload(b"two", transport) == 1
        await asyncio.sleep(0)
        return session, transport

    session, transport = asyncio.run(scenario())

    assert len(transport.frames) == 1
    assert [chunk.data for chunk in _chunks(transport.frames[0])] == [b"\x00\x00\x00\x03one", b"\x00\x00\x00\x03two"]
    assert session.batch_datagrams_sent == 1
    assert session.batch_chunks_sent == 2


def test_myudp2_session_splits_final_record_to_use_remaining_batch_space() -> None:
    async def scenario() -> _Transport:
        session = MyUDP2Session(proto=Protocol(BaseFrameV2))
        transport = _Transport()
        session.send_application_payload(b"a" * 1000, transport)
        session.send_application_payload(b"b" * 1000, transport)
        await asyncio.sleep(0)
        return transport

    transport = asyncio.run(scenario())

    first_batch = _chunks(transport.frames[0])
    assert [len(chunk.data) for chunk in first_batch] == [1004, 415]
    assert len(transport.frames) == 2
    assert len(_chunks(transport.frames[1])[0].data) == 589


def test_myudp2_session_delivers_only_contiguous_stream_bytes_after_reorder() -> None:
    sender = MyUDP2Session(proto=Protocol(BaseFrameV2))
    wire = sender._stream_serializer.encode(b"payload")
    receiver = MyUDP2Session(proto=Protocol(BaseFrameV2))

    advanced, completed = receiver.process_data(StreamChunk(2, wire[3:]))
    assert advanced is False
    assert completed == []
    assert receiver.missing == {1}

    advanced, completed = receiver.process_data(StreamChunk(1, wire[:3]))
    assert advanced is True
    assert completed == [b"payload"]
    assert receiver.expected == 3

    advanced, completed = receiver.process_data(StreamChunk(1, wire[:3]))
    assert advanced is False
    assert completed == []


def test_myudp2_session_counter_rollover_keeps_stream_delivery_contiguous() -> None:
    async def scenario() -> tuple[MyUDP2Session, _Transport]:
        sender = MyUDP2Session(proto=Protocol(BaseFrameV2))
        sender.next_ctr = 65535
        transport = _Transport()
        sender.send_application_payload(b"one", transport)
        sender.send_application_payload(b"two", transport)
        await asyncio.sleep(0)
        return sender, transport

    sender, transport = asyncio.run(scenario())

    chunks = _chunks(transport.frames[0])
    assert [chunk.counter for chunk in chunks] == [65535, 1]

    receiver = MyUDP2Session(proto=Protocol(BaseFrameV2))
    receiver.expected = 65535
    completed: list[bytes] = []
    for chunk in chunks:
        _, delivered = receiver.process_data(chunk)
        completed.extend(delivered)
    assert completed == [b"one", b"two"]


def test_myudp2_session_epoch_reset_clears_queued_and_partial_stream_state() -> None:
    session = MyUDP2Session(proto=Protocol(BaseFrameV2))
    transport = _Transport()
    session.send_application_payload(b"queued", transport)
    session._stream_deserializer.feed(b"\x00\x00")

    session.reset_transport_epoch()

    assert session.waiting_count() == 0
    assert session._stream_deserializer.buffered_bytes == 0


def test_myudp2_session_reports_stream_and_batch_budgets() -> None:
    session = MyUDP2Session(proto=Protocol(BaseFrameV2))
    transport = _Transport()
    session.send_application_payload(b"payload", transport)

    assert session.batch_stream_bytes_sent == len(b"\x00\x00\x00\x07payload")
    assert session.stream_queue_age_ms() == 0.0
