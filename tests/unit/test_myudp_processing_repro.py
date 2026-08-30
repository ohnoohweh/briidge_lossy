from __future__ import annotations

import asyncio
import unittest

from obstacle_bridge.bridge import (
    BaseFrameV2,
    MYUDP2_MAX_CHUNK_BYTES,
    MyUDP2BatchCodec,
    MyUDP2Session,
    PeerProtocol,
    Protocol,
    StreamChunk,
    StreamSerializer,
)


class _FakeDatagramTransport:
    def __init__(self, *, sockname=("0.0.0.0", 49000), peername=None):
        self.sent: list[tuple[bytes, tuple[str, int] | None]] = []
        self._sockname = sockname
        self._peername = peername

    def sendto(self, data: bytes, addr=None):
        self.sent.append((bytes(data), addr))

    def get_extra_info(self, name: str, default=None):
        if name == "sockname":
            return self._sockname
        if name == "peername":
            return self._peername
        return default


def _batch_frame(proto: Protocol, chunks: list[StreamChunk]) -> bytes:
    return proto.build_frame(proto.PTYPE_DATA, MyUDP2BatchCodec.encode_batch(chunks))


class MyUdpProcessingReproTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.proto = Protocol(BaseFrameV2)
        self.session = MyUDP2Session(proto=self.proto)
        self.completed: list[bytes] = []
        self.peer = ("127.0.0.1", 4433)
        self.transport = _FakeDatagramTransport(sockname=("0.0.0.0", 60953))
        self.peer_proto = PeerProtocol(
            self.session,
            lambda: None,
            self.completed.append,
            peer=self.peer,
            proto=self.proto,
        )
        self.peer_proto.connection_made(self.transport)  # type: ignore[arg-type]

    async def asyncTearDown(self) -> None:
        self.peer_proto.controltimerstop()
        self.peer_proto.retxtimerstop()

    async def _flush_callbacks(self, rounds: int = 8) -> None:
        for _ in range(rounds):
            await asyncio.sleep(0)

    async def test_channelmux_to_network_tx_emits_myudp_frames(self) -> None:
        payload = bytes((i % 251 for i in range((MYUDP2_MAX_CHUNK_BYTES * 2) + 17)))

        produced = self.session.send_application_payload(payload, self.peer_proto.send_port)
        await self._flush_callbacks()

        self.assertEqual(produced, 1)

        counters: list[int] = []
        for raw, dst in self.transport.sent:
            self.assertEqual(dst, self.peer)
            parsed = self.proto.parse_frame_with_times(raw)
            self.assertIsNotNone(parsed)
            if parsed[0] != self.proto.PTYPE_DATA:
                continue
            counters.extend(chunk.counter for chunk in MyUDP2BatchCodec.decode_batch(parsed[1]))

        self.assertEqual(counters, list(range(1, len(counters) + 1)))
        self.assertGreaterEqual(len(counters), 3)

    async def test_network_rx_to_channelmux_edge_reassembles_large_payload(self) -> None:
        sender = MyUDP2Session(proto=Protocol(BaseFrameV2))
        sender_transport = _FakeDatagramTransport(sockname=("0.0.0.0", 40001))
        payload = bytes((i % 239 for i in range((MYUDP2_MAX_CHUNK_BYTES * 3) + 101)))

        produced = sender.send_application_payload(payload, sender_transport)
        await self._flush_callbacks()
        self.assertEqual(produced, 1)

        for raw, _dst in sender_transport.sent:
            self.peer_proto.datagram_received(raw, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [payload])

    async def test_network_rx_gap_state_reproduces_stall_shape_until_missing_frame_arrives(self) -> None:
        wire = StreamSerializer().encode(b"abcdefghi")
        pkt2 = _batch_frame(self.proto, [StreamChunk(2, wire[3:6])])
        pkt3 = _batch_frame(self.proto, [StreamChunk(3, wire[6:])])

        self.peer_proto.datagram_received(pkt2, self.peer)
        self.peer_proto.datagram_received(pkt3, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [])
        self.assertEqual(self.session.expected, 1)
        self.assertEqual(set(self.session.pending), {2, 3})
        self.assertEqual(self.session.missing, {1})

        pkt1 = _batch_frame(self.proto, [StreamChunk(1, wire[:3])])
        self.peer_proto.datagram_received(pkt1, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [b"abcdefghi"])
        self.assertEqual(self.session.expected, 4)
        self.assertEqual(self.session.pending, {})
        self.assertEqual(self.session.missing, set())

    async def test_lost_multi_chunk_batch_recovers_with_per_chunk_retransmits(self) -> None:
        self.session.send_application_payload(b"one", self.peer_proto.send_port)
        self.session.send_application_payload(b"two", self.peer_proto.send_port)
        await self._flush_callbacks()
        original_count = len(self.transport.sent)
        original = self.transport.sent[-1][0]
        self.assertEqual([chunk.counter for chunk in MyUDP2BatchCodec.decode_batch(self.proto.parse_frame_with_times(original)[1])], [1, 2])

        self.peer_proto._schedule_retrans([1, 2])
        retransmits = [raw for raw, _dst in self.transport.sent[original_count:]]
        self.assertEqual(len(retransmits), 2)
        self.assertEqual(self.session.retransmitted_chunks, 2)
        self.assertEqual(
            [[chunk.counter for chunk in MyUDP2BatchCodec.decode_batch(self.proto.parse_frame_with_times(raw)[1])] for raw in retransmits],
            [[1], [2]],
        )

        receiver = MyUDP2Session(proto=Protocol(BaseFrameV2))
        completed: list[bytes] = []
        for raw in reversed(retransmits):
            chunks = MyUDP2BatchCodec.decode_batch(self.proto.parse_frame_with_times(raw)[1])
            for chunk in chunks:
                _, delivered = receiver.process_data(chunk)
                completed.extend(delivered)
        self.assertEqual(completed, [b"one", b"two"])

    async def test_malformed_stream_record_is_counted_and_not_delivered(self) -> None:
        malformed = _batch_frame(self.proto, [StreamChunk(1, b"\x00\x01\x00\x00")])

        self.peer_proto.datagram_received(malformed, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [])
        self.assertEqual(self.session.stream_decode_errors, 1)

    async def test_sender_reset_does_not_clobber_network_rx_gap_state(self) -> None:
        wire = StreamSerializer().encode(b"abcdefghi")
        pkt2 = _batch_frame(self.proto, [StreamChunk(2, wire[3:6])])
        pkt3 = _batch_frame(self.proto, [StreamChunk(3, wire[6:])])
        self.peer_proto.datagram_received(pkt2, self.peer)
        self.peer_proto.datagram_received(pkt3, self.peer)
        await self._flush_callbacks()

        self.session.send_application_payload(b"close", self.peer_proto.send_port)
        self.session.reset_sender()

        self.assertEqual(self.session.expected, 1)
        self.assertEqual(set(self.session.pending), {2, 3})
        self.assertEqual(self.session.missing, {1})

        pkt1 = _batch_frame(self.proto, [StreamChunk(1, wire[:3])])
        self.peer_proto.datagram_received(pkt1, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [b"abcdefghi"])


if __name__ == "__main__":
    unittest.main()
