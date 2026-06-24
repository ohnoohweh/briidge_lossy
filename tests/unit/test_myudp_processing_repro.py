from __future__ import annotations

import asyncio
import unittest

from obstacle_bridge.bridge import (
    BaseFrameV2,
    DATA_MAX_CHUNK,
    DataPacket,
    FRAME_CONT,
    FRAME_FIRST,
    PeerProtocol,
    Protocol,
    Session,
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


class MyUdpProcessingReproTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.proto = Protocol(BaseFrameV2)
        self.session = Session(proto=self.proto)
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
        payload = bytes((i % 251 for i in range((DATA_MAX_CHUNK * 2) + 17)))

        produced = self.session.send_application_payload(payload, self.peer_proto.send_port)

        self.assertGreaterEqual(produced, 3)

        counters: list[int] = []
        for raw, dst in self.transport.sent:
            pkt = DataPacket.parse_full(raw)
            if pkt is None:
                continue
            self.assertEqual(dst, self.peer)
            counters.append(pkt.pkt_counter)

        self.assertEqual(counters, list(range(1, produced + 1)))

    async def test_network_rx_to_channelmux_edge_reassembles_large_payload(self) -> None:
        sender = Session(proto=Protocol(BaseFrameV2))
        sender_transport = _FakeDatagramTransport(sockname=("0.0.0.0", 40001))
        payload = bytes((i % 239 for i in range((DATA_MAX_CHUNK * 3) + 101)))

        produced = sender.send_application_payload(payload, sender_transport)
        self.assertGreaterEqual(produced, 4)

        for raw, _dst in sender_transport.sent:
            self.peer_proto.datagram_received(raw, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [payload])

    async def test_network_rx_gap_state_reproduces_stall_shape_until_missing_frame_arrives(self) -> None:
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")

        self.peer_proto.datagram_received(pkt2.raw, self.peer)
        self.peer_proto.datagram_received(pkt3.raw, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [])
        self.assertEqual(self.session.expected, 1)
        self.assertEqual(set(self.session.pending), {2, 3})
        self.assertEqual(self.session.missing, {1})

        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
        self.peer_proto.datagram_received(pkt1.raw, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [b"abcdefghi"])
        self.assertEqual(self.session.expected, 4)
        self.assertEqual(self.session.pending, {})
        self.assertEqual(self.session.missing, set())

    async def test_sender_reset_does_not_clobber_network_rx_gap_state(self) -> None:
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        self.peer_proto.datagram_received(pkt2.raw, self.peer)
        self.peer_proto.datagram_received(pkt3.raw, self.peer)
        await self._flush_callbacks()

        self.session.send_application_payload(b"close", self.peer_proto.send_port)
        self.session.reset_sender()

        self.assertEqual(self.session.expected, 1)
        self.assertEqual(set(self.session.pending), {2, 3})
        self.assertEqual(self.session.missing, {1})

        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
        self.peer_proto.datagram_received(pkt1.raw, self.peer)
        await self._flush_callbacks()

        self.assertEqual(self.completed, [b"abcdefghi"])


if __name__ == "__main__":
    unittest.main()
