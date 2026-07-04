#!/usr/bin/env python3
import unittest

from obstacle_bridge.bridge_tun_helper_protocol import (
    TUN_HELPER_PROTOCOL_VERSION,
    TunHelperControlMessage,
    TunHelperFrameKind,
    decode_control_payload,
    encode_control_frame,
    encode_frame,
    try_decode_frame,
)


class TunHelperProtocolTests(unittest.TestCase):
    def test_control_frame_round_trip(self) -> None:
        encoded = encode_control_frame(
            TunHelperFrameKind.CONTROL_REQUEST,
            TunHelperControlMessage(op="OPEN_TUN", payload={"ifname": "obtun0", "mtu": 1600}),
        )

        decoded = try_decode_frame(encoded)

        self.assertIsNotNone(decoded)
        assert decoded is not None
        kind, payload, remainder = decoded
        self.assertEqual(kind, TunHelperFrameKind.CONTROL_REQUEST)
        self.assertEqual(remainder, b"")
        message = decode_control_payload(payload)
        self.assertEqual(message.version, TUN_HELPER_PROTOCOL_VERSION)
        self.assertEqual(message.op, "OPEN_TUN")
        self.assertEqual(message.payload["ifname"], "obtun0")
        self.assertEqual(message.payload["mtu"], 1600)

    def test_decode_control_payload_rejects_unknown_version(self) -> None:
        encoded = encode_frame(
            TunHelperFrameKind.CONTROL_RESPONSE,
            b'{"version":99,"op":"OPEN_TUN","payload":{}}',
        )

        decoded = try_decode_frame(encoded)

        self.assertIsNotNone(decoded)
        assert decoded is not None
        _kind, payload, _remainder = decoded
        with self.assertRaisesRegex(ValueError, "unsupported TUN helper protocol version"):
            decode_control_payload(payload)

    def test_try_decode_frame_returns_none_for_incomplete_payload(self) -> None:
        encoded = encode_frame(TunHelperFrameKind.PACKET_TO_HELPER, b"\x01\x02\x03\x04")

        self.assertIsNone(try_decode_frame(encoded[:-1]))

    def test_packet_frame_preserves_binary_boundaries(self) -> None:
        packet = b"\x00\x45\x00\x00\x54\x12\x34\x00\x00\x40\x11\x7a\xc0hello\x00world"
        combined = (
            encode_frame(TunHelperFrameKind.PACKET_TO_HELPER, packet)
            + encode_frame(TunHelperFrameKind.EVENT, b"diag")
        )

        decoded_first = try_decode_frame(combined)

        self.assertIsNotNone(decoded_first)
        assert decoded_first is not None
        kind, payload, remainder = decoded_first
        self.assertEqual(kind, TunHelperFrameKind.PACKET_TO_HELPER)
        self.assertEqual(payload, packet)
        decoded_second = try_decode_frame(remainder)
        self.assertIsNotNone(decoded_second)
        assert decoded_second is not None
        self.assertEqual(decoded_second[0], TunHelperFrameKind.EVENT)
        self.assertEqual(decoded_second[1], b"diag")
        self.assertEqual(decoded_second[2], b"")

    def test_try_decode_frame_rejects_unknown_kind(self) -> None:
        encoded = bytes([99]) + (4).to_bytes(4, "big") + b"test"

        with self.assertRaisesRegex(ValueError, "unknown TUN helper frame kind"):
            try_decode_frame(encoded)


if __name__ == "__main__":
    unittest.main()
