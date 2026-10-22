#!/usr/bin/env python3
import unittest

from obstacle_bridge.bridge_tun_helper_protocol import (
    TUN_HELPER_CAPABILITIES,
    TUN_HELPER_CLIENT_ROLE,
    TUN_HELPER_MAX_FRAME_BYTES,
    TUN_HELPER_SERVER_ROLE,
    TunHelperControlMessage,
    TunHelperFrameKind,
    decode_control_payload,
    encode_control_frame,
    encode_frame,
    encode_hello,
    negotiated_hello,
    try_decode_frame,
)


class TunHelperProtocolTests(unittest.TestCase):
    def test_control_frame_uses_common_obip_header_and_generation(self) -> None:
        encoded = encode_control_frame(
            TunHelperFrameKind.REQUEST,
            7,
            TunHelperControlMessage(op="OPEN_TUN", payload={"ifname": "obtun0", "mtu": 1600}),
        )
        self.assertTrue(encoded.startswith(b"OBIP"))
        decoded = try_decode_frame(encoded)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        frame, remainder = decoded
        self.assertEqual(frame.kind, TunHelperFrameKind.REQUEST)
        self.assertEqual(frame.generation, 7)
        self.assertEqual(remainder, b"")
        message = decode_control_payload(frame.payload)
        self.assertEqual(message.op, "OPEN_TUN")
        self.assertEqual(message.payload["ifname"], "obtun0")
        self.assertEqual(message.payload["mtu"], 1600)

    def test_common_hello_negotiates_helper_capabilities(self) -> None:
        decoded = try_decode_frame(encode_hello(9))
        self.assertIsNotNone(decoded)
        assert decoded is not None
        frame, remainder = decoded
        self.assertEqual(remainder, b"")
        self.assertEqual(frame.kind, TunHelperFrameKind.HELLO)
        self.assertEqual(frame.generation, 9)
        self.assertEqual(negotiated_hello(frame), (TUN_HELPER_CLIENT_ROLE, tuple(sorted(TUN_HELPER_CAPABILITIES))))
        server = try_decode_frame(encode_hello(9, role=TUN_HELPER_SERVER_ROLE))
        self.assertIsNotNone(server)
        assert server is not None
        self.assertEqual(negotiated_hello(server[0]), (TUN_HELPER_SERVER_ROLE, tuple(sorted(TUN_HELPER_CAPABILITIES))))

    def test_control_frame_normalizes_and_bounds_operation(self) -> None:
        encoded = encode_control_frame(
            TunHelperFrameKind.REQUEST,
            1,
            TunHelperControlMessage(op="  SNAPSHOT  "),
        )
        decoded = try_decode_frame(encoded)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decode_control_payload(decoded[0].payload).op, "SNAPSHOT")
        for operation in ("", "   ", "x" * 65, 1):
            with self.assertRaises(ValueError):
                encode_control_frame(TunHelperFrameKind.REQUEST, 1, TunHelperControlMessage(op=operation))  # type: ignore[arg-type]

    def test_control_payload_rejects_duplicate_nonfinite_and_invalid_operations(self) -> None:
        for payload in (
            b'{"op":"SNAPSHOT","op":"STOP","payload":{}}',
            b'{"op":"SNAPSHOT","payload":{"value":NaN}}',
            b'[]',
            b'{"op":1,"payload":{}}',
            b'{"op":"' + b"x" * 65 + b'","payload":{}}',
        ):
            with self.assertRaises(ValueError):
                decode_control_payload(payload)

    def test_try_decode_frame_returns_none_for_incomplete_payload(self) -> None:
        encoded = encode_frame(TunHelperFrameKind.DATA, 2, b"\x01\x02\x03\x04")
        self.assertIsNone(try_decode_frame(encoded[:-1]))

    def test_packet_frames_preserve_boundaries_and_generation(self) -> None:
        packet = b"\x00\x45\x00\x00\x54\x12\x34\x00\x00\x40\x11\x7a\xc0hello\x00world"
        combined = encode_frame(TunHelperFrameKind.DATA, 3, packet) + encode_control_frame(
            TunHelperFrameKind.EVENT, 3, TunHelperControlMessage(op="EVENT", payload={"detail": "diag"})
        )
        first = try_decode_frame(combined)
        self.assertIsNotNone(first)
        assert first is not None
        frame, remainder = first
        self.assertEqual((frame.kind, frame.generation, frame.payload), (TunHelperFrameKind.DATA, 3, packet))
        second = try_decode_frame(remainder)
        self.assertIsNotNone(second)
        assert second is not None
        self.assertEqual(second[0].kind, TunHelperFrameKind.EVENT)
        self.assertEqual(second[1], b"")

    def test_frame_size_bound_matches_common_ipc_and_rejects_invalid_header(self) -> None:
        payload = b"x" * TUN_HELPER_MAX_FRAME_BYTES
        encoded = encode_frame(TunHelperFrameKind.DATA, 4, payload)
        decoded = try_decode_frame(encoded)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded[0].payload, payload)
        with self.assertRaisesRegex(ValueError, "invalid TUN helper frame"):
            encode_frame(TunHelperFrameKind.DATA, 4, payload + b"x")
        invalid = b"OBIP\x01\x63\x00\x00" + (4).to_bytes(8, "big") + (0).to_bytes(4, "big")
        with self.assertRaisesRegex(ValueError, "invalid TUN helper frame"):
            try_decode_frame(invalid)


if __name__ == "__main__":
    unittest.main()
