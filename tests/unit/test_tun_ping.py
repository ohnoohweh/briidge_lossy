import socket
import unittest

from obstacle_bridge.bridge_tun_ping import (
    PROBE_KIND_PEER,
    build_ipv4_echo_request,
    build_ipv6_echo_request,
    parse_echo_reply,
    probe_payload,
)


class TunPingPacketTests(unittest.TestCase):
    def test_build_ipv4_echo_request_encodes_reply_match_fields(self):
        payload = probe_payload(probe_kind=PROBE_KIND_PEER, nonce=b"12345678", sent_monotonic_ns=42)
        packet = build_ipv4_echo_request(
            source_ip="192.168.106.2",
            destination_ip="192.168.106.1",
            identifier=0x1111,
            sequence=0x2222,
            payload=payload,
        )

        self.assertEqual(packet[0] >> 4, 4)
        self.assertEqual(packet[9], 1)
        self.assertEqual(packet[20], 8)
        self.assertEqual(packet[24:26], b"\x11\x11")
        self.assertEqual(packet[26:28], b"\x22\x22")
        self.assertEqual(packet[28:], payload)

    def test_parse_ipv4_echo_reply(self):
        payload = probe_payload(probe_kind=PROBE_KIND_PEER, nonce=b"ABCDEFGH", sent_monotonic_ns=99)
        packet = bytearray(
            build_ipv4_echo_request(
                source_ip="192.168.106.1",
                destination_ip="192.168.106.2",
                identifier=7,
                sequence=9,
                payload=payload,
            )
        )
        packet[20] = 0
        parsed = parse_echo_reply(bytes(packet))

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["family"], socket.AF_INET)
        self.assertEqual(parsed["source_ip"], "192.168.106.1")
        self.assertEqual(parsed["destination_ip"], "192.168.106.2")
        self.assertEqual(parsed["identifier"], 7)
        self.assertEqual(parsed["sequence"], 9)
        self.assertEqual(parsed["payload"], payload)

    def test_parse_ipv6_echo_reply(self):
        payload = probe_payload(probe_kind=PROBE_KIND_PEER, nonce=b"HGFEDCBA", sent_monotonic_ns=100)
        packet = bytearray(
            build_ipv6_echo_request(
                source_ip="fd20:106::1",
                destination_ip="fd20:106::2",
                identifier=3,
                sequence=5,
                payload=payload,
            )
        )
        packet[40] = 129
        parsed = parse_echo_reply(bytes(packet))

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["family"], socket.AF_INET6)
        self.assertEqual(parsed["source_ip"], "fd20:106::1")
        self.assertEqual(parsed["destination_ip"], "fd20:106::2")
        self.assertEqual(parsed["identifier"], 3)
        self.assertEqual(parsed["sequence"], 5)
        self.assertEqual(parsed["payload"], payload)


if __name__ == "__main__":
    unittest.main()
