import argparse
import asyncio
import json
import time
import unittest

from obstacle_bridge.bridge import (
    AdminWebUI,
    BaseFrameV2,
    ControlPacket,
    DATA_MAX_CHUNK,
    DataPacket,
    FRAME_CONT,
    FRAME_FIRST,
    PeerProtocol,
    PROTO,
    Runner,
    Session,
    SessionMetrics,
    UdpSession,
)


class _WriterStub:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        return None


class _TransportStub:
    def __init__(self):
        self.frames = []

    def sendto(self, data, *_args):
        self.frames.append(bytes(data))


def _http_status(writer: _WriterStub) -> int:
    head = writer.buffer.decode("utf-8").split("\r\n", 1)[0]
    return int(head.split()[1])


def _http_headers(writer: _WriterStub) -> dict:
    header_blob = writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[0]
    headers = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    return headers


def _http_json(writer: _WriterStub) -> dict:
    return json.loads(writer.buffer.decode("utf-8").split("\r\n\r\n", 1)[1])


def _admin_args(**overrides):
    base = dict(
        admin_web=True,
        admin_web_bind="127.0.0.1",
        admin_web_port=18080,
        admin_web_path="/",
        admin_web_dir="./admin_web",
        admin_web_name="Lab Node",
        admin_web_auth_disable=False,
        admin_web_username="admin",
        admin_web_password="admin-secret",
        admin_web_security_advisor_disable=False,
        admin_web_security_advisor_startup_disable=False,
        admin_web_first_tab="home",
        secure_link_mode="off",
        secure_link_psk="",
        overlay_transport="myudp",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class _RunnerStub:
    def __init__(self, args):
        self.args = args


class AdminAuthRequirementUnitTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_disabled_reports_authenticated_without_session(self):
        args = _admin_args(admin_web_auth_disable=True, admin_web_username="", admin_web_password="")
        ui = AdminWebUI(args, _RunnerStub(args))

        state_writer = _WriterStub()
        await ui._handle_auth_state(state_writer, headers={})
        state = _http_json(state_writer)

        challenge_writer = _WriterStub()
        await ui._handle_auth_challenge(challenge_writer, "GET")
        challenge = _http_json(challenge_writer)

        self.assertFalse(state["auth_required"])
        self.assertTrue(state["authenticated"])
        self.assertFalse(challenge["auth_required"])

    async def test_auth_required_rejects_bad_login_and_accepts_challenge_proof(self):
        args = _admin_args()
        ui = AdminWebUI(args, _RunnerStub(args))

        unauth_writer = _WriterStub()
        await ui._handle_auth_state(unauth_writer, headers={})
        self.assertFalse(_http_json(unauth_writer)["authenticated"])

        challenge_writer = _WriterStub()
        await ui._handle_auth_challenge(challenge_writer, "GET")
        challenge = _http_json(challenge_writer)

        bad_writer = _WriterStub()
        await ui._handle_auth_login(
            bad_writer,
            "POST",
            json.dumps({"challenge_id": challenge["challenge_id"], "proof": "bad"}).encode("utf-8"),
        )
        self.assertEqual(_http_status(bad_writer), 403)
        self.assertFalse(ui._auth_sessions)

        challenge_writer = _WriterStub()
        await ui._handle_auth_challenge(challenge_writer, "GET")
        challenge = _http_json(challenge_writer)
        proof = ui._build_auth_response(challenge["seed"], args.admin_web_username, args.admin_web_password)

        good_writer = _WriterStub()
        await ui._handle_auth_login(
            good_writer,
            "POST",
            json.dumps({"challenge_id": challenge["challenge_id"], "proof": proof}).encode("utf-8"),
        )

        self.assertEqual(_http_status(good_writer), 200)
        self.assertTrue(_http_json(good_writer)["authenticated"])
        self.assertIn("set-cookie", _http_headers(good_writer))

    async def test_admin_auth_sessions_are_cookie_scoped_per_client(self):
        args = _admin_args()
        ui = AdminWebUI(args, _RunnerStub(args))
        cookie_name = ui._session_cookie_name()
        ui._auth_sessions["client-a"] = time.time() + 60

        self.assertTrue(ui._is_authenticated({"cookie": f"{cookie_name}=client-a"}))
        self.assertFalse(ui._is_authenticated({"cookie": f"{cookie_name}=client-b"}))
        self.assertFalse(ui._is_authenticated({"cookie": "other_cookie=client-a"}))


class _FakeSession:
    def __init__(self, peers):
        self._peers = peers

    def is_connected(self):
        return any(peer["connected"] for peer in self._peers)

    def get_metrics(self):
        return SessionMetrics()

    def get_overlay_peers_snapshot(self):
        return list(self._peers)


class _MuxWithoutChannels:
    def snapshot_connections(self):
        return {
            "udp": [],
            "tcp": [],
            "tun": [],
            "counts": {"udp": 0, "tcp": 0, "tun": 0, "udp_listening": 0, "tcp_listening": 0},
        }

    def snapshot_peer_payload_totals(self):
        return {}


class ListenerPeerRequirementUnitTests(unittest.TestCase):
    def test_listener_peer_snapshot_preserves_distinct_peers_across_listener_transports(self):
        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp,tcp,quic")
        runner = Runner(args)
        runner._sessions = [
            _FakeSession(
                [
                    {"peer_id": -1, "connected": False, "peer": None, "mux_chans": [], "listening": True},
                    {"peer_id": 1, "connected": True, "peer": "198.51.100.1:4433", "mux_chans": []},
                    {"peer_id": 2, "connected": True, "peer": "198.51.100.2:4433", "mux_chans": []},
                ]
            ),
            _FakeSession(
                [
                    {"peer_id": -1, "connected": False, "peer": None, "mux_chans": [], "listening": True},
                    {"peer_id": 1, "connected": True, "peer": "198.51.100.3:8081", "mux_chans": []},
                ]
            ),
            _FakeSession(
                [
                    {"peer_id": -1, "connected": False, "peer": None, "mux_chans": [], "listening": True},
                    {"peer_id": 1, "connected": True, "peer": "198.51.100.4:8443", "mux_chans": []},
                ]
            ),
        ]
        runner._muxes = [_MuxWithoutChannels(), _MuxWithoutChannels(), _MuxWithoutChannels()]
        runner._session_labels = ["myudp", "tcp", "quic"]

        peers = runner.get_peer_connections_snapshot()["peers"]
        connected = [peer for peer in peers if peer["connected"]]

        self.assertEqual({peer["transport"] for peer in connected}, {"myudp", "tcp", "quic"})
        self.assertEqual(
            {peer["peer"] for peer in connected},
            {"198.51.100.1:4433", "198.51.100.2:4433", "198.51.100.3:8081", "198.51.100.4:8443"},
        )
        self.assertEqual(len({peer["id"] for peer in peers}), len(peers))

    def test_udp_peer_labels_bracket_ipv6_and_plain_ipv4(self):
        self.assertEqual(UdpSession._format_peer_label("2001:db8::1", 4433), "[2001:db8::1]:4433")
        self.assertEqual(UdpSession._format_peer_label("192.0.2.10", 4433), "192.0.2.10:4433")


class MyUdpReliabilityRequirementUnitTests(unittest.TestCase):
    def _session_and_transport(self, max_in_flight=32767):
        session = Session(max_in_flight=max_in_flight, proto=PROTO.__class__(BaseFrameV2))
        transport = _TransportStub()
        return session, transport

    def test_myudp_large_payload_is_chunked_and_backpressured_by_inflight_window(self):
        session, transport = self._session_and_transport(max_in_flight=2)
        payload = bytes((idx % 251 for idx in range((DATA_MAX_CHUNK * 2) + 17)))

        produced = session.send_application_payload(payload, transport)

        self.assertEqual(produced, 3)
        self.assertEqual(len(transport.frames), 2)
        self.assertEqual(session.in_flight(), 2)
        self.assertEqual(session.waiting_count(), 1)

        session.confirm_with_feedback(last_in_order=1, highest=1, missed=[])
        session.try_flush_send_queue(transport)

        self.assertEqual(len(transport.frames), 3)
        self.assertEqual(session.in_flight(), 2)
        self.assertEqual(session.waiting_count(), 0)

    def test_myudp_out_of_order_delivery_tracks_missing_and_reassembles_without_corruption(self):
        session, _transport = self._session_and_transport()
        packets = [
            DataPacket.build_full(3, FRAME_CONT, 6, b"ghi"),
            DataPacket.build_full(1, FRAME_FIRST, 9, b"abc"),
            DataPacket.build_full(2, FRAME_CONT, 3, b"def"),
        ]

        completed = []
        for pkt in packets:
            _advanced, emitted = session.process_data(pkt)
            completed.extend(emitted)

        self.assertEqual(completed, [b"abcdefghi"])
        self.assertEqual(session.expected, 4)
        self.assertEqual(session.missing, set())
        self.assertEqual(session.pending, {})

    def test_myudp_control_feedback_retransmits_only_reported_missing_frames(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)
        original_second = transport.frames[1]

        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
        proto.send_port = transport

        feedback = ControlPacket.build_full(0, 2, [2])
        session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
        proto._schedule_retrans(feedback.missed)

        self.assertEqual(len(transport.frames), 3)
        retransmitted = DataPacket.parse_full(transport.frames[-1])
        self.assertIsNotNone(retransmitted)
        self.assertEqual(retransmitted.pkt_counter, 2)
        self.assertNotEqual(transport.frames[-1], original_second)
        self.assertEqual(session.send_attempts[1], 1)
        self.assertEqual(session.send_attempts[2], 2)

    def test_myudp_bidirectional_sessions_deliver_independent_payloads(self):
        left, left_tx = self._session_and_transport()
        right, right_tx = self._session_and_transport()

        left.send_application_payload(b"left-to-right", left_tx)
        right.send_application_payload(b"right-to-left", right_tx)

        left_frame = DataPacket.parse_full(left_tx.frames[0])
        right_frame = DataPacket.parse_full(right_tx.frames[0])
        self.assertIsNotNone(left_frame)
        self.assertIsNotNone(right_frame)

        _advanced, delivered_right = right.process_data(left_frame)
        _advanced, delivered_left = left.process_data(right_frame)

        self.assertEqual(delivered_right, [b"left-to-right"])
        self.assertEqual(delivered_left, [b"right-to-left"])

    def test_myudp_sender_reset_clears_stale_reconnect_state(self):
        session, transport = self._session_and_transport(max_in_flight=1)
        session.send_application_payload(b"before", transport)
        session.send_application_payload(b"queued", transport)
        session.process_data(DataPacket.build_full(2, FRAME_FIRST, 3, b"two"))

        session.reset_sender()

        self.assertEqual(session.next_ctr, 1)
        self.assertEqual(session.expected, 1)
        self.assertEqual(session.in_flight(), 0)
        self.assertEqual(session.waiting_count(), 0)
        self.assertEqual(session.pending, {})
        self.assertEqual(session.missing, set())


if __name__ == "__main__":
    unittest.main()
