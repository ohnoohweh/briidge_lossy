import argparse
import asyncio
import concurrent.futures
import json
import time
import types
import unittest
from unittest import mock

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
from obstacle_bridge.bridge_transport_quic import QuicSession
from obstacle_bridge.bridge_transport_tcp import TcpStreamSession
from obstacle_bridge.bridge_transport_ws import WebSocketSession


def _peer_endpoint(host: str, port: int) -> dict:
    return {"host": host, "port": port}


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

    def get_async_diagnostics_snapshot(self):
        return {
            "async": {
                "last_started_name": "myudp.mux.start",
                "last_started_kind": "await",
                "last_started_age_sec": 12.5,
                "last_finished_name": "myudp.session.start",
                "last_finished_kind": "await",
                "last_finished_age_sec": 13.0,
                "last_failed_name": "",
                "last_failed_kind": "",
                "last_failed_age_sec": None,
                "last_failed_error": "",
            },
            "sync": {
                "last_started_name": "ChannelMux._on_local_tun_packet",
                "last_started_kind": "callback",
                "last_started_age_sec": 0.25,
                "last_finished_name": "ChannelMux._send_mux",
                "last_finished_kind": "callback",
                "last_finished_age_sec": 0.1,
                "last_failed_name": "",
                "last_failed_kind": "",
                "last_failed_age_sec": None,
                "last_failed_error": "",
            },
        }


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


class AdminWebResilienceUnitTests(unittest.TestCase):
    def test_status_snapshot_falls_back_to_cached_payload_when_runner_busy(self):
        args = _admin_args()
        ui = AdminWebUI(args, _RunnerStub(args))
        ui._cache_snapshot("status", {"ok": True, "state": "connected"})

        with mock.patch.object(ui, "_call_runner", side_effect=concurrent.futures.TimeoutError()):
            payload = ui._build_status_payload()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["state"], "connected")
        self.assertTrue(payload["admin_web_snapshot"]["stale"])
        self.assertEqual(payload["admin_web_snapshot"]["error"], "runner_loop_timeout")
        self.assertEqual(payload["runner_async_diagnostics"]["async"]["last_started_name"], "myudp.mux.start")
        self.assertEqual(payload["runner_async_diagnostics"]["sync"]["last_started_name"], "ChannelMux._on_local_tun_packet")

    def test_connections_snapshot_marks_fresh_payload_when_runner_responds(self):
        args = _admin_args()
        ui = AdminWebUI(args, _RunnerStub(args))
        with mock.patch.object(
            ui,
            "_call_runner",
            return_value={"udp": [], "tcp": [], "tun": [], "counts": {}, "app": "udp-bidirectional-mux", "milestone": "C"},
        ):
            payload = ui._build_connections_payload()

        self.assertFalse(payload["admin_web_snapshot"]["stale"])
        self.assertEqual(payload["app"], "udp-bidirectional-mux")
        self.assertEqual(payload["runner_async_diagnostics"]["async"]["last_started_kind"], "await")
        self.assertEqual(payload["runner_async_diagnostics"]["sync"]["last_started_kind"], "callback")


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
                    {"peer_id": 1, "connected": True, "peer": _peer_endpoint("198.51.100.1", 4433), "mux_chans": []},
                    {"peer_id": 2, "connected": True, "peer": _peer_endpoint("198.51.100.2", 4433), "mux_chans": []},
                ]
            ),
            _FakeSession(
                [
                    {"peer_id": -1, "connected": False, "peer": None, "mux_chans": [], "listening": True},
                    {"peer_id": 1, "connected": True, "peer": _peer_endpoint("198.51.100.3", 8081), "mux_chans": []},
                ]
            ),
            _FakeSession(
                [
                    {"peer_id": -1, "connected": False, "peer": None, "mux_chans": [], "listening": True},
                    {"peer_id": 1, "connected": True, "peer": _peer_endpoint("198.51.100.4", 8443), "mux_chans": []},
                ]
            ),
        ]
        runner._muxes = [_MuxWithoutChannels(), _MuxWithoutChannels(), _MuxWithoutChannels()]
        runner._session_labels = ["myudp", "tcp", "quic"]

        peers = runner.get_peer_connections_snapshot()["peers"]
        connected = [peer for peer in peers if peer["connected"]]

        self.assertEqual({peer["transport"] for peer in connected}, {"myudp", "tcp", "quic"})
        self.assertEqual(
            {(peer["peer"]["host"], peer["peer"]["port"]) for peer in connected},
            {
                ("198.51.100.1", 4433),
                ("198.51.100.2", 4433),
                ("198.51.100.3", 8081),
                ("198.51.100.4", 8443),
            },
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

    def test_myudp_retransmit_rebuilds_fresh_transport_timestamps(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)
        original_second = transport.frames[1]
        parsed_original = session.proto.parse_frame_with_times(original_second)

        self.assertIsNotNone(parsed_original)
        _ptype, _payload, original_tx_ns, original_echo_ns = parsed_original
        self.assertEqual(original_echo_ns, 0)

        session.proto.on_frame_received(10_000_000_000, time.monotonic_ns() - 1_000_000)

        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
        proto.send_port = transport

        feedback = ControlPacket.build_full(0, 2, [2])
        session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
        proto._schedule_retrans(feedback.missed)

        self.assertEqual(len(transport.frames), 3)
        parsed_retx = session.proto.parse_frame_with_times(transport.frames[-1])
        self.assertIsNotNone(parsed_retx)
        _ptype, _payload, retrans_tx_ns, retrans_echo_ns = parsed_retx
        retransmitted = DataPacket.parse_full(transport.frames[-1])
        self.assertIsNotNone(retransmitted)
        self.assertEqual(retransmitted.pkt_counter, 2)
        self.assertGreater(retrans_tx_ns, original_tx_ns)
        self.assertGreater(retrans_echo_ns, 0)
        self.assertNotEqual(transport.frames[-1], original_second)

    def test_myudp_ack_samples_transmit_delay_from_first_send_minus_half_rtt(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)
        session.proto.rtt_est_ms = 100.0

        first_send_ctr1_ns = session.send_txns[1]
        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=first_send_ctr1_ns + 350_000_000,
        ):
            session.confirm_with_feedback(last_in_order=1, highest=1, missed=[])

        self.assertAlmostEqual(session.transmit_delay_sample_ms, 300.0, places=3)
        self.assertAlmostEqual(session.transmit_delay_est_ms, 300.0, places=3)

    def test_myudp_empty_pipeline_rebases_transmit_delay_est_to_half_rtt(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.proto.rtt_est_ms = 100.0

        first_send_ctr1_ns = session.send_txns[1]
        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=first_send_ctr1_ns + 350_000_000,
        ):
            session.confirm_with_feedback(last_in_order=1, highest=1, missed=[])

        self.assertEqual(session.send_buf, {})
        self.assertAlmostEqual(session.transmit_delay_sample_ms, 300.0, places=3)
        self.assertAlmostEqual(session.transmit_delay_est_ms, 50.0, places=3)

    def test_myudp_rtt_refresh_rebases_transmit_delay_est_to_half_rtt(self):
        session, _transport = self._session_and_transport()
        session.transmit_delay_est_ms = 9000.0

        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=1_000_000_000,
        ):
            session.update_rtt(880_000_000, from_idle=True)

        self.assertAlmostEqual(session.rtt_sample_ms, 120.0, places=3)
        self.assertAlmostEqual(session.rtt_est_ms, 120.0, places=3)
        self.assertAlmostEqual(session.transmit_delay_est_ms, 60.0, places=3)

    def test_myudp_non_idle_rtt_refresh_does_not_rebase_transmit_delay_est(self):
        session, _transport = self._session_and_transport()
        session.transmit_delay_est_ms = 9000.0

        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=1_000_000_000,
        ):
            session.update_rtt(880_000_000, from_idle=False)

        self.assertAlmostEqual(session.rtt_sample_ms, 120.0, places=3)
        self.assertAlmostEqual(session.rtt_est_ms, 120.0, places=3)
        self.assertAlmostEqual(session.transmit_delay_est_ms, 9000.0, places=3)

    def test_stream_transports_publish_transmit_delay_as_half_rtt(self):
        for session_cls in (TcpStreamSession, QuicSession, WebSocketSession):
            session = session_cls.__new__(session_cls)
            session._rtt = types.SimpleNamespace(
                rtt_sample_ms=40.0,
                rtt_est_ms=84.0,
                last_rtt_ok_ns=123456789,
            )

            metrics = session.get_metrics()

            self.assertEqual(metrics.rtt_sample_ms, 40.0)
            self.assertEqual(metrics.rtt_est_ms, 84.0)
            self.assertEqual(metrics.transmit_delay_est_ms, 42.0)
            self.assertEqual(metrics.last_rtt_ok_ns, 123456789)

    def test_myudp_retransmit_skips_stale_raw_frame_when_send_meta_is_missing(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)

        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
        proto.send_port = transport

        session.send_meta.pop(2, None)
        original_attempts = dict(session.send_attempts)

        feedback = ControlPacket.build_full(0, 2, [2])
        session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
        proto._schedule_retrans(feedback.missed)

        self.assertEqual(len(transport.frames), 2)
        self.assertEqual(session.send_attempts, original_attempts)

    def test_myudp_reported_missing_frame_retries_every_rtt_until_cumulative_ack(self):
        session, transport = self._session_and_transport()
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)
        session.send_application_payload(b"three", transport)

        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
        proto.send_port = transport
        session.proto.rtt_est_ms = 100.0

        session.confirm_with_feedback(last_in_order=0, highest=3, missed=[2])
        self.assertEqual(session.peer_reported_missing, {2})

        with mock.patch("obstacle_bridge.bridge_transport_udp.now_ns", return_value=session.send_txns[2] + 150_000_000):
            proto._schedule_retrans([2])
        self.assertEqual(session.send_attempts[2], 2)

        session.confirm_with_feedback(last_in_order=0, highest=3, missed=[])
        self.assertEqual(session.peer_reported_missing, {2})
        self.assertIn(2, session.send_buf)

        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=session.last_retx_ns[2] + 110_000_000,
        ):
            proto._retx_sweep_reported_missing()
        self.assertEqual(session.send_attempts[2], 3)

        session.confirm_with_feedback(last_in_order=3, highest=3, missed=[])
        self.assertNotIn(2, session.peer_reported_missing)
        self.assertNotIn(2, session.send_buf)

    def test_myudp_persistent_missing_retries_survive_flight_window_pressure(self):
        session, transport = self._session_and_transport(max_in_flight=200)
        for idx in range(205):
            session.send_application_payload(f"pkt-{idx:03d}".encode("ascii"), transport)

        self.assertEqual(session.in_flight(), 200)
        self.assertEqual(session.waiting_count(), 5)

        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
        proto.send_port = transport
        session.proto.rtt_est_ms = 80.0

        session.confirm_with_feedback(last_in_order=0, highest=200, missed=[1])
        self.assertEqual(session.peer_reported_missing, {1})

        before_flush = len(transport.frames)
        session.try_flush_send_queue(transport)
        self.assertEqual(session.waiting_count(), 0)
        self.assertGreater(len(transport.frames), before_flush)

        with mock.patch("obstacle_bridge.bridge_transport_udp.now_ns", return_value=session.send_txns[1] + 100_000_000):
            proto._schedule_retrans([1])
        attempts_after_control = session.send_attempts[1]

        session.confirm_with_feedback(last_in_order=0, highest=205, missed=[])
        self.assertIn(1, session.peer_reported_missing)
        self.assertIn(1, session.send_buf)

        with mock.patch(
            "obstacle_bridge.bridge_transport_udp.now_ns",
            return_value=session.last_retx_ns[1] + 90_000_000,
        ):
            proto._retx_sweep_reported_missing()
        self.assertGreater(session.send_attempts[1], attempts_after_control)
        self.assertIn(1, session.send_buf)

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
        self.assertEqual(session.in_flight(), 0)
        self.assertEqual(session.waiting_count(), 0)
        self.assertEqual(session.send_buf, {})
        self.assertEqual(session.send_meta, {})
        self.assertEqual(session.send_txns, {})
        self.assertEqual(session.last_retx_ns, {})
        self.assertEqual(session.send_attempts, {})
        self.assertEqual(session.data_pkt_flags, {})
        self.assertEqual(session.expected, 1)
        self.assertEqual(set(session.pending), {2})
        self.assertEqual(session.missing, {1})

    def test_myudp_sender_reset_preserves_receiver_gap_state_and_allows_recovery(self):
        session, transport = self._session_and_transport(max_in_flight=1)
        session.send_application_payload(b"before", transport)
        session.send_application_payload(b"queued", transport)

        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        _advanced, completed = session.process_data(pkt2)
        self.assertEqual(completed, [])
        _advanced, completed = session.process_data(pkt3)
        self.assertEqual(completed, [])
        self.assertEqual(session.expected, 1)
        self.assertEqual(set(session.pending), {2, 3})
        self.assertEqual(session.missing, {1})

        session.reset_sender()

        self.assertEqual(session.next_ctr, 1)
        self.assertEqual(session.in_flight(), 0)
        self.assertEqual(session.waiting_count(), 0)
        self.assertEqual(session.expected, 1)
        self.assertEqual(set(session.pending), {2, 3})
        self.assertEqual(session.missing, {1})

        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
        _advanced, completed = session.process_data(pkt1)
        self.assertEqual(completed, [b"abcdefghi"])
        self.assertEqual(session.expected, 4)
        self.assertEqual(session.pending, {})
        self.assertEqual(session.missing, set())

    def test_myudp_transport_epoch_reset_clears_receiver_gap_state(self):
        session, transport = self._session_and_transport(max_in_flight=1)
        session.send_application_payload(b"before", transport)
        session.send_application_payload(b"queued", transport)

        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        _advanced, completed = session.process_data(pkt2)
        self.assertEqual(completed, [])
        _advanced, completed = session.process_data(pkt3)
        self.assertEqual(completed, [])
        self.assertEqual(session.expected, 1)
        self.assertEqual(set(session.pending), {2, 3})
        self.assertEqual(session.missing, {1})

        session.reset_transport_epoch()

        self.assertEqual(session.next_ctr, 1)
        self.assertEqual(session.in_flight(), 0)
        self.assertEqual(session.waiting_count(), 0)
        self.assertEqual(session.expected, 1)
        self.assertEqual(session.pending, {})
        self.assertEqual(session.missing, set())
        self.assertIsNone(session.reass)

    def test_myudp_peer_protocol_epoch_reset_drops_queued_datagrams_and_control_state(self):
        session, _transport = self._session_and_transport()
        proto = PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)

        proto._last_control_sent_ns = 123
        proto._last_sent_last_in_order = 77
        proto._established_ns = 456
        proto._rx_pending.append((b"stale", ("127.0.0.1", 9999)))
        proto._rx_pending_scheduled = True
        proto._completed_pending.append(b"payload")
        proto._completed_pending_scheduled = True

        proto.reset_transport_epoch_runtime()

        self.assertEqual(proto._last_control_sent_ns, 0)
        self.assertEqual(proto._last_sent_last_in_order, 0)
        self.assertEqual(proto._established_ns, 0)
        self.assertEqual(list(proto._rx_pending), [])
        self.assertFalse(proto._rx_pending_scheduled)
        self.assertEqual(list(proto._completed_pending), [])
        self.assertFalse(proto._completed_pending_scheduled)


if __name__ == "__main__":
    unittest.main()
