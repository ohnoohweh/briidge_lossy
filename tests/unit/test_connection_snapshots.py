import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import ChannelMux, Runner, SessionMetrics, UdpSession


class _FakeSession:
    def is_connected(self):
        return False

    def set_on_app_payload(self, _cb):
        pass

    def set_on_peer_disconnect(self, _cb):
        pass


class _FakeDatagramTransport:
    def __init__(self, sockname, peername=None):
        self._sockname = sockname
        self._peername = peername

    def get_extra_info(self, key):
        if key == "sockname":
            return self._sockname
        if key == "peername":
            return self._peername
        return None

    def close(self):
        pass


class _FakeSocket:
    def __init__(self, sockname):
        self._sockname = sockname

    def getsockname(self):
        return self._sockname


class _FakeTcpServer:
    def __init__(self, sockets):
        self.sockets = sockets


class _FakeWriterTransport:
    def __init__(self, sockname, peername):
        self._sockname = sockname
        self._peername = peername

    def get_extra_info(self, key):
        if key == "sockname":
            return self._sockname
        if key == "peername":
            return self._peername
        return None


class _FakeWriter:
    def __init__(self, sockname, peername):
        self.transport = _FakeWriterTransport(sockname, peername)


class ChannelMuxSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.mux = ChannelMux(_FakeSession(), self.loop)
        self.udp_spec = ChannelMux.ServiceSpec(1, "udp", "0.0.0.0", 1111, "udp", "192.0.2.10", 9991)
        self.tcp_spec = ChannelMux.ServiceSpec(2, "tcp", "0.0.0.0", 2222, "tcp", "192.0.2.20", 9992)
        self.udp_key = ("local", 0, 1)
        self.tcp_key = ("local", 0, 2)
        self.mux._local_services[self.udp_key] = self.udp_spec
        self.mux._local_services[self.tcp_key] = self.tcp_spec

    def tearDown(self):
        self.loop.close()

    def test_snapshot_counts_listeners_when_no_clients_connected(self):
        self.mux._svc_udp_servers[self.udp_key] = _FakeDatagramTransport(("0.0.0.0", 1111))
        self.mux._svc_tcp_servers[self.tcp_key] = _FakeTcpServer([_FakeSocket(("0.0.0.0", 2222))])

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["udp"], 0)
        self.assertEqual(snap["counts"]["tcp"], 0)
        self.assertEqual(snap["counts"]["udp_listening"], 1)
        self.assertEqual(snap["counts"]["tcp_listening"], 1)

        udp_listener = [row for row in snap["udp"] if row.get("state") == "listening"]
        tcp_listener = [row for row in snap["tcp"] if row.get("state") == "listening"]
        self.assertEqual(len(udp_listener), 1)
        self.assertEqual(len(tcp_listener), 1)
        self.assertIsNone(udp_listener[0]["chan_id"])
        self.assertIsNone(tcp_listener[0]["chan_id"])

    def test_snapshot_mixed_listeners_and_active_connections(self):
        self.mux._svc_udp_servers[self.udp_key] = _FakeDatagramTransport(("0.0.0.0", 1111))
        self.mux._svc_tcp_servers[self.tcp_key] = _FakeTcpServer([_FakeSocket(("0.0.0.0", 2222))])

        self.mux._udp_by_chan[101] = (self.udp_key, ("10.10.10.10", 40001))
        self.mux._tcp_by_chan[201] = (2, _FakeWriter(("0.0.0.0", 2222), ("10.10.10.20", 40002)))
        self.mux._tcp_role_by_chan[201] = "server"

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["udp"], 1)
        self.assertEqual(snap["counts"]["tcp"], 1)
        self.assertEqual(snap["counts"]["udp_listening"], 1)
        self.assertEqual(snap["counts"]["tcp_listening"], 1)
        self.assertIn("connected", {row.get("state") for row in snap["udp"]})
        self.assertIn("connected", {row.get("state") for row in snap["tcp"]})


class _PeerSession:
    def __init__(self):
        self._metrics = SessionMetrics()

    def get_metrics(self):
        return self._metrics

    def is_connected(self):
        return True

    def get_overlay_peers_snapshot(self):
        return [
            {
                "peer_id": 7,
                "connected": True,
                "peer": "198.51.100.7:4433",
                "mux_chans": [101],
            }
        ]


class _MuxWithListeners:
    def snapshot_connections(self):
        return {
            "udp": [
                {
                    "protocol": "udp",
                    "state": "listening",
                    "chan_id": None,
                    "stats": {"rx_bytes": 0, "tx_bytes": 0},
                },
                {
                    "protocol": "udp",
                    "state": "connected",
                    "chan_id": 101,
                    "stats": {"rx_bytes": 1234, "tx_bytes": 4321},
                },
            ],
            "tcp": [
                {
                    "protocol": "tcp",
                    "state": "listening",
                    "chan_id": None,
                    "stats": {"rx_bytes": 0, "tx_bytes": 0},
                }
            ],
            "counts": {"udp": 1, "tcp": 0, "udp_listening": 1, "tcp_listening": 1},
        }


class RunnerPeerSnapshotTests(unittest.TestCase):
    def test_peer_open_connections_excludes_idle_listeners(self):
        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        runner._sessions = [_PeerSession()]
        runner._muxes = [_MuxWithListeners()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        self.assertEqual(len(out["peers"]), 1)
        peer = out["peers"][0]
        self.assertEqual(peer["open_connections"]["udp"], 1)
        self.assertEqual(peer["open_connections"]["tcp"], 0)
        self.assertEqual(peer["traffic"]["rx_bytes"], 1234)
        self.assertEqual(peer["traffic"]["tx_bytes"], 4321)

    def test_listener_snapshot_includes_myudp_listener_row(self):
        class _ListenerSession:
            def __init__(self):
                self._metrics = SessionMetrics()

            def get_metrics(self):
                return self._metrics

            def is_connected(self):
                return True

            def get_overlay_peers_snapshot(self):
                return [
                    {
                        "peer_id": -1,
                        "connected": False,
                        "peer": None,
                        "mux_chans": [],
                        "rtt_est_ms": None,
                        "listening": True,
                    },
                    {
                        "peer_id": 7,
                        "connected": True,
                        "peer": "198.51.100.7:4433",
                        "mux_chans": [101],
                        "secure_link": {
                            "enabled": True,
                            "mode": "psk",
                            "state": "authenticated",
                            "authenticated": True,
                            "session_id": 77,
                            "connected_since_unix_ts": 1700000000.0,
                            "failure_reason": None,
                            "transport": "myudp",
                        },
                    },
                ]

        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        runner._sessions = [_ListenerSession()]
        runner._muxes = [_MuxWithListeners()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        self.assertEqual(len(out["peers"]), 2)
        listener = next(p for p in out["peers"] if p["id"] == "0:-1")
        peer = next(p for p in out["peers"] if p["id"] == "0:7")

        self.assertFalse(listener["connected"])
        self.assertIsNone(listener["peer"])
        self.assertEqual(listener["open_connections"]["udp"], 0)
        self.assertEqual(listener["open_connections"]["tcp"], 0)
        self.assertEqual(listener["secure_link"]["state"], "disabled")

        self.assertTrue(peer["connected"])
        self.assertEqual(peer["open_connections"]["udp"], 1)
        self.assertEqual(peer["traffic"]["rx_bytes"], 1234)
        self.assertEqual(peer["traffic"]["tx_bytes"], 4321)
        self.assertEqual(peer["secure_link"]["state"], "authenticated")
        self.assertTrue(peer["secure_link"]["authenticated"])
        self.assertEqual(peer["secure_link"]["connected_since_unix_ts"], 1700000000.0)

    def test_listener_snapshot_shows_invalid_myudp_sender_as_connecting_peer(self):
        class _EmptyMux:
            def snapshot_connections(self):
                return {
                    "udp": [],
                    "tcp": [],
                    "counts": {"udp": 0, "tcp": 0, "udp_listening": 0, "tcp_listening": 0},
                }

        args = argparse.Namespace(
            no_dashboard=True,
            overlay_transport="myudp",
            max_inflight=32,
            udp_bind="0.0.0.0",
            udp_own_port=4443,
            udp_peer=None,
            udp_peer_port=4433,
            peer_resolve_family="prefer-ipv6",
        )
        session = UdpSession(args)
        session._listener_mode = True
        session._transport = _FakeDatagramTransport(("0.0.0.0", 4443))

        session._dispatch_listener_datagram(b"port-scan-junk", ("38.180.143.5", 50227))

        overlay_rows = session.get_overlay_peers_snapshot()
        self.assertEqual(len(overlay_rows), 2)
        peer_row = next(row for row in overlay_rows if row["peer_id"] != -1)
        self.assertFalse(peer_row["connected"])
        self.assertEqual(peer_row["peer"], "38.180.143.5:50227")
        self.assertIsNotNone(peer_row["last_incoming_age_seconds"])
        self.assertGreaterEqual(peer_row["last_incoming_age_seconds"], 0)

        ctx = session._server_peers[peer_row["peer_id"]]
        self.assertFalse(ctx["connected"])
        self.assertEqual(ctx["peer_proto"].unidentified_frames, 1)

        runner = Runner(args)
        runner._sessions = [session]
        runner._muxes = [_EmptyMux()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        self.assertEqual(len(out["peers"]), 2)
        peer = next(p for p in out["peers"] if p["id"] != "0:-1")
        self.assertEqual(peer["id"], f"0:{peer_row['peer_id']}")
        self.assertFalse(peer["connected"])
        self.assertEqual(peer["state"], "connecting")
        self.assertEqual(peer["peer"], "38.180.143.5:50227")
        self.assertIsNotNone(peer["last_incoming_age_seconds"])
        self.assertGreaterEqual(peer["last_incoming_age_seconds"], 0)
        self.assertEqual(peer["decode_errors"], 1)
        self.assertEqual(peer["open_connections"]["udp"], 0)
        self.assertEqual(peer["open_connections"]["tcp"], 0)

    def test_listener_peer_snapshot_uses_child_myudp_session_stats(self):
        class _InnerStats:
            def __init__(self, inflight, confirmed_total):
                self.max_in_flight = 32
                self.rtt_est_ms = None
                self.last_rtt_ok_ns = None
                self.last_ack_peer = None
                self.last_sent_ctr = None
                self.expected = None
                self.peer_missed_count = None
                self.missing = []
                self.stats_hist = {"confirmed_total": confirmed_total}
                self._inflight = inflight

            def in_flight(self):
                return self._inflight

            def waiting_count(self):
                return 0

        class _ListenerSession:
            def __init__(self):
                self.inner_session = _InnerStats(inflight=0, confirmed_total=0)
                self._server_peers = {
                    1: {
                        "session": _InnerStats(inflight=7, confirmed_total=11),
                    }
                }

            def get_metrics(self):
                return SessionMetrics(inflight=7)

            def is_connected(self):
                return True

            def get_overlay_peers_snapshot(self):
                return [
                    {
                        "peer_id": -1,
                        "connected": False,
                        "peer": None,
                        "mux_chans": [],
                        "rtt_est_ms": None,
                        "listening": True,
                    },
                    {
                        "peer_id": 1,
                        "connected": True,
                        "peer": "198.51.100.1:4433",
                        "mux_chans": [101],
                    },
                ]

        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        runner._sessions = [_ListenerSession()]
        runner._muxes = [_MuxWithListeners()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        listener = next(p for p in out["peers"] if p["id"] == "0:-1")
        peer = next(p for p in out["peers"] if p["id"] == "0:1")

        self.assertEqual(listener["inflight"], 0)
        self.assertEqual(listener["myudp"]["confirmed_total"], 0)
        self.assertEqual(peer["inflight"], 7)
        self.assertEqual(peer["myudp"]["confirmed_total"], 11)

    def test_listener_peer_snapshot_unwraps_secure_link_wrapper_for_myudp_stats(self):
        class _InnerStats:
            def __init__(self, inflight, confirmed_total):
                self.max_in_flight = 32
                self.rtt_est_ms = None
                self.last_rtt_ok_ns = None
                self.last_ack_peer = None
                self.last_sent_ctr = None
                self.expected = None
                self.peer_missed_count = None
                self.missing = []
                self.stats_hist = {"confirmed_total": confirmed_total, "once": confirmed_total}
                self._inflight = inflight

            def in_flight(self):
                return self._inflight

            def waiting_count(self):
                return 0

        class _UdpSessionLike:
            def __init__(self):
                self.inner_session = _InnerStats(inflight=0, confirmed_total=0)
                self._server_peers = {
                    1: {
                        "session": _InnerStats(inflight=5, confirmed_total=9),
                    }
                }

            def get_metrics(self):
                return SessionMetrics(inflight=5)

            def is_connected(self):
                return True

            def get_overlay_peers_snapshot(self):
                return [
                    {
                        "peer_id": -1,
                        "connected": False,
                        "peer": None,
                        "mux_chans": [],
                        "rtt_est_ms": None,
                        "listening": True,
                    },
                    {
                        "peer_id": 1,
                        "connected": True,
                        "peer": "198.51.100.1:4433",
                        "mux_chans": [101],
                        "secure_link": {
                            "enabled": True,
                            "mode": "psk",
                            "state": "authenticated",
                            "authenticated": True,
                        },
                    },
                ]

        class _SecureLinkWrapper:
            def __init__(self):
                self._real = _UdpSessionLike()
                self._inner = self._real

            def get_metrics(self):
                return self._inner.get_metrics()

            def is_connected(self):
                return True

            def get_overlay_peers_snapshot(self):
                return self._inner.get_overlay_peers_snapshot()

        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        runner._sessions = [_SecureLinkWrapper()]
        runner._muxes = [_MuxWithListeners()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        listener = next(p for p in out["peers"] if p["id"] == "0:-1")
        peer = next(p for p in out["peers"] if p["id"] == "0:1")

        self.assertEqual(listener["myudp"]["confirmed_total"], 0)
        self.assertEqual(peer["myudp"]["confirmed_total"], 9)
        self.assertEqual(peer["myudp"]["first_pass"], 9)


if __name__ == "__main__":
    unittest.main()
