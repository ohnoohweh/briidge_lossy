import argparse
import asyncio
import time
import types
import unittest

from obstacle_bridge.bridge import ChannelMux, Runner, SessionMetrics, StatsBoard, TcpStreamSession, QuicSession, UdpSession


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
        self.udp_spec = ChannelMux.ServiceSpec(1, "udp", "0.0.0.0", 1111, "udp", "192.0.2.10", 9991, name="lab-udp")
        self.tcp_spec = ChannelMux.ServiceSpec(2, "tcp", "0.0.0.0", 2222, "tcp", "192.0.2.20", 9992, name="lab-tcp")
        self.tun_spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1400, "tun", "obtun1", 1400, name="lab-tun")
        self.udp_key = ("local", 0, 1)
        self.tcp_key = ("local", 0, 2)
        self.tun_key = ("local", 0, 3)
        self.mux._local_services[self.udp_key] = self.udp_spec
        self.mux._local_services[self.tcp_key] = self.tcp_spec
        self.mux._local_services[self.tun_key] = self.tun_spec

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
        self.assertEqual(udp_listener[0]["service_name"], "lab-udp")
        self.assertEqual(tcp_listener[0]["service_name"], "lab-tcp")

    def test_snapshot_counts_idle_tun_interface_as_listening_not_open(self):
        self.mux._svc_tun_devices[self.tun_key] = ChannelMux.TunDevice(
            fd=-1,
            ifname="obtun0",
            mtu=1400,
            service_key=self.tun_key,
        )

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["tun"], 0)
        self.assertEqual(snap["counts"]["tun_listening"], 1)
        self.assertEqual(len(snap["tun"]), 1)
        row = snap["tun"][0]
        self.assertEqual(row["state"], "listening")
        self.assertIsNone(row["chan_id"])
        self.assertEqual(row["service_name"], "lab-tun")
        self.assertEqual(row["local"]["ifname"], "obtun0")
        self.assertEqual(row["remote_destination"]["ifname"], "obtun1")

    def test_snapshot_counts_active_tun_channel_as_open(self):
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1400, service_key=self.tun_key)
        dev.chan_id = 301
        self.mux._svc_tun_devices[self.tun_key] = dev
        self.mux._tun_by_chan[301] = dev
        ctr = self.mux._ctr(ChannelMux.Proto.TUN, 301)
        ctr.msgs_in = 2
        ctr.msgs_out = 3
        ctr.bytes_in = 100
        ctr.bytes_out = 200

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["tun"], 1)
        self.assertEqual(snap["counts"]["tun_listening"], 0)
        self.assertEqual(len(snap["tun"]), 1)
        row = snap["tun"][0]
        self.assertEqual(row["state"], "connected")
        self.assertEqual(row["chan_id"], 301)
        self.assertEqual(row["service_name"], "lab-tun")
        self.assertEqual(row["stats"]["rx_msgs"], 2)
        self.assertEqual(row["stats"]["tx_msgs"], 3)

    def test_snapshot_collapses_tun_channel_aliases_into_one_logical_connection(self):
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1400, service_key=self.tun_key)
        dev.chan_id = 302
        self.mux._svc_tun_devices[self.tun_key] = dev
        self.mux._tun_by_chan[302] = dev
        self.mux._tun_by_chan[301] = dev
        ctr_a = self.mux._ctr(ChannelMux.Proto.TUN, 302)
        ctr_a.msgs_in = 2
        ctr_a.bytes_in = 100
        ctr_b = self.mux._ctr(ChannelMux.Proto.TUN, 301)
        ctr_b.msgs_out = 3
        ctr_b.bytes_out = 200

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["tun"], 1)
        self.assertEqual(len(snap["tun"]), 1)
        row = snap["tun"][0]
        self.assertEqual(row["chan_id"], 302)
        self.assertEqual(row["channel_aliases"], [301, 302])
        self.assertEqual(row["stats"]["rx_msgs"], 2)
        self.assertEqual(row["stats"]["tx_msgs"], 3)
        self.assertEqual(row["stats"]["rx_bytes"], 100)
        self.assertEqual(row["stats"]["tx_bytes"], 200)
        self.assertEqual(self.mux.tun_open_count(), 1)

    def test_snapshot_mixed_listeners_and_active_connections(self):
        self.mux._svc_udp_servers[self.udp_key] = _FakeDatagramTransport(("0.0.0.0", 1111))
        self.mux._svc_tcp_servers[self.tcp_key] = _FakeTcpServer([_FakeSocket(("0.0.0.0", 2222))])

        self.mux._udp_by_chan[101] = (self.udp_key, ("10.10.10.10", 40001))
        self.mux._tcp_by_chan[201] = (2, _FakeWriter(("0.0.0.0", 2222), ("10.10.10.20", 40002)))
        self.mux._tcp_role_by_chan[201] = "server"

        snap = self.mux.snapshot_connections()

        self.assertEqual(snap["counts"]["udp"], 1)
        self.assertEqual(snap["counts"]["tcp"], 1)
        udp_connected = [row for row in snap["udp"] if row.get("state") == "connected"]
        tcp_connected = [row for row in snap["tcp"] if row.get("state") == "connected"]
        self.assertEqual(udp_connected[0]["service_name"], "lab-udp")
        self.assertEqual(tcp_connected[0]["service_name"], "lab-tcp")
        self.assertEqual(snap["counts"]["udp_listening"], 1)
        self.assertEqual(snap["counts"]["tcp_listening"], 1)
        self.assertIn("connected", {row.get("state") for row in snap["udp"]})
        self.assertIn("connected", {row.get("state") for row in snap["tcp"]})

    def test_closed_channel_stats_are_archived_by_owner_peer(self):
        self.mux._chan_owner_peer_id[201] = 7
        ctr = self.mux._ctr(ChannelMux.Proto.TCP, 201)
        ctr.msgs_in = 2
        ctr.msgs_out = 3
        ctr.bytes_in = 123
        ctr.bytes_out = 456

        self.mux._finalize_channel_stats(201, ChannelMux.Proto.TCP)

        totals = self.mux.snapshot_peer_payload_totals()
        self.assertEqual(totals[7]["rx_msgs"], 2)
        self.assertEqual(totals[7]["tx_msgs"], 3)
        self.assertEqual(totals[7]["rx_bytes"], 123)
        self.assertEqual(totals[7]["tx_bytes"], 456)
        self.assertNotIn((201, ChannelMux.Proto.TCP), self.mux._chan_stats)


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


class _MuxWithMutableTun:
    def __init__(self):
        self.rx_bytes = 100
        self.tx_bytes = 200

    def snapshot_connections(self):
        return {
            "udp": [],
            "tcp": [],
            "tun": [
                {
                    "protocol": "tun",
                    "state": "connected",
                    "chan_id": 101,
                    "stats": {"rx_bytes": self.rx_bytes, "tx_bytes": self.tx_bytes},
                }
            ],
            "counts": {"udp": 0, "tcp": 0, "tun": 1, "udp_listening": 0, "tcp_listening": 0},
        }


class _MuxWithOpenCounts:
    def __init__(self, udp=0, tcp=0, tun=0):
        self.udp = udp
        self.tcp = tcp
        self.tun = tun

    def udp_open_count(self):
        return self.udp

    def tcp_open_count(self):
        return self.tcp

    def tun_open_count(self):
        return self.tun


class _MuxWithArchivedPeerTotals:
    def snapshot_connections(self):
        return {
            "udp": [],
            "tcp": [
                {
                    "protocol": "tcp",
                    "state": "connected",
                    "chan_id": 101,
                    "stats": {"rx_bytes": 10, "tx_bytes": 20},
                }
            ],
            "tun": [],
            "counts": {"udp": 0, "tcp": 1, "tun": 0, "udp_listening": 0, "tcp_listening": 0},
        }

    def snapshot_peer_payload_totals(self):
        return {
            7: {
                "rx_msgs": 2,
                "tx_msgs": 2,
                "rx_bytes": 300,
                "tx_bytes": 400,
            }
        }


class StatsBoardSnapshotTests(unittest.TestCase):
    def test_status_snapshot_includes_tun_open_connection_count(self):
        board = StatsBoard(argparse.Namespace(no_dashboard=True, overlay_transport="myudp"))
        board.set_mux_ref(_MuxWithOpenCounts(udp=1, tcp=2, tun=3))

        status = board.snapshot_status()

        self.assertEqual(status["open_connections"]["udp"], 1)
        self.assertEqual(status["open_connections"]["tcp"], 2)
        self.assertEqual(status["open_connections"]["tun"], 3)


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

    def test_peer_snapshot_includes_archived_closed_channel_payload_totals(self):
        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        runner._sessions = [_PeerSession()]
        runner._muxes = [_MuxWithArchivedPeerTotals()]
        runner._session_labels = ["myudp"]

        out = runner.get_peer_connections_snapshot()
        peer = out["peers"][0]

        self.assertEqual(peer["open_connections"]["tcp"], 1)
        self.assertEqual(peer["traffic"]["rx_bytes"], 310)
        self.assertEqual(peer["traffic"]["tx_bytes"], 420)

    def test_peer_snapshot_includes_tun_payload_and_rates(self):
        args = argparse.Namespace(no_dashboard=True, overlay_transport="myudp")
        runner = Runner(args)
        mux = _MuxWithMutableTun()
        runner._sessions = [_PeerSession()]
        runner._muxes = [mux]
        runner._session_labels = ["myudp"]

        first = runner.get_peer_connections_snapshot()["peers"][0]
        self.assertEqual(first["open_connections"]["tun"], 1)
        self.assertEqual(first["traffic"]["rx_bytes"], 100)
        self.assertEqual(first["traffic"]["tx_bytes"], 200)
        self.assertEqual(first["traffic"]["rx_bytes_per_sec"], 0.0)
        self.assertEqual(first["traffic"]["tx_bytes_per_sec"], 0.0)

        mux.rx_bytes = 612
        mux.tx_bytes = 712
        second = runner.get_peer_connections_snapshot()["peers"][0]
        self.assertEqual(second["traffic"]["rx_bytes"], 612)
        self.assertEqual(second["traffic"]["tx_bytes"], 712)
        self.assertGreater(second["traffic"]["rx_bytes_per_sec"], 0.0)
        self.assertGreater(second["traffic"]["tx_bytes_per_sec"], 0.0)

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


class TransportPeerSnapshotLastIncomingTests(unittest.TestCase):
    def test_tcp_client_snapshot_includes_last_incoming_age_seconds(self):
        session = TcpStreamSession.__new__(TcpStreamSession)
        session._peer_tuple = ("127.0.0.1", 8081)
        session._peer_host = "127.0.0.1"
        session._peer_port = 8081
        session._rtt = types.SimpleNamespace(rtt_est_ms=1.5, _last_rx_wall_ns=time.monotonic_ns())
        session.is_connected = lambda: True

        rows = session.get_overlay_peers_snapshot()

        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0]["last_incoming_age_seconds"])
        self.assertGreaterEqual(rows[0]["last_incoming_age_seconds"], 0.0)

    def test_tcp_server_snapshot_includes_last_incoming_age_seconds(self):
        session = TcpStreamSession.__new__(TcpStreamSession)
        session._peer_tuple = None
        session._server_chan_to_peer = {101: (1, 7)}
        session._server_peers = {
            1: {
                "addr": ("198.51.100.10", 5000),
                "connected": True,
                "rtt": types.SimpleNamespace(rtt_est_ms=2.5, _last_rx_wall_ns=time.monotonic_ns()),
            }
        }

        rows = session.get_overlay_peers_snapshot()

        peer_row = next(row for row in rows if row["peer_id"] == 1)
        self.assertIsNotNone(peer_row["last_incoming_age_seconds"])
        self.assertGreaterEqual(peer_row["last_incoming_age_seconds"], 0.0)

    def test_quic_client_snapshot_includes_last_incoming_age_seconds(self):
        session = QuicSession.__new__(QuicSession)
        session._peer_tuple = ("127.0.0.1", 443)
        session._peer_host = "127.0.0.1"
        session._peer_port = 443
        session._rtt = types.SimpleNamespace(rtt_est_ms=3.5, _last_rx_wall_ns=time.monotonic_ns())
        session.is_connected = lambda: True

        rows = session.get_overlay_peers_snapshot()

        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0]["last_incoming_age_seconds"])
        self.assertGreaterEqual(rows[0]["last_incoming_age_seconds"], 0.0)

    def test_quic_server_snapshot_includes_last_incoming_age_seconds(self):
        session = QuicSession.__new__(QuicSession)
        session._peer_tuple = None
        session._server_chan_to_peer = {201: (2, 9)}
        session._server_peers = {
            2: {
                "peer_host": "203.0.113.20",
                "peer_port": 8443,
                "rtt": types.SimpleNamespace(rtt_est_ms=4.5, _last_rx_wall_ns=time.monotonic_ns()),
            }
        }

        rows = session.get_overlay_peers_snapshot()

        peer_row = next(row for row in rows if row["peer_id"] == 2)
        self.assertIsNotNone(peer_row["last_incoming_age_seconds"])
        self.assertGreaterEqual(peer_row["last_incoming_age_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
