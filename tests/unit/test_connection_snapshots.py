import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import ChannelMux, Runner, SessionMetrics


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

        self.assertTrue(peer["connected"])
        self.assertEqual(peer["open_connections"]["udp"], 1)
        self.assertEqual(peer["traffic"]["rx_bytes"], 1234)
        self.assertEqual(peer["traffic"]["tx_bytes"], 4321)


if __name__ == "__main__":
    unittest.main()
