#!/usr/bin/env python3
import argparse
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner, TcpStreamSession, UdpSession, QuicSession, WebSocketSession


def _args(**overrides):
    base = dict(
        overlay_transport='myudp',
        udp_listen_port=4433,
        udp_peer=None,
        tcp_listen_port=8081,
        quic_listen_port=443,
        ws_listen_port=8080,
        overlay_port_myudp=None,
        overlay_port_tcp=None,
        overlay_port_quic=None,
        overlay_port_ws=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class RunnerOverlayTransportTests(unittest.TestCase):
    def test_parse_overlay_transports_accepts_comma_separated_values(self):
        args = _args(overlay_transport='myudp, tcp,quic,ws')
        self.assertEqual(Runner._parse_overlay_transports(args), ['myudp', 'tcp', 'quic', 'ws'])

    def test_parse_overlay_transports_rejects_multi_transport_clients(self):
        args = _args(overlay_transport='myudp,ws', udp_peer='127.0.0.1')
        with self.assertRaises(ValueError):
            Runner._parse_overlay_transports(args)

    def test_overlay_port_for_uses_deterministic_offsets(self):
        args = _args(udp_listen_port=9000)
        self.assertEqual(Runner._overlay_port_for(args, 'myudp', 4), 9000)
        self.assertEqual(Runner._overlay_port_for(args, 'tcp', 4), 8082)
        self.assertEqual(Runner._overlay_port_for(args, 'quic', 4), 445)
        self.assertEqual(Runner._overlay_port_for(args, 'ws', 4), 8083)

    def test_build_sessions_from_overlay_uses_per_transport_ports(self):
        args = _args(overlay_transport='myudp,tcp,quic,ws', udp_listen_port=7000, tcp_listen_port=7000, quic_listen_port=7000, ws_listen_port=7000)
        seen = []

        def _factory(name):
            def _inner(ns):
                port = ns.udp_listen_port if name == 'myudp' else ns.tcp_listen_port if name == 'tcp' else ns.quic_listen_port if name == 'quic' else ns.ws_listen_port
                seen.append((name, port))
                return {'transport': name, 'port': port}
            return _inner

        with mock.patch.object(UdpSession, 'from_args', side_effect=_factory('myudp')), \
             mock.patch.object(TcpStreamSession, 'from_args', side_effect=_factory('tcp')), \
             mock.patch.object(QuicSession, 'from_args', side_effect=_factory('quic')), \
             mock.patch.object(WebSocketSession, 'from_args', side_effect=_factory('ws')):
            sessions = Runner.build_sessions_from_overlay(args)

        self.assertEqual([name for name, _ in sessions], ['myudp', 'tcp', 'quic', 'ws'])
        self.assertEqual(
            [s[1] for s in seen],
            [7000, 7001, 7002, 7003],
        )


if __name__ == '__main__':
    unittest.main()
