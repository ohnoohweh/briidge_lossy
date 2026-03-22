#!/usr/bin/env python3
import argparse
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner, TcpStreamSession, UdpSession, QuicSession, WebSocketSession


def _args(**overrides):
    base = dict(
        overlay_transport='myudp',
        port443=443,
        peer=None,
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
        args = _args(overlay_transport='myudp,ws', peer='127.0.0.1')
        with self.assertRaises(ValueError):
            Runner._parse_overlay_transports(args)

    def test_overlay_port_for_uses_deterministic_offsets(self):
        args = _args(port443=9000)
        self.assertEqual(Runner._overlay_port_for(args, 'myudp', 4), 9000)
        self.assertEqual(Runner._overlay_port_for(args, 'tcp', 4), 9001)
        self.assertEqual(Runner._overlay_port_for(args, 'quic', 4), 9002)
        self.assertEqual(Runner._overlay_port_for(args, 'ws', 4), 9003)

    def test_build_sessions_from_overlay_uses_per_transport_ports(self):
        args = _args(overlay_transport='myudp,tcp,quic,ws', port443=7000)
        seen = []

        def _factory(name):
            def _inner(ns):
                seen.append((name, ns.port443))
                return {'transport': name, 'port': ns.port443}
            return _inner

        with mock.patch.object(UdpSession, 'from_args', side_effect=_factory('myudp')), \
             mock.patch.object(TcpStreamSession, 'from_args', side_effect=_factory('tcp')), \
             mock.patch.object(QuicSession, 'from_args', side_effect=_factory('quic')), \
             mock.patch.object(WebSocketSession, 'from_args', side_effect=_factory('ws')):
            sessions = Runner.build_sessions_from_overlay(args)

        self.assertEqual([name for name, _ in sessions], ['myudp', 'tcp', 'quic', 'ws'])
        self.assertEqual(seen, [('myudp', 7000), ('tcp', 7001), ('quic', 7002), ('ws', 7003)])


if __name__ == '__main__':
    unittest.main()
