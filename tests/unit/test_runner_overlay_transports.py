#!/usr/bin/env python3
import argparse
import pathlib
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner, TcpStreamSession, UdpSession, QuicSession, WebSocketSession, SecureLinkPskSession

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "secure_link_cert"


def _args(**overrides):
    base = dict(
        overlay_transport='myudp',
        udp_own_port=4433,
        udp_peer=None,
        tcp_own_port=8081,
        quic_own_port=443,
        ws_own_port=8080,
        overlay_port_myudp=None,
        overlay_port_tcp=None,
        overlay_port_quic=None,
        overlay_port_ws=None,
        secure_link=False,
        secure_link_mode='off',
        secure_link_psk='',
        secure_link_require=False,
        secure_link_rekey_after_frames=0,
        secure_link_root_pub='',
        secure_link_cert_body='',
        secure_link_cert_sig='',
        secure_link_private_key='',
        secure_link_revoked_serials='',
        secure_link_cert_reload_on_restart=True,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class RunnerOverlayTransportTests(unittest.TestCase):
    def test_request_secure_link_rekey_targets_matching_peer_id_only(self):
        class _Session:
            def __init__(self, peer_ids):
                self._peer_ids = peer_ids
                self.requests = 0

            def get_overlay_peers_snapshot(self):
                return [{"peer_id": peer_id} for peer_id in self._peer_ids]

            def request_secure_link_rekey(self):
                self.requests += 1
                return (True, "rekey_started")

        runner = Runner.__new__(Runner)
        runner._sessions = [_Session([1]), _Session([2])]
        runner._session_labels = ["tcp", "ws"]

        payload = Runner.request_secure_link_rekey(runner, target_peer_id="1:2")

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["target_peer_id"], "1:2")
        self.assertEqual(payload["requested"], 1)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(runner._sessions[0].requests, 0)
        self.assertEqual(runner._sessions[1].requests, 1)
        self.assertEqual(payload["results"][0]["peer_ids"], ["1:2"])

    def test_request_secure_link_rekey_rejects_unknown_peer_id(self):
        class _Session:
            def get_overlay_peers_snapshot(self):
                return [{"peer_id": 1}]

            def request_secure_link_rekey(self):
                raise AssertionError("should not be called for unknown peer")

        runner = Runner.__new__(Runner)
        runner._sessions = [_Session()]
        runner._session_labels = ["tcp"]

        payload = Runner.request_secure_link_rekey(runner, target_peer_id="0:99")

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["target_peer_id"], "0:99")
        self.assertEqual(payload["requested"], 0)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["error"], "unknown peer_id")

    def test_request_secure_link_reload_targets_matching_peer_id_only(self):
        class _Session:
            def __init__(self, peer_ids):
                self._peer_ids = peer_ids
                self.requests = []

            def get_overlay_peers_snapshot(self):
                return [{"peer_id": peer_id} for peer_id in self._peer_ids]

            def request_secure_link_reload(self, *, scope, target_peer_id=None):
                self.requests.append((scope, target_peer_id))
                return {"ok": True, "scope": scope, "dropped": 1}

        runner = Runner.__new__(Runner)
        runner._sessions = [_Session([1]), _Session([2])]
        runner._session_labels = ["tcp", "ws"]

        payload = Runner.request_secure_link_reload(runner, scope="revocation", target_peer_id="1:2")

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["target_peer_id"], "1:2")
        self.assertEqual(payload["requested"], 1)
        self.assertEqual(payload["reloaded"], 1)
        self.assertEqual(payload["dropped"], 1)
        self.assertEqual(payload["failed"], 0)
        self.assertEqual(runner._sessions[0].requests, [])
        self.assertEqual(runner._sessions[1].requests, [("revocation", "1:2")])

    def test_request_secure_link_reload_rejects_unknown_peer_id(self):
        class _Session:
            def get_overlay_peers_snapshot(self):
                return [{"peer_id": 1}]

            def request_secure_link_reload(self, *, scope, target_peer_id=None):
                raise AssertionError("should not be called for unknown peer")

        runner = Runner.__new__(Runner)
        runner._sessions = [_Session()]
        runner._session_labels = ["tcp"]

        payload = Runner.request_secure_link_reload(runner, scope="all", target_peer_id="0:99")

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["target_peer_id"], "0:99")
        self.assertEqual(payload["requested"], 0)
        self.assertEqual(payload["reloaded"], 0)
        self.assertEqual(payload["dropped"], 0)
        self.assertEqual(payload["failed"], 0)
        self.assertEqual(payload["reason"], "unknown_peer_id")

    def test_parse_overlay_transports_accepts_comma_separated_values(self):
        args = _args(overlay_transport='myudp, tcp,quic,ws')
        self.assertEqual(Runner._parse_overlay_transports(args), ['myudp', 'tcp', 'quic', 'ws'])

    def test_parse_overlay_transports_rejects_multi_transport_clients(self):
        args = _args(overlay_transport='myudp,ws', udp_peer='127.0.0.1')
        with self.assertRaises(ValueError):
            Runner._parse_overlay_transports(args)

    def test_overlay_port_for_uses_transport_port(self):
        args = _args(udp_own_port=9000)
        self.assertEqual(Runner._overlay_port_for(args, 'myudp', 4), 9000)
        self.assertEqual(Runner._overlay_port_for(args, 'tcp', 4), 8081)
        self.assertEqual(Runner._overlay_port_for(args, 'quic', 4), 443)
        self.assertEqual(Runner._overlay_port_for(args, 'ws', 4), 8080)

    def test_build_sessions_from_overlay_uses_per_transport_ports(self):
        args = _args(overlay_transport='myudp,tcp,quic,ws', udp_own_port=7000, tcp_own_port=7000, quic_own_port=7000, ws_own_port=7000)
        seen = []

        def _factory(name):
            def _inner(ns):
                port = ns.udp_own_port if name == 'myudp' else ns.tcp_own_port if name == 'tcp' else ns.quic_own_port if name == 'quic' else ns.ws_own_port
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
            [7000, 7000, 7000, 7000],
        )

    def test_build_sessions_from_overlay_wraps_supported_transports_with_secure_link_psk(self):
        cases = [
            ('myudp', 'udp_peer', UdpSession, '127.0.0.1'),
            ('tcp', 'tcp_peer', TcpStreamSession, '127.0.0.1'),
            ('quic', 'quic_peer', QuicSession, '127.0.0.1'),
            ('ws', 'ws_peer', WebSocketSession, '127.0.0.1'),
        ]
        for overlay_transport, peer_attr, cls, peer_value in cases:
            with self.subTest(overlay_transport=overlay_transport):
                args = _args(
                    overlay_transport=overlay_transport,
                    secure_link=True,
                    secure_link_mode='psk',
                    secure_link_psk='lab-secret',
                    **{peer_attr: peer_value},
                )
                with mock.patch.object(cls, 'from_args', return_value=mock.Mock(spec=cls)) as factory:
                    sessions = Runner.build_sessions_from_overlay(args)
                self.assertEqual([name for name, _ in sessions], [overlay_transport])
                self.assertIsInstance(sessions[0][1], SecureLinkPskSession)
                factory.assert_called_once()

    def test_build_sessions_from_overlay_wraps_supported_transports_with_secure_link_cert(self):
        cases = [
            ('myudp', 'udp_peer', UdpSession, '127.0.0.1'),
            ('tcp', 'tcp_peer', TcpStreamSession, '127.0.0.1'),
            ('quic', 'quic_peer', QuicSession, '127.0.0.1'),
            ('ws', 'ws_peer', WebSocketSession, '127.0.0.1'),
        ]
        for overlay_transport, peer_attr, cls, peer_value in cases:
            with self.subTest(overlay_transport=overlay_transport):
                args = _args(
                    overlay_transport=overlay_transport,
                    secure_link=True,
                    secure_link_mode='cert',
                    secure_link_root_pub=str(FIXTURES / 'root_a_pub.pem'),
                    secure_link_cert_body=str(FIXTURES / 'client_valid_cert_body.json'),
                    secure_link_cert_sig=str(FIXTURES / 'client_valid_cert.sig'),
                    secure_link_private_key=str(FIXTURES / 'client_valid_key.pem'),
                    **{peer_attr: peer_value},
                )
                with mock.patch.object(cls, 'from_args', return_value=mock.Mock(spec=cls)) as factory:
                    sessions = Runner.build_sessions_from_overlay(args)
                self.assertEqual([name for name, _ in sessions], [overlay_transport])
                self.assertIsInstance(sessions[0][1], SecureLinkPskSession)
                factory.assert_called_once()

    def test_build_sessions_from_overlay_rejects_missing_cert_material(self):
        args = _args(
            overlay_transport='tcp',
            secure_link=True,
            secure_link_mode='cert',
            tcp_peer='127.0.0.1',
            secure_link_root_pub=str(FIXTURES / 'root_a_pub.pem'),
            secure_link_cert_body='',
            secure_link_cert_sig=str(FIXTURES / 'client_valid_cert.sig'),
            secure_link_private_key=str(FIXTURES / 'client_valid_key.pem'),
        )
        with mock.patch.object(TcpStreamSession, 'from_args', return_value=mock.Mock(spec=TcpStreamSession)):
            with self.assertRaises(ValueError):
                Runner.build_sessions_from_overlay(args)


if __name__ == '__main__':
    unittest.main()
