#!/usr/bin/env python3
import argparse
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from obstacle_bridge.bridge import ChannelMux


class _FakeSession:
    def __init__(self):
        self.app_cb = None
        self.peer_disconnect_cb = None
        self.sent = []

    def is_connected(self):
        return False

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def set_on_peer_disconnect(self, cb):
        self.peer_disconnect_cb = cb

    def send_app(self, payload):
        self.sent.append(payload)
        return len(payload)


class ChannelMuxListenerModeTests(unittest.TestCase):
    def test_listener_mode_ignores_own_servers_and_remote_servers(self):
        args = argparse.Namespace(
            peer=None,
            udp_peer=None,
            tcp_peer=None,
            ws_peer=None,
            quic_peer=None,
            overlay_transport='myudp',
            own_servers=['udp,16667,0.0.0.0,udp,127.0.0.1,16666'],
            remote_servers=['tcp,3129,0.0.0.0,tcp,127.0.0.1,3128'],
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(mux._local_services, {})
            self.assertEqual(mux._remote_services_requested, [])
        finally:
            mux.loop.close()

    def test_client_mode_keeps_own_servers(self):
        args = argparse.Namespace(
            peer='127.0.0.1',
            udp_peer='127.0.0.1',
            overlay_transport='myudp',
            own_servers=['udp,16667,0.0.0.0,udp,127.0.0.1,16666'],
            remote_servers=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(len(mux._local_services), 1)
            spec = mux._local_services[('local', 0, 1)]
            self.assertEqual(spec.l_proto, 'udp')
            self.assertEqual(spec.l_port, 16667)
            self.assertEqual(spec.r_proto, 'udp')
            self.assertEqual(spec.r_host, '127.0.0.1')
            self.assertEqual(spec.r_port, 16666)
        finally:
            mux.loop.close()

    def test_parse_remote_servers_accepts_valid_specs(self):
        specs = [
            'udp,16667,0.0.0.0,udp,127.0.0.1,16666',
            'tcp,3129,::,tcp,::1,3128',
        ]

        parsed = ChannelMux._parse_remote_servers(specs)

        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].svc_id, 1)
        self.assertEqual(parsed[0].l_proto, 'udp')
        self.assertEqual(parsed[1].svc_id, 2)
        self.assertEqual(parsed[1].l_proto, 'tcp')
        self.assertEqual(parsed[1].r_host, '::1')

    def test_parse_remote_servers_rejects_invalid_specs(self):
        with self.assertRaisesRegex(ValueError, '--remote-servers item must have 6 comma-separated fields'):
            ChannelMux._parse_remote_servers(['udp,16667,0.0.0.0,udp,127.0.0.1'])

        with self.assertRaisesRegex(ValueError, '--remote-servers local protocol must be udp or tcp'):
            ChannelMux._parse_remote_servers(['icmp,16667,0.0.0.0,udp,127.0.0.1,16666'])

        with self.assertRaisesRegex(ValueError, '--remote-servers ports must be integers in 1..65535'):
            ChannelMux._parse_remote_servers(['udp,0,0.0.0.0,udp,127.0.0.1,16666'])


class ChannelMuxRemoteCatalogTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session = _FakeSession()
        self.mux = ChannelMux(self.session, asyncio.get_running_loop())
        self.mux._overlay_connected = True
        self.mux._accepting_enabled = True

    async def test_sends_control_install_when_overlay_connects(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=1,
            l_proto='udp',
            l_bind='0.0.0.0',
            l_port=16667,
            r_proto='udp',
            r_host='127.0.0.1',
            r_port=16666,
        )
        self.mux._remote_services_requested = [spec]
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, patch.object(self.mux, '_send_mux') as send_mux:
            await self.mux.on_overlay_state(True)

        start_all.assert_awaited_once()
        send_mux.assert_called_once()
        chan, proto, mtype, payload = send_mux.call_args.args
        self.assertEqual(chan, 0)
        self.assertEqual(proto, ChannelMux.Proto.UDP)
        self.assertEqual(mtype, ChannelMux.MType.REMOTE_SERVICES_SET_V1)
        self.assertEqual(self.mux._decode_remote_services_set_v1(payload), [spec])

    async def test_receiver_starts_udp_and_tcp_listeners_from_remote_catalog(self):
        udp_spec = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        tcp_spec = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)
        payload = self.mux._encode_remote_services_set_v1([udp_spec, tcp_spec])
        frame = self.mux._pack_mux(0, ChannelMux.Proto.UDP, 0, ChannelMux.MType.REMOTE_SERVICES_SET_V1, payload)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp:
            ok = self.mux.on_app_payload_from_peer(frame, peer_id=77)
            self.assertTrue(ok)
            await asyncio.sleep(0)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        self.assertIn(('peer', 77, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 77, 2), self.mux._peer_installed_services)

    async def test_remote_catalog_replacement_adds_and_removes_services(self):
        svc1 = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        svc2 = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp, patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            await self.mux._apply_peer_installed_services([svc1], peer_id=7)
            await self.mux._apply_peer_installed_services([svc2], peer_id=7)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        stop_listener.assert_awaited_once_with(('peer', 7, 1), 'udp')
        self.assertNotIn(('peer', 7, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 7, 2), self.mux._peer_installed_services)

    async def test_per_peer_cleanup_on_disconnect(self):
        svc = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        await self.mux._apply_peer_installed_services([svc], peer_id=11)
        await self.mux._apply_peer_installed_services([svc], peer_id=22)

        with patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            self.mux.on_peer_disconnected(11)
            await asyncio.sleep(0)

        stop_listener.assert_awaited_once_with(('peer', 11, 1), 'udp')
        self.assertNotIn(('peer', 11, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 22, 1), self.mux._peer_installed_services)


if __name__ == '__main__':
    unittest.main()
