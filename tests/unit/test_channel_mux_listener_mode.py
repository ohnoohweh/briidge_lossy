#!/usr/bin/env python3
import argparse
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from obstacle_bridge.bridge import ChannelMux


class _FakeSession:
    def __init__(self, *, connected=False, max_app_payload_size=65535):
        self.app_cb = None
        self.peer_disconnect_cb = None
        self.sent = []
        self.connected = connected
        self.max_app_payload_size = max_app_payload_size

    def is_connected(self):
        return self.connected

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def set_on_peer_disconnect(self, cb):
        self.peer_disconnect_cb = cb

    def send_app(self, payload):
        self.sent.append(payload)
        return len(payload)

    def get_max_app_payload_size(self):
        return self.max_app_payload_size


class ChannelMuxListenerModeTests(unittest.TestCase):
    def test_select_hook_argv_uses_list_directly(self):
        selected = ChannelMux._select_hook_argv({"argv": ["cmd", "arg1"]}, platform_key="linux")
        self.assertEqual(selected, ["cmd", "arg1"])

    def test_select_hook_argv_uses_platform_specific_mapping(self):
        cmd = {
            "argv": {
                "linux": ["ip", "route", "add", "{target_host}/32", "dev", "{ifname}"],
                "windows": ["route", "ADD", "{target_host}", "MASK", "255.255.255.255", "{ifname}"],
                "default": ["echo", "fallback"],
            }
        }
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="linux"),
            ["ip", "route", "add", "{target_host}/32", "dev", "{ifname}"],
        )
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="windows"),
            ["route", "ADD", "{target_host}", "MASK", "255.255.255.255", "{ifname}"],
        )
        self.assertEqual(
            ChannelMux._select_hook_argv(cmd, platform_key="freebsd"),
            ["echo", "fallback"],
        )

    def test_select_hook_argv_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "argv list"):
            ChannelMux._select_hook_argv({"argv": "bad"}, platform_key="linux")

    def test_resolve_hook_argv_resolves_relative_executable_against_base_dir(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            mux._hook_base_dir = "/opt/obbridge"
            self.assertEqual(
                mux._resolve_hook_argv(["./scripts/server-tun-hook.sh", "up", "obtun1"]),
                ["/opt/obbridge/scripts/server-tun-hook.sh", "up", "obtun1"],
            )
            self.assertEqual(
                mux._resolve_hook_argv(["ip", "link", "show"]),
                ["ip", "link", "show"],
            )
        finally:
            mux.loop.close()

    def test_render_hook_value_replaces_known_placeholders(self):
        rendered = ChannelMux._render_hook_value(
            "route add {target_host} dev {ifname} svc={service_id}",
            {"target_host": "198.18.30.2", "ifname": "obtun0", "service_id": 3},
        )
        self.assertEqual(rendered, "route add 198.18.30.2 dev obtun0 svc=3")

    def test_hook_context_exposes_resolved_overlay_peer(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        loop = asyncio.new_event_loop()
        mux = ChannelMux.from_args(_FakeSession(), loop, args)
        try:
            spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1400, "tun", "obtun1", 1400)
            context = mux._hook_context(spec, ("local", 0, 3), "on_created", "listener")

            self.assertEqual(context["overlay_transport"], "myudp")
            self.assertEqual(context["overlay_peer_name"], "127.0.0.1")
            self.assertEqual(context["overlay_peer_host"], "127.0.0.1")
            self.assertEqual(context["overlay_peer_port"], 4433)
            self.assertEqual(
                ChannelMux._render_hook_value("{overlay_peer_host}:{overlay_peer_port}", context),
                "127.0.0.1:4433",
            )
        finally:
            mux.loop.close()

    def test_open_payload_roundtrip_preserves_hook_metadata(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=7,
                l_proto='tcp',
                l_bind='0.0.0.0',
                l_port=18080,
                r_proto='tcp',
                r_host='127.0.0.1',
                r_port=8080,
                name='web-service',
                lifecycle_hooks={'client': {'on_connected': {'argv': ['echo', 'ok']}}},
                options={'note': 'metadata'},
            )
            payload = mux._build_open_v4(spec)
            parsed = mux._parse_open_with_meta(payload)
            self.assertIsNotNone(parsed)
            assert parsed is not None
            self.assertEqual(parsed[2], 7)
            self.assertEqual(parsed[9], 'web-service')
            self.assertEqual(parsed[10], {'client': {'on_connected': {'argv': ['echo', 'ok']}}})
            self.assertEqual(parsed[11], {'note': 'metadata'})
        finally:
            mux.loop.close()

    def test_remote_services_roundtrip_preserves_hook_metadata(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=3,
                l_proto='udp',
                l_bind='0.0.0.0',
                l_port=16667,
                r_proto='udp',
                r_host='127.0.0.1',
                r_port=16666,
                name='udp-publish',
                lifecycle_hooks={'listener': {'on_created': {'argv': ['echo', 'created']}}},
                options={'tag': 'alpha'},
            )
            payload = mux._encode_remote_services_set_v2([spec])
            decoded = mux._decode_remote_services_set_v2(payload)
            self.assertIsNotNone(decoded)
            assert decoded is not None
            _iid, _seq, services = decoded
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].name, 'udp-publish')
            self.assertEqual(services[0].lifecycle_hooks, {'listener': {'on_created': {'argv': ['echo', 'created']}}})
            self.assertEqual(services[0].options, {'tag': 'alpha'})
        finally:
            mux.loop.close()

    def test_chunked_remote_services_transfer_reassembles_metadata(self):
        session = _FakeSession(connected=True, max_app_payload_size=96)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=5,
                l_proto='udp',
                l_bind='0.0.0.0',
                l_port=26667,
                r_proto='udp',
                r_host='127.0.0.1',
                r_port=26666,
                name='chunked-remote',
                lifecycle_hooks={'listener': {'on_channel_connected': {'argv': ['echo', 'x' * 220]}}},
                options={'meta': 'y' * 220},
            )
            mux._remote_services_requested = [spec]
            mux._send_remote_services_catalog_if_any()
            self.assertGreater(len(session.sent), 1)
            chunk_frames = []
            for wire in session.sent:
                parsed = mux._unpack_mux(wire)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                _chan, proto, _ctr, mtype, payload_mv = parsed
                self.assertEqual(proto, ChannelMux.Proto.UDP)
                if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK:
                    chunk_frames.append(bytes(payload_mv))
            self.assertGreaterEqual(len(chunk_frames), 2)

            assembled = None
            for chunk in chunk_frames:
                assembled = mux._consume_control_chunk(
                    chan_id=0,
                    proto=ChannelMux.Proto.UDP,
                    mtype=ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
                    payload=chunk,
                    peer_id=99,
                ) or assembled
            self.assertIsNotNone(assembled)
            decoded = mux._decode_remote_services_set_v2(assembled or b"")
            self.assertIsNotNone(decoded)
            assert decoded is not None
            _iid, _seq, services = decoded
            self.assertEqual(services[0].name, 'chunked-remote')
            self.assertIsInstance(services[0].lifecycle_hooks, dict)
            self.assertIsInstance(services[0].options, dict)
        finally:
            mux.loop.close()

    def test_chunked_open_transfer_reassembles_metadata(self):
        session = _FakeSession(connected=True, max_app_payload_size=96)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=11,
                l_proto='tcp',
                l_bind='0.0.0.0',
                l_port=31000,
                r_proto='tcp',
                r_host='127.0.0.1',
                r_port=32000,
                name='chunked-open',
                lifecycle_hooks={'client': {'before_connect': {'argv': ['echo', 'z' * 220]}}},
                options={'description': 'q' * 220},
            )
            mux._send_open_for_service(17, ChannelMux.Proto.TCP, spec)
            self.assertGreater(len(session.sent), 1)
            chunk_frames = []
            for wire in session.sent:
                parsed = mux._unpack_mux(wire)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                chan, proto, _ctr, mtype, payload_mv = parsed
                self.assertEqual(chan, 17)
                self.assertEqual(proto, ChannelMux.Proto.TCP)
                if mtype == ChannelMux.MType.OPEN_CHUNK:
                    chunk_frames.append(bytes(payload_mv))
            self.assertGreaterEqual(len(chunk_frames), 2)

            assembled = None
            for chunk in chunk_frames:
                assembled = mux._consume_control_chunk(
                    chan_id=17,
                    proto=ChannelMux.Proto.TCP,
                    mtype=ChannelMux.MType.OPEN_CHUNK,
                    payload=chunk,
                    peer_id=7,
                ) or assembled
            self.assertIsNotNone(assembled)
            parsed_open = mux._parse_open_with_meta(assembled or b"")
            self.assertIsNotNone(parsed_open)
            assert parsed_open is not None
            self.assertEqual(parsed_open[9], 'chunked-open')
            self.assertIsInstance(parsed_open[10], dict)
            self.assertIsInstance(parsed_open[11], dict)
        finally:
            mux.loop.close()

    def test_listener_mode_ignores_own_servers_and_remote_servers(self):
        args = argparse.Namespace(
            peer=None,
            udp_peer=None,
            tcp_peer=None,
            ws_peer=None,
            quic_peer=None,
            overlay_transport='myudp',
            own_servers=[{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
            }],
            remote_servers=[{
                'listen': {'protocol': 'tcp', 'bind': '0.0.0.0', 'port': 3129},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 3128},
            }],
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
            own_servers=[{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
            }],
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

    def test_parse_remote_servers_accepts_json_string_specs(self):
        specs = [
            '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}',
            '{"listen":{"protocol":"tcp","bind":"::","port":3129},"target":{"protocol":"tcp","host":"::1","port":3128}}',
            '{"listen":{"protocol":"tun","ifname":"obtun0","mtu":1500},"target":{"protocol":"tun","ifname":"obtun1","mtu":1500}}',
        ]

        parsed = ChannelMux._parse_remote_servers(specs)

        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0].svc_id, 1)
        self.assertEqual(parsed[0].l_proto, 'udp')
        self.assertEqual(parsed[1].svc_id, 2)
        self.assertEqual(parsed[1].l_proto, 'tcp')
        self.assertEqual(parsed[1].r_host, '::1')
        self.assertEqual(parsed[2].svc_id, 3)
        self.assertEqual(parsed[2].l_proto, 'tun')
        self.assertEqual(parsed[2].l_bind, 'obtun0')
        self.assertEqual(parsed[2].r_host, 'obtun1')

    def test_parse_remote_servers_accepts_structured_specs(self):
        specs = [
            {
                'name': 'public-http',
                'listen': {'protocol': 'tcp', 'bind': '0.0.0.0', 'port': 80},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 8080},
                'lifecycle_hooks': {
                    'listener': {
                        'on_created': {'argv': ['hook.cmd', 'created']},
                    }
                },
                'options': {'note': 'reserved'},
            },
            {
                'listen': {'protocol': 'tun', 'ifname': 'obtun0', 'mtu': 1400},
                'target': {'protocol': 'tun', 'ifname': 'obtun1', 'mtu': 1400},
            },
        ]

        parsed = ChannelMux._parse_remote_servers(specs)

        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].name, 'public-http')
        self.assertEqual(parsed[0].l_proto, 'tcp')
        self.assertEqual(parsed[0].l_bind, '0.0.0.0')
        self.assertEqual(parsed[0].l_port, 80)
        self.assertEqual(parsed[0].r_host, '127.0.0.1')
        self.assertEqual(parsed[0].r_port, 8080)
        self.assertEqual(parsed[0].lifecycle_hooks['listener']['on_created']['argv'], ['hook.cmd', 'created'])
        self.assertEqual(parsed[0].options['note'], 'reserved')
        self.assertEqual(parsed[1].l_proto, 'tun')
        self.assertEqual(parsed[1].l_bind, 'obtun0')
        self.assertEqual(parsed[1].l_port, 1400)
        self.assertEqual(parsed[1].r_host, 'obtun1')
        self.assertEqual(parsed[1].r_port, 1400)

    def test_parse_remote_servers_rejects_invalid_specs(self):
        with self.assertRaisesRegex(ValueError, '--remote-servers listen protocol must be udp, tcp or tun'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"icmp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'
            ])

        with self.assertRaisesRegex(ValueError, '--remote-servers listen port must be an integer in 1..65535'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":0},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'
            ])

        with self.assertRaisesRegex(ValueError, '--remote-servers target port must be an integer in 1..65535'):
            ChannelMux._parse_remote_servers([
                '{"listen":{"protocol":"udp","bind":"0.0.0.0","port":16667},"target":{"protocol":"udp","host":"127.0.0.1","port":"bad"}}'
            ])

        with self.assertRaisesRegex(ValueError, 'JSON value must be a service object or array of service objects'):
            ChannelMux._parse_remote_servers(['123'])

    def test_parse_remote_servers_rejects_invalid_structured_specs(self):
        with self.assertRaisesRegex(ValueError, 'requires object field listen'):
            ChannelMux._parse_remote_servers([{'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 80}}])

        with self.assertRaisesRegex(ValueError, 'structured tcp listen requires bind'):
            ChannelMux._parse_remote_servers([{
                'listen': {'protocol': 'tcp', 'port': 80},
                'target': {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 8080},
            }])

        with self.assertRaisesRegex(ValueError, 'lifecycle_hooks must be an object'):
            ChannelMux._parse_remote_servers([{
                'listen': {'protocol': 'udp', 'bind': '0.0.0.0', 'port': 16667},
                'target': {'protocol': 'udp', 'host': '127.0.0.1', 'port': 16666},
                'lifecycle_hooks': ['bad'],
            }])

    def test_parse_service_specs_treats_empty_config_entries_as_no_services(self):
        self.assertEqual(ChannelMux._parse_own_servers([None]), [])
        self.assertEqual(ChannelMux._parse_remote_servers([None, '  ']), [])


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
        self.assertEqual(mtype, ChannelMux.MType.REMOTE_SERVICES_SET_V2)
        self.assertEqual(self.mux._decode_remote_services_set_v2(payload)[2], [spec])

    async def test_receiver_starts_udp_and_tcp_listeners_from_remote_catalog(self):
        udp_spec = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        tcp_spec = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)
        tun_spec = ChannelMux.ServiceSpec(3, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
        payload = self.mux._encode_remote_services_set_v2([udp_spec, tcp_spec, tun_spec])
        frame = self.mux._pack_mux(0, ChannelMux.Proto.UDP, 0, ChannelMux.MType.REMOTE_SERVICES_SET_V2, payload)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp, patch.object(self.mux, '_start_tun_server_for', new=AsyncMock()) as start_tun:
            ok = self.mux.on_app_payload_from_peer(frame, peer_id=77)
            self.assertTrue(ok)
            await asyncio.sleep(0)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        start_tun.assert_awaited_once()
        self.assertIn(('peer', 77, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 77, 2), self.mux._peer_installed_services)
        self.assertIn(('peer', 77, 3), self.mux._peer_installed_services)

    async def test_tun_open_uses_pending_peer_listener_before_async_catalog_start(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook']}}},
        )
        catalog_payload = self.mux._encode_remote_services_set_v2([remote_tun])
        catalog_frame = self.mux._pack_mux(
            0,
            ChannelMux.Proto.UDP,
            0,
            ChannelMux.MType.REMOTE_SERVICES_SET_V2,
            catalog_payload,
        )
        local_tun = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
        open_payload = self.mux._build_open_v4(local_tun)
        svc_key = ('peer', 77, 2)

        def open_tun(ifname, mtu, svc_key=None):
            return ChannelMux.TunDevice(fd=44, ifname=ifname, mtu=mtu, service_key=svc_key)

        with patch.object(self.mux, '_apply_peer_installed_services', new=AsyncMock()) as apply_peer, \
             patch.object(self.mux, '_open_tun_device', side_effect=open_tun) as open_tun_device, \
             patch.object(self.mux, '_register_tun_reader') as register_reader, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            self.mux._rx_tun_open(1, open_payload, peer_id=77)
            await asyncio.sleep(0)

        apply_peer.assert_awaited_once()
        open_tun_device.assert_called_once_with('obtun1', 1500, svc_key=svc_key)
        register_reader.assert_called_once()
        self.assertIn(svc_key, self.mux._peer_installed_services)
        self.assertIs(self.mux._tun_by_chan[1], self.mux._svc_tun_devices[svc_key])
        schedule_hook.assert_any_call(remote_tun, svc_key, 'listener', 'on_created')

    async def test_remote_catalog_replacement_adds_and_removes_services(self):
        svc1 = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        svc2 = ChannelMux.ServiceSpec(2, 'tcp', '127.0.0.1', 10002, 'tcp', '127.0.0.1', 20002)

        with patch.object(self.mux, '_start_udp_server_for', new=AsyncMock()) as start_udp, patch.object(self.mux, '_start_tcp_server_for', new=AsyncMock()) as start_tcp, patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            await self.mux._apply_peer_installed_services([svc1], peer_id=7)
            await self.mux._apply_peer_installed_services([svc2], peer_id=7)

        start_udp.assert_awaited_once()
        start_tcp.assert_awaited_once()
        stop_listener.assert_awaited_once_with(('peer', 7, 1), 'udp', spec=svc1)
        self.assertNotIn(('peer', 7, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 7, 2), self.mux._peer_installed_services)

    async def test_per_peer_cleanup_on_disconnect(self):
        svc = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 10001, 'udp', '127.0.0.1', 20001)
        await self.mux._apply_peer_installed_services([svc], peer_id=11)
        await self.mux._apply_peer_installed_services([svc], peer_id=22)

        with patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            self.mux.on_peer_disconnected(11)
            await asyncio.sleep(0)

        stop_listener.assert_awaited_once_with(('peer', 11, 1), 'udp', spec=svc)
        self.assertNotIn(('peer', 11, 1), self.mux._peer_installed_services)
        self.assertIn(('peer', 22, 1), self.mux._peer_installed_services)

    async def test_peer_installed_tun_stop_runs_listener_on_stopped_before_close(self):
        svc_key = ('peer', 7, 1)
        spec = ChannelMux.ServiceSpec(
            1,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            lifecycle_hooks={'listener': {'on_stopped': {'argv': ['echo', 'down']}}},
        )
        dev = object()
        self.mux._peer_installed_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = dev

        with patch.object(self.mux, '_run_service_hook', new=AsyncMock()) as run_hook, patch.object(self.mux, '_close_tun_device') as close_tun:
            await self.mux._drop_peer_installed_services(peer_id=7)

        run_hook.assert_awaited_once_with(spec, svc_key, 'listener', 'on_stopped')
        close_tun.assert_called_once_with(dev)
        self.assertNotIn(svc_key, self.mux._peer_installed_services)
        self.assertNotIn(svc_key, self.mux._svc_tun_devices)


class ChannelMuxSessionBudgetTests(unittest.TestCase):
    def test_safe_tcp_read_uses_session_payload_budget(self):
        session = _FakeSession(max_app_payload_size=512)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            self.assertEqual(mux._SAFE_TCP_READ, 512 - ChannelMux.MUX_HDR.size)
        finally:
            mux.loop.close()

    def test_send_mux_drops_payloads_above_session_budget(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._send_mux(
                7,
                ChannelMux.Proto.UDP,
                ChannelMux.MType.REMOTE_SERVICES_SET_V2,
                b"x" * (32 - ChannelMux.MUX_HDR.size + 1),
            )
            self.assertEqual(session.sent, [])
        finally:
            mux.loop.close()

    def test_send_mux_fragments_oversized_udp_data(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b"abcdefghijklmnopqrstuvwxyz"
            mux._send_mux(7, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, payload)

            self.assertGreater(len(session.sent), 1)
            rebuilt = bytearray()
            seen_datagram_ids = set()
            for frame in session.sent:
                parsed = mux._unpack_mux(frame)
                self.assertIsNotNone(parsed)
                chan_id, proto, _counter, mtype, payload_mv = parsed
                self.assertEqual(chan_id, 7)
                self.assertEqual(proto, ChannelMux.Proto.UDP)
                self.assertEqual(mtype, ChannelMux.MType.DATA_FRAG)
                frag = bytes(payload_mv)
                datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(frag[:ChannelMux.UDP_FRAG_HDR.size])
                seen_datagram_ids.add(datagram_id)
                chunk = frag[ChannelMux.UDP_FRAG_HDR.size:]
                self.assertEqual(total_len, len(payload))
                self.assertLessEqual(len(frame), session.max_app_payload_size)
                self.assertEqual(offset, len(rebuilt))
                rebuilt.extend(chunk)

            self.assertEqual(seen_datagram_ids.__len__(), 1)
            self.assertEqual(bytes(rebuilt), payload)
        finally:
            mux.loop.close()

    def test_reassembles_udp_fragments_before_local_delivery(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b"fragmented-udp-datagram"
            datagram_id = 41
            fragment_size = 5
            with patch.object(mux, '_rx_udp_data') as rx_udp_data:
                for offset in range(0, len(payload), fragment_size):
                    frag_payload = ChannelMux.UDP_FRAG_HDR.pack(
                        datagram_id,
                        len(payload),
                        offset,
                    ) + payload[offset:offset + fragment_size]
                    frame = mux._pack_mux(
                        11,
                        ChannelMux.Proto.UDP,
                        offset // fragment_size,
                        ChannelMux.MType.DATA_FRAG,
                        frag_payload,
                    )
                    mux.on_app_payload_from_peer(frame)

                rx_udp_data.assert_called_once_with(11, payload)
        finally:
            mux.loop.close()

    def test_drops_udp_fragments_above_service_datagram_cap(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._udp_service_datagram_cap = 8
            with patch.object(mux, '_rx_udp_data') as rx_udp_data:
                frag_payload = ChannelMux.UDP_FRAG_HDR.pack(7, 16, 0) + b'abcdefgh'
                frame = mux._pack_mux(
                    3,
                    ChannelMux.Proto.UDP,
                    0,
                    ChannelMux.MType.DATA_FRAG,
                    frag_payload,
                )
                mux.on_app_payload_from_peer(frame)
                rx_udp_data.assert_not_called()
        finally:
            mux.loop.close()

    def test_drops_local_udp_datagram_above_service_datagram_cap(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._udp_service_datagram_cap = 4
            spec = ChannelMux.ServiceSpec(1, 'udp', '127.0.0.1', 20001, 'udp', '127.0.0.1', 20002)
            svc_key = ('local', 0, 1)
            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_udp_datagram(spec, svc_key, b'abcdef', ('127.0.0.1', 32000))
                send_mux.assert_not_called()
        finally:
            mux.loop.close()

    def test_local_tun_packet_opens_channel_and_sends_data(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev

            mux._on_local_tun_packet(dev, b'\x45hello')

            self.assertEqual(len(session.sent), 2)
            first = mux._unpack_mux(session.sent[0])
            second = mux._unpack_mux(session.sent[1])
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertEqual(first[1], ChannelMux.Proto.TUN)
            self.assertEqual(first[3], ChannelMux.MType.OPEN)
            self.assertEqual(second[1], ChannelMux.Proto.TUN)
            self.assertEqual(second[3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(second[4]), b'\x45hello')
            self.assertIsNotNone(dev.chan_id)
        finally:
            mux.loop.close()

    def test_tun_device_keeps_symmetric_channel_aliases_routable(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            svc_key = ('local', 0, 5)
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)

            mux._bind_tun_channel(2, dev)
            mux._bind_tun_channel(1, dev)

            self.assertIs(mux._tun_by_chan[2], dev)
            self.assertIs(mux._tun_by_chan[1], dev)
            self.assertEqual(dev.chan_id, 2)
            self.assertEqual(mux._tun_chan_by_service[svc_key], 2)
        finally:
            mux.loop.close()

    def test_send_mux_fragments_oversized_tun_packet(self):
        session = _FakeSession(connected=True, max_app_payload_size=32)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            payload = b'abcdefghijklmnopqrstuvwxyz'
            mux._send_mux(9, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, payload)

            self.assertGreater(len(session.sent), 1)
            rebuilt = bytearray()
            for frame in session.sent:
                parsed = mux._unpack_mux(frame)
                self.assertIsNotNone(parsed)
                chan_id, proto, _counter, mtype, payload_mv = parsed
                self.assertEqual(chan_id, 9)
                self.assertEqual(proto, ChannelMux.Proto.TUN)
                self.assertEqual(mtype, ChannelMux.MType.DATA_FRAG)
                frag = bytes(payload_mv)
                _datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(frag[:ChannelMux.UDP_FRAG_HDR.size])
                chunk = frag[ChannelMux.UDP_FRAG_HDR.size:]
                self.assertEqual(total_len, len(payload))
                self.assertEqual(offset, len(rebuilt))
                rebuilt.extend(chunk)
            self.assertEqual(bytes(rebuilt), payload)
        finally:
            mux.loop.close()

    def test_reassembles_tun_fragments_before_device_write(self):
        session = _FakeSession()
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._tun_by_chan[12] = ChannelMux.TunDevice(fd=44, ifname='obtun0', mtu=64)
            payload = b'fragmented-tun-packet'
            with patch('obstacle_bridge.bridge.os.write') as os_write:
                for offset in range(0, len(payload), 5):
                    frag_payload = ChannelMux.UDP_FRAG_HDR.pack(31, len(payload), offset) + payload[offset:offset + 5]
                    frame = mux._pack_mux(12, ChannelMux.Proto.TUN, offset // 5, ChannelMux.MType.DATA_FRAG, frag_payload)
                    mux.on_app_payload_from_peer(frame)
                os_write.assert_called_once_with(44, payload)
        finally:
            mux.loop.close()


if __name__ == '__main__':
    unittest.main()
