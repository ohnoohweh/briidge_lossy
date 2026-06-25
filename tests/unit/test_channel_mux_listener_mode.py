#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import unittest
from unittest.mock import AsyncMock, patch

from obstacle_bridge.bridge import ChannelMux, ProcessSharedTunRegistry, SessionMetrics
from obstacle_bridge.bridge_tun_routing import TunRoutingSettings


class _FakeSession:
    def __init__(
        self,
        *,
        connected=False,
        max_app_payload_size=65535,
        transmit_delay_est_ms=None,
        waiting_count=0,
        inflight=0,
        max_inflight=0,
        last_rtt_ok_ns=None,
        last_rx_ns=None,
        egress_prev_window_bytes=0,
        egress_curr_window_bytes=0,
    ):
        self.app_cb = None
        self.peer_disconnect_cb = None
        self.sent = []
        self.connected = connected
        self.max_app_payload_size = max_app_payload_size
        self._metrics = SessionMetrics(
            transmit_delay_est_ms=transmit_delay_est_ms,
            waiting_count=waiting_count,
            inflight=inflight,
            max_inflight=max_inflight,
            last_rtt_ok_ns=last_rtt_ok_ns,
            last_rx_ns=last_rx_ns,
            egress_prev_window_bytes=egress_prev_window_bytes,
            egress_curr_window_bytes=egress_curr_window_bytes,
        )

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

    def get_metrics(self):
        return self._metrics


class _FakeDatagramTransport:
    def __init__(self, *, sockname=("127.0.0.1", 30000), peername=("127.0.0.1", 16666)):
        self.sent = []
        self.sockname = sockname
        self.peername = peername
        self.closed = False

    def sendto(self, data, addr=None):
        self.sent.append((bytes(data), addr))

    def get_extra_info(self, name):
        if name == "sockname":
            return self.sockname
        if name == "peername":
            return self.peername
        return None

    def close(self):
        self.closed = True


def _ipv4_packet(src: str, dst: str, payload: bytes = b"x") -> bytes:
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed
    total_len = 20 + len(payload)
    header = bytes([
        0x45,
        0x00,
        (total_len >> 8) & 0xFF,
        total_len & 0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        64,
        1,
        0x00,
        0x00,
    ]) + src_b + dst_b
    return header + payload


def _ipv6_packet(src: str, dst: str, payload: bytes = b"x") -> bytes:
    src_b = ipaddress.IPv6Address(src).packed
    dst_b = ipaddress.IPv6Address(dst).packed
    payload_len = len(payload)
    header = bytes([
        0x60,
        0x00,
        0x00,
        0x00,
        (payload_len >> 8) & 0xFF,
        payload_len & 0xFF,
        58,
        64,
    ]) + src_b + dst_b
    return header + payload


class ChannelMuxListenerModeTests(unittest.TestCase):
    def test_unified_ingress_throttle_applies_to_udp_from_transport_metrics(self):
        now_ns = 5_000_000_000
        sess = _FakeSession(
            connected=True,
            waiting_count=3,
            inflight=200,
            max_inflight=200,
            last_rtt_ok_ns=now_ns,
            egress_prev_window_bytes=1000,
            egress_curr_window_bytes=0,
        )
        mux = ChannelMux(sess, argparse.Namespace(overlay_transport="myudp"))
        scope_key = ("udp", ("local", 1), 7)

        self.assertTrue(mux._local_ingress_send_allowed(800, now_ns=now_ns, scope_key=scope_key))
        mux._record_local_udp_forward(800, now_ns=now_ns, scope_key=scope_key)
        self.assertFalse(mux._local_ingress_send_allowed(101, now_ns=now_ns, scope_key=scope_key))

    def test_unified_ingress_stall_without_backpressure_does_not_block_udp(self):
        now_ns = 9_000_000_000
        sess = _FakeSession(
            connected=True,
            waiting_count=1,
            last_rtt_ok_ns=now_ns - (2 * ChannelMux.TUN_STREAM_OVERLAY_STALL_NS),
            egress_prev_window_bytes=1000,
        )
        mux = ChannelMux(sess, argparse.Namespace(overlay_transport="myudp"))

        self.assertTrue(
            mux._local_ingress_send_allowed(100, now_ns=now_ns, scope_key=("udp", "client", 9))
        )

    def test_unified_ingress_throttle_sums_udp_and_tun_against_shared_budget(self):
        now_ns = 7_000_000_000
        sess = _FakeSession(
            connected=True,
            waiting_count=2,
            inflight=200,
            max_inflight=200,
            last_rtt_ok_ns=now_ns,
            egress_prev_window_bytes=1000,
            egress_curr_window_bytes=0,
        )
        mux = ChannelMux(sess, argparse.Namespace(overlay_transport="myudp"))
        udp_scope = ("udp", ("local", 1), 7)
        tun_scope = ("direct", ("local", 0, 5))

        self.assertTrue(mux._local_ingress_send_allowed(500, now_ns=now_ns, scope_key=udp_scope))
        mux._record_local_udp_forward(500, now_ns=now_ns, scope_key=udp_scope)
        self.assertTrue(mux._local_ingress_send_allowed(400, now_ns=now_ns, scope_key=tun_scope))
        mux._record_local_tun_forward(400, now_ns=now_ns, scope_key=tun_scope)
        self.assertFalse(mux._local_ingress_send_allowed(1, now_ns=now_ns, scope_key=udp_scope))

    def test_tun_routing_defaults_match_bootstrap_shape(self):
        settings = TunRoutingSettings()
        self.assertEqual(settings.tunnel_address, "192.168.106.1")
        self.assertEqual(settings.tunnel_gateway, "192.168.106.2")
        self.assertEqual(settings.included_routes, ["0.0.0.0/0"])
        self.assertEqual(settings.excluded_routes, ["127.0.0.0/8"])
        self.assertEqual(settings.tunnel_address6, "fd20:106::1")
        self.assertEqual(settings.tunnel_gateway6, "fd20:106::2")
        self.assertEqual(settings.included_routes6, ["::/0"])
        self.assertEqual(settings.excluded_routes6, ["::1/128"])
        self.assertEqual(settings.dns_servers, ["1.1.1.1"])
        self.assertEqual(settings.mtu, 1600)
        self.assertEqual(settings.log_TUN_routing, "CRITICAL")
        self.assertFalse(settings.enable_tcpmss)
        self.assertFalse(settings.enable_tun_tcpdump)
        self.assertEqual(settings.tun_tcpdump_pcap_path, "")
        self.assertFalse(settings.shared_tun_disable_outgoing_normalization)
        self.assertFalse(settings.shared_tun_disable_inflow_filter)
        self.assertFalse(settings.shared_tun_disable_outflow_filter)
        self.assertFalse(settings.disable_channelmux_inflow_throttle)
        self.assertFalse(settings.shared_tun_disable_scoped_throttle)

    def test_tun_routing_diagnostic_switches_parse_from_mapping(self):
        settings = TunRoutingSettings.from_mapping(
            {
                "TUN_routing": {
                    "disable_channelmux_inflow_throttle": "yes",
                    "shared_tun_disable_outgoing_normalization": "true",
                    "shared_tun_disable_inflow_filter": True,
                    "shared_tun_disable_outflow_filter": "1",
                    "shared_tun_disable_scoped_throttle": "yes",
                    "enable_tcpmss": "true",
                    "enable_tun_tcpdump": "1",
                    "tun_tcpdump_pcap_path": "/tmp/shared-tun-test.pcap",
                }
            }
        )
        self.assertTrue(settings.enable_tcpmss)
        self.assertTrue(settings.enable_tun_tcpdump)
        self.assertEqual(settings.tun_tcpdump_pcap_path, "/tmp/shared-tun-test.pcap")
        self.assertTrue(settings.shared_tun_disable_outgoing_normalization)
        self.assertTrue(settings.shared_tun_disable_inflow_filter)
        self.assertTrue(settings.shared_tun_disable_outflow_filter)
        self.assertTrue(settings.disable_channelmux_inflow_throttle)
        self.assertTrue(settings.shared_tun_disable_scoped_throttle)

    def test_tun_routing_legacy_scoped_throttle_flag_enables_global_channelmux_disable(self):
        settings = TunRoutingSettings.from_mapping(
            {
                "TUN_routing": {
                    "shared_tun_disable_scoped_throttle": "yes",
                }
            }
        )
        self.assertTrue(settings.shared_tun_disable_scoped_throttle)
        self.assertTrue(settings.disable_channelmux_inflow_throttle)

    def test_tun_routing_explicit_empty_gateways_are_preserved(self):
        settings = TunRoutingSettings.from_mapping(
            {
                "TUN_routing": {
                    "tunnel_address": "192.168.106.1",
                    "tunnel_prefix": 24,
                    "tunnel_gateway": "",
                    "tunnel_address6": "fd20:106::1",
                    "tunnel_prefix6": 64,
                    "tunnel_gateway6": "",
                }
            }
        )
        self.assertEqual(settings.tunnel_gateway, "")
        self.assertEqual(settings.tunnel_gateway6, "")
        env = settings.local_hook_env()
        self.assertNotIn("TUN_GW", env)
        self.assertNotIn("PEER_ADDR", env)
        self.assertNotIn("TUN_GW6", env)
        self.assertNotIn("PEER_ADDR6", env)

    def test_shared_tun_disable_inflow_filter_allows_unowned_source(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            mux._tun_routing_settings = TunRoutingSettings(
                shared_tun_disable_inflow_filter=True,
            )
            svc_key = ("peer", 77, 2)
            dev = ChannelMux.TunDevice(fd=44, ifname="obtun1", mtu=1500, service_key=svc_key)
            mux._tun_by_chan[7] = dev
            mux._chan_owner_peer_id[7] = 77
            spec = ChannelMux.ServiceSpec(
                2,
                "tun",
                "obtun1",
                1500,
                "tun",
                "obtun0",
                1500,
                options={
                    "shared_tun_ownership": {
                        "mode": "server_shared",
                        "peers": [
                            {
                                "peer_ref": "linux-client",
                                "ipv4": ["192.168.107.2"],
                                "ipv6": ["fd20:107::2"],
                            }
                        ],
                    }
                },
            )
            mux._install_shared_tun_ownership_for_service(svc_key, spec)
            allowed, parsed, reason = mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=7,
                packet=_ipv4_packet("172.20.10.4", "192.168.107.1"),
            )
            self.assertTrue(allowed)
            self.assertEqual(parsed["source_ip"], "172.20.10.4")
            self.assertIsNone(reason)
        finally:
            mux.loop.close()

    def test_shared_tun_disable_outflow_filter_skips_shared_route_planning(self):
        mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            mux._tun_routing_settings = TunRoutingSettings(
                shared_tun_disable_outflow_filter=True,
            )
            svc_key = ("peer", 77, 2)
            mux._shared_tun_ownership_by_service[svc_key] = {
                "owner_by_ipv4": {"192.168.107.4": "ios-client"},
                "owner_by_ipv6": {},
            }
            route = mux._shared_tun_plan_local_delivery(
                svc_key,
                _ipv4_packet("192.168.107.1", "192.168.107.4"),
            )
            self.assertIsNone(route)
            relay = mux._shared_tun_plan_inbound_peer_relay(
                svc_key,
                77,
                _ipv4_packet("192.168.107.2", "192.168.107.4"),
            )
            self.assertIsNone(relay)
        finally:
            mux.loop.close()

    def test_shared_tun_disable_scoped_throttle_allows_buffered_send(self):
        mux = ChannelMux(_FakeSession(waiting_count=5), asyncio.new_event_loop())
        try:
            mux._tun_routing_settings = TunRoutingSettings(
                disable_channelmux_inflow_throttle=True,
            )
            self.assertTrue(
                mux._local_tun_send_allowed(
                    4096,
                    now_ns=1,
                    scope_key=("peer", 7),
                )
            )
        finally:
            mux.loop.close()

    def test_shared_tun_disable_scoped_throttle_does_not_bypass_backpressured_stream_stall_guard(self):
        session = _FakeSession(waiting_count=5, inflight=200, max_inflight=200)
        session._metrics.last_rtt_ok_ns = 1
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_transport = "ws"
            mux._tun_routing_settings = TunRoutingSettings(
                disable_channelmux_inflow_throttle=True,
            )
            self.assertFalse(
                mux._local_tun_send_allowed(
                    4096,
                    now_ns=ChannelMux.TUN_STREAM_OVERLAY_STALL_NS + 2,
                    scope_key=("peer", 7),
                )
            )
        finally:
            mux.loop.close()

    def test_stream_overlay_stalls_on_recent_rx_idle_without_waiting_count_signal(self):
        session = _FakeSession(waiting_count=0, inflight=200, max_inflight=200, transmit_delay_est_ms=60.0)
        session._metrics.last_rx_ns = 1
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_transport = "ws"
            self.assertFalse(
                mux._local_tun_send_allowed(
                    4096,
                    now_ns=600_000_000,
                    scope_key=("peer", 7),
                )
            )
        finally:
            mux.loop.close()

    def test_throttle_snapshot_reports_inactive_when_not_backpressured(self):
        now_ns = 7_000_000_000
        session = _FakeSession(
            connected=True,
            waiting_count=1,
            inflight=10,
            max_inflight=200,
            last_rtt_ok_ns=now_ns,
            egress_prev_window_bytes=2048,
        )
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            snapshot = mux._local_ingress_throttle_snapshot_for_scope(
                ("udp", ("local", 1), 7),
                now_ns=now_ns,
            )
            self.assertFalse(snapshot["active"])
            self.assertFalse(snapshot["stalled"])
            self.assertFalse(snapshot["backpressure_active"])
        finally:
            mux.loop.close()

    def test_shared_tun_service_snapshot_reports_inactive_when_not_backpressured(self):
        now_ns = 7_000_000_000
        session = _FakeSession(
            connected=True,
            waiting_count=1,
            inflight=10,
            max_inflight=200,
            last_rtt_ok_ns=now_ns,
            egress_prev_window_bytes=2048,
        )
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            svc_key = ("local", 0, 5)
            mux._shared_tun_runtime_by_peer[(svc_key, 7)] = {
                "preferred_chan_id": 1,
                "bound_chan_ids": {1},
                "throttle_prev_window_bytes": 2048,
                "throttle_curr_window_bytes": 512,
                "throttle_drop_count": 0,
            }
            snapshot = mux._local_ingress_throttle_snapshot_for_shared_tun_service(
                svc_key,
                now_ns=now_ns,
            )
            self.assertFalse(snapshot["active"])
            self.assertFalse(snapshot["stalled"])
            self.assertFalse(snapshot["backpressure_active"])
        finally:
            mux.loop.close()

    def test_shared_tun_disable_scoped_throttle_does_not_bypass_stream_backpressure(self):
        session = _FakeSession(waiting_count=1, inflight=200, max_inflight=200)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_transport = "ws"
            mux._tun_routing_settings = TunRoutingSettings(
                disable_channelmux_inflow_throttle=True,
            )
            self.assertFalse(
                mux._local_tun_send_allowed(
                    4096,
                    now_ns=1,
                    scope_key=("peer", 7),
                )
            )
        finally:
            mux.loop.close()

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
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["1.1.1.1", "8.8.8.8"],
            mtu=1600,
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

    def test_hook_context_prefers_live_overlay_peer_over_initial_candidate(self):
        session = _FakeSession()
        session._peer_host = "198.51.100.10"
        session._peer_port = 4433
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="::",
            udp_peer="[2001:db8::10],198.51.100.10",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["1.1.1.1", "8.8.8.8"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        loop = asyncio.new_event_loop()
        mux = ChannelMux.from_args(session, loop, args)
        try:
            spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1400, "tun", "obtun1", 1400)
            context = mux._hook_context(spec, ("local", 0, 3), "on_channel_connected", "listener")

            self.assertEqual(context["overlay_peer_name"], "[2001:db8::10],198.51.100.10")
            self.assertEqual(context["overlay_peer_host"], "198.51.100.10")
            self.assertEqual(context["overlay_peer_port"], 4433)
        finally:
            mux.loop.close()

    def test_tunnel_hook_env_defaults_follow_tun_routing_config(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["9.9.9.9", "1.1.1.1"],
            mtu=1600,
            enable_tcpmss=True,
            enable_tun_tcpdump=True,
            tun_tcpdump_pcap_path="/tmp/shared-tun-defaults.pcap",
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            local_spec = ChannelMux.ServiceSpec(3, "tun", "ios-utun", 1600, "tun", "obtun2", 1600)
            remote_spec = ChannelMux.ServiceSpec(4, "tun", "obtun2", 1600, "tun", "ios-utun", 1600)

            local_env = mux._tunnel_hook_env_defaults(local_spec, ("local", 0, 3))
            remote_env = mux._tunnel_hook_env_defaults(remote_spec, ("peer", 9, 4))

            self.assertEqual(local_env["TUN_ADDR"], "192.168.107.1/30")
            self.assertEqual(local_env["TUN_GW"], "192.168.107.2")
            self.assertEqual(local_env["MTU"], "1600")
            self.assertEqual(local_env["ENABLE_TCPMSS"], "1")
            self.assertEqual(local_env["ENABLE_TUN_TCPDUMP"], "1")
            self.assertEqual(local_env["TCPDUMP_PCAP_PATH"], "/tmp/shared-tun-defaults.pcap")
            self.assertEqual(local_env["PEER_ADDR"], "192.168.107.2")
            self.assertEqual(local_env["TUN_SUBNET"], "192.168.107.0/30")
            self.assertEqual(local_env["TUN_ADDR6"], "fd20:107::1/126")
            self.assertEqual(local_env["PEER_ADDR6"], "fd20:107::2")
            self.assertEqual(local_env["TUN_SUBNET6"], "fd20:107::/126")
            self.assertEqual(local_env["DNS1"], "9.9.9.9")
            self.assertEqual(local_env["INCLUDED_ROUTES"], "0.0.0.0/0")
            self.assertEqual(local_env["EXCLUDED_ROUTES"], "127.0.0.0/8,127.0.0.1/32")
            self.assertEqual(local_env["INCLUDED_ROUTES6"], "::/0")
            self.assertEqual(local_env["EXCLUDED_ROUTES6"], "::1/128,::ffff:127.0.0.1/128")
            self.assertEqual(remote_env["TUN_ADDR"], "192.168.107.2/30")
            self.assertEqual(remote_env["MTU"], "1600")
            self.assertEqual(remote_env["ENABLE_TCPMSS"], "1")
            self.assertEqual(remote_env["ENABLE_TUN_TCPDUMP"], "1")
            self.assertEqual(remote_env["TCPDUMP_PCAP_PATH"], "/tmp/shared-tun-defaults.pcap")
            self.assertEqual(remote_env["PEER_ADDR"], "192.168.107.1")
            self.assertEqual(remote_env["TUN_SUBNET"], "192.168.107.0/30")
        finally:
            mux.loop.close()

    def test_parse_structured_tun_service_accepts_shared_tun_ownership_options(self):
        spec = ChannelMux._parse_structured_service_spec(
            {
                "name": "shared-tun",
                "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                "options": {
                    "shared_tun_ownership": {
                        "mode": "server_shared",
                        "peers": [
                            {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                            {"peer_ref": "ios-client", "ipv4": ["192.168.107.4/32"], "ipv6": ["fd20:107::4/128"]},
                        ],
                    }
                },
            },
            "--own-servers",
            7,
        )
        self.assertEqual(spec.l_proto, "tun")
        self.assertEqual(spec.r_proto, "tun")
        self.assertEqual(
            spec.options["shared_tun_ownership"]["peers"][0]["peer_ref"],
            "linux-client",
        )

    def test_shared_tun_ownership_snapshot_normalizes_host_addresses(self):
        spec = ChannelMux.ServiceSpec(
            7,
            "tun",
            "obtun0",
            1500,
            "tun",
            "obtun1",
            1500,
            name="shared-tun",
            options={
                "shared_tun_ownership": {
                    "mode": "server_shared",
                    "peers": [
                        {"peer_ref": "linux-client", "ipv4": ["192.168.107.2/32"], "ipv6": ["fd20:107::2/128"]},
                        {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                    ],
                }
            },
        )

        snapshot = ChannelMux._shared_tun_ownership_snapshot_for_spec(spec)

        self.assertEqual(
            snapshot,
            {
                "mode": "server_shared",
                "peer_count": 2,
                "address_count": 4,
                "peer_refs": ["linux-client", "ios-client"],
                "peers": [
                    {
                        "peer_ref": "linux-client",
                        "ipv4": ["192.168.107.2"],
                        "ipv6": ["fd20:107::2"],
                        "address_count": 2,
                    },
                    {
                        "peer_ref": "ios-client",
                        "ipv4": ["192.168.107.4"],
                        "ipv6": ["fd20:107::4"],
                        "address_count": 2,
                    },
                ],
                "owner_by_ipv4": {
                    "192.168.107.2": "linux-client",
                    "192.168.107.4": "ios-client",
                },
                "owner_by_ipv6": {
                    "fd20:107::2": "linux-client",
                    "fd20:107::4": "ios-client",
                },
            },
        )

    def test_shared_tun_ownership_snapshot_returns_none_without_option(self):
        spec = ChannelMux.ServiceSpec(7, "tun", "obtun0", 1500, "tun", "obtun1", 1500)
        self.assertIsNone(ChannelMux._shared_tun_ownership_snapshot_for_spec(spec))

    def test_parse_structured_tun_service_rejects_duplicate_shared_tun_owned_address(self):
        with self.assertRaisesRegex(ValueError, "IPv4 addresses must be unique"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                    "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"]},
                                {"peer_ref": "ios-client", "ipv4": ["192.168.107.2/32"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_parse_structured_tun_service_rejects_non_host_prefix_in_shared_tun_ownership(self):
        with self.assertRaisesRegex(ValueError, "optionally /32 or /128 only"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tun", "ifname": "obtun0", "mtu": 1500},
                    "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1500},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.0/30"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_parse_structured_non_tun_service_rejects_shared_tun_ownership_option(self):
        with self.assertRaisesRegex(ValueError, "supported only on tun->tun services"):
            ChannelMux._parse_structured_service_spec(
                {
                    "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": 8080},
                    "target": {"protocol": "tcp", "host": "127.0.0.1", "port": 80},
                    "options": {
                        "shared_tun_ownership": {
                            "mode": "server_shared",
                            "peers": [
                                {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"]},
                            ],
                        }
                    },
                },
                "--own-servers",
                7,
            )

    def test_listener_mode_retains_prestarted_server_owned_shared_tun_service(self):
        args = argparse.Namespace(
            own_servers=[
                '{"name":"shared-tun","listen":{"protocol":"tun","ifname":"obtun0","mtu":1400},'
                '"target":{"protocol":"tun","ifname":"obtun0","mtu":1400},'
                '"options":{"shared_tun_ownership":{"mode":"server_shared","peers":['
                '{"peer_ref":"linux-client","ipv4":["192.168.107.2"]}]}}}'
            ],
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_own_port=4433,
            udp_peer="",
            udp_peer_port=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(connected=False), asyncio.new_event_loop(), args)
        try:
            self.assertIn(("local", 0, 1), mux._local_services)
            self.assertTrue(ChannelMux._is_server_shared_tun_service(mux._local_services[("local", 0, 1)]))
        finally:
            mux.loop.close()

    def test_listener_mode_still_ignores_ambiguous_non_shared_own_services(self):
        args = argparse.Namespace(
            own_servers=[
                '{"listen":{"protocol":"udp","bind":"127.0.0.1","port":10001},'
                '"target":{"protocol":"udp","host":"127.0.0.1","port":10002}}'
            ],
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_own_port=4433,
            udp_peer="",
            udp_peer_port=None,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(connected=False), asyncio.new_event_loop(), args)
        try:
            self.assertEqual(mux._local_services, {})
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

    def test_remote_tun_services_auto_inject_tun_routing_hook_env(self):
        args = argparse.Namespace(
            own_servers=None,
            remote_servers=None,
            overlay_transport="myudp",
            udp_bind="0.0.0.0",
            udp_peer="127.0.0.1",
            udp_peer_port=4433,
            tunnel_address="192.168.107.1",
            tunnel_prefix=30,
            tunnel_gateway="192.168.107.2",
            included_routes=["0.0.0.0/0"],
            excluded_routes=["127.0.0.0/8"],
            tunnel_address6="fd20:107::1",
            tunnel_prefix6=126,
            tunnel_gateway6="fd20:107::2",
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["9.9.9.9", "1.1.1.1"],
            mtu=1600,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )
        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            spec = ChannelMux.ServiceSpec(
                svc_id=3,
                l_proto='tun',
                l_bind='obtun2',
                l_port=1600,
                r_proto='tun',
                r_host='ios-utun',
                r_port=1600,
                name='remote-tun',
                lifecycle_hooks={'listener': {'on_created': {'argv': ['echo', 'created']}}},
                options=None,
            )
            payload = mux._encode_remote_services_set_v2([spec])
            decoded = mux._decode_remote_services_set_v2(payload)
            self.assertIsNotNone(decoded)
            assert decoded is not None
            remote_spec = decoded[2][0]
            env = remote_spec.lifecycle_hooks["listener"]["on_created"]["env"]
            self.assertEqual(env["TUN_ADDR"], "192.168.107.2/30")
            self.assertEqual(env["PEER_ADDR"], "192.168.107.1")
            self.assertEqual(env["TUN_SUBNET"], "192.168.107.0/30")
            self.assertEqual(env["TUN_ADDR6"], "fd20:107::2/126")
            self.assertEqual(env["PEER_ADDR6"], "fd20:107::1")
            self.assertEqual(env["TUN_SUBNET6"], "fd20:107::/126")
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

    def test_parse_structured_tun_service_allows_omitted_mtu(self):
        spec = ChannelMux._parse_structured_service_spec(
            {
                'listen': {'protocol': 'tun', 'ifname': 'obtun0'},
                'target': {'protocol': 'tun', 'ifname': 'obtun1'},
            },
            '--own-servers',
            1,
        )
        self.assertEqual(spec.l_port, 0)
        self.assertEqual(spec.r_port, 0)

    def test_from_args_defaults_omitted_tun_mtu_from_tun_routing(self):
        args = argparse.Namespace(
            peer='127.0.0.1',
            udp_peer='127.0.0.1',
            overlay_transport='myudp',
            own_servers=[{
                'listen': {'protocol': 'tun', 'ifname': 'obtun0'},
                'target': {'protocol': 'tun', 'ifname': 'obtun1'},
            }],
            remote_servers=[{
                'listen': {'protocol': 'tun', 'ifname': 'obtun2'},
                'target': {'protocol': 'tun', 'ifname': 'obtun3'},
            }],
            mtu=1420,
            mux_tcp_bp_threshold=1,
            mux_tcp_bp_latency_ms=300,
            mux_tcp_bp_poll_interval_ms=50,
        )

        mux = ChannelMux.from_args(_FakeSession(), asyncio.new_event_loop(), args)
        try:
            local_spec = mux._local_services[('local', 0, 1)]
            remote_spec = mux._remote_services_requested[0]
            self.assertEqual(local_spec.l_port, 1420)
            self.assertEqual(local_spec.r_port, 1420)
            self.assertEqual(remote_spec.l_port, 1420)
            self.assertEqual(remote_spec.r_port, 1420)
        finally:
            mux.loop.close()

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

    async def test_process_shared_tun_registry_reuses_prestarted_server_owned_tun(self):
        session2 = _FakeSession()
        mux2 = ChannelMux(session2, asyncio.get_running_loop())
        mux2._overlay_connected = True
        mux2._accepting_enabled = True
        registry = ProcessSharedTunRegistry()
        self.mux._process_shared_tun_registry = registry
        mux2._process_shared_tun_registry = registry
        spec = ChannelMux.ServiceSpec(
            1,
            'tun',
            'obtun0',
            1600,
            'tun',
            'obtun0',
            1600,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.106.2']},
                    ],
                }
            },
        )
        svc_key = ('local', 0, 1)
        self.mux._local_services[svc_key] = spec
        mux2._local_services[svc_key] = spec
        dev = ChannelMux.TunDevice(fd=55, ifname='obtun0', mtu=1600, service_key=svc_key)

        with patch.object(self.mux, '_open_tun_device', return_value=dev) as open1, \
             patch.object(self.mux, '_register_tun_reader') as reg1, \
             patch.object(mux2, '_open_tun_device') as open2, \
             patch.object(mux2, '_register_tun_reader') as reg2:
            opened = self.mux._start_tun_server_for_sync(spec, svc_key)
            attached = mux2._start_tun_server_for_sync(spec, svc_key)
            await asyncio.sleep(0)

        self.assertIs(opened, dev)
        self.assertIs(attached, dev)
        open1.assert_called_once()
        reg1.assert_called_once_with(dev)
        open2.assert_not_called()
        reg2.assert_not_called()
        self.assertIs(self.mux._svc_tun_devices[svc_key], dev)
        self.assertIs(mux2._svc_tun_devices[svc_key], dev)

    async def test_local_tun_packet_source_normalizes_to_configured_ipv4_tunnel_address(self):
        self.mux.args = argparse.Namespace(
            TUN_routing={
                "tunnel_address": "192.168.106.2",
                "tunnel_address6": "fd20:106::2",
                "shared_tun_disable_outgoing_normalization": False,
            }
        )
        spec = ChannelMux.ServiceSpec(6, "tun", "obtun0", 1600, "tun", "obtun0", 1600)
        svc_key = ("local", 0, 6)
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1600, service_key=svc_key)
        packet = _ipv4_packet("192.168.0.8", "49.13.72.183")

        self.mux._local_services[svc_key] = spec

        normalized = self.mux._normalize_local_tun_packet_source(dev, packet)

        self.assertEqual(normalized[12:16], b"\xc0\xa8\x6a\x02")
        self.assertEqual(normalized[16:20], ipaddress.IPv4Address("49.13.72.183").packed)

    async def test_local_tun_packet_source_normalizes_to_configured_ipv6_tunnel_address(self):
        self.mux.args = argparse.Namespace(
            TUN_routing={
                "tunnel_address": "192.168.106.2",
                "tunnel_address6": "fd20:106::2",
                "shared_tun_disable_outgoing_normalization": False,
            }
        )
        spec = ChannelMux.ServiceSpec(6, "tun", "obtun0", 1600, "tun", "obtun0", 1600)
        svc_key = ("local", 0, 6)
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1600, service_key=svc_key)
        packet = _ipv6_packet("fe80::5982:73cb:ba81:e36c", "ff02::16")

        self.mux._local_services[svc_key] = spec

        normalized = self.mux._normalize_local_tun_packet_source(dev, packet)

        self.assertEqual(normalized[8:24], ipaddress.IPv6Address("fd20:106::2").packed)
        self.assertEqual(normalized[24:40], ipaddress.IPv6Address("ff02::16").packed)

    async def test_local_tun_packet_source_normalization_can_be_disabled(self):
        self.mux.args = argparse.Namespace(
            TUN_routing={
                "tunnel_address": "192.168.106.2",
                "shared_tun_disable_outgoing_normalization": True,
            }
        )
        spec = ChannelMux.ServiceSpec(6, "tun", "obtun0", 1600, "tun", "obtun0", 1600)
        svc_key = ("local", 0, 6)
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1600, service_key=svc_key)
        packet = _ipv4_packet("192.168.0.8", "49.13.72.183")

        self.mux._local_services[svc_key] = spec

        self.assertEqual(self.mux._normalize_local_tun_packet_source(dev, packet), packet)

    async def test_local_tun_packet_source_normalization_disabled_warns_once(self):
        self.mux.args = argparse.Namespace(
            TUN_routing={
                "tunnel_address": "192.168.106.2",
                "shared_tun_disable_outgoing_normalization": True,
            }
        )
        spec = ChannelMux.ServiceSpec(6, "tun", "obtun0", 1600, "tun", "obtun0", 1600)
        svc_key = ("local", 0, 6)
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1600, service_key=svc_key)
        packet = _ipv4_packet("192.168.0.8", "49.13.72.183")

        self.mux._local_services[svc_key] = spec

        with patch.object(self.mux.log, "warning") as warn:
            self.assertEqual(self.mux._normalize_local_tun_packet_source(dev, packet), packet)
            self.assertEqual(self.mux._normalize_local_tun_packet_source(dev, packet), packet)

        warn.assert_called_once()
        self.assertIn("outgoing normalization disabled", warn.call_args.args[0])

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

    async def test_overlay_connect_does_not_replay_tun_on_created_hook_for_active_tun_service(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=3,
            l_proto='tun',
            l_bind='obtun0',
            l_port=1500,
            r_proto='tun',
            r_host='obtun1',
            r_port=1500,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook', 'up']}}},
        )
        svc_key = ('local', 0, 3)
        self.mux._local_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = ChannelMux.TunDevice(fd=44, ifname='obtun0', mtu=1500, service_key=svc_key)
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, \
             patch.object(self.mux, '_send_remote_services_catalog_if_any') as send_catalog, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            await self.mux.on_overlay_state(True)

        start_all.assert_awaited_once()
        send_catalog.assert_called_once()
        schedule_hook.assert_not_called()

    async def test_local_tun_reader_activation_waits_for_on_created_hook_success(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=6,
            l_proto='tun',
            l_bind='obtun0',
            l_port=1600,
            r_proto='tun',
            r_host='obtun0',
            r_port=1600,
            lifecycle_hooks={'listener': {'on_created': {'argv': ['hook', 'up']}}},
        )
        svc_key = ('local', 0, 6)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun0', mtu=1600, service_key=svc_key)

        class _Proc:
            returncode = 0

            async def communicate(self):
                return (b'', b'hook ok')

        async def fake_create_subprocess_exec(*_args, **_kwargs):
            return _Proc()

        with patch.object(self.mux, '_open_tun_device', return_value=dev), \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook, \
             patch.object(self.mux, '_schedule_tun_reader_registration') as schedule_reader, \
             patch('obstacle_bridge.bridge_channelmux.asyncio.create_subprocess_exec', side_effect=fake_create_subprocess_exec):
            self.mux._start_tun_server_for_sync(spec, svc_key)
            schedule_hook.assert_called_once_with(spec, svc_key, 'listener', 'on_created')
            schedule_reader.assert_called_once_with(dev)

            await self.mux._run_service_hook(spec, svc_key, 'listener', 'on_created')

        self.assertNotIn(svc_key, self.mux._tun_reader_activation_deferred)

    async def test_start_prestarts_listener_shared_tun_service_while_overlay_disconnected(self):
        spec = ChannelMux.ServiceSpec(
            svc_id=9,
            l_proto='tun',
            l_bind='obtun0',
            l_port=1400,
            r_proto='tun',
            r_host='obtun0',
            r_port=1400,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        svc_key = ('local', 0, 9)
        self.mux._local_services[svc_key] = spec
        self.mux._overlay_connected = False
        self.mux._accepting_enabled = False

        with patch.object(self.mux, '_start_tun_server_for', new=AsyncMock()) as start_tun, \
             patch.object(self.mux, '_start_all_services', new=AsyncMock()) as start_all, \
             patch.object(self.mux, '_send_remote_services_catalog_if_any') as send_catalog:
            await self.mux.start()

        start_tun.assert_awaited_once_with(spec, svc_key)
        start_all.assert_not_awaited()
        send_catalog.assert_not_called()

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
        self.assertGreaterEqual(register_reader.call_count, 1)
        register_reader.assert_any_call(self.mux._svc_tun_devices[svc_key], force_owner=True)
        self.assertIn(svc_key, self.mux._peer_installed_services)
        self.assertIs(self.mux._tun_by_chan[1], self.mux._svc_tun_devices[svc_key])
        schedule_hook.assert_any_call(remote_tun, svc_key, 'listener', 'on_created')

    async def test_tun_open_reuses_mirrored_peer_listener_target_without_opening_remote_ifname(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'Obtun3',
            1600,
            'tun',
            'ios-utun',
            1600,
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
        mirrored_open = ChannelMux.ServiceSpec(5, 'tun', 'ios-utun', 1600, 'tun', 'ios-utun', 1600)
        open_payload = self.mux._build_open_v4(mirrored_open)
        svc_key = ('peer', 77, 2)

        def open_tun(ifname, mtu, svc_key=None):
            return ChannelMux.TunDevice(fd=45, ifname=ifname, mtu=mtu, service_key=svc_key)

        with patch.object(self.mux, '_apply_peer_installed_services', new=AsyncMock()) as apply_peer, \
             patch.object(self.mux, '_open_tun_device', side_effect=open_tun) as open_tun_device, \
             patch.object(self.mux, '_register_tun_reader') as register_reader, \
             patch.object(self.mux, '_schedule_service_hook') as schedule_hook:
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            self.mux._rx_tun_open(1, open_payload, peer_id=77)
            await asyncio.sleep(0)

        apply_peer.assert_awaited_once()
        open_tun_device.assert_called_once_with('Obtun3', 1600, svc_key=svc_key)
        self.assertGreaterEqual(register_reader.call_count, 1)
        register_reader.assert_any_call(self.mux._svc_tun_devices[svc_key], force_owner=True)
        self.assertIn(svc_key, self.mux._peer_installed_services)
        self.assertIs(self.mux._tun_by_chan[1], self.mux._svc_tun_devices[svc_key])
        schedule_hook.assert_any_call(remote_tun, svc_key, 'listener', 'on_created')

    async def test_shared_tun_runtime_binding_tracks_open_and_disconnect_cleanup(self):
        remote_tun = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
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

        with patch.object(self.mux, '_open_tun_device', side_effect=open_tun), \
             patch.object(self.mux, '_register_tun_reader'), \
             patch.object(self.mux, '_schedule_service_hook'):
            self.assertTrue(self.mux.on_app_payload_from_peer(catalog_frame, peer_id=77))
            await asyncio.sleep(0)
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        snapshot = self.mux._shared_tun_runtime_snapshot_for_service(svc_key)
        self.assertEqual(snapshot["mode"], "server_shared")
        self.assertEqual(snapshot["peer_count"], 1)
        self.assertEqual(snapshot["address_count"], 2)
        self.assertEqual(snapshot["peer_refs"], ["linux-client"])
        self.assertEqual(
            snapshot["peers"],
            [
                {
                    'peer_ref': 'linux-client',
                    'ipv4': ['192.168.107.2'],
                    'ipv6': ['fd20:107::2'],
                    'address_count': 2,
                }
            ],
        )
        self.assertEqual(snapshot["owner_by_ipv4"], {'192.168.107.2': 'linux-client'})
        self.assertEqual(snapshot["owner_by_ipv6"], {'fd20:107::2': 'linux-client'})
        self.assertEqual(
            snapshot["active_peer_bindings"],
            [
                {
                    'peer_id': 77,
                    'peer_ref': 'linux-client',
                    'preferred_chan_id': 1,
                    'bound_chan_ids': [1],
                    'ipv4': ['192.168.107.2'],
                    'ipv6': ['fd20:107::2'],
                    'address_count': 2,
                    'throttle_prev_window_bytes': 0,
                    'throttle_curr_window_bytes': 0,
                    'throttle_drop_count': 0,
                }
            ],
        )
        self.assertEqual(snapshot["throttle_scopes"], [])

        with patch.object(self.mux, '_stop_listener_for_service_id', new=AsyncMock()) as stop_listener:
            self.mux.on_peer_disconnected(77)
            await asyncio.sleep(0)

        stop_listener.assert_awaited_once_with(svc_key, 'tun', spec=remote_tun)
        self.assertEqual(
            self.mux._shared_tun_runtime_snapshot_for_service(svc_key)["active_peer_bindings"],
            [],
        )

    def test_shared_tun_guard_accepts_owned_ipv4_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["ip_version"], 4)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(parsed["destination_ip"], '192.168.107.1')
        self.assertIsNone(reason)

    def test_shared_tun_guard_accepts_owned_ipv4_source_to_broadcast_destination(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '255.255.255.255'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(parsed["destination_ip"], '255.255.255.255')
        self.assertIsNone(reason)

    def test_shared_tun_guard_rejects_unowned_ipv4_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.9', '192.168.107.1'),
        )

        self.assertFalse(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.9')
        self.assertEqual(reason, 'source_not_owned_by_peer')

    def test_shared_tun_guard_accepts_owned_ipv6_source(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv6_packet('fd20:107::2', 'fd20:107::1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["ip_version"], 6)
        self.assertEqual(parsed["source_ip"], 'fd20:107::2')
        self.assertEqual(reason, None)

    def test_shared_tun_guard_rejects_malformed_packet(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2'], 'ipv6': ['fd20:107::2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=b'\x45\x00',
        )

        self.assertFalse(allowed)
        self.assertIsNone(parsed)
        self.assertEqual(reason, 'ipv4_too_short')

    def test_shared_tun_guard_binds_peer_ref_and_rejects_second_owner_claim(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                        {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )

        self.assertTrue(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertIsNone(reason)
        self.assertEqual(
            self.mux._shared_tun_peer_ref_by_peer[(svc_key, 77)],
            'linux-client',
        )
        self.assertEqual(
            self.mux._shared_tun_peer_id_by_ref[(svc_key, 'linux-client')],
            77,
        )

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
        )

        self.assertFalse(allowed)
        self.assertEqual(parsed["source_ip"], '192.168.107.4')
        self.assertEqual(reason, 'source_not_owned_by_peer')

    def test_shared_tun_guard_allows_rebind_after_peer_disconnect(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        svc_key = ('peer', 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname='obtun1', mtu=1500, service_key=svc_key)
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        self.mux._chan_owner_peer_id[1] = 77

        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=1,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )
        self.assertTrue(allowed)
        self.assertIsNone(reason)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(self.mux._shared_tun_peer_id_by_ref[(svc_key, 'linux-client')], 77)

        self.mux.on_peer_disconnected(77)
        self.mux.loop.run_until_complete(asyncio.sleep(0))
        self.assertNotIn((svc_key, 'linux-client'), self.mux._shared_tun_peer_id_by_ref)

        self.mux._chan_owner_peer_id[2] = 88
        allowed, parsed, reason = self.mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=2,
            packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
        )
        self.assertTrue(allowed)
        self.assertIsNone(reason)
        self.assertEqual(parsed["source_ip"], '192.168.107.2')
        self.assertEqual(self.mux._shared_tun_peer_id_by_ref[(svc_key, 'linux-client')], 88)

    def test_shared_tun_open_requires_prestarted_server_owned_service(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        open_payload = self.mux._build_open_v4(spec)
        with patch.object(self.mux, '_ensure_peer_tun_listener_for_target') as ensure_peer_listener, \
             patch.object(self.mux, '_log_tun_open_diagnostics') as log_diag:
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        ensure_peer_listener.assert_not_called()
        self.assertEqual([call.kwargs.get('note') for call in log_diag.call_args_list], [
            'received_open_v4',
            'shared_attach_rejected_no_prestarted_match',
        ])
        self.assertNotIn(1, self.mux._tun_by_chan)

    def test_shared_tun_open_binds_to_prestarted_server_owned_service(self):
        spec = ChannelMux.ServiceSpec(
            2,
            'tun',
            'obtun1',
            1500,
            'tun',
            'obtun0',
            1500,
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                    ],
                }
            },
        )
        svc_key = ('local', 0, 2)
        dev = ChannelMux.TunDevice(fd=55, ifname='obtun0', mtu=1500, service_key=svc_key)
        self.mux._local_services[svc_key] = spec
        self.mux._svc_tun_devices[svc_key] = dev
        self.mux._install_shared_tun_ownership_for_service(svc_key, spec)
        open_payload = self.mux._build_open_v4(spec)

        with patch.object(self.mux, '_ensure_peer_tun_listener_for_target') as ensure_peer_listener, \
             patch.object(self.mux, '_register_tun_reader') as register_reader, \
             patch.object(self.mux, '_log_tun_open_diagnostics') as log_diag:
            self.mux._rx_tun_open(1, open_payload, peer_id=77)

        ensure_peer_listener.assert_not_called()
        register_reader.assert_called_once_with(dev, force_owner=True)
        self.assertEqual([call.kwargs.get('note') for call in log_diag.call_args_list], [
            'received_open_v4',
            'matched_prestarted_service',
        ])
        self.assertIs(self.mux._tun_by_chan.get(1), dev)

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

    async def test_shared_server_tun_stop_skips_on_stopped_hook_when_device_is_retained(self):
        svc_key = ('local', 0, 1)
        spec = ChannelMux.ServiceSpec(
            1,
            'tun',
            'obtun0',
            1500,
            'tun',
            'obtun0',
            1500,
            lifecycle_hooks={'listener': {'on_stopped': {'argv': ['echo', 'down']}}},
            options={
                'shared_tun_ownership': {
                    'mode': 'server_shared',
                    'peers': [
                        {'peer_ref': 'linux-client', 'ipv4': ['192.168.106.2'], 'ipv6': ['fd20:106::2']},
                    ],
                }
            },
        )
        dev = ChannelMux.TunDevice(fd=-1, ifname='obtun0', mtu=1500, service_key=svc_key)
        registry = ProcessSharedTunRegistry()
        registry.register(self.mux, svc_key, dev)
        keeper_mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
        try:
            registry.attach_existing(keeper_mux, 'obtun0', 1500)
            self.mux._process_shared_tun_registry = registry
            self.mux._local_services[svc_key] = spec
            self.mux._svc_tun_devices[svc_key] = dev

            with patch.object(self.mux, '_run_service_hook', new=AsyncMock()) as run_hook, patch.object(self.mux, '_close_tun_device') as close_tun:
                await self.mux._stop_listener_for_service_id(svc_key, 'tun', spec=spec)

            run_hook.assert_not_awaited()
            close_tun.assert_not_called()
            self.assertNotIn(svc_key, self.mux._svc_tun_devices)
        finally:
            keeper_mux.loop.close()


class ChannelMuxSessionBudgetTests(unittest.TestCase):
    def test_safe_tcp_read_uses_session_payload_budget(self):
        session = _FakeSession(max_app_payload_size=512)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            self.assertEqual(mux._SAFE_TCP_READ, 512 - ChannelMux.MUX_HDR.size)
        finally:
            mux.loop.close()

    def test_stream_overlay_tcp_read_size_is_capped_for_ws(self):
        session = _FakeSession(max_app_payload_size=65535)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_transport = "ws"
            self.assertEqual(
                mux._tcp_overlay_read_size(),
                ChannelMux.STREAM_OVERLAY_TCP_READ_CAP,
            )
        finally:
            mux.loop.close()

    def test_datagram_overlay_tcp_read_size_keeps_session_budget(self):
        session = _FakeSession(max_app_payload_size=512)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_transport = "myudp"
            self.assertEqual(mux._tcp_overlay_read_size(), mux._SAFE_TCP_READ)
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

    def test_local_udp_datagram_emits_debug_level_direction_diagnostic(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(1, 'udp', '0.0.0.0', 16666, 'udp', '127.0.0.1', 16666)
            svc_key = ('local', 0, 1)
            mux._svc_udp_servers[svc_key] = _FakeDatagramTransport(sockname=('0.0.0.0', 16666))

            with self.assertLogs('channel_mux', level='DEBUG') as logs:
                mux._on_local_udp_datagram(spec, svc_key, b'wg-handshake', ('127.0.0.1', 51820))

            text = "\n".join(logs.output)
            self.assertIn("[UDP/DIAG]", text)
            self.assertIn("direction=local->overlay", text)
            self.assertIn("path=127.0.0.1:51820->0.0.0.0:16666", text)
            self.assertIn("remote_target=127.0.0.1:16666", text)
        finally:
            mux.loop.close()

    def test_overlay_udp_to_target_emits_debug_level_direction_diagnostic(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            transport = _FakeDatagramTransport(
                sockname=('127.0.0.1', 40000),
                peername=('127.0.0.1', 16666),
            )
            mux._udp_client_transports[7] = transport

            with self.assertLogs('channel_mux', level='DEBUG') as logs:
                mux._rx_udp_data(7, b'wg-target')

            text = "\n".join(logs.output)
            self.assertIn("[UDP/DIAG]", text)
            self.assertIn("direction=overlay->target", text)
            self.assertIn("path=127.0.0.1:40000->127.0.0.1:16666", text)
            self.assertEqual(transport.sent, [(b'wg-target', None)])
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

    def test_local_tun_packet_routes_shared_unicast_only_to_designated_peer_channel(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '192.168.107.4'))

            send_mux.assert_called_once_with(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '192.168.107.4'))
        finally:
            mux.loop.close()

    def test_local_tun_packet_routes_shared_broadcast_only_to_active_peer_channels(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '255.255.255.255'))

            self.assertEqual(
                send_mux.call_args_list,
                [
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '255.255.255.255')),
                    unittest.mock.call(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.1', '255.255.255.255')),
                ],
            )
        finally:
            mux.loop.close()

    def test_local_tun_packet_shared_throttle_is_scoped_per_peer_channel(self):
        session = _FakeSession(connected=True, waiting_count=0)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )
            packet_a = _ipv4_packet('192.168.107.1', '192.168.107.2', b'a' * 100)
            packet_b_seed = _ipv4_packet('192.168.107.1', '192.168.107.4', b'b' * 100)
            packet_a_budget = _ipv4_packet('192.168.107.1', '192.168.107.2', b'c' * 80)
            packet_a_over = _ipv4_packet('192.168.107.1', '192.168.107.2', b'd' * 20)
            packet_b_budget = _ipv4_packet('192.168.107.1', '192.168.107.4', b'e' * 80)

            with patch("obstacle_bridge.bridge_channelmux.time.monotonic_ns", side_effect=[0, 0, 100_000_000, 100_000_000, 100_000_000]), patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, packet_a)
                mux._on_local_tun_packet(dev, packet_b_seed)
                session._metrics.waiting_count = 1
                session._metrics.inflight = 200
                session._metrics.max_inflight = 200
                mux._on_local_tun_packet(dev, packet_a_budget)
                mux._on_local_tun_packet(dev, packet_a_over)
                mux._on_local_tun_packet(dev, packet_b_budget)

            self.assertEqual(
                send_mux.call_args_list,
                [
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet_a),
                    unittest.mock.call(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet_b_seed),
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet_a_budget),
                    unittest.mock.call(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet_b_budget),
                ],
            )
            snapshot = mux._shared_tun_runtime_snapshot_for_service(svc_key)
            assert snapshot is not None
            scopes = {entry["scope_id"]: entry for entry in snapshot["throttle_scopes"]}
            linux_scope = next(entry for entry in scopes.values() if entry["selected_peer_ids"] == [77])
            ios_scope = next(entry for entry in scopes.values() if entry["selected_peer_ids"] == [88])
            self.assertEqual(linux_scope["throttle_drop_count"], 1)
            self.assertEqual(linux_scope["prev_window_bytes"], len(packet_a))
            self.assertEqual(ios_scope["throttle_drop_count"], 0)
            self.assertEqual(
                [entry for entry in snapshot["active_peer_bindings"] if entry["peer_id"] == 77][0]["throttle_drop_count"],
                1,
            )
            self.assertEqual(
                [entry for entry in snapshot["active_peer_bindings"] if entry["peer_id"] == 88][0]["throttle_drop_count"],
                0,
            )
        finally:
            mux.loop.close()

    def test_shared_tun_drop_snapshot_tracks_reasons_and_bounds_recent_entries(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)
            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '192.168.107.9'))
            send_mux.assert_not_called()

            with patch.object(mux, '_write_tun_packet') as write_tun:
                for idx in range(ChannelMux.SHARED_TUN_RECENT_DROP_LIMIT + 4):
                    mux._rx_tun_data(11, _ipv4_packet(f'192.168.200.{(idx % 200) + 1}', '192.168.107.1'))
            write_tun.assert_not_called()

            snapshot = mux._shared_tun_runtime_snapshot_for_service(svc_key)
            assert snapshot is not None
            self.assertEqual(snapshot["drop_counters"]["total"], ChannelMux.SHARED_TUN_RECENT_DROP_LIMIT + 5)
            self.assertEqual(snapshot["drop_counters"]["by_reason"]["unknown_destination"], 1)
            self.assertEqual(
                snapshot["drop_counters"]["by_reason"]["source_not_owned_by_peer"],
                ChannelMux.SHARED_TUN_RECENT_DROP_LIMIT + 4,
            )
            self.assertEqual(len(snapshot["recent_drops"]), ChannelMux.SHARED_TUN_RECENT_DROP_LIMIT)
            self.assertEqual(snapshot["recent_drops"][-1]["reason"], "source_not_owned_by_peer")
            self.assertEqual(snapshot["recent_drops"][-1]["direction"], "peer_to_local")
        finally:
            mux.loop.close()

    def test_shared_tun_broadcast_throttle_scope_does_not_consume_unicast_budget(self):
        session = _FakeSession(connected=True, waiting_count=0)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            broadcast_seed = _ipv4_packet('192.168.107.1', '255.255.255.255', b'b' * 100)
            broadcast_over = _ipv4_packet('192.168.107.1', '255.255.255.255', b'c' * 100)
            unicast_seed = _ipv4_packet('192.168.107.1', '192.168.107.2', b'u' * 100)
            unicast_budget = _ipv4_packet('192.168.107.1', '192.168.107.2', b'v' * 80)

            with patch("obstacle_bridge.bridge_channelmux.time.monotonic_ns", side_effect=[0, 100_000_000, 200_000_000, 300_000_000]), patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, broadcast_seed)
                session._metrics.waiting_count = 1
                session._metrics.inflight = 200
                session._metrics.max_inflight = 200
                mux._on_local_tun_packet(dev, broadcast_over)
                session._metrics.waiting_count = 0
                session._metrics.inflight = 0
                mux._on_local_tun_packet(dev, unicast_seed)
                session._metrics.waiting_count = 1
                session._metrics.inflight = 200
                session._metrics.max_inflight = 200
                mux._on_local_tun_packet(dev, unicast_budget)

            self.assertEqual(
                send_mux.call_args_list,
                [
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, broadcast_seed),
                    unittest.mock.call(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, broadcast_seed),
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, unicast_seed),
                    unittest.mock.call(11, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, unicast_budget),
                ],
            )
            snapshot = mux._shared_tun_runtime_snapshot_for_service(svc_key)
            assert snapshot is not None
            broadcast_scope = next(entry for entry in snapshot["throttle_scopes"] if entry["route_class"] == "broadcast")
            unicast_scope = next(entry for entry in snapshot["throttle_scopes"] if entry["selected_peer_ids"] == [77])
            self.assertEqual(broadcast_scope["throttle_drop_count"], 1)
            self.assertEqual(unicast_scope["throttle_drop_count"], 0)
        finally:
            mux.loop.close()

    def test_local_tun_packet_drops_shared_unknown_destination(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)
            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux:
                mux._on_local_tun_packet(dev, _ipv4_packet('192.168.107.1', '192.168.107.9'))

            send_mux.assert_not_called()
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_relays_to_other_owned_peer_channel(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._chan_owner_peer_id[22] = 88
            mux._bind_tun_channel(22, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=22,
                packet=_ipv4_packet('192.168.107.4', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '192.168.107.4'))

            send_mux.assert_called_once_with(22, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, _ipv4_packet('192.168.107.2', '192.168.107.4'))
            write_tun.assert_not_called()
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_unknown_destination_still_writes_local_tun(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '8.8.8.8'))

            send_mux.assert_not_called()
            write_tun.assert_called_once_with(dev, _ipv4_packet('192.168.107.2', '8.8.8.8'))
        finally:
            mux.loop.close()

    def test_inbound_shared_tun_packet_sender_owned_destination_does_not_self_loop(self):
        session = _FakeSession(connected=True)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            spec = ChannelMux.ServiceSpec(
                5,
                'tun',
                'obtun0',
                1500,
                'tun',
                'obtun1',
                1500,
                options={
                    'shared_tun_ownership': {
                        'mode': 'server_shared',
                        'peers': [
                            {'peer_ref': 'linux-client', 'ipv4': ['192.168.107.2']},
                            {'peer_ref': 'ios-client', 'ipv4': ['192.168.107.4']},
                        ],
                    }
                },
            )
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev
            mux._install_shared_tun_ownership_for_service(svc_key, spec)

            mux._chan_owner_peer_id[11] = 77
            mux._bind_tun_channel(11, dev)
            mux._shared_tun_guard_inbound_packet(
                dev=dev,
                chan=11,
                packet=_ipv4_packet('192.168.107.2', '192.168.107.1'),
            )

            with patch.object(mux, '_send_mux') as send_mux, patch.object(mux, '_write_tun_packet') as write_tun:
                mux._rx_tun_data(11, _ipv4_packet('192.168.107.2', '192.168.107.2'))

            send_mux.assert_not_called()
            write_tun.assert_called_once_with(dev, _ipv4_packet('192.168.107.2', '192.168.107.2'))
        finally:
            mux.loop.close()

    def test_local_tun_packet_ignores_transmit_delay_without_buffered_frames(self):
        session = _FakeSession(connected=True, transmit_delay_est_ms=3000.0, waiting_count=0)
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
            self.assertIsNotNone(dev.chan_id)
        finally:
            mux.loop.close()

    def test_local_tun_packet_throttles_when_buffered_frames_exceed_recent_budget(self):
        session = _FakeSession(connected=True, waiting_count=0)
        mux = ChannelMux(session, asyncio.new_event_loop())
        try:
            mux._overlay_connected = True
            mux._accepting_enabled = True
            spec = ChannelMux.ServiceSpec(5, 'tun', 'obtun0', 1500, 'tun', 'obtun1', 1500)
            svc_key = ('local', 0, 5)
            mux._local_services[svc_key] = spec
            dev = ChannelMux.TunDevice(fd=10, ifname='obtun0', mtu=1500, service_key=svc_key)
            mux._svc_tun_devices[svc_key] = dev

            with patch("obstacle_bridge.bridge_channelmux.time.monotonic_ns", side_effect=[0, 100_000_000, 100_000_000]):
                mux._on_local_tun_packet(dev, b'a' * 100)
                session._metrics.waiting_count = 1
                session._metrics.inflight = 200
                session._metrics.max_inflight = 200
                mux._on_local_tun_packet(dev, b'b' * 80)
                mux._on_local_tun_packet(dev, b'c' * 20)

            self.assertEqual(len(session.sent), 3)
            data_frames = [mux._unpack_mux(frame) for frame in session.sent]
            self.assertEqual(data_frames[0][3], ChannelMux.MType.OPEN)
            self.assertEqual(data_frames[1][3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(data_frames[1][4]), b'a' * 100)
            self.assertEqual(data_frames[2][3], ChannelMux.MType.DATA)
            self.assertEqual(bytes(data_frames[2][4]), b'b' * 80)
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
