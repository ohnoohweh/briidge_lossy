from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.m25_ui import M25Config, profile_from_m25_config
from obstacle_bridge_ios.m3_tunnel import (
    M3_APP_MESSAGE_SCHEMA,
    M3NetworkSettings,
    m3_tunnel_config_from_profile,
    m3_vpn_profile_from_profile,
    network_settings_from_runtime_config,
    provider_status_request_message,
    provider_configuration_from_m3_config,
    tunnel_status_from_provider_payload,
)


def _m25_profile() -> dict:
    return profile_from_m25_config(
        M25Config(
            profile_id="ios-m3-site-a",
            display_name="M3 Site A",
            transport="tcp",
            peer_host="bridge.example.net",
            peer_port=4433,
            local_tcp_port=18080,
            local_udp_port=18081,
            target_host="127.0.0.1",
            target_tcp_port=8080,
            target_udp_port=8081,
        )
    )


def test_m3_tunnel_config_uses_profile_peer_and_network_settings() -> None:
    cfg = m3_tunnel_config_from_profile(
        _m25_profile(),
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
        network=M3NetworkSettings(
            tunnel_address="10.88.0.2",
            included_routes=["10.88.0.0/24"],
            excluded_routes=["192.168.0.0/16"],
            tunnel_address6="fd20:88::2",
            tunnel_prefix6=126,
            included_routes6=["::/0"],
            excluded_routes6=["::1/128"],
            dns_servers=["9.9.9.9"],
            mtu=1360,
        ),
    )

    assert cfg.profile_id == "ios-m3-site-a"
    assert cfg.transport == "tcp"
    assert cfg.peer_host == "bridge.example.net"
    assert cfg.peer_port == 4433
    assert cfg.server_address == "bridge.example.net:4433"
    assert cfg.network.included_routes == ["10.88.0.0/24"]


def test_provider_configuration_is_native_extension_contract() -> None:
    cfg = m3_tunnel_config_from_profile(
        {
            **_m25_profile(),
            "obstacle_bridge": {
                **_m25_profile()["obstacle_bridge"],
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_udp",
                    "bind_host": "127.0.0.1",
                    "bind_port": 5555,
                    "peer_host": "127.0.0.1",
                    "peer_port": 5556,
                },
            },
        },
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
    )

    provider_config = provider_configuration_from_m3_config(cfg)

    assert provider_config["schema"] == "obstaclebridge.ios.packet-tunnel.v1"
    assert provider_config["milestone"] == "M3"
    assert provider_config["peer"] == {"host": "bridge.example.net", "port": 4433}
    assert provider_config["runtime_config"]["overlay_transport"] == "tcp"
    assert provider_config["runtime_config"]["tcp_peer"] == "bridge.example.net"
    assert provider_config["runtime_config"]["tcp_peer_port"] == 4433
    assert provider_config["runtime_config"]["iOS_TUN_connector"]["bind_host"] == "127.0.0.1"
    assert provider_config["runtime_config"]["iOS_TUN_connector"]["peer_host"] == "127.0.0.1"
    assert provider_config["runtime_config"]["iOS_TUN_connector"]["peer_port"] == 5556
    assert provider_config["network_settings"]["tunnel_address"] == "192.168.106.1"
    assert provider_config["network_settings"]["tunnel_prefix"] == 30
    assert provider_config["network_settings"]["included_routes"] == ["0.0.0.0/0"]
    assert provider_config["network_settings"]["excluded_routes"] == ["127.0.0.0/8"]
    assert provider_config["network_settings"]["tunnel_address6"] == "fd20:106::1"
    assert provider_config["network_settings"]["included_routes6"] == ["::/0"]
    assert provider_config["network_settings"]["excluded_routes6"] == ["::1/128"]
    assert provider_config["poc"]["packet_flow"] == "NEPacketTunnelFlow"
    assert provider_config["poc"]["secure_link"] == "deferred-to-M4"


def test_m3_vpn_profile_describes_netunnel_provider_install() -> None:
    vpn_profile = m3_vpn_profile_from_profile(
        _m25_profile(),
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
    )

    assert vpn_profile["install_path"] == "NETunnelProviderManager"
    assert vpn_profile["provider_bundle_identifier"] == "com.obstaclebridge.ObstacleBridge.PacketTunnel"
    assert vpn_profile["server_address"] == "bridge.example.net:4433"
    assert vpn_profile["provider_configuration"]["transport"] == "tcp"


def test_network_settings_from_runtime_config_prefers_local_ios_tun_hook_env() -> None:
    settings = network_settings_from_runtime_config(
        {
            "channel_mux": {
                "own_servers": [
                    {
                        "listen": {"protocol": "tun", "ifname": "ios-utun", "mtu": 1400},
                        "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1400},
                        "lifecycle_hooks": {
                            "listener": {
                                "on_created": {
                                    "argv": {"linux": ["./scripts/client-tun-hook.sh", "up", "{ifname}"]},
                                    "env": {"TUN_ADDR": "192.168.105.1/30", "TUN_ADDR6": "fd20:105::1/126"},
                                }
                            }
                        },
                    }
                ]
            }
        }
    )

    assert settings.tunnel_address == "192.168.105.1"
    assert settings.tunnel_prefix == 30
    assert settings.included_routes == ["0.0.0.0/0"]
    assert settings.excluded_routes == ["127.0.0.0/8"]
    assert settings.tunnel_address6 == "fd20:105::1"
    assert settings.tunnel_prefix6 == 126
    assert settings.included_routes6 == ["::/0"]
    assert settings.excluded_routes6 == ["::1/128"]
    assert settings.mtu == 1400


def test_network_settings_from_runtime_config_can_fallback_to_remote_peer_addr() -> None:
    settings = network_settings_from_runtime_config(
        {
            "channel_mux": {
                "remote_servers": [
                    {
                        "listen": {"protocol": "tun", "ifname": "obtun1", "mtu": 1280},
                        "target": {"protocol": "tun", "ifname": "ios-utun", "mtu": 1280},
                        "lifecycle_hooks": {
                            "listener": {
                                "on_created": {
                                    "argv": {"linux": ["./scripts/server-tun-hook.sh", "up", "{ifname}"]},
                                    "env": {
                                        "TUN_ADDR": "192.168.105.2/30",
                                        "PEER_ADDR": "192.168.105.1",
                                        "TUN_ADDR6": "fd20:105::2/126",
                                        "PEER_ADDR6": "fd20:105::1",
                                        "TUN_SUBNET": "192.168.105.0/30",
                                        "TUN_SUBNET6": "fd20:105::/126",
                                    },
                                }
                            }
                        },
                    }
                ]
            }
        }
    )

    assert settings.tunnel_address == "192.168.105.1"
    assert settings.tunnel_prefix == 30
    assert settings.tunnel_address6 == "fd20:105::1"
    assert settings.tunnel_prefix6 == 126
    assert settings.included_routes6 == ["::/0"]
    assert settings.excluded_routes6 == ["::1/128"]


def test_network_settings_from_runtime_config_applies_tun_routing_override() -> None:
    settings = network_settings_from_runtime_config(
        {
            "TUN_routing": {
                "included_routes": ["198.18.0.254/32"],
                "excluded_routes": ["0.0.0.0/0"],
                "included_routes6": ["2001:db8:ffff::254/128"],
                "excluded_routes6": ["::/0"],
                "dns_servers": ["9.9.9.9"],
                "mtu": 1600,
            },
            "channel_mux": {
                "own_servers": [
                    {
                        "listen": {"protocol": "tun", "ifname": "ios-utun", "mtu": 1400},
                        "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1400},
                        "lifecycle_hooks": {
                            "listener": {
                                "on_created": {
                                    "env": {"TUN_ADDR": "192.168.105.1/30", "TUN_ADDR6": "fd20:105::1/126"}
                                }
                            }
                        },
                    }
                ]
            },
        }
    )

    assert settings.tunnel_address == "192.168.105.1"
    assert settings.tunnel_prefix == 30
    assert settings.included_routes == ["198.18.0.254/32"]
    assert settings.excluded_routes == ["0.0.0.0/0"]
    assert settings.tunnel_address6 == "fd20:105::1"
    assert settings.tunnel_prefix6 == 126
    assert settings.included_routes6 == ["2001:db8:ffff::254/128"]
    assert settings.excluded_routes6 == ["::/0"]
    assert settings.dns_servers == ["9.9.9.9"]
    assert settings.mtu == 1600


def test_m3_network_settings_can_derive_client_and_server_hook_env() -> None:
    settings = M3NetworkSettings(
        tunnel_address="192.168.107.1",
        tunnel_prefix=30,
        tunnel_gateway="192.168.107.2",
        tunnel_address6="fd20:107::1",
        tunnel_prefix6=126,
        tunnel_gateway6="fd20:107::2",
        dns_servers=["9.9.9.9", "1.1.1.1"],
    )

    local_env = settings.local_hook_env()
    remote_env = settings.remote_hook_env()

    assert local_env["TUN_ADDR"] == "192.168.107.1/30"
    assert local_env["TUN_GW"] == "192.168.107.2"
    assert local_env["TUN_ADDR6"] == "fd20:107::1/126"
    assert local_env["TUN_GW6"] == "fd20:107::2"
    assert local_env["DNS1"] == "9.9.9.9"
    assert local_env["DNS2"] == "1.1.1.1"
    assert remote_env["TUN_ADDR"] == "192.168.107.2/30"
    assert remote_env["PEER_ADDR"] == "192.168.107.1"
    assert remote_env["TUN_SUBNET"] == "192.168.107.0/30"
    assert remote_env["TUN_ADDR6"] == "fd20:107::2/126"
    assert remote_env["PEER_ADDR6"] == "fd20:107::1"
    assert remote_env["TUN_SUBNET6"] == "fd20:107::/126"


def test_provider_status_request_message_is_versioned() -> None:
    payload = provider_status_request_message(request_id="req-123")

    assert payload == {
        "schema": M3_APP_MESSAGE_SCHEMA,
        "request_id": "req-123",
        "action": "status",
    }


def test_tunnel_status_from_provider_payload_accepts_current_native_shape() -> None:
    status = tunnel_status_from_provider_payload(
        {
            "state": "running",
            "packetsFromSystem": 11,
            "packetsToSystem": 12,
            "bytesFromSystem": 101,
            "bytesToSystem": 202,
            "lastError": "",
        }
    )

    assert status.state == "running"
    assert status.packets_from_system == 11
    assert status.packets_to_system == 12
    assert status.bytes_from_system == 101
    assert status.bytes_to_system == 202
    assert status.last_error == ""


def test_tunnel_status_from_provider_payload_accepts_versioned_envelope() -> None:
    status = tunnel_status_from_provider_payload(
        {
            "schema": M3_APP_MESSAGE_SCHEMA,
            "request_id": "req-123",
            "action": "status",
            "status": {
                "state": "failed",
                "packets_from_system": 1,
                "packets_to_system": 2,
                "bytes_from_system": 3,
                "bytes_to_system": 4,
                "last_error": "peer disconnected",
            },
        }
    )

    assert status.state == "failed"
    assert status.packets_from_system == 1
    assert status.packets_to_system == 2
    assert status.bytes_from_system == 3
    assert status.bytes_to_system == 4
    assert status.last_error == "peer disconnected"
