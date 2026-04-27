from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.m25_ui import M25Config, profile_from_m25_config
from obstacle_bridge_ios.m3_tunnel import (
    M3NetworkSettings,
    m3_tunnel_config_from_profile,
    m3_vpn_profile_from_profile,
    provider_configuration_from_m3_config,
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
        _m25_profile(),
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
    )

    provider_config = provider_configuration_from_m3_config(cfg)

    assert provider_config["schema"] == "obstaclebridge.ios.packet-tunnel.v1"
    assert provider_config["milestone"] == "M3"
    assert provider_config["peer"] == {"host": "bridge.example.net", "port": 4433}
    assert provider_config["network_settings"]["tunnel_address"] == "10.77.0.2"
    assert provider_config["obstacle_bridge_config"]["overlay_transport"] == "tcp"
    assert provider_config["runtime"]["owner"] == "packet-tunnel-extension"
    assert provider_config["runtime"]["configuration_source"] == "providerConfiguration.obstacle_bridge_config"
    assert provider_config["runtime"]["layers"] == [
        "webadmin",
        "channelmux",
        "compression",
        "securelink",
        "overlay-transports",
        "packet-io",
    ]
    assert provider_config["poc"]["packet_flow"] == "NEPacketTunnelFlow"
    assert provider_config["poc"]["secure_link"] == "extension-owned-obstaclebridge-runtime"


def test_m3_vpn_profile_describes_netunnel_provider_install() -> None:
    vpn_profile = m3_vpn_profile_from_profile(
        _m25_profile(),
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
    )

    assert vpn_profile["install_path"] == "NETunnelProviderManager"
    assert vpn_profile["provider_bundle_identifier"] == "com.obstaclebridge.ObstacleBridge.PacketTunnel"
    assert vpn_profile["server_address"] == "bridge.example.net:4433"
    assert vpn_profile["provider_configuration"]["transport"] == "tcp"
