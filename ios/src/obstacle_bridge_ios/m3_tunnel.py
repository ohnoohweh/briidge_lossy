"""M3 packet tunnel profile and provider-configuration helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


_TRANSPORT_PEER_KEYS = {
    "tcp": ("tcp_peer", "tcp_peer_port"),
    "ws": ("ws_peer", "ws_peer_port"),
    "myudp": ("udp_peer", "udp_peer_port"),
    "quic": ("quic_peer", "quic_peer_port"),
}
M3_TUNNEL_SCHEMA = "obstaclebridge.ios.packet-tunnel.v1"
M3_APP_MESSAGE_SCHEMA = "obstaclebridge.ios.packet-tunnel.app-message.v1"
M3_TUNNEL_STATUS_STATES = {"idle", "starting", "running", "stopping", "stopped", "failed"}


@dataclass
class M3NetworkSettings:
    """Network settings the native Packet Tunnel Provider applies on start."""

    tunnel_address: str = "10.77.0.2"
    tunnel_prefix: int = 32
    included_routes: list[str] = field(default_factory=lambda: ["10.77.0.0/24"])
    excluded_routes: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=lambda: ["1.1.1.1"])
    mtu: int = 1280


@dataclass
class M3TunnelConfig:
    """Serializable M3 POC configuration shared by app and extension."""

    profile_id: str
    display_name: str
    provider_bundle_identifier: str
    transport: str
    peer_host: str
    peer_port: int
    server_address: str
    network: M3NetworkSettings = field(default_factory=M3NetworkSettings)


@dataclass
class M3TunnelStatus:
    """App-facing status snapshot returned by the packet tunnel extension."""

    state: str
    packets_from_system: int = 0
    packets_to_system: int = 0
    bytes_from_system: int = 0
    bytes_to_system: int = 0
    last_error: str = ""


def _required_string(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    return text


def _validate_port(value: Any, name: str) -> int:
    port = int(value)
    if not (1 <= port <= 65535):
        raise ValueError(f"{name} must be between 1 and 65535")
    return port


def _validate_network_settings(settings: M3NetworkSettings) -> None:
    ipaddress.ip_address(settings.tunnel_address)
    if not (1 <= int(settings.tunnel_prefix) <= 32):
        raise ValueError("tunnel_prefix must be between 1 and 32")
    if not (576 <= int(settings.mtu) <= 9000):
        raise ValueError("mtu must be between 576 and 9000")
    for route in settings.included_routes:
        ipaddress.ip_network(route, strict=False)
    for route in settings.excluded_routes:
        ipaddress.ip_network(route, strict=False)
    for server in settings.dns_servers:
        ipaddress.ip_address(server)


def _validate_tunnel_status_state(value: Any) -> str:
    state = _required_string(value, "state").lower()
    if state not in M3_TUNNEL_STATUS_STATES:
        raise ValueError(f"unsupported M3 tunnel status state: {state}")
    return state


def _non_negative_int(value: Any, name: str) -> int:
    amount = int(value)
    if amount < 0:
        raise ValueError(f"{name} must be non-negative")
    return amount


def m3_tunnel_config_from_profile(
    profile: Mapping[str, Any],
    *,
    provider_bundle_identifier: str,
    network: Optional[M3NetworkSettings] = None,
) -> M3TunnelConfig:
    """Build an M3 tunnel config from an existing iOS profile document."""

    profile_id = _required_string(profile.get("profile_id"), "profile_id")
    display_name = _required_string(profile.get("display_name") or profile_id, "display_name")
    provider_id = _required_string(provider_bundle_identifier, "provider_bundle_identifier")
    ob_cfg = profile.get("obstacle_bridge")
    if not isinstance(ob_cfg, Mapping):
        raise ValueError("profile obstacle_bridge config is required")

    transport = str(ob_cfg.get("overlay_transport", "") or "").strip().lower()
    if transport not in _TRANSPORT_PEER_KEYS:
        raise ValueError(f"unsupported M3 transport: {transport}")
    host_key, port_key = _TRANSPORT_PEER_KEYS[transport]
    peer_host = _required_string(ob_cfg.get(host_key), host_key)
    peer_port = _validate_port(ob_cfg.get(port_key), port_key)

    settings = network or M3NetworkSettings()
    _validate_network_settings(settings)
    return M3TunnelConfig(
        profile_id=profile_id,
        display_name=display_name,
        provider_bundle_identifier=provider_id,
        transport=transport,
        peer_host=peer_host,
        peer_port=peer_port,
        server_address=f"{peer_host}:{peer_port}",
        network=settings,
    )


def provider_configuration_from_m3_config(cfg: M3TunnelConfig) -> dict[str, Any]:
    """Return the NETunnelProviderProtocol.providerConfiguration payload."""

    _validate_network_settings(cfg.network)
    return {
        "schema": M3_TUNNEL_SCHEMA,
        "milestone": "M3",
        "profile_id": _required_string(cfg.profile_id, "profile_id"),
        "display_name": _required_string(cfg.display_name, "display_name"),
        "transport": _required_string(cfg.transport, "transport").lower(),
        "peer": {
            "host": _required_string(cfg.peer_host, "peer_host"),
            "port": _validate_port(cfg.peer_port, "peer_port"),
        },
        "network_settings": {
            "tunnel_address": cfg.network.tunnel_address,
            "tunnel_prefix": int(cfg.network.tunnel_prefix),
            "included_routes": list(cfg.network.included_routes),
            "excluded_routes": list(cfg.network.excluded_routes),
            "dns_servers": list(cfg.network.dns_servers),
            "mtu": int(cfg.network.mtu),
        },
        "poc": {
            "packet_flow": "NEPacketTunnelFlow",
            "transport_bridge": "tcp-length-prefixed-packets",
            "secure_link": "deferred-to-M4",
        },
    }


def m3_vpn_profile_from_profile(
    profile: Mapping[str, Any],
    *,
    provider_bundle_identifier: str,
    network: Optional[M3NetworkSettings] = None,
) -> dict[str, Any]:
    """Build the app-side descriptor needed to install an iOS VPN profile."""

    cfg = m3_tunnel_config_from_profile(
        profile,
        provider_bundle_identifier=provider_bundle_identifier,
        network=network,
    )
    return {
        "profile_id": cfg.profile_id,
        "localized_description": cfg.display_name,
        "provider_bundle_identifier": cfg.provider_bundle_identifier,
        "server_address": cfg.server_address,
        "provider_configuration": provider_configuration_from_m3_config(cfg),
        "install_path": "NETunnelProviderManager",
    }


def provider_status_request_message(*, request_id: str = "status") -> dict[str, Any]:
    """Return the versioned app-message request payload for tunnel status."""

    return {
        "schema": M3_APP_MESSAGE_SCHEMA,
        "request_id": _required_string(request_id, "request_id"),
        "action": "status",
    }


def tunnel_status_from_provider_payload(payload: Mapping[str, Any]) -> M3TunnelStatus:
    """Decode a packet tunnel provider status payload.

    Supports both the current native raw `TunnelStatus` JSON object and a future
    versioned app-message envelope that stores the same object under `status`.
    """

    doc: Mapping[str, Any] = payload
    if str(payload.get("schema", "") or "").strip() == M3_APP_MESSAGE_SCHEMA:
        action = _required_string(payload.get("action"), "action").lower()
        if action != "status":
            raise ValueError(f"unsupported M3 app message action: {action}")
        nested = payload.get("status")
        if not isinstance(nested, Mapping):
            raise ValueError("status payload is required")
        doc = nested

    last_error = payload.get("last_error", "")
    if doc is not payload:
        last_error = doc.get("last_error", "")
    return M3TunnelStatus(
        state=_validate_tunnel_status_state(doc.get("state")),
        packets_from_system=_non_negative_int(doc.get("packetsFromSystem", doc.get("packets_from_system", 0)), "packets_from_system"),
        packets_to_system=_non_negative_int(doc.get("packetsToSystem", doc.get("packets_to_system", 0)), "packets_to_system"),
        bytes_from_system=_non_negative_int(doc.get("bytesFromSystem", doc.get("bytes_from_system", 0)), "bytes_from_system"),
        bytes_to_system=_non_negative_int(doc.get("bytesToSystem", doc.get("bytes_to_system", 0)), "bytes_to_system"),
        last_error=str(last_error or ""),
    )
