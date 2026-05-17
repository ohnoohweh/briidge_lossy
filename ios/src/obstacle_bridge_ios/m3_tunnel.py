"""M3 packet tunnel profile and provider-configuration helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional


_TRANSPORT_PEER_KEYS = {
    "tcp": ("tcp_peer", "tcp_peer_port"),
    "ws": ("ws_peer", "ws_peer_port"),
    "myudp": ("udp_peer", "udp_peer_port"),
    "quic": ("quic_peer", "quic_peer_port"),
}
M3_TUNNEL_SCHEMA = "obstaclebridge.ios.packet-tunnel.v1"
M3_APP_MESSAGE_SCHEMA = "obstaclebridge.ios.packet-tunnel.app-message.v1"
M3_TUNNEL_STATUS_STATES = {"idle", "starting", "running", "stopping", "stopped", "failed"}
DEFAULT_IOS_TUNNEL_ADDRESS = "192.168.105.1"
DEFAULT_IOS_TUNNEL_PREFIX = 30
DEFAULT_IOS_INCLUDED_ROUTES = ["0.0.0.0/0"]
DEFAULT_IOS_EXCLUDED_ROUTES = ["127.0.0.0/8"]
DEFAULT_IOS_TUNNEL_ADDRESS6 = ""
DEFAULT_IOS_TUNNEL_PREFIX6 = 126
DEFAULT_IOS_INCLUDED_ROUTES6 = ["::/0"]
DEFAULT_IOS_EXCLUDED_ROUTES6 = ["::1/128"]
DEFAULT_IOS_TUN_IFNAME = "ios-utun"


@dataclass
class M3NetworkSettings:
    """Network settings the native Packet Tunnel Provider applies on start."""

    tunnel_address: str = DEFAULT_IOS_TUNNEL_ADDRESS
    tunnel_prefix: int = DEFAULT_IOS_TUNNEL_PREFIX
    included_routes: list[str] = field(default_factory=lambda: list(DEFAULT_IOS_INCLUDED_ROUTES))
    excluded_routes: list[str] = field(default_factory=lambda: list(DEFAULT_IOS_EXCLUDED_ROUTES))
    tunnel_address6: str = DEFAULT_IOS_TUNNEL_ADDRESS6
    tunnel_prefix6: int = DEFAULT_IOS_TUNNEL_PREFIX6
    included_routes6: list[str] = field(default_factory=list)
    excluded_routes6: list[str] = field(default_factory=list)
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
    runtime_config: dict[str, Any] = field(default_factory=dict)
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


def _service_catalog(config: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    channel_mux = config.get("channel_mux")
    if isinstance(channel_mux, Mapping):
        services = channel_mux.get(key)
    else:
        services = config.get(key)
    if not isinstance(services, list):
        return []
    return [item for item in services if isinstance(item, Mapping)]


def _iter_hook_env_blocks(service: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    hooks = service.get("lifecycle_hooks")
    if not isinstance(hooks, Mapping):
        return []
    listener = hooks.get("listener")
    if not isinstance(listener, Mapping):
        return []
    blocks: list[Mapping[str, Any]] = []
    for event in ("on_created", "on_channel_connected", "on_stopped"):
        command = listener.get(event)
        if not isinstance(command, Mapping):
            continue
        env = command.get("env")
        if isinstance(env, Mapping):
            blocks.append(env)
    return blocks


def _parse_interface_address(value: Any, *, version: Optional[int] = None) -> tuple[str, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        net = ipaddress.ip_interface(text)
    except ValueError:
        return None
    if version is not None and net.version != version:
        return None
    return str(net.ip), int(net.network.prefixlen)


def _prefix_from_subnet(value: Any, *, version: Optional[int] = None) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if version is not None and net.version != version:
        return None
    return int(net.prefixlen)


def network_settings_from_runtime_config(
    config: Mapping[str, Any],
    *,
    ios_ifname: str = DEFAULT_IOS_TUN_IFNAME,
    dns_servers: Optional[list[str]] = None,
    mtu: int = 1280,
) -> M3NetworkSettings:
    """Derive iOS packet-tunnel network settings from live ChannelMux TUN config.

    Preferred source is the local iOS TUN service hook env:
    `own_servers[].lifecycle_hooks.listener.on_created.env.TUN_ADDR`.

    For transition compatibility with existing profiles, this also falls back to
    a matching remote TUN service env using `PEER_ADDR` plus the prefix inferred
    from `TUN_ADDR` or `TUN_SUBNET`.
    """

    chosen_address = DEFAULT_IOS_TUNNEL_ADDRESS
    chosen_prefix = DEFAULT_IOS_TUNNEL_PREFIX
    chosen_address6 = DEFAULT_IOS_TUNNEL_ADDRESS6
    chosen_prefix6 = DEFAULT_IOS_TUNNEL_PREFIX6

    own_services = _service_catalog(config, "own_servers")
    remote_services = _service_catalog(config, "remote_servers")

    tun_services = [
        item
        for item in own_services
        if isinstance(item.get("listen"), Mapping)
        and str(item["listen"].get("protocol") or "").strip().lower() == "tun"
    ]
    tun_services.sort(
        key=lambda item: 0
        if str(item.get("listen", {}).get("ifname") or "").strip() == ios_ifname
        else 1
    )
    for service in tun_services:
        for env in _iter_hook_env_blocks(service):
            parsed4 = _parse_interface_address(env.get("TUN_ADDR"), version=4)
            parsed6 = _parse_interface_address(env.get("TUN_ADDR6"), version=6)
            if parsed4 is None and parsed6 is None:
                continue
            if parsed4 is not None:
                chosen_address, chosen_prefix = parsed4
            if parsed6 is not None:
                chosen_address6, chosen_prefix6 = parsed6
            return M3NetworkSettings(
                tunnel_address=chosen_address,
                tunnel_prefix=chosen_prefix,
                included_routes=list(DEFAULT_IOS_INCLUDED_ROUTES),
                excluded_routes=list(DEFAULT_IOS_EXCLUDED_ROUTES),
                tunnel_address6=chosen_address6,
                tunnel_prefix6=chosen_prefix6,
                included_routes6=list(DEFAULT_IOS_INCLUDED_ROUTES6) if chosen_address6 else [],
                excluded_routes6=list(DEFAULT_IOS_EXCLUDED_ROUTES6) if chosen_address6 else [],
                dns_servers=list(dns_servers or ["1.1.1.1"]),
                mtu=int(service.get("listen", {}).get("mtu") or mtu),
            )

    remote_tun_services = [
        item
        for item in remote_services
        if isinstance(item.get("listen"), Mapping)
        and str(item["listen"].get("protocol") or "").strip().lower() == "tun"
    ]
    remote_tun_services.sort(
        key=lambda item: 0
        if str(item.get("target", {}).get("ifname") or "").strip() == ios_ifname
        else 1
    )
    for service in remote_tun_services:
        for env in _iter_hook_env_blocks(service):
            peer_addr = str(env.get("PEER_ADDR") or "").strip()
            peer_addr6 = str(env.get("PEER_ADDR6") or "").strip()
            if peer_addr:
                try:
                    ip = ipaddress.ip_address(peer_addr)
                except ValueError:
                    ip = None
                if ip is not None and ip.version == 4:
                    prefix = (
                        (_parse_interface_address(env.get("TUN_ADDR"), version=4) or ("", None))[1]
                        or _prefix_from_subnet(env.get("TUN_SUBNET"), version=4)
                        or DEFAULT_IOS_TUNNEL_PREFIX
                    )
                    chosen_address = str(ip)
                    chosen_prefix = int(prefix)
            if peer_addr6:
                try:
                    ip6 = ipaddress.ip_address(peer_addr6)
                except ValueError:
                    ip6 = None
                if ip6 is not None and ip6.version == 6:
                    prefix6 = (
                        (_parse_interface_address(env.get("TUN_ADDR6"), version=6) or ("", None))[1]
                        or _prefix_from_subnet(env.get("TUN_SUBNET6"), version=6)
                        or DEFAULT_IOS_TUNNEL_PREFIX6
                    )
                    chosen_address6 = str(ip6)
                    chosen_prefix6 = int(prefix6)
            if not peer_addr and not peer_addr6:
                continue
            return M3NetworkSettings(
                tunnel_address=chosen_address,
                tunnel_prefix=chosen_prefix,
                included_routes=list(DEFAULT_IOS_INCLUDED_ROUTES),
                excluded_routes=list(DEFAULT_IOS_EXCLUDED_ROUTES),
                tunnel_address6=chosen_address6,
                tunnel_prefix6=chosen_prefix6,
                included_routes6=list(DEFAULT_IOS_INCLUDED_ROUTES6) if chosen_address6 else [],
                excluded_routes6=list(DEFAULT_IOS_EXCLUDED_ROUTES6) if chosen_address6 else [],
                dns_servers=list(dns_servers or ["1.1.1.1"]),
                mtu=int(service.get("target", {}).get("mtu") or service.get("listen", {}).get("mtu") or mtu),
            )

    return M3NetworkSettings(
        tunnel_address=chosen_address,
        tunnel_prefix=chosen_prefix,
        included_routes=list(DEFAULT_IOS_INCLUDED_ROUTES),
        excluded_routes=list(DEFAULT_IOS_EXCLUDED_ROUTES),
        tunnel_address6=chosen_address6,
        tunnel_prefix6=chosen_prefix6,
        included_routes6=list(DEFAULT_IOS_INCLUDED_ROUTES6) if chosen_address6 else [],
        excluded_routes6=list(DEFAULT_IOS_EXCLUDED_ROUTES6) if chosen_address6 else [],
        dns_servers=list(dns_servers or ["1.1.1.1"]),
        mtu=int(mtu),
    )


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
    if settings.tunnel_address6:
        ip6 = ipaddress.ip_address(settings.tunnel_address6)
        if ip6.version != 6:
            raise ValueError("tunnel_address6 must be IPv6")
        if not (1 <= int(settings.tunnel_prefix6) <= 128):
            raise ValueError("tunnel_prefix6 must be between 1 and 128")
    if not (576 <= int(settings.mtu) <= 9000):
        raise ValueError("mtu must be between 576 and 9000")
    for route in settings.included_routes:
        if ipaddress.ip_network(route, strict=False).version != 4:
            raise ValueError("included_routes must contain IPv4 networks")
    for route in settings.excluded_routes:
        if ipaddress.ip_network(route, strict=False).version != 4:
            raise ValueError("excluded_routes must contain IPv4 networks")
    for route in settings.included_routes6:
        if ipaddress.ip_network(route, strict=False).version != 6:
            raise ValueError("included_routes6 must contain IPv6 networks")
    for route in settings.excluded_routes6:
        if ipaddress.ip_network(route, strict=False).version != 6:
            raise ValueError("excluded_routes6 must contain IPv6 networks")
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
        runtime_config=dict(ob_cfg),
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
        "runtime_config": dict(cfg.runtime_config),
        "peer": {
            "host": _required_string(cfg.peer_host, "peer_host"),
            "port": _validate_port(cfg.peer_port, "peer_port"),
        },
        "network_settings": {
            "tunnel_address": cfg.network.tunnel_address,
            "tunnel_prefix": int(cfg.network.tunnel_prefix),
            "included_routes": list(cfg.network.included_routes),
            "excluded_routes": list(cfg.network.excluded_routes),
            "tunnel_address6": cfg.network.tunnel_address6,
            "tunnel_prefix6": int(cfg.network.tunnel_prefix6),
            "included_routes6": list(cfg.network.included_routes6),
            "excluded_routes6": list(cfg.network.excluded_routes6),
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
