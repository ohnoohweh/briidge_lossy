from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


TUN_ROUTING_SECTION = "TUN_routing"
DEFAULT_TUNNEL_ADDRESS = "192.168.106.1"
DEFAULT_TUNNEL_PREFIX = 30
DEFAULT_TUNNEL_GATEWAY = "192.168.106.2"
DEFAULT_INCLUDED_ROUTES = ["0.0.0.0/0"]
DEFAULT_EXCLUDED_ROUTES = ["127.0.0.0/8"]
DEFAULT_TUNNEL_ADDRESS6 = "fd20:106::1"
DEFAULT_TUNNEL_PREFIX6 = 126
DEFAULT_TUNNEL_GATEWAY6 = "fd20:106::2"
DEFAULT_INCLUDED_ROUTES6 = ["::/0"]
DEFAULT_EXCLUDED_ROUTES6 = ["::1/128"]
DEFAULT_DNS_SERVERS = ["1.1.1.1"]
DEFAULT_TUNNEL_MTU = 1600


def _clean_list(value: Any, *, default: list[str]) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return list(default)
        return [item.strip() for item in text.split(",") if item.strip()]
    return list(default)


def _other_host(address: str, prefix: int) -> str:
    text = str(address or "").strip()
    if not text:
        return ""
    try:
        iface = ipaddress.ip_interface(f"{text}/{int(prefix)}")
    except ValueError:
        return ""
    network = iface.network
    if int(network.num_addresses) > 8:
        return ""
    for host in network.hosts():
        if host != iface.ip:
            return str(host)
    return ""


@dataclass
class TunRoutingSettings:
    tunnel_address: str = DEFAULT_TUNNEL_ADDRESS
    tunnel_prefix: int = DEFAULT_TUNNEL_PREFIX
    tunnel_gateway: str = DEFAULT_TUNNEL_GATEWAY
    included_routes: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDED_ROUTES))
    excluded_routes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_ROUTES))
    tunnel_address6: str = DEFAULT_TUNNEL_ADDRESS6
    tunnel_prefix6: int = DEFAULT_TUNNEL_PREFIX6
    tunnel_gateway6: str = DEFAULT_TUNNEL_GATEWAY6
    included_routes6: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDED_ROUTES6))
    excluded_routes6: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_ROUTES6))
    dns_servers: list[str] = field(default_factory=lambda: list(DEFAULT_DNS_SERVERS))
    mtu: int = DEFAULT_TUNNEL_MTU

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        g = p.add_argument_group(TUN_ROUTING_SECTION)
        g.add_argument("--tunnel-address", default=DEFAULT_TUNNEL_ADDRESS, help="Local tunnel IPv4 address")
        g.add_argument("--tunnel-prefix", type=int, default=DEFAULT_TUNNEL_PREFIX, help="Local tunnel IPv4 prefix length")
        g.add_argument("--tunnel-gateway", default=DEFAULT_TUNNEL_GATEWAY, help="Peer tunnel IPv4 gateway address used as TUN_GW")
        g.add_argument("--included-routes", nargs="*", default=list(DEFAULT_INCLUDED_ROUTES), help="IPv4 routes included in tunnel routing")
        g.add_argument("--excluded-routes", nargs="*", default=list(DEFAULT_EXCLUDED_ROUTES), help="IPv4 routes excluded from tunnel routing")
        g.add_argument("--tunnel-address6", default=DEFAULT_TUNNEL_ADDRESS6, help="Local tunnel IPv6 address")
        g.add_argument("--tunnel-prefix6", type=int, default=DEFAULT_TUNNEL_PREFIX6, help="Local tunnel IPv6 prefix length")
        g.add_argument("--tunnel-gateway6", default=DEFAULT_TUNNEL_GATEWAY6, help="Peer tunnel IPv6 gateway address used as TUN_GW6")
        g.add_argument("--included-routes6", nargs="*", default=list(DEFAULT_INCLUDED_ROUTES6), help="IPv6 routes included in tunnel routing")
        g.add_argument("--excluded-routes6", nargs="*", default=list(DEFAULT_EXCLUDED_ROUTES6), help="IPv6 routes excluded from tunnel routing")
        g.add_argument("--dns-servers", nargs="*", default=list(DEFAULT_DNS_SERVERS), help="DNS servers applied to tunnel routing")
        g.add_argument("--mtu", type=int, default=DEFAULT_TUNNEL_MTU, help="Tunnel MTU")

    @classmethod
    def from_mapping(
        cls,
        config: Mapping[str, Any] | None,
        *,
        base: Optional["TunRoutingSettings"] = None,
    ) -> "TunRoutingSettings":
        current = base if base is not None else cls()
        source: Mapping[str, Any] = config or {}
        group = source.get(TUN_ROUTING_SECTION) if isinstance(source, Mapping) else None
        values = group if isinstance(group, Mapping) else source
        return cls(
            tunnel_address=str(values.get("tunnel_address") or current.tunnel_address).strip() or current.tunnel_address,
            tunnel_prefix=int(values.get("tunnel_prefix") or current.tunnel_prefix),
            tunnel_gateway=str(values.get("tunnel_gateway") or current.tunnel_gateway).strip() or current.tunnel_gateway,
            included_routes=_clean_list(values.get("included_routes"), default=list(current.included_routes)),
            excluded_routes=_clean_list(values.get("excluded_routes"), default=list(current.excluded_routes)),
            tunnel_address6=str(values.get("tunnel_address6") or current.tunnel_address6).strip() or current.tunnel_address6,
            tunnel_prefix6=int(values.get("tunnel_prefix6") or current.tunnel_prefix6),
            tunnel_gateway6=str(values.get("tunnel_gateway6") or current.tunnel_gateway6).strip() or current.tunnel_gateway6,
            included_routes6=_clean_list(values.get("included_routes6"), default=list(current.included_routes6)),
            excluded_routes6=_clean_list(values.get("excluded_routes6"), default=list(current.excluded_routes6)),
            dns_servers=_clean_list(values.get("dns_servers"), default=list(current.dns_servers)),
            mtu=int(values.get("mtu") or current.mtu),
        )

    def _local_gateway4(self) -> str:
        return self.tunnel_gateway or _other_host(self.tunnel_address, self.tunnel_prefix)

    def _local_gateway6(self) -> str:
        return self.tunnel_gateway6 or _other_host(self.tunnel_address6, self.tunnel_prefix6)

    def _subnet4(self) -> str:
        try:
            return str(ipaddress.ip_network(f"{self.tunnel_address}/{int(self.tunnel_prefix)}", strict=False))
        except ValueError:
            return ""

    def _subnet6(self) -> str:
        if not str(self.tunnel_address6 or "").strip():
            return ""
        try:
            return str(ipaddress.ip_network(f"{self.tunnel_address6}/{int(self.tunnel_prefix6)}", strict=False))
        except ValueError:
            return ""

    def local_hook_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.tunnel_address:
            env["TUN_ADDR"] = f"{self.tunnel_address}/{int(self.tunnel_prefix)}"
        gateway4 = self._local_gateway4()
        if gateway4:
            env["TUN_GW"] = gateway4
        if self.tunnel_address6:
            env["TUN_ADDR6"] = f"{self.tunnel_address6}/{int(self.tunnel_prefix6)}"
        gateway6 = self._local_gateway6()
        if gateway6:
            env["TUN_GW6"] = gateway6
        if self.dns_servers:
            env["DNS1"] = str(self.dns_servers[0])
        if len(self.dns_servers) > 1:
            env["DNS2"] = str(self.dns_servers[1])
        return env

    def remote_hook_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        gateway4 = self._local_gateway4()
        if gateway4:
            env["TUN_ADDR"] = f"{gateway4}/{int(self.tunnel_prefix)}"
        if self.tunnel_address:
            env["PEER_ADDR"] = self.tunnel_address
        subnet4 = self._subnet4()
        if subnet4:
            env["TUN_SUBNET"] = subnet4
        gateway6 = self._local_gateway6()
        if gateway6:
            env["TUN_ADDR6"] = f"{gateway6}/{int(self.tunnel_prefix6)}"
        if self.tunnel_address6:
            env["PEER_ADDR6"] = self.tunnel_address6
        subnet6 = self._subnet6()
        if subnet6:
            env["TUN_SUBNET6"] = subnet6
        return env