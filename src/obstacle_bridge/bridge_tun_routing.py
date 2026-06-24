from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence


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
DEFAULT_TUN_ROUTING_LOG = "CRITICAL"
DEFAULT_ENABLE_TCPMSS = False
DEFAULT_ENABLE_TUN_TCPDUMP = False
DEFAULT_TUN_TCPDUMP_PCAP_PATH = ""
DEFAULT_SHARED_TUN_DISABLE_OUTGOING_NORMALIZATION = False
DEFAULT_SHARED_TUN_DISABLE_INFLOW_FILTER = False
DEFAULT_SHARED_TUN_DISABLE_OUTFLOW_FILTER = False
DEFAULT_DISABLE_CHANNELMUX_INFLOW_THROTTLE = False
DEFAULT_SHARED_TUN_DISABLE_SCOPED_THROTTLE = False


def _clean_list(value: Any, *, default: list[str]) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return list(default)
        return [item.strip() for item in text.split(",") if item.strip()]
    return list(default)


def _clean_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
    return bool(default)


def _mapping_text_value(
    values: Mapping[str, Any],
    key: str,
    default: str,
    *,
    allow_empty: bool = False,
) -> str:
    if key not in values:
        return default
    raw = values.get(key)
    if raw is None:
        return default
    text = str(raw).strip()
    if text or allow_empty:
        return text
    return default


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


def _normalized_route_cidr(host: str) -> str:
    text = str(host or "").strip()
    if text.startswith("::ffff:"):
        mapped = text.split("::ffff:", 1)[1]
        try:
            return f"{ipaddress.IPv4Address(mapped)}/32"
        except ValueError:
            pass
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return f"{addr}/{'128' if addr.version == 6 else '32'}"


def _ipv4_mapped_ipv6_route_cidr(host: str) -> str:
    text = str(host or "").strip()
    if text.startswith("::ffff:"):
        text = text.split("::ffff:", 1)[1]
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return ""
    return f"::ffff:{addr}/128"


def _dedupe_routes(routes: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for route in routes:
        text = str(route or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def auto_overlay_peer_excluded_routes(config: Mapping[str, Any] | None) -> tuple[list[str], list[str]]:
    source = config or {}
    transport = str(source.get("overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
    if not transport:
        transport = "myudp"
    attr_map = {
        "myudp": ("udp_peer", "udp_peer_port", "udp_bind", "udp_peer_resolve_family"),
        "tcp": ("tcp_peer", "tcp_peer_port", "tcp_bind", "tcp_peer_resolve_family"),
        "quic": ("quic_peer", "quic_peer_port", "quic_bind", "quic_peer_resolve_family"),
        "ws": ("ws_peer", "ws_peer_port", "ws_bind", "ws_peer_resolve_family"),
    }
    peer_attr, port_attr, bind_attr, resolve_attr = attr_map.get(
        transport,
        ("udp_peer", "udp_peer_port", "udp_bind", "udp_peer_resolve_family"),
    )
    peer_host = str(source.get(peer_attr) or "").strip()
    if not peer_host:
        return ([], [])
    raw_port = source.get(port_attr)
    try:
        peer_port = int(raw_port if raw_port is not None else 0)
    except Exception:
        peer_port = 0
    if peer_port <= 0:
        return ([], [])
    resolve_mode = str(source.get(resolve_attr, "prefer-ipv6") or "prefer-ipv6").strip().lower()
    bind_host = str(source.get(bind_attr) or "").strip()
    try:
        from .bridge_transport_common import _resolve_peer_candidates, _split_configured_peer_hosts

        socktype = 1 if transport in {"tcp", "ws"} else 2  # SOCK_STREAM / SOCK_DGRAM
        candidates = []
        for configured_host in _split_configured_peer_hosts(peer_host):
            candidates.extend(
                _resolve_peer_candidates(
                    configured_host,
                    peer_port,
                    resolve_mode=resolve_mode,
                    socktype=socktype,
                    strict_family=False,
                )
            )
        if bind_host:
            import socket

            bind_family = socket.AF_INET6 if ":" in bind_host and bind_host != "::" else (
                socket.AF_INET if "." in bind_host and bind_host != "0.0.0.0" else socket.AF_UNSPEC
            )
            if bind_family != socket.AF_UNSPEC:
                compatible = [item for item in candidates if int(item[2]) == bind_family]
                if compatible:
                    candidates = compatible
    except Exception:
        return ([], [])
    routes4: list[str] = []
    routes6: list[str] = []
    for host, _port, _family in candidates:
        route = _normalized_route_cidr(str(host))
        if not route:
            continue
        if ":" in route:
            routes6.append(route)
        else:
            routes4.append(route)
            mapped_route = _ipv4_mapped_ipv6_route_cidr(str(host))
            if mapped_route:
                routes6.append(mapped_route)
    return (_dedupe_routes(routes4), _dedupe_routes(routes6))


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
    log_TUN_routing: str = DEFAULT_TUN_ROUTING_LOG
    enable_tcpmss: bool = DEFAULT_ENABLE_TCPMSS
    enable_tun_tcpdump: bool = DEFAULT_ENABLE_TUN_TCPDUMP
    tun_tcpdump_pcap_path: str = DEFAULT_TUN_TCPDUMP_PCAP_PATH
    shared_tun_disable_outgoing_normalization: bool = DEFAULT_SHARED_TUN_DISABLE_OUTGOING_NORMALIZATION
    shared_tun_disable_inflow_filter: bool = DEFAULT_SHARED_TUN_DISABLE_INFLOW_FILTER
    shared_tun_disable_outflow_filter: bool = DEFAULT_SHARED_TUN_DISABLE_OUTFLOW_FILTER
    disable_channelmux_inflow_throttle: bool = DEFAULT_DISABLE_CHANNELMUX_INFLOW_THROTTLE
    shared_tun_disable_scoped_throttle: bool = DEFAULT_SHARED_TUN_DISABLE_SCOPED_THROTTLE

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
        g.add_argument("--log-TUN-routing", dest="log_TUN_routing", default=DEFAULT_TUN_ROUTING_LOG, help="Log level for TUN routing hooks and helpers")
        g.add_argument("--enable-tcpmss", action="store_true", default=DEFAULT_ENABLE_TCPMSS, help="Enable TCPMSS clamp rules in generated TUN hook env")
        g.add_argument("--enable-tun-tcpdump", action="store_true", default=DEFAULT_ENABLE_TUN_TCPDUMP, help="Enable tcpdump capture in generated TUN hook env")
        g.add_argument("--tun-tcpdump-pcap-path", default=DEFAULT_TUN_TCPDUMP_PCAP_PATH, help="Optional pcap path for generated TUN tcpdump env")
        g.add_argument("--shared-tun-disable-outgoing-normalization", action="store_true", default=DEFAULT_SHARED_TUN_DISABLE_OUTGOING_NORMALIZATION, help="Disable shared-TUN local packet source normalization (diagnostic)")
        g.add_argument("--shared-tun-disable-inflow-filter", action="store_true", default=DEFAULT_SHARED_TUN_DISABLE_INFLOW_FILTER, help="Disable shared-TUN inbound ownership/source filter (diagnostic)")
        g.add_argument("--shared-tun-disable-outflow-filter", action="store_true", default=DEFAULT_SHARED_TUN_DISABLE_OUTFLOW_FILTER, help="Disable shared-TUN outbound route and relay filtering (diagnostic)")
        g.add_argument("--disable-channelmux-inflow-throttle", action="store_true", default=DEFAULT_DISABLE_CHANNELMUX_INFLOW_THROTTLE, help="Disable ChannelMux local ingress throttle for UDP and TUN (diagnostic)")
        g.add_argument("--shared-tun-disable-scoped-throttle", action="store_true", default=DEFAULT_SHARED_TUN_DISABLE_SCOPED_THROTTLE, help="Disable shared-TUN scoped inflow throttle (diagnostic)")

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
        disable_channelmux_inflow_throttle = _clean_bool(
            values.get("disable_channelmux_inflow_throttle"),
            default=current.disable_channelmux_inflow_throttle,
        )
        legacy_disable_scoped = _clean_bool(
            values.get("shared_tun_disable_scoped_throttle"),
            default=current.shared_tun_disable_scoped_throttle,
        )
        disable_channelmux_inflow_throttle = bool(
            disable_channelmux_inflow_throttle or legacy_disable_scoped
        )
        return cls(
            tunnel_address=_mapping_text_value(values, "tunnel_address", current.tunnel_address),
            tunnel_prefix=int(values.get("tunnel_prefix") or current.tunnel_prefix),
            tunnel_gateway=_mapping_text_value(values, "tunnel_gateway", current.tunnel_gateway, allow_empty=True),
            included_routes=_clean_list(values.get("included_routes"), default=list(current.included_routes)),
            excluded_routes=_clean_list(values.get("excluded_routes"), default=list(current.excluded_routes)),
            tunnel_address6=_mapping_text_value(values, "tunnel_address6", current.tunnel_address6),
            tunnel_prefix6=int(values.get("tunnel_prefix6") or current.tunnel_prefix6),
            tunnel_gateway6=_mapping_text_value(values, "tunnel_gateway6", current.tunnel_gateway6, allow_empty=True),
            included_routes6=_clean_list(values.get("included_routes6"), default=list(current.included_routes6)),
            excluded_routes6=_clean_list(values.get("excluded_routes6"), default=list(current.excluded_routes6)),
            dns_servers=_clean_list(values.get("dns_servers"), default=list(current.dns_servers)),
            mtu=int(values.get("mtu") or current.mtu),
            log_TUN_routing=_mapping_text_value(values, "log_TUN_routing", current.log_TUN_routing),
            enable_tcpmss=_clean_bool(values.get("enable_tcpmss"), default=current.enable_tcpmss),
            enable_tun_tcpdump=_clean_bool(values.get("enable_tun_tcpdump"), default=current.enable_tun_tcpdump),
            tun_tcpdump_pcap_path=_mapping_text_value(values, "tun_tcpdump_pcap_path", current.tun_tcpdump_pcap_path, allow_empty=True),
            shared_tun_disable_outgoing_normalization=_clean_bool(values.get("shared_tun_disable_outgoing_normalization"), default=current.shared_tun_disable_outgoing_normalization),
            shared_tun_disable_inflow_filter=_clean_bool(values.get("shared_tun_disable_inflow_filter"), default=current.shared_tun_disable_inflow_filter),
            shared_tun_disable_outflow_filter=_clean_bool(values.get("shared_tun_disable_outflow_filter"), default=current.shared_tun_disable_outflow_filter),
            disable_channelmux_inflow_throttle=disable_channelmux_inflow_throttle,
            shared_tun_disable_scoped_throttle=legacy_disable_scoped,
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

    def local_hook_env(
        self,
        *,
        extra_excluded_routes: Optional[Sequence[str]] = None,
        extra_excluded_routes6: Optional[Sequence[str]] = None,
    ) -> dict[str, str]:
        env: dict[str, str] = {
            "MTU": str(int(self.mtu)),
            "ENABLE_TCPMSS": "1" if self.enable_tcpmss else "0",
            "ENABLE_TUN_TCPDUMP": "1" if self.enable_tun_tcpdump else "0",
            "INCLUDED_ROUTES": ",".join(self.included_routes),
            "EXCLUDED_ROUTES": ",".join(self.excluded_routes),
            "INCLUDED_ROUTES6": ",".join(self.included_routes6),
            "EXCLUDED_ROUTES6": ",".join(self.excluded_routes6),
        }
        if self.tun_tcpdump_pcap_path:
            env["TCPDUMP_PCAP_PATH"] = self.tun_tcpdump_pcap_path
        if self.tunnel_address:
            env["TUN_ADDR"] = f"{self.tunnel_address}/{int(self.tunnel_prefix)}"
        gateway4 = self._local_gateway4()
        if gateway4:
            env["TUN_GW"] = gateway4
            env["PEER_ADDR"] = gateway4
        subnet4 = self._subnet4()
        if subnet4:
            env["TUN_SUBNET"] = subnet4
        if self.tunnel_address6:
            env["TUN_ADDR6"] = f"{self.tunnel_address6}/{int(self.tunnel_prefix6)}"
        gateway6 = self._local_gateway6()
        if gateway6:
            env["TUN_GW6"] = gateway6
            env["PEER_ADDR6"] = gateway6
        subnet6 = self._subnet6()
        if subnet6:
            env["TUN_SUBNET6"] = subnet6
        if self.dns_servers:
            env["DNS1"] = str(self.dns_servers[0])
        if len(self.dns_servers) > 1:
            env["DNS2"] = str(self.dns_servers[1])
        if self.included_routes:
            env["INCLUDED_ROUTES"] = ",".join(_dedupe_routes(self.included_routes))
        merged_excluded4 = _dedupe_routes([*self.excluded_routes, *(list(extra_excluded_routes or []))])
        if merged_excluded4:
            env["EXCLUDED_ROUTES"] = ",".join(merged_excluded4)
        if self.included_routes6:
            env["INCLUDED_ROUTES6"] = ",".join(_dedupe_routes(self.included_routes6))
        merged_excluded6 = _dedupe_routes([*self.excluded_routes6, *(list(extra_excluded_routes6 or []))])
        if merged_excluded6:
            env["EXCLUDED_ROUTES6"] = ",".join(merged_excluded6)
        return env

    def remote_hook_env(self) -> dict[str, str]:
        env: dict[str, str] = {
            "MTU": str(int(self.mtu)),
            "ENABLE_TCPMSS": "1" if self.enable_tcpmss else "0",
            "ENABLE_TUN_TCPDUMP": "1" if self.enable_tun_tcpdump else "0",
            "INCLUDED_ROUTES": ",".join(self.included_routes),
            "EXCLUDED_ROUTES": ",".join(self.excluded_routes),
            "INCLUDED_ROUTES6": ",".join(self.included_routes6),
            "EXCLUDED_ROUTES6": ",".join(self.excluded_routes6),
        }
        if self.tun_tcpdump_pcap_path:
            env["TCPDUMP_PCAP_PATH"] = self.tun_tcpdump_pcap_path
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
