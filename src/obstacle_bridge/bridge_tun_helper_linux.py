from __future__ import annotations

import contextlib
import inspect
import asyncio
import ipaddress
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Awaitable, Callable, Optional

try:
    import fcntl
except Exception:
    fcntl = None


_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001
_IFF_NO_PI = 0x1000
_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_SIOCSIFMTU = 0x8922
_IFF_UP = 0x1
_IFF_RUNNING = 0x40


def _tun_ifreq_name(name: str) -> bytes:
    return str(name).encode("utf-8", "ignore")[:15].ljust(16, b"\x00")


class LinuxTunHelperBackend:
    """Linux helper backend that owns a real /dev/net/tun descriptor."""

    def __init__(self, *, read_poll_interval_s: float = 0.01) -> None:
        self._packet_sink: Optional[Callable[[bytes], Awaitable[None] | None]] = None
        self._fd: Optional[int] = None
        self._opened = False
        self._ifname = ""
        self._mtu = 0
        self._packets_from_runtime = 0
        self._packets_to_runtime = 0
        self._stopped = False
        self._reader_task: Optional[asyncio.Task] = None
        self._read_poll_interval_s = float(read_poll_interval_s)
        self._network_applied = False
        self._apply_calls = 0
        self._remove_calls = 0
        self._last_apply_payload: dict[str, Any] = {}
        self._last_remove_payload: dict[str, Any] = {}
        self._applied_ipv4_cidr = ""
        self._applied_ipv6_cidr = ""
        self._applied_ipv4_routes: list[str] = []
        self._applied_ipv6_routes: list[str] = []
        self._applied_excluded_ipv4_routes: list[str] = []
        self._applied_excluded_ipv6_routes: list[str] = []
        self._saved_underlay4: dict[str, str] = {}
        self._saved_underlay6: dict[str, str] = {}
        self._policy_table4 = 0
        self._policy_table6 = 0
        self._policy_rules4: list[str] = []
        self._policy_rules6: list[str] = []
        self._applied_dns_servers: list[str] = []
        self._dns_manager = ""
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules: list[str] = []
        self._last_failure: dict[str, Any] = {}
        self._test_failure_consumed: set[tuple[str, str, str]] = set()

    @staticmethod
    def _resolvectl_path() -> str:
        return str(shutil.which("resolvectl") or "").strip()

    def set_packet_sink(self, sink: Callable[[bytes], Awaitable[None] | None]) -> None:
        self._packet_sink = sink
        if self._opened and self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_loop())

    @staticmethod
    def _require_linux_tun_support() -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("Linux native TUN helper backend is supported only on Linux")
        if fcntl is None:
            raise RuntimeError("Linux native TUN helper backend requires fcntl support")

    def _set_iface_mtu(self, ifname: str, mtu: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            ifr = struct.pack("16sI12x", _tun_ifreq_name(ifname), int(mtu))
            fcntl.ioctl(sock.fileno(), _SIOCSIFMTU, ifr)

    def _set_iface_up(self, ifname: str) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            req = _tun_ifreq_name(ifname) + (b"\x00" * 24)
            res = fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, req)
            flags = struct.unpack("16xH", res[:18])[0]
            ifr = struct.pack("16sH14x", _tun_ifreq_name(ifname), flags | _IFF_UP | _IFF_RUNNING)
            fcntl.ioctl(sock.fileno(), _SIOCSIFFLAGS, ifr)

    @staticmethod
    def _run_ip(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ip", *args],
            check=check,
            capture_output=True,
            text=True,
        )

    @classmethod
    def _run_resolvectl(cls, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        binary = cls._resolvectl_path()
        if not binary:
            raise RuntimeError("resolvectl is not available")
        return subprocess.run(
            [binary, *args],
            check=check,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _run_command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*args],
            check=check,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _cidr_from_tun_routing(payload: dict[str, Any], key: str, prefix_key: str) -> str:
        tun_routing = payload.get("tun_routing")
        values = tun_routing if isinstance(tun_routing, dict) else {}
        address = str(values.get(key) or "").strip()
        if not address:
            return ""
        prefix = int(values.get(prefix_key) or 0)
        if prefix <= 0:
            return ""
        return f"{address}/{prefix}"

    @staticmethod
    def _list_from_tun_routing(payload: dict[str, Any], key: str) -> list[str]:
        tun_routing = payload.get("tun_routing")
        values = tun_routing if isinstance(tun_routing, dict) else {}
        raw = values.get(key)
        if isinstance(raw, list):
            items = [str(item or "").strip() for item in raw]
        elif isinstance(raw, str):
            items = [part.strip() for part in raw.split(",")]
        else:
            items = []
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    @staticmethod
    def _gateway_from_tun_routing(payload: dict[str, Any], *, address_key: str, prefix_key: str, gateway_key: str) -> str:
        tun_routing = payload.get("tun_routing")
        values = tun_routing if isinstance(tun_routing, dict) else {}
        explicit = str(values.get(gateway_key) or "").strip()
        if explicit:
            return explicit
        cidr = LinuxTunHelperBackend._cidr_from_tun_routing(payload, address_key, prefix_key)
        if not cidr:
            return ""
        try:
            iface = ipaddress.ip_interface(cidr)
            network = iface.network
            for candidate in network.hosts():
                if candidate != iface.ip:
                    return str(candidate)
        except Exception:
            return ""
        return ""

    @staticmethod
    def _subnet_from_tun_routing(payload: dict[str, Any], key: str, prefix_key: str) -> str:
        cidr = LinuxTunHelperBackend._cidr_from_tun_routing(payload, key, prefix_key)
        if not cidr:
            return ""
        with contextlib.suppress(Exception):
            return str(ipaddress.ip_interface(cidr).network)
        return ""

    @staticmethod
    def _is_default_route(route_spec: str) -> bool:
        normalized = str(route_spec or "").strip().lower()
        return normalized in {"0.0.0.0/0", "::/0", "::0/0", "default"}

    @staticmethod
    def _route_specs_for_helper(
        payload: dict[str, Any],
        *,
        list_key: str,
        local_cidr: str,
    ) -> list[str]:
        routes = LinuxTunHelperBackend._list_from_tun_routing(payload, list_key)
        out: list[str] = []
        local_network = ""
        if local_cidr:
            with contextlib.suppress(ValueError):
                local_network = str(ipaddress.ip_network(local_cidr, strict=False))
        for route_spec in routes:
            if LinuxTunHelperBackend._is_default_route(route_spec):
                continue
            with contextlib.suppress(ValueError):
                normalized = str(ipaddress.ip_network(route_spec, strict=False))
                if local_network and normalized == local_network:
                    continue
                route_spec = normalized
            if route_spec not in out:
                out.append(route_spec)
        return out

    @staticmethod
    def _parse_route_show(text: str) -> dict[str, str]:
        parts = str(text or "").strip().split()
        out: dict[str, str] = {}
        if not parts:
            return out
        if parts[0] == "default":
            out["route"] = "default"
        else:
            out["route"] = parts[0]
        for idx, token in enumerate(parts[:-1]):
            if token in {"via", "dev", "src"}:
                out[token] = parts[idx + 1]
        return out

    def _snapshot_default_route(self, family_flag: str) -> dict[str, str]:
        result = self._run_ip(family_flag, "route", "show", "default", check=False)
        lines = [line.strip() for line in str(result.stdout or "").splitlines() if line.strip()]
        for line in lines:
            if self._ifname and f" dev {self._ifname}" in f" {line} ":
                continue
            parsed = self._parse_route_show(line)
            if parsed:
                return parsed
        return {}

    @staticmethod
    def _route_spec_matches_loopback(route_spec: str, *, family: int) -> bool:
        with contextlib.suppress(ValueError):
            network = ipaddress.ip_network(route_spec, strict=False)
            if int(network.version) != int(family):
                return False
            if family == 4:
                return network.subnet_of(ipaddress.ip_network("127.0.0.0/8"))
            return network.subnet_of(ipaddress.ip_network("::1/128"))
        return False

    @staticmethod
    def _policy_table_id(ifname: str, *, family: int) -> int:
        base = 20000 if int(family) == 4 else 21000
        folded = sum(ord(ch) for ch in str(ifname or "")) % 500
        return base + folded

    @staticmethod
    def _dedupe_route_specs(route_specs: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for route_spec in route_specs:
            with contextlib.suppress(ValueError):
                route_spec = str(ipaddress.ip_network(route_spec, strict=False))
            if not route_spec or route_spec in seen:
                continue
            seen.add(route_spec)
            out.append(route_spec)
        return out

    def _connected_routes(self, family_flag: str, *, dev: str, proto_kernel_only: bool, scope_link: bool) -> list[str]:
        if not str(dev or "").strip():
            return []
        args = [family_flag, "route", "show", "dev", dev]
        if proto_kernel_only:
            args.extend(["proto", "kernel"])
        if scope_link:
            args.extend(["scope", "link"])
        result = self._run_ip(*args, check=False)
        out: list[str] = []
        for line in str(result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_route_show(line)
            route_spec = parsed.get("route", "")
            if not route_spec or route_spec == "default":
                continue
            out.append(route_spec)
        return self._dedupe_route_specs(out)

    def _policy_rule_add(self, family_flag: str, pref: int, route_spec: str, table: str) -> str:
        spec = f"to {route_spec} lookup {table}"
        self._run_ip(family_flag, "rule", "add", "pref", str(pref), "to", route_spec, "lookup", table)
        return spec

    def _delete_policy_rules(self, family_flag: str, table_id: int, stored_specs: list[str]) -> None:
        for idx, spec in enumerate(list(stored_specs)):
            pref = (10000 if family_flag == "-4" else 11000) + idx
            args = [family_flag, "rule", "del", "pref", str(pref), *str(spec).split()]
            self._run_ip(*args, check=False)
        self._run_ip(family_flag, "route", "flush", "table", str(table_id), check=False)

    def _configure_policy_full_tunnel(self, payload: dict[str, Any], *, ifname: str, family_flag: str) -> None:
        is_v4 = family_flag == "-4"
        gateway = self._gateway_from_tun_routing(
            payload,
            address_key="tunnel_address" if is_v4 else "tunnel_address6",
            prefix_key="tunnel_prefix" if is_v4 else "tunnel_prefix6",
            gateway_key="tunnel_gateway" if is_v4 else "tunnel_gateway6",
        )
        if not gateway:
            return
        table_id = self._policy_table_id(ifname, family=4 if is_v4 else 6)
        base_pref = 10000 if is_v4 else 11000
        route_replace = [family_flag, "route", "replace", "table", str(table_id), "default", "via", gateway, "dev", ifname]
        if is_v4:
            route_replace.append("onlink")
        else:
            route_replace.extend(["metric", "1", "onlink"])
        self._run_ip(*route_replace)

        underlay = self._saved_underlay4 if is_v4 else self._saved_underlay6
        excluded = self._applied_excluded_ipv4_routes if is_v4 else self._applied_excluded_ipv6_routes
        bypass_routes = self._dedupe_route_specs(
            [
                *(self._connected_routes(family_flag, dev=str(underlay.get("dev") or ""), proto_kernel_only=True, scope_link=is_v4) if underlay.get("dev") else []),
                *self._connected_routes(family_flag, dev=ifname, proto_kernel_only=True, scope_link=is_v4),
                *excluded,
            ]
        )
        stored_specs: list[str] = []
        for idx, route_spec in enumerate(bypass_routes):
            stored_specs.append(self._policy_rule_add(family_flag, base_pref + idx, route_spec, "main"))
        stored_specs.append(self._policy_rule_add(
            family_flag,
            base_pref + len(bypass_routes),
            "0.0.0.0/0" if is_v4 else "::/0",
            str(table_id),
        ))
        if is_v4:
            self._policy_table4 = table_id
            self._policy_rules4 = stored_specs
        else:
            self._policy_table6 = table_id
            self._policy_rules6 = stored_specs

    def _apply_included_routes(self, payload: dict[str, Any], *, ifname: str) -> None:
        gateway4 = self._gateway_from_tun_routing(
            payload,
            address_key="tunnel_address",
            prefix_key="tunnel_prefix",
            gateway_key="tunnel_gateway",
        )
        gateway6 = self._gateway_from_tun_routing(
            payload,
            address_key="tunnel_address6",
            prefix_key="tunnel_prefix6",
            gateway_key="tunnel_gateway6",
        )
        self._applied_ipv4_routes = self._route_specs_for_helper(
            payload,
            list_key="included_routes",
            local_cidr=self._applied_ipv4_cidr,
        )
        self._applied_ipv6_routes = self._route_specs_for_helper(
            payload,
            list_key="included_routes6",
            local_cidr=self._applied_ipv6_cidr,
        )
        wants_default4 = any(self._is_default_route(item) for item in self._list_from_tun_routing(payload, "included_routes"))
        wants_default6 = any(self._is_default_route(item) for item in self._list_from_tun_routing(payload, "included_routes6"))
        for route_spec in self._applied_ipv4_routes:
            if gateway4:
                self._run_ip("-4", "route", "replace", route_spec, "via", gateway4, "dev", ifname, "onlink")
            else:
                self._run_ip("-4", "route", "replace", route_spec, "dev", ifname)
        for route_spec in self._applied_ipv6_routes:
            if gateway6:
                self._run_ip("-6", "route", "replace", route_spec, "via", gateway6, "dev", ifname, "metric", "1", "onlink")
            else:
                self._run_ip("-6", "route", "replace", route_spec, "dev", ifname, "metric", "1")
        if wants_default4:
            self._configure_policy_full_tunnel(payload, ifname=ifname, family_flag="-4")
        if wants_default6:
            self._configure_policy_full_tunnel(payload, ifname=ifname, family_flag="-6")

    def _remove_included_routes(self, payload: dict[str, Any], *, ifname: str) -> None:
        gateway4 = self._gateway_from_tun_routing(
            payload,
            address_key="tunnel_address",
            prefix_key="tunnel_prefix",
            gateway_key="tunnel_gateway",
        )
        gateway6 = self._gateway_from_tun_routing(
            payload,
            address_key="tunnel_address6",
            prefix_key="tunnel_prefix6",
            gateway_key="tunnel_gateway6",
        )
        for route_spec in list(self._applied_ipv4_routes):
            if gateway4:
                self._run_ip("-4", "route", "del", route_spec, "via", gateway4, "dev", ifname, check=False)
            self._run_ip("-4", "route", "del", route_spec, "dev", ifname, check=False)
        for route_spec in list(self._applied_ipv6_routes):
            if gateway6:
                self._run_ip("-6", "route", "del", route_spec, "via", gateway6, "dev", ifname, check=False)
            self._run_ip("-6", "route", "del", route_spec, "dev", ifname, check=False)
        if self._policy_table4 and self._policy_rules4:
            self._delete_policy_rules("-4", self._policy_table4, self._policy_rules4)
        if self._policy_table6 and self._policy_rules6:
            self._delete_policy_rules("-6", self._policy_table6, self._policy_rules6)
        self._applied_ipv4_routes = []
        self._applied_ipv6_routes = []
        self._policy_rules4 = []
        self._policy_rules6 = []

    def _apply_excluded_routes(self, payload: dict[str, Any], *, ifname: str) -> None:
        del ifname
        routes4 = self._list_from_tun_routing(payload, "excluded_routes")
        routes6 = self._list_from_tun_routing(payload, "excluded_routes6")
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []

        underlay4 = dict(self._saved_underlay4)
        if underlay4.get("dev"):
            for route_spec in routes4:
                if self._route_spec_matches_loopback(route_spec, family=4):
                    continue
                if underlay4.get("via"):
                    args = ["-4", "route", "replace", route_spec, "via", underlay4["via"], "dev", underlay4["dev"]]
                    if underlay4.get("src"):
                        args.extend(["src", underlay4["src"]])
                    self._run_ip(*args)
                else:
                    args = ["-4", "route", "replace", route_spec, "dev", underlay4["dev"]]
                    if underlay4.get("src"):
                        args.extend(["src", underlay4["src"]])
                    self._run_ip(*args)
                self._applied_excluded_ipv4_routes.append(route_spec)

        underlay6 = dict(self._saved_underlay6)
        if underlay6.get("dev"):
            for route_spec in routes6:
                if self._route_spec_matches_loopback(route_spec, family=6):
                    continue
                if underlay6.get("via"):
                    self._run_ip("-6", "route", "replace", route_spec, "via", underlay6["via"], "dev", underlay6["dev"])
                else:
                    self._run_ip("-6", "route", "replace", route_spec, "dev", underlay6["dev"])
                self._applied_excluded_ipv6_routes.append(route_spec)

    def _remove_excluded_routes(self) -> None:
        for route_spec in list(self._applied_excluded_ipv4_routes):
            self._run_ip("-4", "route", "del", route_spec, check=False)
        for route_spec in list(self._applied_excluded_ipv6_routes):
            self._run_ip("-6", "route", "del", route_spec, check=False)
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []

    def _apply_dns(self, payload: dict[str, Any], *, ifname: str) -> None:
        dns_servers = self._list_from_tun_routing(payload, "dns_servers")
        self._applied_dns_servers = []
        self._dns_manager = ""
        if not dns_servers:
            return
        if not self._resolvectl_path():
            return
        self._run_resolvectl("dns", ifname, *dns_servers)
        self._run_resolvectl("domain", ifname, "~.")
        self._run_resolvectl("default-route", ifname, "yes")
        self._applied_dns_servers = list(dns_servers)
        self._dns_manager = "resolvectl"

    @staticmethod
    def _listener_hook_env(payload: dict[str, Any]) -> dict[str, str]:
        raw = payload.get("listener_hook_env")
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for key, value in raw.items():
            text_key = str(key or "").strip()
            if not text_key:
                continue
            out[text_key] = str(value or "").strip()
        return out

    @staticmethod
    def _service_catalog(payload: dict[str, Any]) -> str:
        return str(payload.get("service_catalog") or "").strip().lower()

    @classmethod
    def _iptables_args(cls, binary: str, table: str, op: str, chain: str, rule: list[str]) -> list[str]:
        args = [binary]
        if table:
            args.extend(["-t", table])
        args.extend([op, chain, *rule])
        return args

    @classmethod
    def _iptables_rule_exists(cls, binary: str, table: str, chain: str, rule: list[str]) -> bool:
        result = cls._run_command(*cls._iptables_args(binary, table, "-C", chain, rule), check=False)
        return int(getattr(result, "returncode", 1)) == 0

    @classmethod
    def _iptables_add_unique(cls, binary: str, table: str, chain: str, rule: list[str]) -> None:
        if cls._iptables_rule_exists(binary, table, chain, rule):
            return
        cls._run_command(*cls._iptables_args(binary, table, "-A", chain, rule))

    @classmethod
    def _iptables_delete_if_exists(cls, binary: str, table: str, chain: str, rule: list[str]) -> None:
        while cls._iptables_rule_exists(binary, table, chain, rule):
            cls._run_command(*cls._iptables_args(binary, table, "-D", chain, rule), check=False)

    def _apply_firewall(self, payload: dict[str, Any], *, ifname: str) -> None:
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []
        listener_env = self._listener_hook_env(payload)
        wan_if = str(listener_env.get("WAN_IF") or "").strip()
        if not wan_if or wan_if.lower() == "auto":
            return
        subnet4 = self._subnet_from_tun_routing(payload, "tunnel_address", "tunnel_prefix")
        subnet6 = self._subnet_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6")
        enable_tcpmss = bool(payload.get("tun_routing", {}).get("enable_tcpmss")) if isinstance(payload.get("tun_routing"), dict) else False
        if not subnet4 and not subnet6:
            return
        if subnet4:
            self._run_command("sysctl", "-w", "net.ipv4.ip_forward=1")
            ipv4_rules = [
                ("iptables", "", "FORWARD", ["-i", ifname, "-o", wan_if, "-j", "ACCEPT"]),
                ("iptables", "", "FORWARD", ["-i", wan_if, "-o", ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
                ("iptables", "nat", "POSTROUTING", ["-s", subnet4, "-o", wan_if, "-j", "MASQUERADE"]),
            ]
            if enable_tcpmss:
                ipv4_rules.extend(
                    [
                        ("iptables", "mangle", "FORWARD", ["-i", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                        ("iptables", "mangle", "FORWARD", ["-o", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                    ]
                )
            for binary, table, chain, rule in ipv4_rules:
                self._iptables_add_unique(binary, table, chain, rule)
                self._applied_firewall_rules.append(" ".join(self._iptables_args(binary, table, "-A", chain, rule)))
        if subnet6:
            self._run_command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
            ipv6_rules = [
                ("ip6tables", "", "FORWARD", ["-i", ifname, "-o", wan_if, "-j", "ACCEPT"]),
                ("ip6tables", "", "FORWARD", ["-i", wan_if, "-o", ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
                ("ip6tables", "nat", "POSTROUTING", ["-s", subnet6, "-o", wan_if, "-j", "MASQUERADE"]),
            ]
            if enable_tcpmss:
                ipv6_rules.extend(
                    [
                        ("ip6tables", "mangle", "FORWARD", ["-i", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                        ("ip6tables", "mangle", "FORWARD", ["-o", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                    ]
                )
            for binary, table, chain, rule in ipv6_rules:
                self._iptables_add_unique(binary, table, chain, rule)
                self._applied_firewall_rules.append(" ".join(self._iptables_args(binary, table, "-A", chain, rule)))
        self._firewall_manager = "iptables"
        self._firewall_wan_if = wan_if

    def _remove_firewall(self, payload: dict[str, Any], *, ifname: str) -> None:
        listener_env = self._listener_hook_env(payload)
        wan_if = str(listener_env.get("WAN_IF") or self._firewall_wan_if or "").strip()
        if not wan_if:
            self._firewall_manager = ""
            self._firewall_wan_if = ""
            self._applied_firewall_rules = []
            return
        subnet4 = self._subnet_from_tun_routing(payload, "tunnel_address", "tunnel_prefix")
        subnet6 = self._subnet_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6")
        enable_tcpmss = bool(payload.get("tun_routing", {}).get("enable_tcpmss")) if isinstance(payload.get("tun_routing"), dict) else False
        if subnet4:
            ipv4_rules = [
                ("iptables", "", "FORWARD", ["-i", ifname, "-o", wan_if, "-j", "ACCEPT"]),
                ("iptables", "", "FORWARD", ["-i", wan_if, "-o", ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
                ("iptables", "nat", "POSTROUTING", ["-s", subnet4, "-o", wan_if, "-j", "MASQUERADE"]),
            ]
            if enable_tcpmss:
                ipv4_rules.extend(
                    [
                        ("iptables", "mangle", "FORWARD", ["-i", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                        ("iptables", "mangle", "FORWARD", ["-o", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                    ]
                )
            for binary, table, chain, rule in ipv4_rules:
                self._iptables_delete_if_exists(binary, table, chain, rule)
        if subnet6:
            ipv6_rules = [
                ("ip6tables", "", "FORWARD", ["-i", ifname, "-o", wan_if, "-j", "ACCEPT"]),
                ("ip6tables", "", "FORWARD", ["-i", wan_if, "-o", ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
                ("ip6tables", "nat", "POSTROUTING", ["-s", subnet6, "-o", wan_if, "-j", "MASQUERADE"]),
            ]
            if enable_tcpmss:
                ipv6_rules.extend(
                    [
                        ("ip6tables", "mangle", "FORWARD", ["-i", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                        ("ip6tables", "mangle", "FORWARD", ["-o", ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
                    ]
                )
            for binary, table, chain, rule in ipv6_rules:
                self._iptables_delete_if_exists(binary, table, chain, rule)
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []

    def _remove_dns(self, *, ifname: str) -> None:
        if not self._applied_dns_servers:
            self._dns_manager = ""
            return
        with contextlib.suppress(Exception):
            self._run_resolvectl("revert", ifname, check=False)
        self._applied_dns_servers = []
        self._dns_manager = ""

    def _clear_last_failure(self) -> None:
        self._last_failure = {}

    @staticmethod
    def _split_cidr(cidr: str) -> tuple[str, int]:
        text = str(cidr or "").strip()
        if not text or "/" not in text:
            return "", 0
        addr, _, prefix_text = text.partition("/")
        with contextlib.suppress(Exception):
            prefix = int(prefix_text)
            if addr:
                return addr, prefix
        return "", 0

    @classmethod
    def _payload_from_runtime_snapshot(cls, runtime_snapshot: dict[str, Any]) -> dict[str, Any]:
        runtime = dict(runtime_snapshot or {})
        payload = dict(runtime.get("last_apply_payload") or {})
        tun_routing = payload.get("tun_routing")
        if not isinstance(tun_routing, dict):
            tun_routing = {}
        tun_routing = dict(tun_routing)

        ipv4_addr, ipv4_prefix = cls._split_cidr(str(runtime.get("applied_ipv4_cidr") or ""))
        if ipv4_addr and ipv4_prefix > 0:
            tun_routing.setdefault("tunnel_address", ipv4_addr)
            tun_routing.setdefault("tunnel_prefix", ipv4_prefix)
        ipv6_addr, ipv6_prefix = cls._split_cidr(str(runtime.get("applied_ipv6_cidr") or ""))
        if ipv6_addr and ipv6_prefix > 0:
            tun_routing.setdefault("tunnel_address6", ipv6_addr)
            tun_routing.setdefault("tunnel_prefix6", ipv6_prefix)

        if runtime.get("applied_ipv4_routes") and "included_routes" not in tun_routing:
            tun_routing["included_routes"] = list(runtime.get("applied_ipv4_routes") or [])
        if runtime.get("applied_ipv6_routes") and "included_routes6" not in tun_routing:
            tun_routing["included_routes6"] = list(runtime.get("applied_ipv6_routes") or [])
        if runtime.get("applied_excluded_ipv4_routes") and "excluded_routes" not in tun_routing:
            tun_routing["excluded_routes"] = list(runtime.get("applied_excluded_ipv4_routes") or [])
        if runtime.get("applied_excluded_ipv6_routes") and "excluded_routes6" not in tun_routing:
            tun_routing["excluded_routes6"] = list(runtime.get("applied_excluded_ipv6_routes") or [])
        if runtime.get("applied_dns_servers") and "dns_servers" not in tun_routing:
            tun_routing["dns_servers"] = list(runtime.get("applied_dns_servers") or [])
        if "enable_tcpmss" not in tun_routing:
            tun_routing["enable_tcpmss"] = any("TCPMSS" in str(rule or "") for rule in list(runtime.get("applied_firewall_rules") or []))

        payload["tun_routing"] = tun_routing
        payload.setdefault("ifname", str(runtime.get("ifname") or ""))
        listener_hook_env = payload.get("listener_hook_env")
        if not isinstance(listener_hook_env, dict):
            listener_hook_env = {}
        listener_hook_env = dict(listener_hook_env)
        wan_if = str(runtime.get("firewall_wan_if") or "").strip()
        if wan_if and "WAN_IF" not in listener_hook_env:
            listener_hook_env["WAN_IF"] = wan_if
        if listener_hook_env:
            payload["listener_hook_env"] = listener_hook_env
        return payload

    def _restore_runtime_snapshot(self, runtime_snapshot: dict[str, Any]) -> None:
        runtime = dict(runtime_snapshot or {})
        self._ifname = str(runtime.get("ifname") or "")
        self._mtu = int(runtime.get("mtu") or 0)
        self._opened = bool(runtime.get("opened"))
        self._packets_from_runtime = int(runtime.get("packets_from_runtime") or 0)
        self._packets_to_runtime = int(runtime.get("packets_to_runtime") or 0)
        self._network_applied = bool(runtime.get("network_applied"))
        self._apply_calls = int(runtime.get("apply_calls") or 0)
        self._remove_calls = int(runtime.get("remove_calls") or 0)
        self._last_apply_payload = dict(runtime.get("last_apply_payload") or {})
        self._last_remove_payload = dict(runtime.get("last_remove_payload") or {})
        self._applied_ipv4_cidr = str(runtime.get("applied_ipv4_cidr") or "")
        self._applied_ipv6_cidr = str(runtime.get("applied_ipv6_cidr") or "")
        self._applied_ipv4_routes = list(runtime.get("applied_ipv4_routes") or [])
        self._applied_ipv6_routes = list(runtime.get("applied_ipv6_routes") or [])
        self._applied_excluded_ipv4_routes = list(runtime.get("applied_excluded_ipv4_routes") or [])
        self._applied_excluded_ipv6_routes = list(runtime.get("applied_excluded_ipv6_routes") or [])
        self._policy_table4 = int(runtime.get("policy_table4") or 0)
        self._policy_table6 = int(runtime.get("policy_table6") or 0)
        self._policy_rules4 = list(runtime.get("policy_rules4") or [])
        self._policy_rules6 = list(runtime.get("policy_rules6") or [])
        self._applied_dns_servers = list(runtime.get("applied_dns_servers") or [])
        self._dns_manager = str(runtime.get("dns_manager") or "")
        self._firewall_manager = str(runtime.get("firewall_manager") or "")
        self._firewall_wan_if = str(runtime.get("firewall_wan_if") or "")
        self._applied_firewall_rules = list(runtime.get("applied_firewall_rules") or [])
        self._last_failure = dict(runtime.get("last_failure") or {})

    @classmethod
    def repair_runtime_snapshot(cls, runtime_snapshot: dict[str, Any]) -> dict[str, Any]:
        backend = cls()
        backend._restore_runtime_snapshot(runtime_snapshot)
        payload = cls._payload_from_runtime_snapshot(runtime_snapshot)
        ifname = str(payload.get("ifname") or backend._ifname or "")
        repaired: list[str] = []
        failed: list[dict[str, str]] = []

        def _attempt(label: str, fn: Callable[[], None]) -> None:
            try:
                fn()
            except Exception as exc:
                failed.append({"step": label, "error": str(exc), "error_type": type(exc).__name__})
            else:
                repaired.append(label)

        if ifname:
            _attempt("included_routes", lambda: backend._remove_included_routes(payload, ifname=ifname))
            _attempt("excluded_routes", backend._remove_excluded_routes)
            _attempt("firewall", lambda: backend._remove_firewall(payload, ifname=ifname))
            _attempt("dns", lambda: backend._remove_dns(ifname=ifname))
            if backend._applied_ipv4_cidr:
                _attempt("ipv4_addr", lambda: backend._run_ip("-4", "addr", "del", backend._applied_ipv4_cidr, "dev", ifname, check=False))
                backend._applied_ipv4_cidr = ""
            if backend._applied_ipv6_cidr:
                _attempt("ipv6_addr", lambda: backend._run_ip("-6", "addr", "del", backend._applied_ipv6_cidr, "dev", ifname, check=False))
                backend._applied_ipv6_cidr = ""
        backend._reset_network_state_markers()
        return {
            "ok": not failed,
            "ifname": ifname,
            "repaired": repaired,
            "failed": failed,
            "runtime": backend.local_snapshot(),
        }

    @classmethod
    def verify_runtime_snapshot_repaired(cls, runtime_snapshot: dict[str, Any]) -> dict[str, Any]:
        runtime = dict(runtime_snapshot or {})
        ifname = str(runtime.get("ifname") or "")
        remaining: list[dict[str, str]] = []
        checked: list[str] = []
        skipped: list[dict[str, str]] = []

        def _add_remaining(step: str, detail: str) -> None:
            remaining.append({"step": step, "detail": detail})

        def _check_addr(family_flag: str, label: str, cidr: str) -> None:
            if not cidr or not ifname:
                if cidr:
                    skipped.append({"step": label, "detail": "ifname unavailable for address verification"})
                return
            checked.append(label)
            result = cls._run_command("ip", family_flag, "addr", "show", "dev", ifname, check=False)
            if str(cidr) in str(getattr(result, "stdout", "") or ""):
                _add_remaining(label, str(cidr))

        def _check_route(family_flag: str, label: str, route_spec: str, *, expect_dev: str = "") -> None:
            route_text = str(route_spec or "").strip()
            if not route_text:
                return
            checked.append(label)
            result = cls._run_command("ip", family_flag, "route", "show", route_text, check=False)
            output = str(getattr(result, "stdout", "") or "")
            for line in output.splitlines():
                row = str(line or "").strip()
                if not row or route_text not in row:
                    continue
                if expect_dev and f"dev {expect_dev}" not in row:
                    continue
                _add_remaining(label, row)
                return

        def _check_policy_rule(family_flag: str, label: str, rule_spec: str) -> None:
            rule_text = str(rule_spec or "").strip()
            if not rule_text:
                return
            checked.append(label)
            result = cls._run_command("ip", family_flag, "rule", "show", check=False)
            output = str(getattr(result, "stdout", "") or "")
            for line in output.splitlines():
                row = str(line or "").strip()
                if rule_text in row:
                    _add_remaining(label, row)
                    return

        def _parse_iptables_rule(rule_text: str) -> tuple[str, str, str, list[str]] | None:
            tokens = [str(part or "").strip() for part in shlex.split(str(rule_text or "").strip())]
            if len(tokens) < 4:
                return None
            binary = tokens[0]
            idx = 1
            table = ""
            if idx + 1 < len(tokens) and tokens[idx] == "-t":
                table = tokens[idx + 1]
                idx += 2
            if idx + 1 >= len(tokens):
                return None
            op = tokens[idx]
            chain = tokens[idx + 1]
            rule = tokens[idx + 2 :]
            if op not in {"-A", "-I"} or not chain or not rule:
                return None
            return binary, table, chain, rule

        def _check_firewall_rule(rule_text: str) -> None:
            parsed = _parse_iptables_rule(rule_text)
            if parsed is None:
                skipped.append({"step": "firewall", "detail": f"unparseable rule: {rule_text}"})
                return
            binary, table, chain, rule = parsed
            checked.append("firewall")
            if cls._iptables_rule_exists(binary, table, chain, rule):
                _add_remaining("firewall", str(rule_text))

        def _check_dns(dns_servers: list[str]) -> None:
            if not dns_servers:
                return
            if not ifname:
                skipped.append({"step": "dns", "detail": "ifname unavailable for DNS verification"})
                return
            resolvectl = cls._resolvectl_path()
            if not resolvectl:
                skipped.append({"step": "dns", "detail": "resolvectl unavailable for DNS verification"})
                return
            checked.append("dns")
            result = cls._run_command(resolvectl, "dns", ifname, check=False)
            output = str(getattr(result, "stdout", "") or "")
            for server in dns_servers:
                if str(server) in output:
                    _add_remaining("dns", str(server))

        _check_addr("-4", "ipv4_addr", str(runtime.get("applied_ipv4_cidr") or ""))
        _check_addr("-6", "ipv6_addr", str(runtime.get("applied_ipv6_cidr") or ""))
        for route_spec in list(runtime.get("applied_ipv4_routes") or []):
            _check_route("-4", "included_routes", str(route_spec), expect_dev=ifname)
        for route_spec in list(runtime.get("applied_ipv6_routes") or []):
            _check_route("-6", "included_routes", str(route_spec), expect_dev=ifname)
        for route_spec in list(runtime.get("applied_excluded_ipv4_routes") or []):
            _check_route("-4", "excluded_routes", str(route_spec))
        for route_spec in list(runtime.get("applied_excluded_ipv6_routes") or []):
            _check_route("-6", "excluded_routes", str(route_spec))
        for rule_spec in list(runtime.get("policy_rules4") or []):
            _check_policy_rule("-4", "policy_rules4", str(rule_spec))
        for rule_spec in list(runtime.get("policy_rules6") or []):
            _check_policy_rule("-6", "policy_rules6", str(rule_spec))
        for rule_text in list(runtime.get("applied_firewall_rules") or []):
            _check_firewall_rule(str(rule_text))
        _check_dns([str(item or "").strip() for item in list(runtime.get("applied_dns_servers") or []) if str(item or "").strip()])

        stale_state_remaining = bool(remaining) or bool(skipped)
        summary = (
            "Post-repair verification did not find remaining helper-owned host state."
            if not stale_state_remaining
            else "Post-repair verification could not confirm that all helper-owned host state was cleared."
        )
        return {
            "ok": not stale_state_remaining,
            "checked": checked,
            "remaining": remaining,
            "skipped": skipped,
            "stale_state_remaining": stale_state_remaining,
            "summary": summary,
        }

    def _maybe_inject_test_failure(self, *, operation: str, stage: str) -> None:
        spec = str(os.environ.get("OBSTACLEBRIDGE_TUN_HELPER_TEST_FAIL") or "").strip()
        if not spec:
            return
        parts = [str(part or "").strip().lower() for part in spec.split(":")]
        if len(parts) < 2:
            return
        spec_operation = parts[0]
        spec_stage = parts[1]
        action = parts[2] if len(parts) >= 3 and parts[2] else "raise"
        if spec_operation != str(operation or "").strip().lower():
            return
        if spec_stage != str(stage or "").strip().lower():
            return
        key = (spec_operation, spec_stage, action)
        if key in self._test_failure_consumed:
            return
        self._test_failure_consumed.add(key)
        if action == "exit":
            os._exit(92)
        raise RuntimeError(f"test-injected helper failure at {spec_operation}:{spec_stage}")

    def _record_failure(
        self,
        *,
        operation: str,
        stage: str,
        exc: BaseException,
        cleanup_attempted: bool = False,
        cleanup_ok: bool = False,
    ) -> None:
        self._last_failure = {
            "operation": str(operation or ""),
            "stage": str(stage or ""),
            "error_type": type(exc).__name__,
            "detail": str(exc),
            "cleanup_attempted": bool(cleanup_attempted),
            "cleanup_ok": bool(cleanup_ok),
            "unix_ts": float(time.time()),
        }

    def _reset_network_state_markers(self) -> None:
        self._network_applied = False
        self._applied_ipv4_cidr = ""
        self._applied_ipv6_cidr = ""
        self._applied_ipv4_routes = []
        self._applied_ipv6_routes = []
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []
        self._saved_underlay4 = {}
        self._saved_underlay6 = {}
        self._policy_table4 = 0
        self._policy_table6 = 0
        self._policy_rules4 = []
        self._policy_rules6 = []
        self._applied_dns_servers = []
        self._dns_manager = ""
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []

    def _rollback_partial_apply(self, *, ifname: str) -> None:
        with contextlib.suppress(Exception):
            self._remove_included_routes({}, ifname=ifname)
        with contextlib.suppress(Exception):
            self._remove_excluded_routes()
        with contextlib.suppress(Exception):
            self._remove_firewall(self._last_apply_payload, ifname=ifname)
        with contextlib.suppress(Exception):
            self._remove_dns(ifname=ifname)
        if self._applied_ipv4_cidr:
            with contextlib.suppress(Exception):
                self._run_ip("-4", "addr", "del", self._applied_ipv4_cidr, "dev", ifname, check=False)
        if self._applied_ipv6_cidr:
            with contextlib.suppress(Exception):
                self._run_ip("-6", "addr", "del", self._applied_ipv6_cidr, "dev", ifname, check=False)
        self._reset_network_state_markers()

    async def open_tun(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._opened and self._fd is not None:
            return self.local_snapshot()
        self._require_linux_tun_support()
        requested_ifname = str(payload.get("ifname") or "obtun0")
        requested_mtu = int(payload.get("mtu") or 1600)
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        try:
            ifr = struct.pack("16sH14x", _tun_ifreq_name(requested_ifname), _IFF_TUN | _IFF_NO_PI)
            res = fcntl.ioctl(fd, _TUNSETIFF, ifr)
            actual = bytes(res[:16]).split(b"\x00", 1)[0].decode("utf-8", "ignore") or requested_ifname
            os.set_blocking(fd, False)
            self._set_iface_mtu(actual, requested_mtu)
            self._set_iface_up(actual)
            self._fd = fd
            self._opened = True
            self._ifname = actual
            self._mtu = requested_mtu
            self._stopped = False
            if self._packet_sink is not None and self._reader_task is None:
                self._reader_task = asyncio.create_task(self._read_loop())
            return self.local_snapshot()
        except Exception:
            with contextlib.suppress(Exception):
                os.close(fd)
            raise

    async def write_packet(self, packet: bytes) -> dict[str, Any]:
        if self._fd is None:
            raise RuntimeError("Linux native TUN helper backend is not opened")
        os.write(self._fd, bytes(packet))
        self._packets_from_runtime += 1
        return {"accepted": True, "len": len(packet)}

    async def snapshot(self) -> dict[str, Any]:
        return self.local_snapshot()

    def local_snapshot(self) -> dict[str, Any]:
        return {
            "backend": "linux-native",
            "opened": self._opened,
            "ifname": self._ifname,
            "mtu": self._mtu,
            "packets_from_runtime": self._packets_from_runtime,
            "packets_to_runtime": self._packets_to_runtime,
            "network_applied": self._network_applied,
            "apply_calls": self._apply_calls,
            "remove_calls": self._remove_calls,
            "last_apply_payload": dict(self._last_apply_payload),
            "last_remove_payload": dict(self._last_remove_payload),
            "applied_ipv4_cidr": self._applied_ipv4_cidr,
            "applied_ipv6_cidr": self._applied_ipv6_cidr,
            "applied_ipv4_routes": list(self._applied_ipv4_routes),
            "applied_ipv6_routes": list(self._applied_ipv6_routes),
            "applied_excluded_ipv4_routes": list(self._applied_excluded_ipv4_routes),
            "applied_excluded_ipv6_routes": list(self._applied_excluded_ipv6_routes),
            "policy_table4": self._policy_table4,
            "policy_table6": self._policy_table6,
            "policy_rules4": list(self._policy_rules4),
            "policy_rules6": list(self._policy_rules6),
            "applied_dns_servers": list(self._applied_dns_servers),
            "dns_manager": self._dns_manager,
            "firewall_manager": self._firewall_manager,
            "firewall_wan_if": self._firewall_wan_if,
            "applied_firewall_rules": list(self._applied_firewall_rules),
            "last_failure": dict(self._last_failure),
            "stopped": self._stopped,
        }

    async def apply_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._apply_calls += 1
        self._network_applied = True
        self._last_apply_payload = dict(payload or {})
        ifname = str(payload.get("ifname") or self._ifname or "obtun0")
        self._clear_last_failure()
        stage = "start"
        try:
            ipv4_cidr = self._cidr_from_tun_routing(payload, "tunnel_address", "tunnel_prefix")
            ipv6_cidr = self._cidr_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6")
            if ipv4_cidr:
                stage = "ipv4_addr_apply"
                self._maybe_inject_test_failure(operation="apply_network", stage=stage)
                self._run_ip("-4", "addr", "replace", ipv4_cidr, "dev", ifname)
                self._applied_ipv4_cidr = ipv4_cidr
            if ipv6_cidr:
                stage = "ipv6_addr_apply"
                self._maybe_inject_test_failure(operation="apply_network", stage=stage)
                self._run_ip("-6", "addr", "replace", ipv6_cidr, "dev", ifname)
                self._applied_ipv6_cidr = ipv6_cidr
            stage = "underlay_snapshot"
            self._maybe_inject_test_failure(operation="apply_network", stage=stage)
            self._saved_underlay4 = self._snapshot_default_route("-4")
            self._saved_underlay6 = self._snapshot_default_route("-6")
            stage = "excluded_routes_apply"
            self._maybe_inject_test_failure(operation="apply_network", stage=stage)
            self._apply_excluded_routes(payload, ifname=ifname)
            stage = "included_routes_apply"
            self._maybe_inject_test_failure(operation="apply_network", stage=stage)
            self._apply_included_routes(payload, ifname=ifname)
            stage = "firewall_apply"
            self._maybe_inject_test_failure(operation="apply_network", stage=stage)
            self._apply_firewall(payload, ifname=ifname)
            stage = "dns_apply"
            self._maybe_inject_test_failure(operation="apply_network", stage=stage)
            self._apply_dns(payload, ifname=ifname)
        except Exception as exc:
            cleanup_ok = False
            try:
                self._rollback_partial_apply(ifname=ifname)
                cleanup_ok = True
            finally:
                self._record_failure(
                    operation="apply_network",
                    stage=stage,
                    exc=exc,
                    cleanup_attempted=True,
                    cleanup_ok=cleanup_ok,
                )
            raise
        return {
            "applied": True,
            "backend": "linux-native",
            "ifname": ifname,
            "apply_calls": self._apply_calls,
            "applied_ipv4_cidr": self._applied_ipv4_cidr,
            "applied_ipv6_cidr": self._applied_ipv6_cidr,
            "applied_ipv4_routes": list(self._applied_ipv4_routes),
            "applied_ipv6_routes": list(self._applied_ipv6_routes),
            "applied_excluded_ipv4_routes": list(self._applied_excluded_ipv4_routes),
            "applied_excluded_ipv6_routes": list(self._applied_excluded_ipv6_routes),
            "policy_table4": self._policy_table4,
            "policy_table6": self._policy_table6,
            "policy_rules4": list(self._policy_rules4),
            "policy_rules6": list(self._policy_rules6),
            "applied_dns_servers": list(self._applied_dns_servers),
            "dns_manager": self._dns_manager,
            "firewall_manager": self._firewall_manager,
            "firewall_wan_if": self._firewall_wan_if,
            "applied_firewall_rules": list(self._applied_firewall_rules),
            "last_failure": dict(self._last_failure),
        }

    async def remove_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._remove_calls += 1
        self._network_applied = False
        self._last_remove_payload = dict(payload or {})
        ifname = str(payload.get("ifname") or self._ifname or "obtun0")
        self._clear_last_failure()
        stage = "start"
        try:
            stage = "included_routes_remove"
            self._maybe_inject_test_failure(operation="remove_network", stage=stage)
            self._remove_included_routes(payload, ifname=ifname)
            stage = "excluded_routes_remove"
            self._maybe_inject_test_failure(operation="remove_network", stage=stage)
            self._remove_excluded_routes()
            stage = "firewall_remove"
            self._maybe_inject_test_failure(operation="remove_network", stage=stage)
            self._remove_firewall(payload, ifname=ifname)
            stage = "dns_remove"
            self._maybe_inject_test_failure(operation="remove_network", stage=stage)
            self._remove_dns(ifname=ifname)
            ipv4_cidr = self._applied_ipv4_cidr or self._cidr_from_tun_routing(payload, "tunnel_address", "tunnel_prefix")
            ipv6_cidr = self._applied_ipv6_cidr or self._cidr_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6")
            if ipv4_cidr:
                stage = "ipv4_addr_remove"
                self._maybe_inject_test_failure(operation="remove_network", stage=stage)
                self._run_ip("-4", "addr", "del", ipv4_cidr, "dev", ifname, check=False)
                self._applied_ipv4_cidr = ""
            if ipv6_cidr:
                stage = "ipv6_addr_remove"
                self._maybe_inject_test_failure(operation="remove_network", stage=stage)
                self._run_ip("-6", "addr", "del", ipv6_cidr, "dev", ifname, check=False)
                self._applied_ipv6_cidr = ""
            self._saved_underlay4 = {}
            self._saved_underlay6 = {}
            self._policy_table4 = 0
            self._policy_table6 = 0
        except Exception as exc:
            self._record_failure(
                operation="remove_network",
                stage=stage,
                exc=exc,
                cleanup_attempted=False,
                cleanup_ok=False,
            )
            raise
        return {
            "removed": True,
            "backend": "linux-native",
            "ifname": ifname,
            "remove_calls": self._remove_calls,
        }

    async def stop(self) -> None:
        self._stopped = True
        if self._network_applied and self._ifname:
            with contextlib.suppress(Exception):
                await self.remove_network({"ifname": self._ifname})
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
            self._reader_task = None
        if self._fd is not None:
            with contextlib.suppress(Exception):
                os.close(self._fd)
            self._fd = None
        self._opened = False

    async def _read_loop(self) -> None:
        while True:
            fd = self._fd
            if fd is None:
                return
            try:
                packet = os.read(fd, max(68, int(self._mtu or 1600) + 4))
                if packet:
                    self._packets_to_runtime += 1
                    if self._packet_sink is not None:
                        result = self._packet_sink(bytes(packet))
                        if inspect.isawaitable(result):
                            await result
                    continue
            except BlockingIOError:
                pass
            except OSError as exc:
                if getattr(exc, "errno", None) not in (11,):
                    raise
            await asyncio.sleep(self._read_poll_interval_s)


class LinuxTunHelperInMemoryBackend:
    """Linux-first helper backend stub used before real TUN ownership exists."""

    def __init__(self) -> None:
        self._packet_sink: Optional[Callable[[bytes], Awaitable[None] | None]] = None
        self._opened = False
        self._ifname = ""
        self._mtu = 0
        self._packets_from_runtime = 0
        self._packets_to_runtime = 0
        self._written_packets: list[bytes] = []
        self._stopped = False
        self._incoming_packets: asyncio.Queue[bytes] = asyncio.Queue()
        self._network_applied = False
        self._apply_calls = 0
        self._remove_calls = 0
        self._last_apply_payload: dict[str, Any] = {}
        self._last_remove_payload: dict[str, Any] = {}

    def set_packet_sink(self, sink: Callable[[bytes], Awaitable[None] | None]) -> None:
        self._packet_sink = sink

    async def open_tun(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.local_open_tun(payload)

    def local_open_tun(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._opened = True
        self._ifname = str(payload.get("ifname") or "obtun0")
        self._mtu = int(payload.get("mtu") or 1600)
        return {
            "backend": "linux-python-memory",
            "ifname": self._ifname,
            "mtu": self._mtu,
            "opened": True,
        }

    async def write_packet(self, packet: bytes) -> dict[str, Any]:
        return self.local_write_packet(packet)

    def local_write_packet(self, packet: bytes) -> dict[str, Any]:
        self._packets_from_runtime += 1
        self._written_packets.append(bytes(packet))
        return {"accepted": True, "len": len(packet)}

    async def snapshot(self) -> dict[str, Any]:
        return self.local_snapshot()

    def local_snapshot(self) -> dict[str, Any]:
        return {
            "backend": "linux-python-memory",
            "opened": self._opened,
            "ifname": self._ifname,
            "mtu": self._mtu,
            "packets_from_runtime": self._packets_from_runtime,
            "packets_to_runtime": self._packets_to_runtime,
            "network_applied": self._network_applied,
            "apply_calls": self._apply_calls,
            "remove_calls": self._remove_calls,
            "last_apply_payload": dict(self._last_apply_payload),
            "last_remove_payload": dict(self._last_remove_payload),
            "stopped": self._stopped,
        }

    async def apply_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.local_apply_network(payload)

    def local_apply_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._apply_calls += 1
        self._network_applied = True
        self._last_apply_payload = dict(payload or {})
        return {
            "applied": True,
            "backend": "linux-python-memory",
            "ifname": str(payload.get("ifname") or self._ifname or "obtun0"),
            "apply_calls": self._apply_calls,
        }

    async def remove_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.local_remove_network(payload)

    def local_remove_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._remove_calls += 1
        self._network_applied = False
        self._last_remove_payload = dict(payload or {})
        return {
            "removed": True,
            "backend": "linux-python-memory",
            "ifname": str(payload.get("ifname") or self._ifname or "obtun0"),
            "remove_calls": self._remove_calls,
        }

    async def stop(self) -> None:
        self._stopped = True

    async def feed_incoming_packet(self, packet: bytes) -> None:
        self.local_feed_incoming_packet(packet)
        if self._packet_sink is None:
            return
        result = self._packet_sink(bytes(packet))
        if inspect.isawaitable(result):
            await result

    def local_feed_incoming_packet(self, packet: bytes) -> None:
        self._packets_to_runtime += 1
        self._incoming_packets.put_nowait(bytes(packet))

    async def read_packet(self) -> bytes:
        return await self._incoming_packets.get()

    def drain_written_packets(self) -> list[bytes]:
        packets = list(self._written_packets)
        self._written_packets.clear()
        return packets
