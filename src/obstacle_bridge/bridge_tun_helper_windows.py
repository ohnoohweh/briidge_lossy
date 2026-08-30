from __future__ import annotations

import asyncio
import contextlib
import inspect
import ipaddress
import json
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from . import bridge_tun_windows


class _HelperLog:
    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@dataclass
class _HelperTunDevice:
    fd: Any
    ifname: str
    mtu: int
    service_key: Optional[object] = None
    chan_id: Optional[int] = None


class _HelperMux:
    def __init__(self, backend: "WindowsTunHelperBackend") -> None:
        self.loop = asyncio.get_running_loop()
        self.log = _HelperLog()
        self._backend = backend
        self.TunDevice = _HelperTunDevice

    def _on_local_tun_packet(self, _dev: _HelperTunDevice, packet: bytes) -> None:
        self.loop.create_task(self._backend._emit_packet(bytes(packet)))


class WindowsTunHelperBackend:
    """Windows helper backend that wraps the existing inline Wintun path."""

    POWERSHELL_TIMEOUT_S = 10.0

    def __init__(self) -> None:
        self._log = logging.getLogger("tun_helper_windows")
        self._packet_sink: Optional[Callable[[bytes], Awaitable[None] | None]] = None
        self._dev: Optional[_HelperTunDevice] = None
        self._mux: Optional[_HelperMux] = None
        self._opened = False
        self._ifname = ""
        self._ifindex = 0
        self._mtu = 0
        self._packets_from_runtime = 0
        self._packets_to_runtime = 0
        self._stopped = False
        self._apply_calls = 0
        self._remove_calls = 0
        self._network_applied = False
        self._included_routes_active = False
        self._included_routes_startup_enabled = True
        self._suspend_calls = 0
        self._resume_calls = 0
        self._last_apply_payload: dict[str, Any] = {}
        self._last_remove_payload: dict[str, Any] = {}
        self._applied_ipv4_cidr = ""
        self._applied_ipv6_cidr = ""
        self._applied_ipv4_routes: list[str] = []
        self._applied_ipv6_routes: list[str] = []
        self._applied_excluded_ipv4_routes: list[str] = []
        self._applied_excluded_ipv6_routes: list[str] = []
        self._applied_dns_servers: list[str] = []
        self._dns_manager = ""
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules: list[str] = []
        self._saved_underlay4: dict[str, Any] = {}
        self._saved_underlay6: dict[str, Any] = {}
        self._last_failure: dict[str, Any] = {}

    @staticmethod
    def _ps_quote(text: str) -> str:
        return "'" + str(text or "").replace("'", "''") + "'"

    def _run_powershell(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        self._log.debug("[TUN/HELPER/WIN] powershell start check=%s command=%s", bool(check), str(command or "")[:240])
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", str(command or "")],
                check=check,
                capture_output=True,
                text=True,
                timeout=self.POWERSHELL_TIMEOUT_S,
            )
        except subprocess.CalledProcessError as exc:
            self._log.debug(
                "[TUN/HELPER/WIN] powershell failed rc=%s stdout=%s stderr=%s",
                int(exc.returncode or 0),
                str(exc.stdout or "")[:240],
                str(exc.stderr or "")[:240],
            )
            raise
        self._log.debug(
            "[TUN/HELPER/WIN] powershell done rc=%s stdout=%s stderr=%s",
            int(result.returncode or 0),
            str(result.stdout or "")[:240],
            str(result.stderr or "")[:240],
        )
        return result

    def _run_powershell_json(self, command: str) -> dict[str, Any]:
        result = self._run_powershell(command, check=False)
        if int(result.returncode or 0) != 0:
            return {}
        text = str(result.stdout or "").strip()
        if not text:
            return {}
        with contextlib.suppress(Exception):
            payload = json.loads(text)
            if isinstance(payload, list):
                return dict(payload[0]) if payload else {}
            if isinstance(payload, dict):
                return dict(payload)
        return {}

    @staticmethod
    def _tun_routing(payload: dict[str, Any]) -> dict[str, Any]:
        tun_routing = payload.get("tun_routing")
        return dict(tun_routing) if isinstance(tun_routing, dict) else {}

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

    @classmethod
    def _cidr_from_tun_routing(cls, payload: dict[str, Any], key: str, prefix_key: str) -> str:
        values = cls._tun_routing(payload)
        address = str(values.get(key) or "").strip()
        if not address:
            return ""
        prefix = int(values.get(prefix_key) or 0)
        if prefix <= 0:
            return ""
        return f"{address}/{prefix}"

    @classmethod
    def _list_from_tun_routing(cls, payload: dict[str, Any], key: str) -> list[str]:
        values = cls._tun_routing(payload)
        raw = values.get(key)
        if isinstance(raw, list):
            items = [str(item or "").strip() for item in raw]
        elif isinstance(raw, str):
            items = [part.strip() for part in raw.split(",")]
        else:
            items = []
        out: list[str] = []
        seen: set[str] = set()
        for item in items:
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    @staticmethod
    def _is_default_route(route_spec: str) -> bool:
        normalized = str(route_spec or "").strip().lower()
        return normalized in {"0.0.0.0/0", "::/0", "::0/0", "default"}

    @staticmethod
    def _route_spec_matches_loopback(route_spec: str, *, family: int) -> bool:
        with contextlib.suppress(ValueError):
            network = ipaddress.ip_network(route_spec, strict=False)
            if int(network.version) != int(family):
                return False
            if int(family) == 4:
                return network.subnet_of(ipaddress.ip_network("127.0.0.0/8"))
            return network.subnet_of(ipaddress.ip_network("::1/128"))
        return False

    @classmethod
    def _route_specs_for_helper(cls, payload: dict[str, Any], *, list_key: str, local_cidr: str) -> list[str]:
        routes = cls._list_from_tun_routing(payload, list_key)
        local_network = ""
        if local_cidr:
            with contextlib.suppress(ValueError):
                local_network = str(ipaddress.ip_network(local_cidr, strict=False))
        out: list[str] = []
        seen: set[str] = set()
        for route_spec in routes:
            if cls._is_default_route(route_spec):
                route_spec = "::/0" if ":" in route_spec else "0.0.0.0/0"
            else:
                with contextlib.suppress(ValueError):
                    route_spec = str(ipaddress.ip_network(route_spec, strict=False))
            if local_network and route_spec == local_network:
                continue
            if not route_spec or route_spec in seen:
                continue
            seen.add(route_spec)
            out.append(route_spec)
        return out

    def _resolve_interface_index(self, ifname: str) -> int:
        needle = self._ps_quote(ifname)
        command = (
            "$adapter = Get-NetAdapter -IncludeHidden -Name " + needle + " -ErrorAction SilentlyContinue; "
            "if (-not $adapter) { $adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -eq " + needle + " -or $_.InterfaceAlias -eq " + needle + " } | Select-Object -First 1 }; "
            "if ($adapter) { $adapter | Select-Object ifIndex,InterfaceAlias,Name | ConvertTo-Json -Depth 2 }"
        )
        record = self._run_powershell_json(command)
        if_index = int(record.get("ifIndex") or 0)
        if if_index <= 0:
            raise RuntimeError(f"Windows helper could not resolve interface index for {ifname!r}")
        return if_index

    @staticmethod
    def _subnet_from_cidr(cidr: str) -> str:
        text = str(cidr or "").strip()
        if not text:
            return ""
        with contextlib.suppress(ValueError):
            return str(ipaddress.ip_interface(text).network)
        return ""

    def _snapshot_default_route(self, family: int) -> dict[str, Any]:
        if int(family) == 6:
            destination = "::/0"
            address_family = "IPv6"
        else:
            destination = "0.0.0.0/0"
            address_family = "IPv4"
        command = (
            "$route = Get-NetRoute -AddressFamily " + address_family + " -DestinationPrefix " + self._ps_quote(destination) + " "
            "-ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric,InterfaceMetric | Select-Object -First 1; "
            "if ($route) { $route | Select-Object InterfaceIndex,InterfaceAlias,NextHop,RouteMetric | ConvertTo-Json -Depth 2 }"
        )
        return self._run_powershell_json(command)

    def _clear_last_failure(self) -> None:
        self._last_failure = {}

    @staticmethod
    def _split_cidr(cidr: str) -> tuple[str, int]:
        text = str(cidr or "").strip()
        if not text or "/" not in text:
            return "", 0
        address, prefix_text = text.split("/", 1)
        try:
            prefix = int(prefix_text)
        except Exception:
            return "", 0
        return str(address or "").strip(), prefix

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
        listener_hook_env = payload.get("listener_hook_env")
        if not isinstance(listener_hook_env, dict):
            listener_hook_env = {}
        listener_hook_env = dict(listener_hook_env)
        wan_if = str(runtime.get("firewall_wan_if") or "").strip()
        if wan_if and "WAN_IF" not in listener_hook_env:
            listener_hook_env["WAN_IF"] = wan_if
        if listener_hook_env:
            payload["listener_hook_env"] = listener_hook_env
        payload["tun_routing"] = tun_routing
        payload.setdefault("ifname", str(runtime.get("ifname") or ""))
        return payload

    def _restore_runtime_snapshot(self, runtime_snapshot: dict[str, Any]) -> None:
        runtime = dict(runtime_snapshot or {})
        self._ifname = str(runtime.get("ifname") or "")
        self._ifindex = int(runtime.get("ifindex") or 0)
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
        self._applied_dns_servers = list(runtime.get("applied_dns_servers") or [])
        self._dns_manager = str(runtime.get("dns_manager") or "")
        self._firewall_manager = str(runtime.get("firewall_manager") or "")
        self._firewall_wan_if = str(runtime.get("firewall_wan_if") or "")
        self._applied_firewall_rules = list(runtime.get("applied_firewall_rules") or [])
        self._saved_underlay4 = dict(runtime.get("saved_underlay4") or {})
        self._saved_underlay6 = dict(runtime.get("saved_underlay6") or {})
        self._last_failure = dict(runtime.get("last_failure") or {})

    def _reset_network_state_markers(self) -> None:
        self._network_applied = False
        self._applied_ipv4_cidr = ""
        self._applied_ipv6_cidr = ""
        self._applied_ipv4_routes = []
        self._applied_ipv6_routes = []
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []
        self._applied_dns_servers = []
        self._dns_manager = ""
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []
        self._saved_underlay4 = {}
        self._saved_underlay6 = {}

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

        interface_index = int(backend._ifindex or 0)
        if interface_index <= 0 and ifname:
            try:
                interface_index = backend._resolve_interface_index(ifname)
                backend._ifindex = int(interface_index)
            except Exception:
                interface_index = 0

        if ifname:
            if interface_index > 0:
                _attempt("dns", lambda: backend._remove_dns(interface_index=interface_index))
                _attempt("included_routes", lambda: backend._remove_included_routes(interface_index=interface_index))
            elif backend._applied_dns_servers:
                failed.append({"step": "dns", "error": "interface index unavailable", "error_type": "RuntimeError"})
            elif backend._applied_ipv4_routes or backend._applied_ipv6_routes:
                failed.append({"step": "included_routes", "error": "interface index unavailable", "error_type": "RuntimeError"})
            _attempt("excluded_routes", backend._remove_excluded_routes)
            _attempt("firewall", lambda: backend._remove_firewall(payload, ifname=ifname))
            if backend._applied_ipv4_cidr:
                if interface_index > 0:
                    _attempt("ipv4_addr", lambda: backend._remove_interface_address(interface_index=interface_index, cidr=backend._applied_ipv4_cidr))
                    backend._applied_ipv4_cidr = ""
                else:
                    failed.append({"step": "ipv4_addr", "error": "interface index unavailable", "error_type": "RuntimeError"})
            if backend._applied_ipv6_cidr:
                if interface_index > 0:
                    _attempt("ipv6_addr", lambda: backend._remove_interface_address(interface_index=interface_index, cidr=backend._applied_ipv6_cidr))
                    backend._applied_ipv6_cidr = ""
                else:
                    failed.append({"step": "ipv6_addr", "error": "interface index unavailable", "error_type": "RuntimeError"})
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
        backend = cls()
        ifname = str(runtime.get("ifname") or "")
        remaining: list[dict[str, str]] = []
        checked: list[str] = []
        skipped: list[dict[str, str]] = []

        def _add_remaining(step: str, detail: str) -> None:
            remaining.append({"step": step, "detail": detail})

        interface_index = int(runtime.get("ifindex") or 0)
        if interface_index <= 0 and ifname:
            try:
                interface_index = backend._resolve_interface_index(ifname)
            except Exception:
                interface_index = 0

        def _check_addr(label: str, cidr: str) -> None:
            address, _prefix = cls._split_cidr(cidr)
            if not address:
                return
            if interface_index <= 0:
                skipped.append({"step": label, "detail": "interface index unavailable for address verification"})
                return
            checked.append(label)
            result = backend._run_powershell(
                "Get-NetIPAddress -InterfaceIndex " + str(interface_index) + " -IPAddress " + backend._ps_quote(address) + " -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2",
                check=False,
            )
            if str(result.stdout or "").strip():
                _add_remaining(label, str(cidr))

        def _check_route(label: str, route_spec: str, *, route_interface_index: int, family: int) -> None:
            route_text = str(route_spec or "").strip()
            if not route_text:
                return
            if route_interface_index <= 0:
                skipped.append({"step": label, "detail": "route interface index unavailable for route verification"})
                return
            checked.append(label)
            family_name = "IPv6" if int(family) == 6 else "IPv4"
            result = backend._run_powershell(
                "Get-NetRoute -InterfaceIndex " + str(route_interface_index) + " -AddressFamily " + family_name + " -DestinationPrefix " + backend._ps_quote(route_text) + " -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2",
                check=False,
            )
            if str(result.stdout or "").strip():
                _add_remaining(label, route_text)

        def _check_dns(dns_servers: list[str]) -> None:
            if not dns_servers:
                return
            if interface_index <= 0:
                skipped.append({"step": "dns", "detail": "interface index unavailable for DNS verification"})
                return
            checked.append("dns")
            result = backend._run_powershell(
                "Get-DnsClientServerAddress -InterfaceIndex " + str(interface_index) + " -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4",
                check=False,
            )
            output = str(result.stdout or "")
            for server in dns_servers:
                if str(server) in output:
                    _add_remaining("dns", str(server))

        _check_addr("ipv4_addr", str(runtime.get("applied_ipv4_cidr") or ""))
        _check_addr("ipv6_addr", str(runtime.get("applied_ipv6_cidr") or ""))
        for route_spec in list(runtime.get("applied_ipv4_routes") or []):
            _check_route("included_routes", str(route_spec), route_interface_index=interface_index, family=4)
        for route_spec in list(runtime.get("applied_ipv6_routes") or []):
            _check_route("included_routes", str(route_spec), route_interface_index=interface_index, family=6)
        saved_underlay4_index = int(dict(runtime.get("saved_underlay4") or {}).get("InterfaceIndex") or 0)
        saved_underlay6_index = int(dict(runtime.get("saved_underlay6") or {}).get("InterfaceIndex") or 0)
        for route_spec in list(runtime.get("applied_excluded_ipv4_routes") or []):
            _check_route("excluded_routes", str(route_spec), route_interface_index=saved_underlay4_index, family=4)
        for route_spec in list(runtime.get("applied_excluded_ipv6_routes") or []):
            _check_route("excluded_routes", str(route_spec), route_interface_index=saved_underlay6_index, family=6)
        for rule_name in list(runtime.get("applied_firewall_rules") or []):
            checked.append("firewall")
            if backend._firewall_rule_exists(str(rule_name)):
                _add_remaining("firewall", str(rule_name))
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

    def _apply_interface_address(self, *, interface_index: int, cidr: str, family: int) -> None:
        iface = ipaddress.ip_interface(cidr)
        command = (
            "$ErrorActionPreference='Stop'; "
            "if (-not (Get-NetIPAddress -InterfaceIndex " + str(interface_index) + " -IPAddress " + self._ps_quote(str(iface.ip)) + " -ErrorAction SilentlyContinue)) "
            "{ New-NetIPAddress -InterfaceIndex " + str(interface_index) + " -IPAddress " + self._ps_quote(str(iface.ip)) + " -PrefixLength " + str(int(iface.network.prefixlen)) + " -AddressFamily " + ("IPv6" if int(family) == 6 else "IPv4") + " -PolicyStore ActiveStore | Out-Null }"
        )
        self._run_powershell(command)

    def _remove_interface_address(self, *, interface_index: int, cidr: str) -> None:
        iface = ipaddress.ip_interface(cidr)
        command = (
            "Remove-NetIPAddress -InterfaceIndex " + str(interface_index) + " -IPAddress " + self._ps_quote(str(iface.ip)) + " "
            "-Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
        )
        self._run_powershell(command, check=False)

    def _apply_route(self, *, interface_index: int, route_spec: str, next_hop: str) -> None:
        network = ipaddress.ip_network(route_spec, strict=False)
        family = "IPv6" if int(network.version) == 6 else "IPv4"
        command = (
            "$ErrorActionPreference='Stop'; "
            "if (-not (Get-NetRoute -InterfaceIndex " + str(interface_index) + " -AddressFamily " + family + " -DestinationPrefix " + self._ps_quote(str(network)) + " -ErrorAction SilentlyContinue)) "
            "{ New-NetRoute -InterfaceIndex " + str(interface_index) + " -AddressFamily " + family + " -DestinationPrefix " + self._ps_quote(str(network)) + " -NextHop " + self._ps_quote(str(next_hop)) + " -PolicyStore ActiveStore | Out-Null }"
        )
        self._run_powershell(command)

    def _remove_route(self, *, interface_index: int, route_spec: str) -> None:
        network = ipaddress.ip_network(route_spec, strict=False)
        family = "IPv6" if int(network.version) == 6 else "IPv4"
        command = (
            "Remove-NetRoute -InterfaceIndex " + str(interface_index) + " -AddressFamily " + family + " -DestinationPrefix " + self._ps_quote(str(network)) + " "
            "-Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
        )
        self._run_powershell(command, check=False)

    def _apply_dns(self, *, interface_index: int, payload: dict[str, Any]) -> None:
        dns_servers = self._list_from_tun_routing(payload, "dns_servers")
        self._applied_dns_servers = []
        self._dns_manager = ""
        if not dns_servers:
            return
        server_list = ", ".join(self._ps_quote(item) for item in dns_servers)
        command = (
            "Set-DnsClientServerAddress -InterfaceIndex " + str(interface_index) + " -ServerAddresses @(" + server_list + ") -ErrorAction Stop | Out-Null"
        )
        self._run_powershell(command)
        self._applied_dns_servers = list(dns_servers)
        self._dns_manager = "dnsclient"

    def _remove_dns(self, *, interface_index: int) -> None:
        if self._applied_dns_servers:
            command = (
                "Set-DnsClientServerAddress -InterfaceIndex " + str(interface_index) + " -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null"
            )
            self._run_powershell(command, check=False)
        self._applied_dns_servers = []
        self._dns_manager = ""

    @staticmethod
    def _firewall_rule_name(ifname: str, family: int, direction: str) -> str:
        family_label = "IPv6" if int(family) == 6 else "IPv4"
        direction_label = str(direction or "").strip().lower()
        if direction_label == "outbound":
            direction_label = "Outbound"
        else:
            direction_label = "Inbound"
        return f"ObstacleBridge-TunHelper-{ifname}-{family_label}-{direction_label}"

    def _firewall_rule_exists(self, rule_name: str) -> bool:
        command = (
            "Get-NetFirewallRule -DisplayName " + self._ps_quote(rule_name) + " -ErrorAction SilentlyContinue | "
            "Select-Object -First 1 | ConvertTo-Json -Depth 2"
        )
        result = self._run_powershell(command, check=False)
        return bool(str(result.stdout or "").strip())

    def _add_firewall_rule(self, *, rule_name: str, direction: str, subnet: str, wan_if: str) -> None:
        if self._firewall_rule_exists(rule_name):
            return
        command = (
            "$ErrorActionPreference='Stop'; "
            "New-NetFirewallRule -DisplayName " + self._ps_quote(rule_name) + " "
            "-Direction " + self._ps_quote(direction) + " "
            "-Action Allow -Enabled True -Profile Any "
            "-RemoteAddress " + self._ps_quote(subnet) + " "
            "-InterfaceAlias " + self._ps_quote(wan_if) + " | Out-Null"
        )
        self._run_powershell(command)

    def _delete_firewall_rule(self, rule_name: str) -> None:
        while self._firewall_rule_exists(rule_name):
            command = (
                "Remove-NetFirewallRule -DisplayName " + self._ps_quote(rule_name) + " "
                "-ErrorAction SilentlyContinue | Out-Null"
            )
            self._run_powershell(command, check=False)

    def _apply_firewall(self, payload: dict[str, Any], *, ifname: str) -> None:
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []
        listener_env = self._listener_hook_env(payload)
        wan_if = str(listener_env.get("WAN_IF") or "").strip()
        if not wan_if or wan_if.lower() == "auto":
            return
        subnet4 = self._subnet_from_cidr(self._applied_ipv4_cidr or self._cidr_from_tun_routing(payload, "tunnel_address", "tunnel_prefix"))
        subnet6 = self._subnet_from_cidr(self._applied_ipv6_cidr or self._cidr_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6"))
        for family, subnet in ((4, subnet4), (6, subnet6)):
            if not subnet:
                continue
            for direction in ("Inbound", "Outbound"):
                rule_name = self._firewall_rule_name(ifname, family, direction)
                self._add_firewall_rule(rule_name=rule_name, direction=direction, subnet=subnet, wan_if=wan_if)
                self._applied_firewall_rules.append(rule_name)
        if self._applied_firewall_rules:
            self._firewall_manager = "windows-firewall"
            self._firewall_wan_if = wan_if

    def _remove_firewall(self, payload: dict[str, Any], *, ifname: str) -> None:
        listener_env = self._listener_hook_env(payload)
        wan_if = str(listener_env.get("WAN_IF") or self._firewall_wan_if or "").strip()
        if not wan_if:
            self._firewall_manager = ""
            self._firewall_wan_if = ""
            self._applied_firewall_rules = []
            return
        subnet4 = self._subnet_from_cidr(self._applied_ipv4_cidr or self._cidr_from_tun_routing(payload, "tunnel_address", "tunnel_prefix"))
        subnet6 = self._subnet_from_cidr(self._applied_ipv6_cidr or self._cidr_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6"))
        for family, subnet in ((4, subnet4), (6, subnet6)):
            if not subnet:
                continue
            for direction in ("Inbound", "Outbound"):
                self._delete_firewall_rule(self._firewall_rule_name(ifname, family, direction))
        self._firewall_manager = ""
        self._firewall_wan_if = ""
        self._applied_firewall_rules = []

    def _apply_excluded_routes(self, payload: dict[str, Any]) -> None:
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []
        underlay4 = dict(self._saved_underlay4)
        underlay6 = dict(self._saved_underlay6)
        underlay4_index = int(underlay4.get("InterfaceIndex") or 0)
        underlay6_index = int(underlay6.get("InterfaceIndex") or 0)
        underlay4_hop = str(underlay4.get("NextHop") or "0.0.0.0").strip() or "0.0.0.0"
        underlay6_hop = str(underlay6.get("NextHop") or "::").strip() or "::"
        for route_spec in self._list_from_tun_routing(payload, "excluded_routes"):
            if self._route_spec_matches_loopback(route_spec, family=4) or underlay4_index <= 0:
                continue
            normalized = str(ipaddress.ip_network(route_spec, strict=False))
            self._apply_route(interface_index=underlay4_index, route_spec=normalized, next_hop=underlay4_hop)
            self._applied_excluded_ipv4_routes.append(normalized)
        for route_spec in self._list_from_tun_routing(payload, "excluded_routes6"):
            if self._route_spec_matches_loopback(route_spec, family=6) or underlay6_index <= 0:
                continue
            normalized = str(ipaddress.ip_network(route_spec, strict=False))
            self._apply_route(interface_index=underlay6_index, route_spec=normalized, next_hop=underlay6_hop)
            self._applied_excluded_ipv6_routes.append(normalized)

    def _remove_excluded_routes(self) -> None:
        underlay4_index = int(self._saved_underlay4.get("InterfaceIndex") or 0)
        underlay6_index = int(self._saved_underlay6.get("InterfaceIndex") or 0)
        for route_spec in list(self._applied_excluded_ipv4_routes):
            if underlay4_index > 0:
                self._remove_route(interface_index=underlay4_index, route_spec=route_spec)
        for route_spec in list(self._applied_excluded_ipv6_routes):
            if underlay6_index > 0:
                self._remove_route(interface_index=underlay6_index, route_spec=route_spec)
        self._applied_excluded_ipv4_routes = []
        self._applied_excluded_ipv6_routes = []

    def _apply_included_routes(self, payload: dict[str, Any], *, interface_index: int) -> None:
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
        for route_spec in self._applied_ipv4_routes:
            self._apply_route(interface_index=interface_index, route_spec=route_spec, next_hop="0.0.0.0")
        for route_spec in self._applied_ipv6_routes:
            self._apply_route(interface_index=interface_index, route_spec=route_spec, next_hop="::")

    def _remove_included_routes(self, *, interface_index: int) -> None:
        for route_spec in list(self._applied_ipv4_routes):
            self._remove_route(interface_index=interface_index, route_spec=route_spec)
        for route_spec in list(self._applied_ipv6_routes):
            self._remove_route(interface_index=interface_index, route_spec=route_spec)
        self._applied_ipv4_routes = []
        self._applied_ipv6_routes = []

    def _rollback_partial_apply(self, *, interface_index: int) -> None:
        self._remove_dns(interface_index=interface_index)
        self._remove_included_routes(interface_index=interface_index)
        self._remove_excluded_routes()
        self._remove_firewall(self._last_apply_payload, ifname=str(self._last_apply_payload.get("ifname") or self._ifname or "obtun0"))
        if self._applied_ipv4_cidr:
            self._remove_interface_address(interface_index=interface_index, cidr=self._applied_ipv4_cidr)
            self._applied_ipv4_cidr = ""
        if self._applied_ipv6_cidr:
            self._remove_interface_address(interface_index=interface_index, cidr=self._applied_ipv6_cidr)
            self._applied_ipv6_cidr = ""

    def set_packet_sink(self, sink: Callable[[bytes], Awaitable[None] | None]) -> None:
        self._packet_sink = sink
        if self._opened and self._dev is not None and self._mux is not None:
            bridge_tun_windows.register_tun_reader(self._mux, self._dev)

    async def _emit_packet(self, packet: bytes) -> None:
        self._packets_to_runtime += 1
        if self._packet_sink is None:
            return
        result = self._packet_sink(bytes(packet))
        if inspect.isawaitable(result):
            await result

    async def open_tun(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._opened and self._dev is not None:
            return self.local_snapshot()
        mux = _HelperMux(self)
        ifname = str(payload.get("ifname") or "obtun0")
        mtu = int(payload.get("mtu") or 1600)
        bridge_tun_windows.require_tun_support(mux)
        dev = bridge_tun_windows.open_tun_device(mux, ifname, mtu, payload.get("service_key"))
        self._mux = mux
        self._dev = dev
        self._opened = True
        self._ifname = str(getattr(dev, "ifname", ifname) or ifname)
        self._ifindex = 0
        self._mtu = int(getattr(dev, "mtu", mtu) or mtu)
        self._stopped = False
        if self._packet_sink is not None:
            bridge_tun_windows.register_tun_reader(mux, dev)
        return self.local_snapshot()

    async def write_packet(self, packet: bytes) -> dict[str, Any]:
        if self._dev is None or self._mux is None:
            raise RuntimeError("Windows native TUN helper backend is not opened")
        bridge_tun_windows.write_tun_packet(self._mux, self._dev, bytes(packet))
        self._packets_from_runtime += 1
        return {"accepted": True, "len": len(packet)}

    async def apply_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._apply_calls += 1
        self._network_applied = True
        self._included_routes_startup_enabled = bool(payload.get("tun_routing", {}).get("enabled_on_startup", True)) if isinstance(payload.get("tun_routing"), dict) else True
        self._included_routes_active = False
        self._last_apply_payload = dict(payload or {})
        ifname = str(payload.get("ifname") or self._ifname or "obtun0")
        interface_index = int(self._ifindex or 0)
        self._clear_last_failure()
        stage = "start"
        try:
            if interface_index <= 0:
                self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", "resolve_ifindex", ifname)
                interface_index = self._resolve_interface_index(ifname)
                self._ifindex = int(interface_index)
            ipv4_cidr = self._cidr_from_tun_routing(payload, "tunnel_address", "tunnel_prefix")
            ipv6_cidr = self._cidr_from_tun_routing(payload, "tunnel_address6", "tunnel_prefix6")
            if ipv4_cidr:
                stage = "ipv4_addr_apply"
                self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s cidr=%s", stage, ifname, ipv4_cidr)
                self._apply_interface_address(interface_index=interface_index, cidr=ipv4_cidr, family=4)
                self._applied_ipv4_cidr = ipv4_cidr
            if ipv6_cidr:
                stage = "ipv6_addr_apply"
                self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s cidr=%s", stage, ifname, ipv6_cidr)
                self._apply_interface_address(interface_index=interface_index, cidr=ipv6_cidr, family=6)
                self._applied_ipv6_cidr = ipv6_cidr
            stage = "underlay_snapshot"
            self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", stage, ifname)
            self._saved_underlay4 = self._snapshot_default_route(4)
            self._saved_underlay6 = self._snapshot_default_route(6)
            stage = "excluded_routes_apply"
            self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", stage, ifname)
            self._apply_excluded_routes(payload)
            stage = "included_routes_apply"
            self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", stage, ifname)
            if self._included_routes_startup_enabled:
                self._apply_included_routes(payload, interface_index=interface_index)
                self._included_routes_active = True
            stage = "dns_apply"
            self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", stage, ifname)
            self._apply_dns(interface_index=interface_index, payload=payload)
            stage = "firewall_apply"
            self._log.debug("[TUN/HELPER/WIN] apply_network stage=%s ifname=%s", stage, ifname)
            self._apply_firewall(payload, ifname=ifname)
            self._log.debug("[TUN/HELPER/WIN] apply_network complete ifname=%s", ifname)
        except Exception as exc:
            cleanup_ok = False
            self._network_applied = False
            try:
                self._rollback_partial_apply(interface_index=interface_index)
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
            "backend": "windows-native",
            "ifname": ifname,
            "apply_calls": self._apply_calls,
            "applied_ipv4_cidr": self._applied_ipv4_cidr,
            "applied_ipv6_cidr": self._applied_ipv6_cidr,
            "applied_ipv4_routes": list(self._applied_ipv4_routes),
            "applied_ipv6_routes": list(self._applied_ipv6_routes),
            "applied_excluded_ipv4_routes": list(self._applied_excluded_ipv4_routes),
            "applied_excluded_ipv6_routes": list(self._applied_excluded_ipv6_routes),
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
        self._included_routes_active = False
        self._last_remove_payload = dict(payload or {})
        ifname = str(payload.get("ifname") or self._ifname or "obtun0")
        interface_index = int(self._ifindex or self._resolve_interface_index(ifname))
        self._clear_last_failure()
        stage = "start"
        try:
            stage = "firewall_remove"
            self._remove_firewall(payload, ifname=ifname)
            stage = "dns_remove"
            self._remove_dns(interface_index=interface_index)
            stage = "included_routes_remove"
            self._remove_included_routes(interface_index=interface_index)
            stage = "excluded_routes_remove"
            self._remove_excluded_routes()
            stage = "ipv4_addr_remove"
            if self._applied_ipv4_cidr:
                self._remove_interface_address(interface_index=interface_index, cidr=self._applied_ipv4_cidr)
                self._applied_ipv4_cidr = ""
            stage = "ipv6_addr_remove"
            if self._applied_ipv6_cidr:
                self._remove_interface_address(interface_index=interface_index, cidr=self._applied_ipv6_cidr)
                self._applied_ipv6_cidr = ""
            self._saved_underlay4 = {}
            self._saved_underlay6 = {}
        except Exception as exc:
            self._record_failure(operation="remove_network", stage=stage, exc=exc)
            raise
        return {
            "removed": True,
            "backend": "windows-native",
            "ifname": ifname,
            "remove_calls": self._remove_calls,
            "last_failure": dict(self._last_failure),
        }

    async def snapshot(self) -> dict[str, Any]:
        return self.local_snapshot()

    def local_snapshot(self) -> dict[str, Any]:
        return {
            "backend": "windows-native",
            "opened": self._opened,
            "ifname": self._ifname,
            "ifindex": self._ifindex,
            "mtu": self._mtu,
            "packets_from_runtime": self._packets_from_runtime,
            "packets_to_runtime": self._packets_to_runtime,
            "network_applied": self._network_applied,
            "included_routes_active": self._included_routes_active,
            "included_routes_startup_enabled": self._included_routes_startup_enabled,
            "included_routes_toggle_supported": True,
            "suspend_calls": self._suspend_calls,
            "resume_calls": self._resume_calls,
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
            "applied_dns_servers": list(self._applied_dns_servers),
            "dns_manager": self._dns_manager,
            "firewall_manager": self._firewall_manager,
            "firewall_wan_if": self._firewall_wan_if,
            "applied_firewall_rules": list(self._applied_firewall_rules),
            "saved_underlay4": dict(self._saved_underlay4),
            "saved_underlay6": dict(self._saved_underlay6),
            "last_failure": dict(self._last_failure),
            "stopped": self._stopped,
        }

    async def set_tun_enabled(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._network_applied:
            raise RuntimeError("TUN network is not applied")
        enabled = bool(payload.get("enabled"))
        ifname = str(payload.get("ifname") or self._ifname or "obtun0")
        interface_index = int(self._ifindex or self._resolve_interface_index(ifname))
        self._clear_last_failure()
        if enabled:
            self._resume_calls += 1
            if not self._included_routes_active:
                self._apply_included_routes(payload, interface_index=interface_index)
                self._included_routes_active = True
        else:
            self._suspend_calls += 1
            if self._included_routes_active:
                self._remove_included_routes(interface_index=interface_index)
                self._included_routes_active = False
        snapshot = self.local_snapshot()
        snapshot.update({"ok": True, "enabled": enabled, "ifname": ifname})
        return snapshot

    async def stop(self) -> None:
        self._stopped = True
        if self._network_applied:
            with contextlib.suppress(Exception):
                await self.remove_network(self._last_apply_payload or {"ifname": self._ifname})
        if self._dev is not None and self._mux is not None:
            bridge_tun_windows.close_tun_device(self._mux, self._dev)
        self._dev = None
        self._mux = None
        self._opened = False
