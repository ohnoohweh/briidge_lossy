import json
import socket
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional

import ctypes
import pytest

from tests.integration import test_overlay_e2e as overlay_e2e


class TunBridgePair:
    def __init__(self, case: overlay_e2e.Case, server_proc: overlay_e2e.Proc, client_proc: overlay_e2e.Proc):
        self.case = case
        self.server_proc = server_proc
        self.client_proc = client_proc

    def stop(self) -> None:
        overlay_e2e.stop_proc(self.client_proc)
        overlay_e2e.stop_proc(self.server_proc)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.windows_elevated,
    pytest.mark.windows_only,
]


def _require_windows_elevated_runtime() -> None:
    if sys.platform != "win32":
        pytest.skip("windows_elevated tests are supported only on Windows")
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        pytest.skip("windows_elevated tests require Administrator privileges")


def _tun_name(tag: str, side: str) -> str:
    return f"ob{tag}{side}"[:63]


def _get_adapter_record(ifname: str) -> Optional[dict]:
    cp = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "$adapter = Get-NetAdapter -IncludeHidden -Name '" + ifname + "' -ErrorAction SilentlyContinue; "
                "if (-not $adapter) { "
                "$adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Name -eq '" + ifname + "' -or $_.InterfaceAlias -eq '" + ifname + "' } | "
                "Select-Object -First 1 } ; "
                "if ($adapter) { $adapter | Select-Object Name,InterfaceAlias,InterfaceDescription,DriverDescription,ifIndex,Status | ConvertTo-Json -Depth 2 }"
            ),
        ],
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0 or not cp.stdout.strip():
        return None
    try:
        rows = json.loads(cp.stdout)
    except Exception:
        return None
    if isinstance(rows, list):
        return dict(rows[0]) if rows else None
    if isinstance(rows, dict):
        return dict(rows)
    return None


def _wait_interface(ifname: str, timeout: float = 20.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        record = _get_adapter_record(ifname)
        if record is not None:
            return record
        try:
            socket.if_nametoindex(ifname)
            return {"Name": ifname, "ifIndex": socket.if_nametoindex(ifname)}
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} did not appear")


def _configure_tun_route(adapter: dict, source_ip: str, dest_ip: str) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    if if_index <= 0:
        raise RuntimeError(f"adapter missing ifIndex: {adapter!r}")
    cmd = (
        f"$ErrorActionPreference='Stop'; "
        f"if (-not (Get-NetIPAddress -InterfaceIndex {if_index} -IPAddress {source_ip} -ErrorAction SilentlyContinue)) "
        f"{{ New-NetIPAddress -InterfaceIndex {if_index} -IPAddress {source_ip} -PrefixLength 24 -PolicyStore ActiveStore | Out-Null }}; "
        f"if (-not (Get-NetRoute -InterfaceIndex {if_index} -DestinationPrefix '{dest_ip}/32' -ErrorAction SilentlyContinue)) "
        f"{{ New-NetRoute -InterfaceIndex {if_index} -DestinationPrefix '{dest_ip}/32' -NextHop '0.0.0.0' -PolicyStore ActiveStore | Out-Null }}"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], check=True)


def _wait_interface_ip(adapter: dict, ip_address: str, timeout: float = 8.0) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    end = time.time() + timeout
    while time.time() < end:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-NetIPAddress -InterfaceIndex {if_index} -IPAddress {ip_address} "
                    "-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2"
                ),
            ],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return
        time.sleep(0.1)
    raise RuntimeError(f"address {ip_address} did not appear on adapter {adapter!r}")


def _wait_interface_ip_absent(adapter: dict, ip_address: str, timeout: float = 12.0) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    end = time.time() + timeout
    while time.time() < end:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-NetIPAddress -InterfaceIndex {if_index} -IPAddress {ip_address} "
                    "-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2"
                ),
            ],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and not cp.stdout.strip():
            return
        time.sleep(0.1)
    raise RuntimeError(f"address {ip_address} still present on adapter {adapter!r}")


def _wait_route_absent(adapter: dict, route_spec: str, timeout: float = 12.0) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    end = time.time() + timeout
    while time.time() < end:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-NetRoute -InterfaceIndex {if_index} -DestinationPrefix '{route_spec}' "
                    "-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2"
                ),
            ],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and not cp.stdout.strip():
            return
        time.sleep(0.1)
    raise RuntimeError(f"route {route_spec} still present on adapter {adapter!r}")


def _wait_dns_server_present(adapter: dict, dns_server: str, timeout: float = 12.0) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    end = time.time() + timeout
    while time.time() < end:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-DnsClientServerAddress -InterfaceIndex {if_index} "
                    "-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4"
                ),
            ],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and str(dns_server) in str(cp.stdout or ""):
            return
        time.sleep(0.1)
    raise RuntimeError(f"dns server {dns_server} did not appear on adapter {adapter!r}")


def _wait_dns_server_absent(adapter: dict, dns_server: str, timeout: float = 12.0) -> None:
    if_index = int(adapter.get("ifIndex") or 0)
    end = time.time() + timeout
    while time.time() < end:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-DnsClientServerAddress -InterfaceIndex {if_index} "
                    "-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4"
                ),
            ],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and str(dns_server) not in str(cp.stdout or ""):
            return
        time.sleep(0.1)
    raise RuntimeError(f"dns server {dns_server} still present on adapter {adapter!r}")


def _wait_tun_helper_runtime(
    admin_port: int,
    *,
    expected_backend: str,
    timeout: float = 20.0,
) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = overlay_e2e.get_status(admin_port)
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last = helper
        if (
            bool(helper.get("enabled"))
            and bool(helper.get("connected"))
            and str(runtime.get("backend") or "") == str(expected_backend)
            and str(runtime.get("ifname") or "")
            and bool(runtime.get("opened"))
            and bool(runtime.get("network_applied"))
        ):
            return helper
        time.sleep(0.2)
    raise RuntimeError(f"helper runtime did not reach expected state; last={last!r}")


def _wait_tun_helper_runtime_counter(
    admin_port: int,
    counter_name: str,
    before_value: int,
    *,
    timeout: float = 12.0,
) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = overlay_e2e.get_status(admin_port)
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last = runtime
        if int(runtime.get(counter_name) or 0) > int(before_value):
            return runtime
        time.sleep(0.2)
    raise RuntimeError(
        f"helper runtime counter {counter_name} did not increase beyond {before_value}; last={last!r}"
    )


def _wait_tun_helper_disconnected_runtime(
    admin_port: int,
    *,
    expected_ifname: str,
    timeout: float = 20.0,
) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = overlay_e2e.get_status(admin_port)
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last = helper
        if (
            bool(helper.get("enabled"))
            and not bool(helper.get("connected"))
            and str(runtime.get("ifname") or "") == str(expected_ifname)
            and helper.get("process_returncode") is not None
        ):
            return status
        time.sleep(0.2)
    raise RuntimeError(f"helper runtime did not report disconnect for {expected_ifname!r}; last={last!r}")


def _kill_process_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/PID", str(int(pid)), "/F", "/T"],
        check=True,
        capture_output=True,
        text=True,
    )


def _request_tun_helper_repair(admin_port: int, timeout: float = 5.0) -> dict:
    code, body = overlay_e2e.post_json(f"http://127.0.0.1:{int(admin_port)}/api/tun-helper/repair", timeout=timeout)
    if int(code) not in {200, 409}:
        raise RuntimeError(f"unexpected repair response code={code} body={body!r}")
    return dict(body or {})


def _wait_tun_helper_repair_cleared(admin_port: int, *, expected_ifname: str, timeout: float = 20.0) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = overlay_e2e.get_status(admin_port)
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last_repair = dict(helper.get("last_repair") or {})
        last = helper
        if (
            bool(helper.get("enabled"))
            and not bool(helper.get("connected"))
            and str(runtime.get("ifname") or "") == str(expected_ifname)
            and not bool(helper.get("recovery"))
            and bool(last_repair.get("attempted"))
            and bool(last_repair.get("ok"))
            and not bool(last_repair.get("stale_state_remaining"))
        ):
            return status
        time.sleep(0.2)
    raise RuntimeError(f"helper repair did not clear stale state for {expected_ifname!r}; last={last!r}")


def _send_udp(source_ip: str, dest_ip: str, payload: bytes, *, port: int) -> None:
    family = socket.AF_INET6 if ":" in source_ip or ":" in dest_ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((source_ip, 0))
        sock.sendto(payload, (dest_ip, int(port)))


def _strip_option_and_values(args: list[str], option: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg == option:
            i += 1
            while i < len(args) and not str(args[i]).startswith("--"):
                i += 1
            continue
        out.append(arg)
        i += 1
    return out


def _with_service_specs(args: list[str], option: str, specs: list[str]) -> list[str]:
    out = _strip_option_and_values(args, option)
    return out + [option, *specs]


def _start_tun_bridge_pair(
    *,
    base_case: overlay_e2e.Case,
    tmp_path: Path,
    case_index: int,
    client_ifname: str,
    server_ifname: str,
    mtu: int,
    secure_slot: Optional[int] = None,
    server_extra_args: Optional[list[str]] = None,
    client_extra_args: Optional[list[str]] = None,
    server_env_extra: Optional[dict[str, str]] = None,
    client_env_extra: Optional[dict[str, str]] = None,
) -> TunBridgePair:
    materialized = (
        overlay_e2e.materialize_secure_link_case_ports(base_case, secure_slot)
        if secure_slot is not None
        else overlay_e2e.materialize_case_ports(base_case, case_index)
    )
    client_spec = f"tun,{mtu},{client_ifname},tun,{server_ifname},{mtu}"
    server_spec = f"tun,{mtu},{server_ifname},tun,{client_ifname},{mtu}"
    tuned_case = replace(
        materialized,
        bridge_server_args=_with_service_specs(materialized.bridge_server_args, "--remote-servers", [server_spec]),
        bridge_client_args=_with_service_specs(materialized.bridge_client_args, "--own-servers", [client_spec]),
    )
    server_spec_cmd, client_spec_cmd = overlay_e2e.build_commands(tuned_case, tmp_path, case_index, enable_admin=True)

    server_name, server_cmd, server_env, server_admin = server_spec_cmd
    client_name, client_cmd, client_env, client_admin = client_spec_cmd
    if server_extra_args:
        server_cmd = list(server_cmd) + list(server_extra_args)
    if client_extra_args:
        client_cmd = list(client_cmd) + list(client_extra_args)
    if server_env_extra:
        server_env = dict(server_env)
        server_env.update(server_env_extra)
    if client_env_extra:
        client_env = dict(client_env)
        client_env.update(client_env_extra)

    server_proc = overlay_e2e.start_proc(
        f"{tuned_case.name}_{server_name}",
        server_cmd,
        tmp_path,
        env_extra=server_env,
        admin_port=server_admin,
    )
    client_proc = overlay_e2e.start_proc(
        f"{tuned_case.name}_{client_name}",
        client_cmd,
        tmp_path,
        env_extra=client_env,
        admin_port=client_admin,
    )
    try:
        time.sleep(0.5)
        overlay_e2e.assert_running(server_proc)
        overlay_e2e.assert_running(client_proc)
        overlay_e2e.wait_admin_up(server_proc.admin_port or 0, timeout=10.0)
        overlay_e2e.wait_admin_up(client_proc.admin_port or 0, timeout=10.0)
        client_proc = overlay_e2e.wait_status_connected_proc(client_proc, tmp_path, timeout=20.0, label="client")
        overlay_e2e.wait_status_connected(server_proc.admin_port or 0, timeout=20.0, label="server")
        return TunBridgePair(tuned_case, server_proc, client_proc)
    except Exception:
        overlay_e2e.stop_proc(client_proc)
        overlay_e2e.stop_proc(server_proc)
        raise


def _wait_tun_open_and_peer_bind(pair: TunBridgePair, *, client_ifname: str, server_ifname: str, timeout: float = 12.0) -> None:
    open_line = overlay_e2e.wait_log_contains(pair.client_proc.log_path, "OPENv", timeout=timeout)
    assert client_ifname in open_line
    assert server_ifname in open_line
    bind_line = overlay_e2e.wait_log_contains(pair.server_proc.log_path, f"bound if={server_ifname}", timeout=timeout)
    assert f"bound if={server_ifname}" in bind_line


def test_overlay_e2e_windows_elevated_tun_over_myudp_channel_open(tmp_path: Path) -> None:
    _require_windows_elevated_runtime()
    case_tag = "wt301"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=301,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
    )
    try:
        client_adapter = _wait_interface(client_ifname)
        server_adapter = _wait_interface(server_ifname)
        _configure_tun_route(client_adapter, "198.18.30.1", "198.18.30.2")
        _configure_tun_route(server_adapter, "198.18.30.2", "198.18.30.1")
        _wait_interface_ip(client_adapter, "198.18.30.1")
        _wait_interface_ip(server_adapter, "198.18.30.2")

        _wait_tun_open_and_peer_bind(pair, client_ifname=client_ifname, server_ifname=server_ifname)
    finally:
        pair.stop()


def test_overlay_e2e_windows_elevated_tun_over_ws_secure_link_channel_open(tmp_path: Path) -> None:
    _require_windows_elevated_runtime()
    case_tag = "wt302"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    secure_args = [
        "--secure-link", "--secure-link-mode", "psk", "--secure-link-psk", "lab-secret",
        "--ws-proxy-mode", "off",
        "--ws-payload-mode", "semi-text-shape",
        "--ws-max-size", "160",
        "--log-channel-mux", "DEBUG",
        "--log-ws-session", "DEBUG",
        "--log-secure-link", "DEBUG",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case08_overlay_ws_ipv4"],
        tmp_path=tmp_path,
        case_index=302,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        secure_slot=10,
        server_extra_args=secure_args,
        client_extra_args=secure_args,
        server_env_extra={"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"},
        client_env_extra={"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"},
    )
    try:
        overlay_e2e.wait_status_secure_link_state(
            pair.client_proc.admin_port or 0,
            expected_state="authenticated",
            timeout=12.0,
            label="client",
            authenticated=True,
        )
        client_adapter = _wait_interface(client_ifname)
        server_adapter = _wait_interface(server_ifname)
        _configure_tun_route(client_adapter, "198.18.31.1", "198.18.31.2")
        _configure_tun_route(server_adapter, "198.18.31.2", "198.18.31.1")
        _wait_interface_ip(client_adapter, "198.18.31.1")
        _wait_interface_ip(server_adapter, "198.18.31.2")
        _wait_tun_open_and_peer_bind(pair, client_ifname=client_ifname, server_ifname=server_ifname, timeout=15.0)
    finally:
        pair.stop()


def test_overlay_e2e_windows_elevated_tun_helper_native_applies_network_and_carries_packets(tmp_path: Path) -> None:
    _require_windows_elevated_runtime()
    case_tag = "wt303"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "windows-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_routing_args = [
        "--tunnel-address", "198.18.66.1",
        "--tunnel-prefix", "30",
        "--tunnel-gateway", "198.18.66.2",
        "--included-routes", "198.18.66.2/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.66.1",
        "--tunnel-prefix", "30",
        "--tunnel-gateway", "198.18.66.2",
        "--included-routes", "198.18.66.1/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=303,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    try:
        client_helper = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="windows-native",
        )
        server_helper = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="windows-native",
        )
        client_runtime = dict(client_helper.get("runtime") or {})
        server_runtime = dict(server_helper.get("runtime") or {})

        assert str(client_runtime.get("ifname") or "") == client_ifname
        assert str(server_runtime.get("ifname") or "") == server_ifname
        assert client_runtime.get("applied_ipv4_cidr") == "198.18.66.1/30"
        assert server_runtime.get("applied_ipv4_cidr") == "198.18.66.1/30"
        assert client_runtime.get("applied_ipv4_routes") == ["198.18.66.2/32"]
        assert server_runtime.get("applied_ipv4_routes") == ["198.18.66.1/32"]

        client_adapter = _wait_interface(client_ifname)
        server_adapter = _wait_interface(server_ifname)
        _wait_interface_ip(client_adapter, "198.18.66.1")
        _wait_interface_ip(server_adapter, "198.18.66.2")
        _wait_tun_open_and_peer_bind(pair, client_ifname=client_ifname, server_ifname=server_ifname)

        client_before = int(client_runtime.get("packets_to_runtime") or 0)
        server_before = int(server_runtime.get("packets_from_runtime") or 0)
        _send_udp("198.18.66.1", "198.18.66.2", b"windows-helper-native-packet-carry-303", port=50303)
        _wait_tun_helper_runtime_counter(
            pair.client_proc.admin_port or 0,
            "packets_to_runtime",
            client_before,
        )
        _wait_tun_helper_runtime_counter(
            pair.server_proc.admin_port or 0,
            "packets_from_runtime",
            server_before,
        )
    finally:
        pair.stop()


def test_overlay_e2e_windows_elevated_tun_helper_native_reports_helper_death_warning(tmp_path: Path) -> None:
    _require_windows_elevated_runtime()
    case_tag = "wt304"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "windows-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_routing_args = [
        "--tunnel-address", "198.18.67.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.67.2",
        "--included-routes", "198.18.167.0/24",
        "--excluded-routes", "127.0.0.0/8",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.67.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.67.2",
        "--included-routes", "198.18.67.1/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=304,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    try:
        client_helper = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="windows-native",
        )
        client_runtime = dict(client_helper.get("runtime") or {})
        helper_pid = int(client_helper.get("pid") or 0)

        assert helper_pid > 0
        assert str(client_runtime.get("ifname") or "") == client_ifname
        _wait_interface(client_ifname)

        _kill_process_tree(helper_pid)

        disconnected = _wait_tun_helper_disconnected_runtime(
            pair.client_proc.admin_port or 0,
            expected_ifname=client_ifname,
        )
        helper_after = dict(disconnected.get("tun_helper") or {})
        runtime_after = dict(helper_after.get("runtime") or {})
        recovery = dict(helper_after.get("recovery") or {})

        assert runtime_after.get("backend") == "windows-native"
        assert runtime_after.get("ifname") == client_ifname
        assert recovery.get("needs_manual_cleanup") is True
        assert recovery.get("stale_network_possible") is True
        assert recovery.get("stale_firewall_possible") is False
        warnings = list(recovery.get("warnings") or [])
        assert "helper_owned_network_state_may_remain" in warnings
        summary = str(recovery.get("summary") or "").lower()
        assert "manual cleanup" in summary
        repair_hint = str(recovery.get("repair_hint") or "").lower()
        assert "routes" in repair_hint
        assert "addresses" in repair_hint
        last_error = str(helper_after.get("last_error") or "").lower()
        assert "connection closed" in last_error or "connection reset" in last_error
    finally:
        pair.stop()


def test_overlay_e2e_windows_elevated_tun_helper_native_repairs_stale_network_state(tmp_path: Path) -> None:
    _require_windows_elevated_runtime()
    case_tag = "wt305"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "windows-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_routing_args = [
        "--tunnel-address", "198.18.68.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.68.2",
        "--included-routes", "198.18.168.0/24",
        "--excluded-routes", "127.0.0.0/8",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers", "9.9.9.9",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.68.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.68.2",
        "--included-routes", "198.18.68.1/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=305,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    try:
        client_helper = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="windows-native",
        )
        client_runtime = dict(client_helper.get("runtime") or {})
        helper_pid = int(client_helper.get("pid") or 0)

        assert helper_pid > 0
        assert str(client_runtime.get("ifname") or "") == client_ifname
        assert client_runtime.get("applied_dns_servers") == ["9.9.9.9"]
        client_adapter = _wait_interface(client_ifname)
        _wait_interface_ip(client_adapter, "198.18.68.1")
        _wait_dns_server_present(client_adapter, "9.9.9.9")

        _kill_process_tree(helper_pid)

        disconnected = _wait_tun_helper_disconnected_runtime(
            pair.client_proc.admin_port or 0,
            expected_ifname=client_ifname,
        )
        helper_after = dict(disconnected.get("tun_helper") or {})
        recovery = dict(helper_after.get("recovery") or {})
        assert recovery.get("needs_manual_cleanup") is True

        repair = _request_tun_helper_repair(pair.client_proc.admin_port or 0)
        assert repair.get("ok") is True
        assert repair.get("cleanup_ok") is True
        assert "ipv4_addr" in list(repair.get("repaired") or [])
        assert "included_routes" in list(repair.get("repaired") or [])
        assert "dns" in list(repair.get("repaired") or [])

        cleared = _wait_tun_helper_repair_cleared(
            pair.client_proc.admin_port or 0,
            expected_ifname=client_ifname,
        )
        helper_cleared = dict(cleared.get("tun_helper") or {})
        runtime_cleared = dict(helper_cleared.get("runtime") or {})
        last_repair = dict(helper_cleared.get("last_repair") or {})
        assert runtime_cleared.get("backend") == "windows-native"
        assert runtime_cleared.get("ifname") == client_ifname
        assert runtime_cleared.get("network_applied") is False
        assert runtime_cleared.get("applied_ipv4_cidr") == ""
        assert runtime_cleared.get("applied_ipv4_routes") == []
        assert runtime_cleared.get("applied_dns_servers") == []
        assert helper_cleared.get("recovery") in ({}, None)
        assert last_repair.get("verified_state") == "stale_state_cleared"

        _wait_interface_ip_absent(client_adapter, "198.18.68.1")
        _wait_route_absent(client_adapter, "198.18.168.0/24")
        _wait_dns_server_absent(client_adapter, "9.9.9.9")
    finally:
        pair.stop()
