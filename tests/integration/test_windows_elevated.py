import json
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
    open_line = overlay_e2e.wait_log_contains(pair.client_proc.log_path, f"OPENv4 iid=", timeout=timeout)
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
