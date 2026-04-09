import os
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional

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
    pytest.mark.linux_elevated,
]


def _require_linux_elevated_runtime() -> None:
    if sys.platform != "linux":
        pytest.skip("linux_elevated tests are supported only on Linux")
    if os.geteuid() != 0:
        pytest.skip("linux_elevated tests require root or equivalent CAP_NET_ADMIN permission")
    if not os.path.exists("/dev/net/tun"):
        pytest.skip("linux_elevated tests require /dev/net/tun")
    if shutil.which("ip") is None:
        pytest.skip("linux_elevated tests require the ip command")


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


def _tun_name(tag: str, side: str) -> str:
    return f"ob{tag}{side}"[:15]


def _wait_interface(ifname: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.if_nametoindex(ifname)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} did not appear")


def _wait_interface_with_bridge_logs(
    ifname: str,
    *,
    server_proc: overlay_e2e.Proc,
    client_proc: overlay_e2e.Proc,
    timeout: float = 12.0,
) -> None:
    try:
        _wait_interface(ifname, timeout=timeout)
        return
    except Exception as exc:
        server_tail = server_proc.log_path.read_text(errors="replace")[-3000:] if server_proc.log_path.exists() else ""
        client_tail = client_proc.log_path.read_text(errors="replace")[-3000:] if client_proc.log_path.exists() else ""
        raise RuntimeError(
            f"{exc}\n--- {server_proc.log_path.name} tail ---\n{server_tail}\n"
            f"--- {client_proc.log_path.name} tail ---\n{client_tail}"
        ) from exc


def _run_ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True, text=True)


def _configure_tun_route(ifname: str, source_ip: str, dest_ip: str) -> None:
    _run_ip("-4", "addr", "add", f"{source_ip}/32", "dev", ifname)
    _run_ip("-4", "route", "add", f"{dest_ip}/32", "dev", ifname, "src", source_ip)
    _run_ip("link", "set", ifname, "up")


def _send_udp(source_ip: str, dest_ip: str, payload: bytes, *, port: int, bind_ifname: Optional[str] = None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if bind_ifname:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bind_ifname.encode("ascii") + b"\x00")
        sock.bind((source_ip, 0))
        sock.sendto(payload, (dest_ip, port))


def _link_total_bytes(ifname: str) -> int:
    cp = subprocess.run(
        ["ip", "-j", "-s", "link", "show", "dev", ifname],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    if not rows:
        raise RuntimeError(f"ip -j -s link show returned no rows for {ifname}")
    stats = rows[0].get("stats64") or rows[0].get("stats") or {}
    rx = int(((stats.get("rx") or {}).get("bytes") or 0))
    tx = int(((stats.get("tx") or {}).get("bytes") or 0))
    return rx + tx


def _wait_link_total_increase(ifname: str, before_total: int, *, timeout: float = 12.0) -> int:
    end = time.time() + timeout
    while time.time() < end:
        current = _link_total_bytes(ifname)
        if current > before_total:
            return current
        time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} bytes did not increase beyond {before_total} within {timeout:.1f}s")


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
) -> TunBridgePair:
    materialized = (
        overlay_e2e.materialize_secure_link_case_ports(base_case, secure_slot)
        if secure_slot is not None
        else overlay_e2e.materialize_case_ports(base_case, case_index)
    )
    client_spec = json.dumps(
        {
            "listen": {"protocol": "tun", "ifname": client_ifname, "mtu": int(mtu)},
            "target": {"protocol": "tun", "ifname": server_ifname, "mtu": int(mtu)},
        },
        separators=(",", ":"),
    )
    server_spec = json.dumps(
        {
            "listen": {"protocol": "tun", "ifname": server_ifname, "mtu": int(mtu)},
            "target": {"protocol": "tun", "ifname": client_ifname, "mtu": int(mtu)},
        },
        separators=(",", ":"),
    )
    server_args = _strip_option_and_values(materialized.bridge_server_args, "--own-servers")
    server_args = _strip_option_and_values(server_args, "--remote-servers")
    client_args = _with_service_specs(materialized.bridge_client_args, "--own-servers", [client_spec])
    client_args = _with_service_specs(client_args, "--remote-servers", [server_spec])
    tuned_case = replace(
        materialized,
        bridge_server_args=server_args,
        bridge_client_args=client_args,
    )
    server_spec_cmd, client_spec_cmd = overlay_e2e.build_commands(tuned_case, tmp_path, case_index, enable_admin=True)

    server_name, server_cmd, server_env, server_admin = server_spec_cmd
    client_name, client_cmd, client_env, client_admin = client_spec_cmd
    if server_extra_args:
        server_cmd = list(server_cmd) + list(server_extra_args)
    if client_extra_args:
        client_cmd = list(client_cmd) + list(client_extra_args)

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


def _assert_tun_one_way(
    *,
    source_ip: str,
    dest_ip: str,
    payload: bytes,
    port: int,
    bind_ifname: str,
    peer_ifname: str,
    timeout: float = 12.0,
) -> int:
    before_total = _link_total_bytes(peer_ifname)
    _send_udp(source_ip, dest_ip, payload, port=port, bind_ifname=bind_ifname)
    return _wait_link_total_increase(peer_ifname, before_total, timeout=timeout)


def test_overlay_e2e_linux_elevated_tun_over_myudp_packet_carry(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt301"
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
        _wait_interface_with_bridge_logs(client_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _configure_tun_route(client_ifname, "198.18.30.1", "198.18.30.2")
        _configure_tun_route(server_ifname, "198.18.30.2", "198.18.30.1")

        forward_payload = b"tun-basic-forward-301"
        after_total = _assert_tun_one_way(
            source_ip="198.18.30.1",
            dest_ip="198.18.30.2",
            payload=forward_payload,
            port=30101,
            bind_ifname=client_ifname,
            peer_ifname=server_ifname,
        )
        assert after_total > 0
    finally:
        pair.stop()


def test_overlay_e2e_linux_elevated_tun_over_ws_secure_link_fragments(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt302"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    secure_args = [
        "--secure-link", "--secure-link-mode", "psk", "--secure-link-psk", "lab-secret",
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
    )
    try:
        overlay_e2e.wait_status_secure_link_state(
            pair.client_proc.admin_port or 0,
            expected_state="authenticated",
            timeout=12.0,
            label="client",
            authenticated=True,
        )
        overlay_e2e.wait_status_secure_link_state(
            pair.server_proc.admin_port or 0,
            expected_state="authenticated",
            timeout=12.0,
            label="server",
            authenticated=True,
        )
        _wait_interface_with_bridge_logs(client_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _configure_tun_route(client_ifname, "198.18.31.1", "198.18.31.2")
        _configure_tun_route(server_ifname, "198.18.31.2", "198.18.31.1")
        payload = b"tun-frag-302-" + (b"F" * 1300)
        after_total = _assert_tun_one_way(
            source_ip="198.18.31.1",
            dest_ip="198.18.31.2",
            payload=payload,
            port=30201,
            bind_ifname=client_ifname,
            peer_ifname=server_ifname,
            timeout=15.0,
        )
        assert after_total > 0
        client_log = overlay_e2e.wait_log_contains(pair.client_proc.log_path, "fragment TUN packet", timeout=10.0)
        assert "frag_payload_limit=" in client_log
    finally:
        pair.stop()
