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


class SharedTunBridgeGroup:
    def __init__(
        self,
        *,
        case: overlay_e2e.Case,
        server_proc: overlay_e2e.Proc,
        client_a_proc: overlay_e2e.Proc,
        client_b_proc: overlay_e2e.Proc,
        client_a_cmd: list[str],
        client_b_cmd: list[str],
        client_env: Optional[dict[str, str]],
        tmp_path: Path,
    ):
        self.case = case
        self.server_proc = server_proc
        self.client_a_proc = client_a_proc
        self.client_b_proc = client_b_proc
        self._client_a_cmd = list(client_a_cmd)
        self._client_b_cmd = list(client_b_cmd)
        self._client_env = dict(client_env or {})
        self._tmp_path = tmp_path

    def stop(self) -> None:
        overlay_e2e.stop_proc(self.client_b_proc)
        overlay_e2e.stop_proc(self.client_a_proc)
        overlay_e2e.stop_proc(self.server_proc)

    def restart_client_a(self) -> overlay_e2e.Proc:
        overlay_e2e.stop_proc(self.client_a_proc)
        proc = overlay_e2e.start_proc(
            f"{self.case.name}_bridge_client_a_restart",
            self._client_a_cmd,
            self._tmp_path,
            env_extra=self._client_env,
            admin_port=self.client_a_proc.admin_port,
        )
        time.sleep(0.5)
        overlay_e2e.assert_running(proc)
        overlay_e2e.wait_admin_up(proc.admin_port or 0, timeout=10.0)
        proc = overlay_e2e.wait_status_connected_proc(proc, self._tmp_path, timeout=20.0, label="client_a_restart")
        self.client_a_proc = proc
        return proc


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


def _with_option_value(args: list[str], option: str, value: str) -> list[str]:
    out = _strip_option_and_values(args, option)
    return out + [option, value]


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


def _run_ip_allow_exists(*args: str) -> None:
    completed = subprocess.run(["ip", *args], check=False, capture_output=True, text=True)
    if completed.returncode == 0:
        return
    stderr = str(completed.stderr or "")
    if "File exists" in stderr:
        return
    raise subprocess.CalledProcessError(
        completed.returncode,
        completed.args,
        output=completed.stdout,
        stderr=completed.stderr,
    )


def _add_tun_address(ifname: str, address: str) -> None:
    _run_ip_allow_exists("-4", "addr", "add", f"{address}/32", "dev", ifname)


def _add_tun_route(ifname: str, source_ip: str, dest_ip: str) -> None:
    _run_ip_allow_exists("-4", "route", "add", f"{dest_ip}/32", "dev", ifname, "src", source_ip)


def _configure_tun_route(ifname: str, source_ip: str, dest_ip: str) -> None:
    _add_tun_address(ifname, source_ip)
    _add_tun_route(ifname, source_ip, dest_ip)
    _run_ip("link", "set", ifname, "up")


def _configure_tun_routes(ifname: str, source_ip: str, *dest_ips: str) -> None:
    _add_tun_address(ifname, source_ip)
    for dest_ip in dest_ips:
        _add_tun_route(ifname, source_ip, dest_ip)
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


def _assert_link_total_unchanged(ifname: str, before_total: int, *, timeout: float = 3.0) -> int:
    end = time.time() + timeout
    while time.time() < end:
        current = _link_total_bytes(ifname)
        if current > before_total:
            raise RuntimeError(
                f"interface {ifname} bytes increased unexpectedly from {before_total} to {current} within {timeout:.1f}s"
            )
        time.sleep(0.1)
    return _link_total_bytes(ifname)


def _structured_tun_spec(
    *,
    listen_ifname: str,
    target_ifname: str,
    mtu: int,
    name: str,
    shared_tun_ownership: Optional[dict] = None,
) -> str:
    spec = {
        "name": name,
        "listen": {"protocol": "tun", "ifname": listen_ifname, "mtu": int(mtu)},
        "target": {"protocol": "tun", "ifname": target_ifname, "mtu": int(mtu)},
    }
    if shared_tun_ownership is not None:
        spec["options"] = {"shared_tun_ownership": shared_tun_ownership}
    return json.dumps(spec, separators=(",", ":"))


def _shared_tun_summary(admin_port: int) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/tun-routing/status", timeout=1.5)
    if status != 200:
        raise RuntimeError(f"/api/tun-routing/status returned {status} on admin port {admin_port}")
    return payload


def _wait_shared_tun_active_bindings(admin_port: int, expected_count: int, *, timeout: float = 12.0) -> dict:
    end = time.time() + timeout
    last_payload: Optional[dict] = None
    while time.time() < end:
        payload = _shared_tun_summary(admin_port)
        last_payload = payload
        current = int(((payload.get("summary") or {}).get("shared_active_peer_bindings") or 0))
        if current == int(expected_count):
            return payload
        time.sleep(0.2)
    raise RuntimeError(
        f"shared active binding count did not reach {expected_count} within {timeout:.1f}s; last={last_payload!r}"
    )


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


def _start_shared_tun_bridge_group(
    *,
    tmp_path: Path,
    case_index: int,
    server_ifname: str,
    client_a_ifname: str,
    client_b_ifname: str,
    mtu: int,
) -> SharedTunBridgeGroup:
    materialized = overlay_e2e.materialize_case_ports(
        overlay_e2e.CASES["case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp"],
        case_index,
    )
    missing_cfg = str(tmp_path / f"{materialized.name}_missing.cfg")
    loopback_v4, _loopback_v6 = overlay_e2e._loopback_hosts_for_case(case_index)
    udp_peer_host = overlay_e2e._connect_host_for_bind(
        overlay_e2e._listener_overlay_bind_host(materialized, "myudp"),
        case_index,
    )
    udp_peer_port = overlay_e2e._listener_overlay_port(materialized, "myudp")
    shared_tun_ownership = {
        "mode": "server_shared",
        "peers": [
            {"peer_ref": "linux-client-a", "ipv4": ["192.168.107.2"]},
            {"peer_ref": "linux-client-b", "ipv4": ["192.168.107.4"]},
        ],
    }
    server_spec = _structured_tun_spec(
        listen_ifname=server_ifname,
        target_ifname=server_ifname,
        mtu=mtu,
        name="shared-server-tun",
        shared_tun_ownership=shared_tun_ownership,
    )
    client_a_spec = _structured_tun_spec(
        listen_ifname=client_a_ifname,
        target_ifname=server_ifname,
        mtu=mtu,
        name="client-a-tun",
    )
    client_b_spec = _structured_tun_spec(
        listen_ifname=client_b_ifname,
        target_ifname=server_ifname,
        mtu=mtu,
        name="client-b-tun",
    )
    server_admin, client_a_admin = overlay_e2e.alloc_admin_ports(case_index)
    client_b_admin = overlay_e2e.alloc_admin_port({server_admin, client_a_admin}, case_index=case_index + 2)

    server_args = _strip_option_and_values(materialized.bridge_server_args, "--own-servers")
    server_args = _strip_option_and_values(server_args, "--remote-servers")
    server_args = _with_service_specs(server_args, "--own-servers", [server_spec])
    server_args = _with_option_value(server_args, "--log-file", str(tmp_path / f"{materialized.name}_bridge_server_shared_tun.txt"))
    server_args += ["--config", missing_cfg, "--admin-web-port", "0"]
    server_args += overlay_e2e.admin_args(server_admin)
    server_cmd = overlay_e2e.build_bridge_command(
        "python",
        case_name=materialized.name,
        side="bridge_server",
        bridge_args=server_args,
        log_dir=tmp_path,
        admin_port=server_admin,
    )

    client_template = _strip_option_and_values(materialized.bridge_client_args, "--own-servers")
    client_template = _strip_option_and_values(client_template, "--remote-servers")
    client_template = _strip_option_and_values(client_template, "--udp-peer")
    client_template = _strip_option_and_values(client_template, "--udp-peer-port")
    client_template = _strip_option_and_values(client_template, "--udp-bind")
    client_template = _strip_option_and_values(client_template, "--udp-own-port")
    client_template += [
        "--udp-peer", udp_peer_host,
        "--udp-peer-port", str(udp_peer_port),
        "--udp-bind", loopback_v4,
        "--udp-own-port", "0",
    ]

    client_a_args = _with_service_specs(client_template, "--own-servers", [client_a_spec])
    client_a_args = _with_option_value(client_a_args, "--log-file", str(tmp_path / f"{materialized.name}_bridge_client_a_shared_tun.txt"))
    client_a_args += ["--config", missing_cfg, "--admin-web-port", "0", "--client-restart-if-disconnected", "10"]
    client_a_args += overlay_e2e.admin_args(client_a_admin)
    client_a_cmd = overlay_e2e.build_bridge_command(
        "python",
        case_name=materialized.name,
        side="bridge_client_a",
        bridge_args=client_a_args,
        log_dir=tmp_path,
        admin_port=client_a_admin,
    )

    client_b_args = _with_service_specs(client_template, "--own-servers", [client_b_spec])
    client_b_args = _with_option_value(client_b_args, "--log-file", str(tmp_path / f"{materialized.name}_bridge_client_b_shared_tun.txt"))
    client_b_args += ["--config", missing_cfg, "--admin-web-port", "0", "--client-restart-if-disconnected", "10"]
    client_b_args += overlay_e2e.admin_args(client_b_admin)
    client_b_cmd = overlay_e2e.build_bridge_command(
        "python",
        case_name=materialized.name,
        side="bridge_client_b",
        bridge_args=client_b_args,
        log_dir=tmp_path,
        admin_port=client_b_admin,
    )

    server_proc = overlay_e2e.start_proc(
        f"{materialized.name}_bridge_server",
        server_cmd,
        tmp_path,
        env_extra=materialized.server_env,
        admin_port=server_admin,
    )
    client_a_proc = overlay_e2e.start_proc(
        f"{materialized.name}_bridge_client_a",
        client_a_cmd,
        tmp_path,
        env_extra=materialized.client_env,
        admin_port=client_a_admin,
    )
    client_b_proc = overlay_e2e.start_proc(
        f"{materialized.name}_bridge_client_b",
        client_b_cmd,
        tmp_path,
        env_extra=materialized.client_env,
        admin_port=client_b_admin,
    )
    try:
        time.sleep(0.8)
        overlay_e2e.assert_running(server_proc)
        overlay_e2e.assert_running(client_a_proc)
        overlay_e2e.assert_running(client_b_proc)
        overlay_e2e.wait_admin_up(server_admin, timeout=10.0)
        overlay_e2e.wait_admin_up(client_a_admin, timeout=10.0)
        overlay_e2e.wait_admin_up(client_b_admin, timeout=10.0)
        client_a_proc = overlay_e2e.wait_status_connected_proc(client_a_proc, tmp_path, timeout=20.0, label="client_a")
        client_b_proc = overlay_e2e.wait_status_connected_proc(client_b_proc, tmp_path, timeout=20.0, label="client_b")
        overlay_e2e.wait_peers_count(server_admin, minimum_count=2, timeout=20.0, label="server")
        return SharedTunBridgeGroup(
            case=materialized,
            server_proc=server_proc,
            client_a_proc=client_a_proc,
            client_b_proc=client_b_proc,
            client_a_cmd=client_a_cmd,
            client_b_cmd=client_b_cmd,
            client_env=materialized.client_env,
            tmp_path=tmp_path,
        )
    except Exception:
        overlay_e2e.stop_proc(client_b_proc)
        overlay_e2e.stop_proc(client_a_proc)
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


def test_overlay_e2e_linux_elevated_shared_tun_two_clients_routes_and_rejects_spoof(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt303"
    server_ifname = _tun_name(case_tag, "s")
    client_a_ifname = _tun_name(case_tag, "a")
    client_b_ifname = _tun_name(case_tag, "b")
    group = _start_shared_tun_bridge_group(
        tmp_path=tmp_path,
        case_index=303,
        server_ifname=server_ifname,
        client_a_ifname=client_a_ifname,
        client_b_ifname=client_b_ifname,
        mtu=1400,
    )
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=group.server_proc, client_proc=group.client_a_proc)
        _wait_interface_with_bridge_logs(client_a_ifname, server_proc=group.server_proc, client_proc=group.client_a_proc)
        _wait_interface_with_bridge_logs(client_b_ifname, server_proc=group.server_proc, client_proc=group.client_b_proc)

        _configure_tun_routes(server_ifname, "192.168.107.1", "192.168.107.2", "192.168.107.4")
        _configure_tun_routes(client_a_ifname, "192.168.107.2", "192.168.107.1", "192.168.107.4")
        _configure_tun_routes(client_b_ifname, "192.168.107.4", "192.168.107.1", "192.168.107.2")

        _assert_tun_one_way(
            source_ip="192.168.107.2",
            dest_ip="192.168.107.1",
            payload=b"shared-prime-client-a",
            port=30301,
            bind_ifname=client_a_ifname,
            peer_ifname=server_ifname,
        )
        _assert_tun_one_way(
            source_ip="192.168.107.4",
            dest_ip="192.168.107.1",
            payload=b"shared-prime-client-b",
            port=30302,
            bind_ifname=client_b_ifname,
            peer_ifname=server_ifname,
        )
        _wait_shared_tun_active_bindings(group.server_proc.admin_port or 0, 2, timeout=12.0)

        to_client_a = _assert_tun_one_way(
            source_ip="192.168.107.1",
            dest_ip="192.168.107.2",
            payload=b"shared-server-to-client-a",
            port=30303,
            bind_ifname=server_ifname,
            peer_ifname=client_a_ifname,
        )
        assert to_client_a > 0

        to_client_b = _assert_tun_one_way(
            source_ip="192.168.107.1",
            dest_ip="192.168.107.4",
            payload=b"shared-server-to-client-b",
            port=30304,
            bind_ifname=server_ifname,
            peer_ifname=client_b_ifname,
        )
        assert to_client_b > 0

        client_peer = _assert_tun_one_way(
            source_ip="192.168.107.2",
            dest_ip="192.168.107.4",
            payload=b"shared-client-a-to-client-b",
            port=30305,
            bind_ifname=client_a_ifname,
            peer_ifname=client_b_ifname,
        )
        assert client_peer > 0

        _add_tun_address(client_a_ifname, "192.168.107.4")
        _send_udp(
            "192.168.107.4",
            "192.168.107.1",
            b"shared-spoof-client-a-as-client-b",
            port=30306,
            bind_ifname=client_a_ifname,
        )
        overlay_e2e.wait_log_contains(group.server_proc.log_path, "source_not_owned_by_peer", timeout=5.0)
        _wait_shared_tun_active_bindings(group.server_proc.admin_port or 0, 2, timeout=12.0)
    finally:
        group.stop()


def test_overlay_e2e_linux_elevated_shared_tun_disconnect_cleanup_rebinds_peer(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt304"
    server_ifname = _tun_name(case_tag, "s")
    client_a_ifname = _tun_name(case_tag, "a")
    client_b_ifname = _tun_name(case_tag, "b")
    group = _start_shared_tun_bridge_group(
        tmp_path=tmp_path,
        case_index=304,
        server_ifname=server_ifname,
        client_a_ifname=client_a_ifname,
        client_b_ifname=client_b_ifname,
        mtu=1400,
    )
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=group.server_proc, client_proc=group.client_a_proc)
        _wait_interface_with_bridge_logs(client_a_ifname, server_proc=group.server_proc, client_proc=group.client_a_proc)
        _wait_interface_with_bridge_logs(client_b_ifname, server_proc=group.server_proc, client_proc=group.client_b_proc)

        _configure_tun_routes(server_ifname, "192.168.107.1", "192.168.107.2", "192.168.107.4")
        _configure_tun_routes(client_a_ifname, "192.168.107.2", "192.168.107.1", "192.168.107.4")
        _configure_tun_routes(client_b_ifname, "192.168.107.4", "192.168.107.1", "192.168.107.2")

        _assert_tun_one_way(
            source_ip="192.168.107.2",
            dest_ip="192.168.107.1",
            payload=b"shared-restart-prime-client-a",
            port=30401,
            bind_ifname=client_a_ifname,
            peer_ifname=server_ifname,
        )
        _assert_tun_one_way(
            source_ip="192.168.107.4",
            dest_ip="192.168.107.1",
            payload=b"shared-restart-prime-client-b",
            port=30402,
            bind_ifname=client_b_ifname,
            peer_ifname=server_ifname,
        )
        _wait_shared_tun_active_bindings(group.server_proc.admin_port or 0, 2, timeout=12.0)

        overlay_e2e.stop_proc(group.client_a_proc)
        _wait_shared_tun_active_bindings(group.server_proc.admin_port or 0, 1, timeout=45.0)

        restarted = group.restart_client_a()
        _wait_interface_with_bridge_logs(client_a_ifname, server_proc=group.server_proc, client_proc=restarted, timeout=12.0)
        _configure_tun_routes(client_a_ifname, "192.168.107.2", "192.168.107.1", "192.168.107.4")

        rebound = _assert_tun_one_way(
            source_ip="192.168.107.2",
            dest_ip="192.168.107.1",
            payload=b"shared-restart-reprime-client-a",
            port=30403,
            bind_ifname=client_a_ifname,
            peer_ifname=server_ifname,
        )
        assert rebound > 0
        _wait_shared_tun_active_bindings(group.server_proc.admin_port or 0, 2, timeout=20.0)

        after_restart = _assert_tun_one_way(
            source_ip="192.168.107.2",
            dest_ip="192.168.107.4",
            payload=b"shared-restart-client-a-to-client-b",
            port=30404,
            bind_ifname=client_a_ifname,
            peer_ifname=client_b_ifname,
        )
        assert after_restart > 0
    finally:
        group.stop()
