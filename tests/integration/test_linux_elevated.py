import asyncio
import ipaddress
import os
import json
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest

from obstacle_bridge.bridge_tun_helper_client import TunHelperClient
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
    if not specs:
        return out
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
    lifecycle_hooks: Optional[dict] = None,
) -> str:
    spec = {
        "name": name,
        "listen": {"protocol": "tun", "ifname": listen_ifname, "mtu": int(mtu)},
        "target": {"protocol": "tun", "ifname": target_ifname, "mtu": int(mtu)},
    }
    if lifecycle_hooks is not None:
        spec["lifecycle_hooks"] = lifecycle_hooks
    if shared_tun_ownership is not None:
        spec["options"] = {"shared_tun_ownership": shared_tun_ownership}
    return json.dumps(spec, separators=(",", ":"))


def _shared_tun_summary(admin_port: int) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/tun-routing/status", timeout=1.5)
    if status != 200:
        raise RuntimeError(f"/api/tun-routing/status returned {status} on admin port {admin_port}")
    return payload


def _wait_tun_helper_runtime(
    admin_port: int,
    *,
    expected_backend: str,
    expected_ifname: str,
    runtime_predicate=None,
    timeout: float = 12.0,
) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    end = time.time() + timeout
    last_payload: Optional[dict] = None
    while time.time() < end:
        status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/status", timeout=1.5)
        if status == 200:
            last_payload = payload
            helper = dict(payload.get("tun_helper") or {})
            runtime = dict(helper.get("runtime") or {})
            if (
                bool(helper.get("enabled"))
                and bool(helper.get("connected"))
                and bool(helper.get("server_started"))
                and str(runtime.get("backend") or "") == str(expected_backend)
                and str(runtime.get("ifname") or "") == str(expected_ifname)
                and bool(runtime.get("opened"))
                and (runtime_predicate is None or bool(runtime_predicate(runtime)))
            ):
                return payload
        time.sleep(0.2)
    raise RuntimeError(
        f"helper runtime did not reach backend={expected_backend!r} ifname={expected_ifname!r} "
        f"within {timeout:.1f}s; last={last_payload!r}"
    )


def _wait_tun_helper_disconnected_runtime(
    admin_port: int,
    *,
    expected_ifname: str,
    timeout: float = 12.0,
) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    end = time.time() + timeout
    last_payload: Optional[dict] = None
    while time.time() < end:
        status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/status", timeout=1.5)
        if status == 200:
            last_payload = payload
            helper = dict(payload.get("tun_helper") or {})
            runtime = dict(helper.get("runtime") or {})
            process_returncode = helper.get("process_returncode")
            last_error = str(helper.get("last_error") or "").lower()
            if (
                bool(helper.get("enabled"))
                and not bool(helper.get("connected"))
                and not bool(helper.get("server_started"))
                and isinstance(process_returncode, int)
                and ("connection closed" in last_error or "connection reset" in last_error)
                and str(runtime.get("ifname") or "") == str(expected_ifname)
            ):
                return payload
        time.sleep(0.2)
    raise RuntimeError(
        f"helper runtime did not report disconnected ifname={expected_ifname!r} "
        f"within {timeout:.1f}s; last={last_payload!r}"
    )


def _wait_tun_helper_recovery_runtime(
    admin_port: int,
    *,
    expected_ifname: str,
    stale_firewall: bool,
    stale_network: bool,
    timeout: float = 12.0,
) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    end = time.time() + timeout
    last_payload: Optional[dict] = None
    while time.time() < end:
        status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/status", timeout=1.5)
        if status == 200:
            last_payload = payload
            helper = dict(payload.get("tun_helper") or {})
            runtime = dict(helper.get("runtime") or {})
            recovery = dict(helper.get("recovery") or {})
            process_returncode = helper.get("process_returncode")
            if (
                bool(helper.get("enabled"))
                and not bool(helper.get("connected"))
                and not bool(helper.get("server_started"))
                and isinstance(process_returncode, int)
                and str(runtime.get("ifname") or "") == str(expected_ifname)
                and bool(recovery.get("needs_manual_cleanup"))
                and bool(recovery.get("stale_firewall_possible")) == bool(stale_firewall)
                and bool(recovery.get("stale_network_possible")) == bool(stale_network)
            ):
                return payload
        time.sleep(0.2)
    raise RuntimeError(
        f"helper runtime did not report stale recovery state ifname={expected_ifname!r} "
        f"within {timeout:.1f}s; last={last_payload!r}"
    )


def _wait_tun_helper_failure_runtime(
    admin_port: int,
    *,
    expected_ifname: str,
    operation: str,
    stage: str,
    timeout: float = 12.0,
) -> dict:
    admin_host = overlay_e2e._admin_host_for_port(admin_port)
    end = time.time() + timeout
    last_payload: Optional[dict] = None
    while time.time() < end:
        status, payload = overlay_e2e.fetch_json(f"http://{admin_host}:{admin_port}/api/status", timeout=1.5)
        if status == 200:
            last_payload = payload
            helper = dict(payload.get("tun_helper") or {})
            runtime = dict(helper.get("runtime") or {})
            last_failure = dict(runtime.get("last_failure") or {})
            if (
                bool(helper.get("enabled"))
                and bool(helper.get("connected"))
                and bool(helper.get("server_started"))
                and str(runtime.get("ifname") or "") == str(expected_ifname)
                and str(last_failure.get("operation") or "") == str(operation)
                and str(last_failure.get("stage") or "") == str(stage)
                and bool(last_failure.get("cleanup_attempted"))
                and bool(last_failure.get("cleanup_ok"))
            ):
                return payload
        time.sleep(0.2)
    raise RuntimeError(
        f"helper runtime did not report failure operation={operation!r} stage={stage!r} "
        f"ifname={expected_ifname!r} within {timeout:.1f}s; last={last_payload!r}"
    )


def _interface_has_cidr(ifname: str, cidr: str, *, family: str) -> bool:
    cp = subprocess.run(
        ["ip", "-j", family, "addr", "show", "dev", ifname],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    if not rows:
        return False
    want_addr, want_prefix = str(cidr).split("/", 1)
    for info in rows[0].get("addr_info") or []:
        addr = str(info.get("local") or "")
        prefix = str(info.get("prefixlen") or "")
        if addr == want_addr and prefix == want_prefix:
            return True
    return False


def _wait_interface_cidr(ifname: str, cidr: str, *, family: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if _interface_has_cidr(ifname, cidr, family=family):
            return
        time.sleep(0.2)
    raise RuntimeError(f"interface {ifname} did not expose {cidr} for family {family} within {timeout:.1f}s")


def _interface_lacks_cidr(ifname: str, cidr: str, *, family: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if not _interface_has_cidr(ifname, cidr, family=family):
            return
        time.sleep(0.2)
    raise RuntimeError(f"interface {ifname} still exposed {cidr} for family {family} beyond {timeout:.1f}s")


def _interface_has_route(route_spec: str, *, family: str, dev: str) -> bool:
    cp = subprocess.run(
        ["ip", "-j", family, "route", "show", "exact", route_spec],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    want_spec = str(route_spec)
    want_host = ""
    want_prefix = -1
    try:
        want_net = ipaddress.ip_network(want_spec, strict=False)
        want_host = str(want_net.network_address)
        want_prefix = int(want_net.prefixlen)
    except ValueError:
        pass
    for row in rows:
        row_dst = str(row.get("dst") or "")
        if row_dst != want_spec:
            if not (
                want_host
                and row_dst == want_host
                and ((want_prefix == 32 and family == "-4") or (want_prefix == 128 and family == "-6"))
            ):
                continue
        if str(row.get("dev") or "") == str(dev):
            return True
    return False


def _wait_interface_route(route_spec: str, *, family: str, dev: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if _interface_has_route(route_spec, family=family, dev=dev):
            return
        time.sleep(0.2)
    raise RuntimeError(f"route {route_spec} for family {family} not present on {dev} within {timeout:.1f}s")


def _interface_lacks_route(route_spec: str, *, family: str, dev: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if not _interface_has_route(route_spec, family=family, dev=dev):
            return
        time.sleep(0.2)
    raise RuntimeError(f"route {route_spec} for family {family} remained present on {dev} beyond {timeout:.1f}s")


def _default_route_row(*, family: str) -> dict:
    cp = subprocess.run(
        ["ip", "-j", family, "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    for row in rows:
        if str(row.get("dst") or "") == "default":
            return dict(row)
    raise RuntimeError(f"no default route row found for family {family}")


def _maybe_default_route_row(*, family: str) -> dict:
    cp = subprocess.run(
        ["ip", "-j", family, "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    for row in rows:
        if str(row.get("dst") or "") == "default":
            return dict(row)
    return {}


def _ip_rule_rows(*, family: str) -> list[dict]:
    cp = subprocess.run(
        ["ip", "-j", family, "rule", "show"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(cp.stdout)
    return [dict(row) for row in rows]


def _rule_rows_for_table(*, family: str, table: int) -> list[dict]:
    want = str(table)
    rows: list[dict] = []
    for row in _ip_rule_rows(family=family):
        lookup = str(row.get("table") or row.get("lookup") or "")
        if lookup == want:
            rows.append(row)
    return rows


def _wait_rule_table_present(*, family: str, table: int, timeout: float = 12.0) -> list[dict]:
    end = time.time() + timeout
    while time.time() < end:
        rows = _rule_rows_for_table(family=family, table=table)
        if rows:
            return rows
        time.sleep(0.2)
    raise RuntimeError(f"policy rules for family {family} table {table} not present within {timeout:.1f}s")


def _wait_rule_table_absent(*, family: str, table: int, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if not _rule_rows_for_table(family=family, table=table):
            return
        time.sleep(0.2)
    raise RuntimeError(f"policy rules for family {family} table {table} remained present beyond {timeout:.1f}s")


def _firewall_rule_present(*cmd: str) -> bool:
    completed = subprocess.run(
        [*cmd],
        check=False,
        capture_output=True,
        text=True,
    )
    return int(completed.returncode) == 0


def _wait_firewall_rule_present(*cmd: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if _firewall_rule_present(*cmd):
            return
        time.sleep(0.2)
    raise RuntimeError(f"firewall rule {' '.join(cmd)} not present within {timeout:.1f}s")


def _wait_firewall_rule_absent(*cmd: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if not _firewall_rule_present(*cmd):
            return
        time.sleep(0.2)
    raise RuntimeError(f"firewall rule {' '.join(cmd)} remained present beyond {timeout:.1f}s")


def _delete_firewall_rule_if_exists(*, check_cmd: list[str], delete_cmd: list[str]) -> None:
    while _firewall_rule_present(*check_cmd):
        subprocess.run(
            delete_cmd,
            check=False,
            capture_output=True,
            text=True,
        )


def _wait_path_exists(path: Path, *, timeout: float = 8.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"path did not appear within {timeout:.1f}s: {path}")


def _wait_proc_exit(proc: overlay_e2e.Proc, *, timeout: float = 8.0) -> int:
    end = time.time() + timeout
    while time.time() < end:
        returncode = proc.popen.poll()
        if returncode is not None:
            return int(returncode)
        time.sleep(0.1)
    raise RuntimeError(f"process {proc.name} did not exit within {timeout:.1f}s")


def _start_direct_tun_helper(
    *,
    tmp_path: Path,
    name: str,
    env_extra: Optional[dict[str, str]] = None,
    backend: str = "linux-native",
    log_level: str = "DEBUG",
) -> tuple[overlay_e2e.Proc, Path, str]:
    socket_path = tmp_path / f"{name}.sock"
    config_path = tmp_path / f"{name}.json"
    session_token = f"{name}-token"
    config_path.write_text(
        json.dumps(
            {
                "socket_path": str(socket_path),
                "session_token": session_token,
                "backend": backend,
                "log_level": log_level,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    proc = overlay_e2e.start_proc(
        name,
        [sys.executable, "-m", "obstacle_bridge.bridge_tun_helper_server", "--config-path", str(config_path)],
        tmp_path,
        env_extra=env_extra or {},
    )
    try:
        time.sleep(0.2)
        overlay_e2e.assert_running(proc)
        _wait_path_exists(socket_path)
    except Exception:
        overlay_e2e.stop_proc(proc)
        raise
    return proc, socket_path, session_token


async def _connect_tun_helper_client(
    *,
    socket_path: Path,
    session_token: str,
    timeout: float = 5.0,
) -> TunHelperClient:
    client = TunHelperClient(socket_path=str(socket_path), session_token=session_token, response_timeout_s=1.0)
    end = time.time() + timeout
    last_exc: Optional[BaseException] = None
    while time.time() < end:
        try:
            await client.connect()
            return client
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.1)
    raise RuntimeError(f"TUN helper client could not connect within {timeout:.1f}s: {last_exc!r}")


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
    server_own_specs: Optional[list[str]] = None,
    server_remote_specs: Optional[list[str]] = None,
    client_own_specs: Optional[list[str]] = None,
    client_remote_specs: Optional[list[str]] = None,
    server_env_extra: Optional[dict[str, str]] = None,
    client_env_extra: Optional[dict[str, str]] = None,
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
    server_args = _with_service_specs(
        _strip_option_and_values(materialized.bridge_server_args, "--remote-servers"),
        "--own-servers",
        list(server_own_specs) if server_own_specs is not None else [],
    )
    server_args = _with_service_specs(
        server_args,
        "--remote-servers",
        list(server_remote_specs) if server_remote_specs is not None else [],
    )
    client_args = _with_service_specs(
        _strip_option_and_values(materialized.bridge_client_args, "--remote-servers"),
        "--own-servers",
        list(client_own_specs) if client_own_specs is not None else [client_spec],
    )
    client_args = _with_service_specs(
        client_args,
        "--remote-servers",
        list(client_remote_specs) if client_remote_specs is not None else [server_spec],
    )
    tuned_case = replace(
        materialized,
        bridge_server_args=server_args,
        bridge_client_args=client_args,
    )
    server_spec_cmd, client_spec_cmd = overlay_e2e.build_commands(tuned_case, tmp_path, case_index, enable_admin=True)

    server_name, server_cmd, server_env, server_admin = server_spec_cmd
    client_name, client_cmd, client_env, client_admin = client_spec_cmd
    server_env = dict(server_env or {})
    client_env = dict(client_env or {})
    if server_env_extra:
        server_env.update({str(k): str(v) for k, v in server_env_extra.items()})
    if client_env_extra:
        client_env.update({str(k): str(v) for k, v in client_env_extra.items()})
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


def test_overlay_e2e_linux_elevated_tun_helper_native_over_myudp_packet_carry(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt305"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_routing_args = [
        "--tunnel-address", "198.18.35.1",
        "--tunnel-prefix", "24",
        "--tunnel-address6", "fd20:305::1",
        "--tunnel-prefix6", "64",
        "--included-routes", "198.18.36.0/24",
        "--included-routes6", "fd20:306::/64",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.35.2",
        "--tunnel-prefix", "24",
        "--tunnel-address6", "fd20:305::2",
        "--tunnel-prefix6", "64",
        "--included-routes", "198.18.37.0/24",
        "--included-routes6", "fd20:307::/64",
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
        _wait_interface_with_bridge_logs(client_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=client_ifname,
        )
        _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=server_ifname,
        )
        _wait_interface_cidr(client_ifname, "198.18.35.1/24", family="-4")
        _wait_interface_cidr(server_ifname, "198.18.35.2/24", family="-4")
        _wait_interface_cidr(client_ifname, "fd20:305::1/64", family="-6")
        _wait_interface_cidr(server_ifname, "fd20:305::2/64", family="-6")
        _wait_interface_route("198.18.36.0/24", family="-4", dev=client_ifname)
        _wait_interface_route("198.18.37.0/24", family="-4", dev=server_ifname)
        _wait_interface_route("fd20:306::/64", family="-6", dev=client_ifname)
        _wait_interface_route("fd20:307::/64", family="-6", dev=server_ifname)

        forward_payload = b"tun-helper-native-forward-305"
        after_total = _assert_tun_one_way(
            source_ip="198.18.35.1",
            dest_ip="198.18.35.2",
            payload=forward_payload,
            port=30501,
            bind_ifname=client_ifname,
            peer_ifname=server_ifname,
        )
        assert after_total > 0
    finally:
        pair.stop()


def test_overlay_e2e_linux_elevated_tun_helper_native_reports_post_start_helper_loss(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt307"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_routing_args = [
        "--tunnel-address", "198.18.37.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.37.2",
        "--tunnel-address6", "fd20:317::1",
        "--tunnel-prefix6", "64",
        "--tunnel-gateway6", "fd20:317::2",
        "--included-routes", "198.18.38.0/24",
        "--included-routes6", "fd20:318::/64",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.37.2",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.37.1",
        "--tunnel-address6", "fd20:317::2",
        "--tunnel-prefix6", "64",
        "--tunnel-gateway6", "fd20:317::1",
        "--included-routes", "198.18.39.0/24",
        "--included-routes6", "fd20:319::/64",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=307,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        server_status = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=server_ifname,
        )
        helper = dict(server_status.get("tun_helper") or {})
        helper_pid = int(helper.get("pid") or 0)
        assert helper_pid > 0

        os.kill(helper_pid, signal.SIGKILL)

        disconnected = _wait_tun_helper_disconnected_runtime(
            pair.server_proc.admin_port or 0,
            expected_ifname=server_ifname,
        )
        helper_after = dict(disconnected.get("tun_helper") or {})
        runtime_after = dict(helper_after.get("runtime") or {})
        assert runtime_after.get("backend") == "linux-native"
        assert runtime_after.get("ifname") == server_ifname
        assert helper_after.get("process_returncode") is not None
        last_error = str(helper_after.get("last_error") or "").lower()
        assert "connection closed" in last_error or "connection reset" in last_error
    finally:
        pair.stop()


def test_overlay_e2e_linux_elevated_tun_helper_native_rolls_back_partial_apply_failure(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt309"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    default4 = _default_route_row(family="-4")
    default6 = _maybe_default_route_row(family="-6")
    underlay4_dev = str(default4.get("dev") or "")
    underlay6_dev = str(default6.get("dev") or "")
    have_ipv6_default = bool(underlay6_dev)
    assert underlay4_dev

    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
    ]
    server_excluded4 = "203.0.113.19/32"
    server_routing_args = [
        "--tunnel-address", "198.18.39.2",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.39.1",
        "--included-routes", "198.18.40.0/24",
        "--excluded-routes", "127.0.0.0/8", server_excluded4,
    ]
    if have_ipv6_default:
        server_excluded6 = "2001:db8:309::19/128"
        server_routing_args += [
            "--tunnel-address6", "fd20:309::2",
            "--tunnel-prefix6", "64",
            "--tunnel-gateway6", "fd20:309::1",
            "--included-routes6", "fd20:310::/64",
            "--excluded-routes6", "::1/128", server_excluded6,
        ]
    else:
        server_excluded6 = ""

    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=309,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=[],
        server_env_extra={"OBSTACLEBRIDGE_TUN_HELPER_TEST_FAIL": "apply_network:dns_apply"},
    )
    server_policy4 = 0
    server_policy6 = 0
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        failed_status = _wait_tun_helper_failure_runtime(
            pair.server_proc.admin_port or 0,
            expected_ifname=server_ifname,
            operation="apply_network",
            stage="dns_apply",
        )
        helper = dict(failed_status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last_failure = dict(runtime.get("last_failure") or {})

        assert runtime.get("backend") == "linux-native"
        assert runtime.get("ifname") == server_ifname
        assert not bool(runtime.get("network_applied"))
        assert runtime.get("applied_ipv4_cidr") == ""
        assert runtime.get("applied_ipv6_cidr") == ""
        assert list(runtime.get("applied_ipv4_routes") or []) == []
        assert list(runtime.get("applied_ipv6_routes") or []) == []
        assert list(runtime.get("applied_excluded_ipv4_routes") or []) == []
        assert list(runtime.get("applied_excluded_ipv6_routes") or []) == []
        server_policy4 = int(runtime.get("policy_table4") or 0)
        server_policy6 = int(runtime.get("policy_table6") or 0)
        assert server_policy4 == 0
        assert server_policy6 == 0
        assert list(runtime.get("policy_rules4") or []) == []
        assert list(runtime.get("policy_rules6") or []) == []
        assert last_failure.get("error_type") == "RuntimeError"
        assert "test-injected helper failure" in str(last_failure.get("detail") or "")

        _interface_lacks_cidr(server_ifname, "198.18.39.2/24", family="-4")
        _interface_lacks_route(server_excluded4, family="-4", dev=underlay4_dev)
        if have_ipv6_default:
            _interface_lacks_cidr(server_ifname, "fd20:309::2/64", family="-6")
            _interface_lacks_route(server_excluded6, family="-6", dev=underlay6_dev)
        if server_policy4:
            _wait_rule_table_absent(family="-4", table=server_policy4)
        if server_policy6:
            _wait_rule_table_absent(family="-6", table=server_policy6)
    finally:
        pair.stop()


def test_overlay_e2e_linux_elevated_tun_helper_native_programs_excluded_routes_and_full_tunnel_policy(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    case_tag = "lt306"
    client_ifname = _tun_name(case_tag, "c")
    server_ifname = _tun_name(case_tag, "s")
    default4 = _default_route_row(family="-4")
    default6 = _maybe_default_route_row(family="-6")
    underlay4_dev = str(default4.get("dev") or "")
    underlay6_dev = str(default6.get("dev") or "")
    have_ipv6_default = bool(underlay6_dev)
    assert underlay4_dev

    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
    ]
    client_excluded4 = "203.0.113.9/32"
    server_excluded4 = "203.0.113.10/32"
    client_excluded6 = "2001:db8:306::9/128"
    server_excluded6 = "2001:db8:306::10/128"
    client_routing_args = [
        "--tunnel-address", "198.18.36.1",
        "--tunnel-prefix", "24",
        "--tunnel-address6", "fd20:306::1",
        "--tunnel-prefix6", "64",
        "--included-routes", "0.0.0.0/0",
        "--excluded-routes", f"127.0.0.0/8,{client_excluded4}",
    ]
    server_routing_args = [
        "--tunnel-address", "198.18.36.2",
        "--tunnel-prefix", "24",
        "--included-routes", "0.0.0.0/0",
        "--excluded-routes", f"127.0.0.0/8,{server_excluded4}",
    ]
    if have_ipv6_default:
        client_routing_args += [
            "--tunnel-address6", "fd20:306::1",
            "--tunnel-prefix6", "64",
            "--included-routes6", "::/0",
            "--excluded-routes6", f"::1/128,{client_excluded6}",
        ]
        server_routing_args += [
            "--tunnel-address6", "fd20:306::2",
            "--tunnel-prefix6", "64",
            "--included-routes6", "::/0",
            "--excluded-routes6", f"::1/128,{server_excluded6}",
        ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=306,
        client_ifname=client_ifname,
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    client_policy4 = 0
    client_policy6 = 0
    server_policy4 = 0
    server_policy6 = 0
    try:
        _wait_interface_with_bridge_logs(client_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)

        client_status = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=client_ifname,
        )
        server_status = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=server_ifname,
            runtime_predicate=lambda runtime: (
                str(runtime.get("firewall_manager") or "") == "iptables"
                and str(runtime.get("firewall_wan_if") or "") == underlay4_dev
            ),
        )

        client_runtime = dict((client_status.get("tun_helper") or {}).get("runtime") or {})
        server_runtime = dict((server_status.get("tun_helper") or {}).get("runtime") or {})
        assert client_excluded4 in list(client_runtime.get("applied_excluded_ipv4_routes") or [])
        assert server_excluded4 in list(server_runtime.get("applied_excluded_ipv4_routes") or [])
        if have_ipv6_default:
            assert client_excluded6 in list(client_runtime.get("applied_excluded_ipv6_routes") or [])
            assert server_excluded6 in list(server_runtime.get("applied_excluded_ipv6_routes") or [])

        client_policy4 = int(client_runtime.get("policy_table4") or 0)
        server_policy4 = int(server_runtime.get("policy_table4") or 0)
        assert client_policy4 > 0
        assert server_policy4 > 0
        if have_ipv6_default:
            client_policy6 = int(client_runtime.get("policy_table6") or 0)
            server_policy6 = int(server_runtime.get("policy_table6") or 0)
            assert client_policy6 > 0
            assert server_policy6 > 0

        _wait_interface_route(client_excluded4, family="-4", dev=underlay4_dev)
        _wait_interface_route(server_excluded4, family="-4", dev=underlay4_dev)
        if have_ipv6_default:
            _wait_interface_route(client_excluded6, family="-6", dev=underlay6_dev)
            _wait_interface_route(server_excluded6, family="-6", dev=underlay6_dev)

        client_rules4 = _wait_rule_table_present(family="-4", table=client_policy4)
        server_rules4 = _wait_rule_table_present(family="-4", table=server_policy4)
        assert any(str(row.get("dst") or "") == "0.0.0.0/0" for row in client_rules4)
        assert any(str(row.get("dst") or "") == "0.0.0.0/0" for row in server_rules4)
        if have_ipv6_default:
            client_rules6 = _wait_rule_table_present(family="-6", table=client_policy6)
            server_rules6 = _wait_rule_table_present(family="-6", table=server_policy6)
            assert any(str(row.get("dst") or "") == "::/0" for row in client_rules6)
            assert any(str(row.get("dst") or "") == "::/0" for row in server_rules6)
    finally:
        pair.stop()

    _interface_lacks_route(client_excluded4, family="-4", dev=underlay4_dev)
    _interface_lacks_route(server_excluded4, family="-4", dev=underlay4_dev)
    if have_ipv6_default:
        _interface_lacks_route(client_excluded6, family="-6", dev=underlay6_dev)
        _interface_lacks_route(server_excluded6, family="-6", dev=underlay6_dev)
    if client_policy4:
        _wait_rule_table_absent(family="-4", table=client_policy4)
    if server_policy4:
        _wait_rule_table_absent(family="-4", table=server_policy4)
    if client_policy6:
        _wait_rule_table_absent(family="-6", table=client_policy6)
    if server_policy6:
        _wait_rule_table_absent(family="-6", table=server_policy6)


def test_overlay_e2e_linux_elevated_tun_helper_native_programs_server_firewall_lifecycle(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    if shutil.which("iptables") is None:
        pytest.skip("linux_elevated firewall helper coverage requires iptables")
    case_tag = "lt308"
    server_ifname = _tun_name(case_tag, "s")
    default4 = _default_route_row(family="-4")
    default6 = _maybe_default_route_row(family="-6")
    underlay4_dev = str(default4.get("dev") or "")
    have_ipv6_default = bool(default6.get("dev"))
    assert underlay4_dev

    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
        "--enable-tcpmss",
    ]
    routing_args = [
        "--tunnel-address", "198.18.38.1",
        "--tunnel-prefix", "24",
        "--included-routes",
        "--enable-tcpmss",
    ]
    if have_ipv6_default:
        routing_args += [
            "--tunnel-address6", "fd20:308::1",
            "--tunnel-prefix6", "64",
            "--included-routes6",
        ]
    server_spec = _structured_tun_spec(
        listen_ifname=server_ifname,
        target_ifname=server_ifname,
        mtu=1400,
        name="helper-firewall-server-tun",
        lifecycle_hooks={
            "listener": {
                "on_created": {
                    "argv": ["./scripts/server-tun-hook.sh", "up", "{ifname}"],
                    "env": {"WAN_IF": underlay4_dev},
                },
                "on_stopped": {
                    "argv": ["./scripts/server-tun-hook.sh", "down", "{ifname}"],
                    "env": {"WAN_IF": underlay4_dev},
                },
            }
        },
    )
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=308,
        client_ifname=_tun_name(case_tag, "c"),
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + routing_args,
        client_extra_args=[],
        client_remote_specs=[server_spec],
    )
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        server_status = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=server_ifname,
            runtime_predicate=lambda runtime: (
                str(runtime.get("firewall_manager") or "") == "iptables"
                and str(runtime.get("firewall_wan_if") or "") == underlay4_dev
            ),
        )
        server_runtime = dict((server_status.get("tun_helper") or {}).get("runtime") or {})
        assert str(server_runtime.get("firewall_manager") or "") == "iptables"
        assert str(server_runtime.get("firewall_wan_if") or "") == underlay4_dev
        applied_rules = list(server_runtime.get("applied_firewall_rules") or [])
        assert any("iptables -A FORWARD" in rule and f"-i {server_ifname}" in rule and f"-o {underlay4_dev}" in rule for rule in applied_rules)
        assert any("iptables -t nat -A POSTROUTING" in rule and "-s 198.18.38.0/24" in rule and f"-o {underlay4_dev}" in rule for rule in applied_rules)

        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.38.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
        _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
        _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
        if have_ipv6_default and shutil.which("ip6tables") is not None:
            assert any("ip6tables -t nat -A POSTROUTING" in rule and "-s fd20:308::/64" in rule and f"-o {underlay4_dev}" in rule for rule in applied_rules)
            _wait_firewall_rule_present("ip6tables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
            _wait_firewall_rule_present("ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", "fd20:308::/64", "-o", underlay4_dev, "-j", "MASQUERADE")
    finally:
        pair.stop()

    _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
    _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
    _wait_firewall_rule_absent("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.38.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
    _wait_firewall_rule_absent("iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
    _wait_firewall_rule_absent("iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
    if have_ipv6_default and shutil.which("ip6tables") is not None:
        _wait_firewall_rule_absent("ip6tables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_absent("ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", "fd20:308::/64", "-o", underlay4_dev, "-j", "MASQUERADE")


def test_overlay_e2e_linux_elevated_tun_helper_native_repairs_stale_firewall_and_routes_after_helper_loss(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    if shutil.which("iptables") is None:
        pytest.skip("linux_elevated helper repair coverage requires iptables")
    case_tag = "lt311"
    server_ifname = _tun_name(case_tag, "s")
    default4 = _default_route_row(family="-4")
    underlay4_dev = str(default4.get("dev") or "")
    assert underlay4_dev

    server_excluded4 = "203.0.113.111/32"
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "linux-native",
        "--log-tun-helper", "DEBUG",
        "--enable-tcpmss",
    ]
    routing_args = [
        "--tunnel-address", "198.18.42.1",
        "--tunnel-prefix", "24",
        "--tunnel-gateway", "198.18.42.2",
        "--tunnel-address6", "fd20:142::1",
        "--tunnel-prefix6", "64",
        "--tunnel-gateway6", "fd20:142::2",
        "--included-routes", "198.18.43.0/24",
        "--included-routes6", "fd20:143::/64",
        "--excluded-routes", "127.0.0.0/8", server_excluded4,
        "--enable-tcpmss",
    ]
    server_spec = _structured_tun_spec(
        listen_ifname=server_ifname,
        target_ifname=server_ifname,
        mtu=1400,
        name="helper-repair-server-tun",
        lifecycle_hooks={
            "listener": {
                "on_created": {
                    "argv": ["./scripts/server-tun-hook.sh", "up", "{ifname}"],
                    "env": {"WAN_IF": underlay4_dev},
                },
                "on_stopped": {
                    "argv": ["./scripts/server-tun-hook.sh", "down", "{ifname}"],
                    "env": {"WAN_IF": underlay4_dev},
                },
            }
        },
    )
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=311,
        client_ifname=_tun_name(case_tag, "c"),
        server_ifname=server_ifname,
        mtu=1400,
        server_extra_args=helper_args + routing_args,
        client_extra_args=[],
        client_remote_specs=[server_spec],
    )
    try:
        _wait_interface_with_bridge_logs(server_ifname, server_proc=pair.server_proc, client_proc=pair.client_proc)
        server_status = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="linux-native",
            expected_ifname=server_ifname,
            runtime_predicate=lambda runtime: (
                str(runtime.get("firewall_manager") or "") == "iptables"
                and str(runtime.get("firewall_wan_if") or "") == underlay4_dev
                and server_excluded4 in list(runtime.get("applied_excluded_ipv4_routes") or [])
            ),
        )
        helper = dict(server_status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        helper_pid = int(helper.get("pid") or 0)
        assert helper_pid > 0
        assert server_excluded4 in list(runtime.get("applied_excluded_ipv4_routes") or [])

        _wait_interface_route(server_excluded4, family="-4", dev=underlay4_dev)
        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")

        os.kill(helper_pid, signal.SIGKILL)

        recovered_status = _wait_tun_helper_recovery_runtime(
            pair.server_proc.admin_port or 0,
            expected_ifname=server_ifname,
            stale_firewall=True,
            stale_network=True,
        )
        recovered_helper = dict(recovered_status.get("tun_helper") or {})
        recovery = dict(recovered_helper.get("recovery") or {})
        assert recovery.get("needs_manual_cleanup") is True
        assert "firewall_rules_may_remain" in list(recovery.get("warnings") or [])
        assert "helper_owned_network_state_may_remain" in list(recovery.get("warnings") or [])

        _wait_interface_route(server_excluded4, family="-4", dev=underlay4_dev)
        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")

        admin_host = overlay_e2e._admin_host_for_port(pair.server_proc.admin_port or 0)
        code, repair_payload = overlay_e2e.request_json(
            f"http://{admin_host}:{pair.server_proc.admin_port}/api/tun-helper/repair",
            method="POST",
            payload={},
            timeout=2.0,
        )
        assert code == 200
        assert repair_payload.get("ok") is True
        repaired_steps = list(repair_payload.get("repaired") or [])
        assert "excluded_routes" in repaired_steps
        assert "firewall" in repaired_steps

        repaired_status = dict(repair_payload.get("status") or {})
        repaired_helper = dict(repaired_status.get("tun_helper") or {})
        repaired_runtime = dict(repaired_helper.get("runtime") or {})
        assert dict(repaired_helper.get("recovery") or {}) == {}
        assert str(repaired_runtime.get("firewall_manager") or "") == ""
        assert list(repaired_runtime.get("applied_firewall_rules") or []) == []
        assert list(repaired_runtime.get("applied_excluded_ipv4_routes") or []) == []

        _interface_lacks_route(server_excluded4, family="-4", dev=underlay4_dev)
        _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_absent("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
    finally:
        pair.stop()
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT"],
            delete_cmd=["iptables", "-D", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            delete_cmd=["iptables", "-D", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE"],
            delete_cmd=["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            delete_cmd=["iptables", "-t", "mangle", "-D", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            delete_cmd=["iptables", "-t", "mangle", "-D", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        )
        subprocess.run(
            ["ip", "route", "del", server_excluded4, "dev", underlay4_dev],
            check=False,
            capture_output=True,
            text=True,
        )

    _interface_lacks_route(server_excluded4, family="-4", dev=underlay4_dev)
    _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
    _wait_firewall_rule_absent("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.42.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")


def test_overlay_e2e_linux_elevated_tun_helper_native_reports_helper_death_during_partial_cleanup(tmp_path: Path) -> None:
    _require_linux_elevated_runtime()
    if shutil.which("iptables") is None:
        pytest.skip("linux_elevated helper cleanup-death coverage requires iptables")
    case_tag = "lt310"
    server_ifname = _tun_name(case_tag, "s")
    default4 = _default_route_row(family="-4")
    underlay4_dev = str(default4.get("dev") or "")
    assert underlay4_dev

    included_route4 = "198.18.41.0/24"
    helper_proc, socket_path, session_token = _start_direct_tun_helper(
        tmp_path=tmp_path,
        name="tun_helper_cleanup_death",
        env_extra={"OBSTACLEBRIDGE_TUN_HELPER_TEST_FAIL": "remove_network:firewall_remove:exit"},
    )

    async def _scenario() -> None:
        client = await _connect_tun_helper_client(socket_path=socket_path, session_token=session_token)
        try:
            opened = await client.open_tun({"ifname": server_ifname, "mtu": 1400})
            assert opened.get("backend") == "linux-native"
            assert opened.get("ifname") == server_ifname

            apply_payload = {
                "ifname": server_ifname,
                "service_catalog": "remote_servers",
                "listener_hook_env": {"WAN_IF": underlay4_dev},
                "tun_routing": {
                    "tunnel_address": "198.18.40.1",
                    "tunnel_prefix": 24,
                    "included_routes": [included_route4],
                    "enable_tcpmss": True,
                },
            }
            applied = await client.apply_network(apply_payload)
            assert applied.get("firewall_manager") == "iptables"
            assert applied.get("firewall_wan_if") == underlay4_dev

            _wait_interface(server_ifname)
            _wait_interface_route(included_route4, family="-4", dev=server_ifname)
            _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
            _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
            _wait_firewall_rule_present("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.40.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
            _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
            _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")

            with pytest.raises((ConnectionError, RuntimeError)):
                await client.remove_network(apply_payload)
        finally:
            try:
                await client.close()
            except Exception:
                pass

    try:
        asyncio.run(_scenario())
        assert _wait_proc_exit(helper_proc) == 92

        _interface_lacks_route(included_route4, family="-4", dev=server_ifname)
        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
        _wait_firewall_rule_present("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.40.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
        _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
        _wait_firewall_rule_present("iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
    finally:
        overlay_e2e.stop_proc(helper_proc)
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT"],
            delete_cmd=["iptables", "-D", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            delete_cmd=["iptables", "-D", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.40.0/24", "-o", underlay4_dev, "-j", "MASQUERADE"],
            delete_cmd=["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "198.18.40.0/24", "-o", underlay4_dev, "-j", "MASQUERADE"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            delete_cmd=["iptables", "-t", "mangle", "-D", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        )
        _delete_firewall_rule_if_exists(
            check_cmd=["iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            delete_cmd=["iptables", "-t", "mangle", "-D", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        )

    _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", server_ifname, "-o", underlay4_dev, "-j", "ACCEPT")
    _wait_firewall_rule_absent("iptables", "-C", "FORWARD", "-i", underlay4_dev, "-o", server_ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
    _wait_firewall_rule_absent("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.40.0/24", "-o", underlay4_dev, "-j", "MASQUERADE")
    _wait_firewall_rule_absent("iptables", "-t", "mangle", "-C", "FORWARD", "-i", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
    _wait_firewall_rule_absent("iptables", "-t", "mangle", "-C", "FORWARD", "-o", server_ifname, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")


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
