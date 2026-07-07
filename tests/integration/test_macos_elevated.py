import asyncio
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
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
    pytest.mark.macos_elevated,
]


def _require_macos_elevated_runtime() -> None:
    if sys.platform != "darwin":
        pytest.skip("macos_elevated tests are supported only on macOS")
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid) or int(geteuid()) != 0:
        pytest.skip("macos_elevated tests require root privileges")
    for binary in ("ifconfig", "networksetup", "route"):
        if shutil.which(binary) is None:
            pytest.skip(f"macos_elevated tests require the {binary} command")


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
    return _strip_option_and_values(args, option) + [option, value]


def _tun_name(tag: str, side: str) -> str:
    return f"ob{tag}{side}"[:15]


def _local_admin_json(admin_port: int, path: str, timeout: float = 1.5) -> dict:
    with socket.create_connection(
        ("127.0.0.1", int(admin_port)),
        timeout=timeout,
        source_address=("127.0.0.1", 0),
    ) as sock:
        sock.settimeout(timeout)
        request_bytes = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{int(admin_port)}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(request_bytes)
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    if b"\r\n\r\n" not in raw:
        raise RuntimeError(f"admin response missing header terminator: {raw[:200]!r}")
    header, body = raw.split(b"\r\n\r\n", 1)
    status_line = header.splitlines()[0].decode("iso-8859-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or int(parts[1]) >= 400:
        raise RuntimeError(f"admin response status was not successful: {status_line!r}")
    return json.loads(body.decode("utf-8", "replace"))


def _route_diag(host: str) -> str:
    try:
        result = subprocess.run(
            ["route", "-n", "get", host],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except Exception as exc:
        return f"route -n get {host} failed: {exc!r}"
    return f"$ route -n get {host}\nrc={result.returncode}\n{result.stdout}{result.stderr}"


def _route_get_interface(host: str) -> str:
    result = subprocess.run(
        ["route", "-n", "get", host],
        check=False,
        capture_output=True,
        text=True,
        timeout=2.0,
    )
    for line in str(result.stdout or "").splitlines():
        if "interface:" in line:
            return line.split("interface:", 1)[1].strip()
    return ""


def _route_get_interface6(host: str) -> str:
    result = subprocess.run(
        ["route", "-n", "get", "-inet6", host],
        check=False,
        capture_output=True,
        text=True,
        timeout=2.0,
    )
    for line in str(result.stdout or "").splitlines():
        if "interface:" in line:
            return line.split("interface:", 1)[1].strip()
    return ""


def _network_service_for_device(device: str) -> str:
    if not device:
        return ""
    result = subprocess.run(
        ["networksetup", "-listnetworkserviceorder"],
        check=False,
        capture_output=True,
        text=True,
        timeout=4.0,
    )
    service = ""
    for raw_line in str(result.stdout or "").splitlines():
        line = raw_line.strip()
        if line.startswith("(") and ")" in line:
            service = line.split(")", 1)[1].strip()
            continue
        if "Device:" in line:
            current = line.split("Device:", 1)[1].split(")", 1)[0].strip()
            if current == device:
                return service
    return ""


def _dns_servers_for_service(service_name: str) -> list[str]:
    if not service_name:
        return []
    result = subprocess.run(
        ["networksetup", "-getdnsservers", service_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=4.0,
    )
    lines = [line.strip() for line in str(result.stdout or "").splitlines() if line.strip()]
    if not lines or any("There aren't any DNS Servers set" in line for line in lines):
        return []
    return lines


def _wait_route_interface(host: str, ifname: str, *, inet6: bool = False, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        last = _route_get_interface6(host) if inet6 else _route_get_interface(host)
        if last == ifname:
            return
        time.sleep(0.2)
    family = "IPv6" if inet6 else "IPv4"
    raise RuntimeError(f"{family} route to {host} did not use {ifname}; last interface={last!r}")


def _wait_route_not_interface(host: str, ifname: str, *, inet6: bool = False, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        last = _route_get_interface6(host) if inet6 else _route_get_interface(host)
        if last != ifname:
            return
        time.sleep(0.2)
    family = "IPv6" if inet6 else "IPv4"
    raise RuntimeError(f"{family} route to {host} still uses {ifname}")


def _send_udp(source_ip: str, dest_ip: str, payload: bytes, *, port: int) -> None:
    family = socket.AF_INET6 if ":" in source_ip or ":" in dest_ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((source_ip, 0))
        sock.sendto(payload, (dest_ip, int(port)))


def _repair_stale_loopback_route() -> None:
    if _route_get_interface("127.0.0.1") == "lo0":
        return
    for args in (
        ["route", "-n", "delete", "-host", "127.0.0.1"],
        ["route", "-n", "delete", "127.0.0.1"],
        ["route", "-n", "delete", "-net", "127.0.0.0"],
        ["route", "-n", "delete", "-net", "127.0.0.0/8"],
        ["route", "-n", "delete", "-net", "127.0.0.0", "-netmask", "255.0.0.0"],
        ["route", "-n", "add", "-net", "127.0.0.0", "-netmask", "255.0.0.0", "-interface", "lo0"],
        ["route", "-n", "add", "-host", "127.0.0.1", "-interface", "lo0"],
    ):
        subprocess.run(args, check=False, capture_output=True, text=True)
    if _route_get_interface("127.0.0.1") != "lo0":
        pytest.skip(
            "macos_elevated tests require 127.0.0.1 to route over lo0 after stale-route repair; "
            f"{_route_diag('127.0.0.1')}"
        )


def _proc_log_tail(*procs: overlay_e2e.Proc) -> str:
    chunks: list[str] = []
    for proc in procs:
        try:
            tail = proc.log_path.read_text(errors="replace")[-4000:]
        except Exception as exc:
            tail = f"<unable to read log: {exc!r}>"
        chunks.append(
            f"--- {proc.name} {proc.log_path} ---\n"
            f"cmd={' '.join(str(part) for part in proc.cmd)}\n"
            f"returncode={proc.popen.poll()!r}\n"
            f"{tail}"
        )
    chunks.append(_route_diag("127.0.0.1"))
    chunks.append(_route_diag("localhost"))
    return "\n".join(chunks)


def _wait_admin_up_local(admin_port: int, *, timeout: float, procs: tuple[overlay_e2e.Proc, ...]) -> dict:
    end = time.time() + timeout
    last_exc: Optional[Exception] = None
    while time.time() < end:
        for path in ("/api/health", "/healthz", "/api/status"):
            try:
                body = _local_admin_json(admin_port, path)
                if isinstance(body, dict) and "ok" not in body:
                    body = {"ok": True, **body}
                if body.get("ok") is True:
                    return body
            except Exception as exc:
                last_exc = exc
        time.sleep(0.25)
    raise RuntimeError(
        f"Admin endpoint not ready on 127.0.0.1:{admin_port}: {last_exc!r}\n{_proc_log_tail(*procs)}"
    )


def _wait_status_connected_local(admin_port: int, *, timeout: float, label: str, procs: tuple[overlay_e2e.Proc, ...]) -> dict:
    end = time.time() + timeout
    last: Optional[dict] = None
    while time.time() < end:
        try:
            last = _local_admin_json(admin_port, "/api/status")
            state = str(last.get("status") or last.get("peer_state") or "").upper()
            if state == "CONNECTED":
                return last
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(
        f"Port {admin_port} did not reach CONNECTED for {label}; last={last!r}\n{_proc_log_tail(*procs)}"
    )


def _start_tun_bridge_pair(
    *,
    base_case: overlay_e2e.Case,
    tmp_path: Path,
    case_index: int,
    client_ifname: str,
    server_ifname: str,
    mtu: int,
    server_extra_args: Optional[list[str]] = None,
    client_extra_args: Optional[list[str]] = None,
) -> TunBridgePair:
    materialized = overlay_e2e.materialize_case_ports(base_case, case_index)
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
    tuned_case = replace(
        materialized,
        bridge_server_args=_with_service_specs(
            _strip_option_and_values(materialized.bridge_server_args, "--remote-servers"),
            "--remote-servers",
            [server_spec],
        ),
        bridge_client_args=_with_service_specs(
            _strip_option_and_values(materialized.bridge_client_args, "--remote-servers"),
            "--own-servers",
            [client_spec],
        ),
    )
    server_spec_cmd, client_spec_cmd = overlay_e2e.build_commands(tuned_case, tmp_path, case_index, enable_admin=True)

    server_name, server_cmd, server_env, server_admin = server_spec_cmd
    client_name, client_cmd, client_env, client_admin = client_spec_cmd
    for admin_port in (server_admin, client_admin):
        if admin_port is not None:
            overlay_e2e.ADMIN_PORT_LOOPBACKS[int(admin_port)] = ("127.0.0.1", "::ffff:127.0.0.1")
    server_cmd = _with_option_value(list(server_cmd), "--admin-web-bind", "127.0.0.1")
    client_cmd = _with_option_value(list(client_cmd), "--admin-web-bind", "127.0.0.1")
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
        _wait_admin_up_local(server_proc.admin_port or 0, timeout=10.0, procs=(server_proc, client_proc))
        _wait_admin_up_local(client_proc.admin_port or 0, timeout=10.0, procs=(server_proc, client_proc))
        _wait_status_connected_local(
            client_proc.admin_port or 0,
            timeout=20.0,
            label="client",
            procs=(server_proc, client_proc),
        )
        _wait_status_connected_local(
            server_proc.admin_port or 0,
            timeout=20.0,
            label="server",
            procs=(server_proc, client_proc),
        )
        return TunBridgePair(tuned_case, server_proc, client_proc)
    except Exception:
        overlay_e2e.stop_proc(client_proc)
        overlay_e2e.stop_proc(server_proc)
        raise


def _ifconfig(ifname: str) -> str:
    result = subprocess.run(
        ["ifconfig", str(ifname)],
        check=True,
        capture_output=True,
        text=True,
    )
    return str(result.stdout or "")


def _wait_interface(ifname: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.if_nametoindex(ifname)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} did not appear")


def _wait_interface_address(ifname: str, address: str, timeout: float = 12.0) -> str:
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        try:
            last = _ifconfig(ifname)
        except Exception as exc:
            last = repr(exc)
        if str(address) in last:
            return last
        time.sleep(0.2)
    raise RuntimeError(f"address {address} did not appear on {ifname}; last={last!r}")


def _wait_interface_absent(ifname: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.if_nametoindex(ifname)
        except OSError:
            return
        time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} still exists after teardown")


def _wait_tun_helper_runtime(
    admin_port: int,
    *,
    expected_backend: str,
    timeout: float = 20.0,
) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = _local_admin_json(admin_port, "/api/status")
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last = helper
        if (
            bool(helper.get("enabled"))
            and bool(helper.get("connected"))
            and str(runtime.get("backend") or "") == str(expected_backend)
            and str(runtime.get("ifname") or "").startswith("utun")
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
        status = _local_admin_json(admin_port, "/api/status")
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
        status = _local_admin_json(admin_port, "/api/status")
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


def test_overlay_e2e_macos_elevated_tun_helper_native_creates_utun_and_applies_hooks(tmp_path: Path) -> None:
    _require_macos_elevated_runtime()
    _repair_stale_loopback_route()
    case_tag = "mt501"
    client_requested_ifname = _tun_name(case_tag, "c")
    server_requested_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "darwin-native",
        "--log-tun-helper", "DEBUG",
    ]
    # Keep this first elevated proof deliberately non-invasive: no default route
    # takeover and no DNS changes.
    client_routing_args = [
        "--tunnel-address", "198.18.65.1",
        "--tunnel-prefix", "30",
        "--tunnel-gateway", "198.18.65.2",
        "--included-routes", "198.18.65.2/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    # Server-side Darwin hooks use remote_hook_env(), so tunnel_address is the
    # peer/client identity and tunnel_gateway is the local server identity.
    server_routing_args = [
        "--tunnel-address", "198.18.65.1",
        "--tunnel-prefix", "30",
        "--tunnel-gateway", "198.18.65.2",
        "--included-routes", "198.18.65.1/32",
        "--excluded-routes",
        "--included-routes6",
        "--excluded-routes6",
        "--dns-servers",
    ]
    pair = _start_tun_bridge_pair(
        base_case=overlay_e2e.CASES["case01_udp_over_own_udp_ipv4"],
        tmp_path=tmp_path,
        case_index=501,
        client_ifname=client_requested_ifname,
        server_ifname=server_requested_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    client_actual_ifname = ""
    server_actual_ifname = ""
    try:
        client_helper = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="darwin-native",
        )
        server_helper = _wait_tun_helper_runtime(
            pair.server_proc.admin_port or 0,
            expected_backend="darwin-native",
        )
        client_runtime = dict(client_helper.get("runtime") or {})
        server_runtime = dict(server_helper.get("runtime") or {})
        client_actual_ifname = str(client_runtime.get("ifname") or "")
        server_actual_ifname = str(server_runtime.get("ifname") or "")
        assert client_actual_ifname.startswith("utun")
        assert server_actual_ifname.startswith("utun")
        _wait_interface(client_actual_ifname)
        _wait_interface(server_actual_ifname)
        _wait_interface_address(client_actual_ifname, "198.18.65.1")
        _wait_interface_address(server_actual_ifname, "198.18.65.2")
        assert str(client_runtime.get("last_hook_action") or "") == "up"
        assert str(server_runtime.get("last_hook_action") or "") == "up"
        assert "client-tun-hook-macos.sh" in " ".join(client_runtime.get("last_hook_argv") or [])
        assert "server-tun-hook-macos.sh" in " ".join(server_runtime.get("last_hook_argv") or [])

        client_before = int(client_runtime.get("packets_to_runtime") or 0)
        server_before = int(server_runtime.get("packets_from_runtime") or 0)
        _send_udp("198.18.65.1", "198.18.65.2", b"darwin-native-packet-carry-501", port=50101)
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
        if client_actual_ifname:
            _wait_interface_absent(client_actual_ifname)
        if server_actual_ifname:
            _wait_interface_absent(server_actual_ifname)


def test_macos_elevated_darwin_native_helper_applies_routes_and_dns_live(tmp_path: Path) -> None:
    _require_macos_elevated_runtime()
    _repair_stale_loopback_route()
    from obstacle_bridge.bridge_tun_helper_macos import DarwinTunHelperBackend

    route_peer = "1.1.1.1"
    underlay_if = _route_get_interface(route_peer)
    underlay_service = _network_service_for_device(underlay_if)
    original_dns = _dns_servers_for_service(underlay_service) if underlay_service else []
    backend = DarwinTunHelperBackend()
    actual_ifname = ""

    async def _run() -> dict:
        opened = await backend.open_tun({"ifname": _tun_name("mt502", "c"), "mtu": 1400})
        payload = {
            "ifname": str(opened.get("ifname") or ""),
            "mtu": 1400,
            "tun_routing": {
                "tunnel_address": "198.18.66.1",
                "tunnel_prefix": 24,
                "tunnel_gateway": "198.18.66.2",
                "tunnel_address6": "fd20:566::1",
                "tunnel_prefix6": 64,
                "tunnel_gateway6": "fd20:566::2",
                "included_routes": ["198.18.166.0/24"],
                "excluded_routes": ["127.0.0.0/8"],
                "included_routes6": ["fd20:166::/64"],
                "excluded_routes6": ["::1/128"],
                "dns_servers": ["9.9.9.9", "149.112.112.112"],
            },
            "listener_hook_env": {
                "OB_OVERLAY_PEER_HOST": route_peer,
            },
        }
        await backend.apply_network(payload)
        return backend.local_snapshot()

    try:
        snapshot = asyncio.run(_run())
        actual_ifname = str(snapshot.get("ifname") or "")
        assert actual_ifname.startswith("utun")
        _wait_interface(actual_ifname)
        _wait_interface_address(actual_ifname, "198.18.66.1")
        _wait_interface_address(actual_ifname, "fd20:566::1")
        _wait_route_interface("198.18.166.10", actual_ifname)
        _wait_route_interface("fd20:166::10", actual_ifname, inet6=True)
        hook_env = dict(snapshot.get("last_hook_env") or {})
        assert hook_env.get("DNS1") == "9.9.9.9"
        assert hook_env.get("DNS2") == "149.112.112.112"
        if underlay_service:
            end = time.time() + 12.0
            while time.time() < end:
                if _dns_servers_for_service(underlay_service) == ["9.9.9.9", "149.112.112.112"]:
                    break
                time.sleep(0.2)
            else:
                pytest.fail(
                    f"DNS servers for {underlay_service!r} were not updated; "
                    f"current={_dns_servers_for_service(underlay_service)!r}"
                )
    finally:
        asyncio.run(backend.stop())
        if actual_ifname:
            _wait_interface_absent(actual_ifname)
            _wait_route_not_interface("198.18.166.10", actual_ifname)
            _wait_route_not_interface("fd20:166::10", actual_ifname, inet6=True)
        if underlay_service:
            end = time.time() + 12.0
            while time.time() < end:
                if _dns_servers_for_service(underlay_service) == original_dns:
                    break
                time.sleep(0.2)
            else:
                pytest.fail(
                    f"DNS servers for {underlay_service!r} were not restored; "
                    f"expected={original_dns!r} current={_dns_servers_for_service(underlay_service)!r}"
                )


def test_overlay_e2e_macos_elevated_tun_helper_native_reports_helper_death_cleanup(tmp_path: Path) -> None:
    _require_macos_elevated_runtime()
    _repair_stale_loopback_route()
    case_tag = "mt503"
    client_requested_ifname = _tun_name(case_tag, "c")
    server_requested_ifname = _tun_name(case_tag, "s")
    helper_args = [
        "--tun-execution-mode", "helper",
        "--tun-helper-backend", "darwin-native",
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
        case_index=503,
        client_ifname=client_requested_ifname,
        server_ifname=server_requested_ifname,
        mtu=1400,
        server_extra_args=helper_args + server_routing_args,
        client_extra_args=helper_args + client_routing_args,
    )
    client_actual_ifname = ""
    try:
        client_helper = _wait_tun_helper_runtime(
            pair.client_proc.admin_port or 0,
            expected_backend="darwin-native",
        )
        client_runtime = dict(client_helper.get("runtime") or {})
        client_actual_ifname = str(client_runtime.get("ifname") or "")
        helper_pid = int(client_helper.get("pid") or 0)
        assert helper_pid > 0
        _wait_interface(client_actual_ifname)
        _wait_route_interface("198.18.167.10", client_actual_ifname)

        os.kill(helper_pid, signal.SIGKILL)

        disconnected = _wait_tun_helper_disconnected_runtime(
            pair.client_proc.admin_port or 0,
            expected_ifname=client_actual_ifname,
        )
        helper_after = dict(disconnected.get("tun_helper") or {})
        runtime_after = dict(helper_after.get("runtime") or {})
        assert runtime_after.get("backend") == "darwin-native"
        assert runtime_after.get("ifname") == client_actual_ifname
        last_error = str(helper_after.get("last_error") or "").lower()
        assert "connection closed" in last_error or "connection reset" in last_error
        _wait_interface_absent(client_actual_ifname)
        _wait_route_not_interface("198.18.167.10", client_actual_ifname)
    finally:
        pair.stop()
        if client_actual_ifname:
            _wait_interface_absent(client_actual_ifname)
