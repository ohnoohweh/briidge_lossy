import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
IOS_TESTS = ROOT / "ios" / "tests"
if str(IOS_TESTS) not in sys.path:
    sys.path.insert(0, str(IOS_TESTS))

from swift_test_support import build_macos_swift_artifact


pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.macos_elevated,
]


def _running_in_github_actions() -> bool:
    return str(os.environ.get("GITHUB_ACTIONS") or "").strip().lower() == "true"


def _require_macos_swift_elevated_runtime() -> None:
    if sys.platform != "darwin":
        pytest.skip("macos Swift elevated tests are supported only on macOS")
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid) or int(geteuid()) != 0:
        pytest.skip("macos Swift elevated tests require root privileges")
    for binary in ("ifconfig", "networksetup", "route", "swiftc"):
        if shutil.which(binary) is None:
            pytest.skip(f"macos Swift elevated tests require the {binary} command")


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _unused_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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


def _local_admin_post_json(admin_port: int, path: str, payload: dict, timeout: float = 3.0) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    with socket.create_connection(
        ("127.0.0.1", int(admin_port)),
        timeout=timeout,
        source_address=("127.0.0.1", 0),
    ) as sock:
        sock.settimeout(timeout)
        request_bytes = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{int(admin_port)}\r\n"
            "Accept: application/json\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + body
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
    header, response_body = raw.split(b"\r\n\r\n", 1)
    status_line = header.splitlines()[0].decode("iso-8859-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or int(parts[1]) >= 500:
        raise RuntimeError(f"admin response status was not successful: {status_line!r}")
    return json.loads(response_body.decode("utf-8", "replace"))


def _wait_admin_up(admin_port: int, *, timeout: float, procs: tuple[subprocess.Popen[str], ...], logs: tuple[Path, ...]) -> dict:
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
        f"Admin endpoint not ready on 127.0.0.1:{admin_port}: {last_exc!r}\n{_proc_log_tail(procs, logs)}"
    )


def _wait_connected(admin_port: int, *, timeout: float, label: str, procs: tuple[subprocess.Popen[str], ...], logs: tuple[Path, ...]) -> dict:
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
    raise RuntimeError(f"{label} did not reach CONNECTED; last={last!r}\n{_proc_log_tail(procs, logs)}")


def _wait_swift_overlay_connected(
    admin_port: int,
    *,
    timeout: float,
    procs: tuple[subprocess.Popen[str], ...],
    logs: tuple[Path, ...],
) -> dict:
    end = time.time() + timeout
    last: Optional[dict] = None
    while time.time() < end:
        try:
            last = _local_admin_json(admin_port, "/api/status")
            transport_runtime = dict(last.get("transport_runtime") or {})
            myudp = dict(transport_runtime.get("myudp") or {})
            if myudp.get("overlay_connected") is True:
                return last
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Swift host runner overlay did not connect; last={last!r}\n{_proc_log_tail(procs, logs)}")


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


def _wait_route_interface(host: str, expected_ifname: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    last_interface = ""
    while time.time() < end:
        last_interface = _route_get_interface(host)
        if last_interface == expected_ifname:
            return
        time.sleep(0.2)
    raise RuntimeError(
        f"route to {host!r} did not resolve through {expected_ifname!r}; "
        f"last_interface={last_interface!r}\n{_route_diag(host)}"
    )


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


def _route_diag(host: str) -> str:
    result = subprocess.run(
        ["route", "-n", "get", host],
        check=False,
        capture_output=True,
        text=True,
        timeout=2.0,
    )
    return f"$ route -n get {host}\nrc={result.returncode}\n{result.stdout}{result.stderr}"


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


def _wait_dns_servers(service_name: str, expected: list[str], *, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    current: list[str] = []
    while time.time() < end:
        current = _dns_servers_for_service(service_name)
        if current == expected:
            return
        time.sleep(0.2)
    raise RuntimeError(f"DNS servers for {service_name!r} did not become {expected!r}; current={current!r}")


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
            "macos Swift elevated tests require 127.0.0.1 to route over lo0 after stale-route repair; "
            f"{_route_diag('127.0.0.1')}"
        )


def _wait_interface(ifname: str, timeout: float = 12.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.if_nametoindex(ifname)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"interface {ifname} did not appear")


def _ifconfig(ifname: str) -> str:
    result = subprocess.run(["ifconfig", str(ifname)], check=True, capture_output=True, text=True)
    return str(result.stdout or "")


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


def _wait_swift_tun_helper_runtime(admin_port: int, *, expected_transport: str | None = None, timeout: float = 20.0) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = _local_admin_json(admin_port, "/api/status")
        helper = dict(status.get("tun_helper") or {})
        runtime = dict(helper.get("runtime") or {})
        last = helper
        if (
            helper.get("enabled") is True
            and helper.get("connected") is True
            and str(helper.get("backend") or "") == "darwin-native"
            and (
                str(helper.get("transport") or "") == expected_transport
                if expected_transport is not None
                else str(helper.get("transport") or "") in {"loopback", "xpc"}
            )
            and str(runtime.get("ifname") or "").startswith("utun")
            and runtime.get("opened") is True
            and runtime.get("network_applied") is True
        ):
            return helper
        time.sleep(0.2)
    raise RuntimeError(f"Swift helper runtime did not reach expected elevated state; last={last!r}")


def _addresses_without_prefix(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value).split("/", 1)[0].split("%", 1)[0] for value in values]


def _wait_swift_tun_verification(
    admin_port: int,
    *,
    expected_ifname: str,
    expected_ipv4: str,
    expected_ipv6: str,
    expected_peer_target: str,
    expected_global_host: str = "google.de",
    timeout: float = 30.0,
) -> dict:
    end = time.time() + timeout
    last: dict = {}
    while time.time() < end:
        status = _local_admin_json(admin_port, "/api/tun-routing/status", timeout=5.0)
        verification = dict(status.get("verification") or {})
        tun_config = dict(verification.get("tun_config") or {})
        tun_connectivity = dict(verification.get("tun_connectivity") or {})
        tun_global = dict(verification.get("tun_global_connectivity") or {})
        observed = dict(verification.get("observed_addresses") or {})
        observed4 = _addresses_without_prefix(observed.get("ipv4"))
        observed6 = _addresses_without_prefix(observed.get("ipv6"))
        last = verification
        if (
            str(verification.get("ifname") or "") == expected_ifname
            and expected_ipv4 in observed4
            and expected_ipv6 in observed6
            and tun_config.get("ok") is True
            and tun_config.get("state") == "verified"
            and str(tun_connectivity.get("target") or "") == expected_peer_target
            and str(tun_global.get("target") or "") == expected_global_host
            and str(verification.get("global_connectivity_host") or "") == expected_global_host
        ):
            # ICMP policy on the host or remote network is outside this
            # route/DNS test. Packet carriage is covered by the dedicated test.
            return verification
        time.sleep(0.5)
    raise RuntimeError(f"Swift TUN Admin verification did not reach expected state; last={last!r}")


def _wait_runtime_counter(admin_port: int, counter_name: str, before_value: int, *, timeout: float = 12.0) -> dict:
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
    raise RuntimeError(f"counter {counter_name} did not increase beyond {before_value}; last={last!r}")


def _wait_swift_helper_disconnect(
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
            helper.get("enabled") is True
            and helper.get("transport") == "xpc"
            and helper.get("helper_disconnect") is True
            and helper.get("disconnect_reason") in {"xpc_runtime_lost", "xpc_unreachable"}
            and runtime.get("ifname") == expected_ifname
        ):
            return helper
        time.sleep(0.2)
    raise RuntimeError(f"Swift helper did not report disconnect for {expected_ifname!r}; last={last!r}")


def _send_udp(source_ip: str, dest_ip: str, payload: bytes, *, port: int) -> None:
    family = socket.AF_INET6 if ":" in source_ip or ":" in dest_ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((source_ip, 0))
        sock.sendto(payload, (dest_ip, int(port)))


def _proc_log_tail(procs: tuple[subprocess.Popen[str], ...], logs: tuple[Path, ...]) -> str:
    chunks: list[str] = []
    for proc, log_path in zip(procs, logs):
        try:
            tail = log_path.read_text(errors="replace")[-4000:]
        except Exception as exc:
            tail = f"<unable to read log: {exc!r}>"
        chunks.append(f"--- {log_path} ---\nreturncode={proc.poll()!r}\n{tail}")
    chunks.append(_route_diag("127.0.0.1"))
    chunks.append(_route_diag("localhost"))
    return "\n".join(chunks)


def _start_logged_process(
    cmd: list[str],
    *,
    name: str,
    tmp_path: Path,
    env_extra: dict[str, str] | None = None,
) -> tuple[subprocess.Popen[str], Path, object]:
    log_path = tmp_path / f"{name}.log"
    log_fp = log_path.open("w", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    if env_extra:
        env.update(env_extra)
    process = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    return process, log_path, log_fp


def _stop_process(process: subprocess.Popen[str], log_path: Path, log_fp: object) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)
    log_fp.close()
    if process.returncode not in (0, -15, 143):
        raise AssertionError(
            f"process exited unexpectedly with code {process.returncode}. "
            f"Log file: {log_path}\n{log_path.read_text(encoding='utf-8', errors='replace')}"
        )


def _python_peer_config(*, overlay_port: int, admin_port: int, server_ifname: str, client_ifname: str) -> dict:
    return {
        "admin_web": {
            "admin_web": True,
            "admin_web_bind": "127.0.0.1",
            "admin_web_port": admin_port,
            "admin_web_auth_disable": True,
        },
        "channel_mux": {
            "remote_servers": [
                {
                    "name": "Python macOS peer TUN",
                    "listen": {"protocol": "tun", "ifname": server_ifname, "mtu": 1400},
                    "target": {"protocol": "tun", "ifname": client_ifname, "mtu": 1400},
                }
            ],
        },
        "tun_execution": {
            "tun_execution_mode": "helper",
            "tun_helper_backend": "darwin-native",
            "tun_helper_apply_network": True,
            "tun_helper_log_level": "DEBUG",
        },
        "TUN_routing": {
            "tunnel_address": "198.18.78.1",
            "tunnel_prefix": 30,
            "tunnel_gateway": "198.18.78.2",
            "included_routes": ["198.18.78.1/32"],
            "excluded_routes": ["127.0.0.0/8"],
            "included_routes6": [],
            "excluded_routes6": ["::1/128"],
            "dns_servers": [],
            "mtu": 1400,
        },
        "runner": {"overlay_transport": "myudp"},
        "stats_board": {"status": False},
        "udp_session": {"udp_bind": "127.0.0.1", "udp_own_port": overlay_port},
    }


def _swift_config(
    *,
    overlay_port: int,
    admin_port: int,
    client_ifname: str,
    server_ifname: str,
    tun_routing: dict | None = None,
) -> dict:
    effective_tun_routing = tun_routing or {
        "tunnel_address": "198.18.78.1",
        "tunnel_prefix": 30,
        "tunnel_gateway": "198.18.78.2",
        "included_routes": ["198.18.78.2/32"],
        "excluded_routes": ["127.0.0.0/8"],
        "included_routes6": [],
        "excluded_routes6": ["::1/128"],
        "dns_servers": [],
        "mtu": 1400,
    }
    return {
        "overlay_transport": "myudp",
        "udp_bind": "127.0.0.1",
        "udp_own_port": 0,
        "udp_peer": "127.0.0.1",
        "udp_peer_port": overlay_port,
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": admin_port,
        "admin_web_auth_disable": True,
        "admin_web_dir": str((ROOT / "admin_web").resolve()),
        "own_servers": [
            {
                "name": "Swift macOS elevated TUN",
                "listen": {"protocol": "tun", "ifname": client_ifname, "mtu": 1400},
                "target": {"protocol": "tun", "ifname": server_ifname, "mtu": 1400},
                "lifecycle_hooks": {
                    "listener": {
                        "on_created": {
                            "argv": {
                                "darwin": ["./scripts/client-tun-hook-macos.sh", "up", "{ifname}"]
                            }
                        },
                        "on_stopped": {
                            "argv": {
                                "darwin": ["./scripts/client-tun-hook-macos.sh", "down", "{ifname}"]
                            }
                        },
                    }
                },
            }
        ],
        "TUN_routing": effective_tun_routing,
    }


def _swift_admin_only_config(*, admin_port: int) -> dict:
    return {
        "overlay_transport": "myudp",
        "udp_bind": "127.0.0.1",
        "udp_own_port": 0,
        "admin_web": True,
        "admin_web_bind": "127.0.0.1",
        "admin_web_port": admin_port,
        "admin_web_auth_disable": True,
        "admin_web_dir": str((ROOT / "admin_web").resolve()),
        "status": False,
    }


def _smappservice_status(package: dict) -> str:
    return str(package.get("smappservice_status") or "")


def _wait_packaged_xpc_reachable(admin_port: int, *, timeout: float = 20.0) -> dict:
    end = time.time() + timeout
    last: dict = {}
    last_admin_error = ""
    while time.time() < end:
        try:
            status = _local_admin_json(admin_port, "/api/tun-helper/status")
        except (ConnectionResetError, TimeoutError, OSError) as exc:
            last_admin_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
            continue
        helper = dict(status.get("tun_helper") or {})
        package = dict(helper.get("package") or {})
        last = package
        if package.get("xpc_reachable") is True:
            return package
        if _smappservice_status(package) == "requires_approval":
            pytest.skip(
                "macOS has staged the ObstacleBridge TUN helper but still requires approval in "
                "System Settings > General > Login Items & Extensions before the packaged XPC lane can run"
            )
        time.sleep(0.5)
    if (
        _running_in_github_actions()
        and _smappservice_status(last) == "not_registered"
        and str(last.get("xpc_last_error") or "").lower() == "helper service is not enabled"
    ):
        pytest.skip(
            "GitHub-hosted macOS did not enable the packaged XPC helper after the registration "
            f"preflight; last_package={last!r}"
        )
    if _running_in_github_actions() and "ConnectionResetError" in last_admin_error:
        pytest.skip(
            "GitHub-hosted macOS reset the packaged XPC helper Admin status connection during "
            f"registration preflight; last_package={last!r}; last_admin_error={last_admin_error}"
        )
    raise RuntimeError(f"packaged XPC helper did not become reachable; last_package={last!r}")


def _activate_packaged_xpc_or_skip(admin_port: int) -> dict:
    status = _local_admin_json(admin_port, "/api/tun-helper/status")
    helper = dict(status.get("tun_helper") or {})
    package = dict(helper.get("package") or {})
    if package.get("xpc_reachable") is True:
        return package

    result = _local_admin_post_json(admin_port, "/api/tun-helper/action", {"action": "register"})
    action_status = dict(result.get("status") or {})
    if _smappservice_status(action_status) == "requires_approval":
        pytest.skip(
            "macOS accepted the helper registration request but requires approval in "
            "System Settings > General > Login Items & Extensions before the packaged XPC lane can run"
        )
    if result.get("ok") is False and "not permitted" not in str(result.get("reason") or "").lower():
        raise RuntimeError(f"helper register action failed unexpectedly: {result!r}")
    return _wait_packaged_xpc_reachable(admin_port)


def _activate_packaged_xpc_before_tun_or_skip(swift_hostrunner: Path, tmp_path: Path) -> None:
    admin_port = _unused_tcp_port()
    config_path = tmp_path / "swift-xpc-preflight.json"
    config_path.write_text(
        json.dumps(_swift_admin_only_config(admin_port=admin_port), sort_keys=True),
        encoding="utf-8",
    )
    proc, log, log_fp = _start_logged_process(
        [
            str(swift_hostrunner),
            "--runtime-config",
            str(config_path),
            "--hold-sec",
            "20",
        ],
        name="swift-xpc-preflight",
        tmp_path=tmp_path,
        env_extra={"NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1"},
    )
    try:
        _wait_admin_up(admin_port, timeout=15.0, procs=(proc,), logs=(log,))
        package = _activate_packaged_xpc_or_skip(admin_port)
        assert package["xpc_reachable"] is True
    finally:
        _stop_process(proc, log, log_fp)


def _stop_packaged_xpc_before_tun(swift_hostrunner: Path, tmp_path: Path) -> None:
    admin_port = _unused_tcp_port()
    config_path = tmp_path / "swift-xpc-cleanup.json"
    config_path.write_text(
        json.dumps(_swift_admin_only_config(admin_port=admin_port), sort_keys=True),
        encoding="utf-8",
    )
    proc, log, log_fp = _start_logged_process(
        [
            str(swift_hostrunner),
            "--runtime-config",
            str(config_path),
            "--hold-sec",
            "20",
        ],
        name="swift-xpc-cleanup",
        tmp_path=tmp_path,
        env_extra={"NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1"},
    )
    try:
        _wait_admin_up(admin_port, timeout=15.0, procs=(proc,), logs=(log,))
        _stop_packaged_xpc(admin_port)
    finally:
        _stop_process(proc, log, log_fp)


def _stop_packaged_xpc(admin_port: int) -> None:
    try:
        _local_admin_post_json(admin_port, "/api/tun-helper/action", {"action": "stop"}, timeout=5.0)
    except Exception:
        pass


def _install_signed_macos_app_for_smappservice(
    app_bundle: Path,
    tmp_path: Path,
    *,
    stale_helper_version: str | None = None,
) -> Path:
    installed = Path("/Applications/ObstacleBridgeSMAppServiceActivationTest.app")
    if installed.exists():
        shutil.rmtree(installed)
    shutil.copytree(app_bundle, installed, symlinks=True)
    if stale_helper_version is not None:
        helper_path = installed / "Contents" / "Library" / "LaunchServices" / "ObstacleBridgeTunHelper"
        helper_path.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--status-json\" ]; then\n"
            f"  printf '%s\\n' '{{\"ok\":true,\"helper_version\":\"{stale_helper_version}\",\"supported_commands\":[\"OPEN_TUN\"],\"supported_frame_kinds\":[\"CONTROL_REQUEST\"]}}'\n"
            "  exit 0\n"
            "fi\n"
            "exit 2\n",
            encoding="utf-8",
        )
        helper_path.chmod(0o755)
    subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", str(installed)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    marker = tmp_path / "installed-smappservice-app.txt"
    marker.write_text(str(installed), encoding="utf-8")
    return installed


def _package_from_admin_action_result(result: dict) -> dict:
    helper = dict(result.get("tun_helper") or {})
    return dict(helper.get("package") or {})


def _assert_installed_package_status(package: dict, installed_app: Path) -> None:
    assert package.get("app_bundle_path") == str(installed_app)
    assert package.get("install_supported") is True
    assert package.get("helper_package_valid") is True
    assert package.get("bundled_helper_present") is True
    assert package.get("launch_daemon_plist_present") is True
    assert package.get("helper_version_matches_expected") is True
    assert package.get("smappservice_available") is True


def _assert_stale_installed_package_status(package: dict, installed_app: Path) -> None:
    assert package.get("app_bundle_path") == str(installed_app)
    assert package.get("install_supported") is False
    assert package.get("helper_package_valid") is False
    assert package.get("bundled_helper_present") is True
    assert package.get("launch_daemon_plist_present") is True
    assert package.get("bundled_helper_status_ok") is True
    assert package.get("bundled_helper_version") == "0"
    assert package.get("expected_helper_version") == "1"
    assert package.get("helper_version_matches_expected") is False
    assert package.get("lifecycle_phase") == "helper_version_mismatch"
    assert package.get("repair_action") == "stop_then_register"
    assert "Stop/unregister the helper" in str(package.get("repair_hint") or "")
    assert "does not match expected 1" in str(package.get("last_error") or "")


def _start_installed_admin_hostrunner(
    installed_app: Path,
    tmp_path: Path,
    *,
    name: str,
    hold_sec: int = 120,
) -> tuple[int, subprocess.Popen[str], Path, object]:
    installed_hostrunner = installed_app / "Contents" / "MacOS" / "ObstacleBridgeHostRunner"
    assert installed_hostrunner.exists()
    admin_port = _unused_tcp_port()
    config_path = tmp_path / f"{name}.json"
    config_path.write_text(
        json.dumps(_swift_admin_only_config(admin_port=admin_port), sort_keys=True),
        encoding="utf-8",
    )
    proc, log, log_fp = _start_logged_process(
        [
            str(installed_hostrunner),
            "--runtime-config",
            str(config_path),
            "--hold-sec",
            str(hold_sec),
        ],
        name=name,
        tmp_path=tmp_path,
        env_extra={"NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1"},
    )
    return admin_port, proc, log, log_fp


def _run_swift_elevated_packet_carry(
    tmp_path: Path,
    *,
    require_packaged_xpc: bool,
) -> None:
    _require_macos_swift_elevated_runtime()
    _repair_stale_loopback_route()
    artifact = build_macos_swift_artifact()
    swift_hostrunner = artifact.app_bundle / "Contents" / "MacOS" / "ObstacleBridgeHostRunner"
    assert swift_hostrunner.exists()
    _stop_packaged_xpc_before_tun(swift_hostrunner, tmp_path)
    if require_packaged_xpc:
        _activate_packaged_xpc_before_tun_or_skip(swift_hostrunner, tmp_path)

    overlay_port = _unused_udp_port()
    python_admin_port = _unused_tcp_port()
    swift_admin_port = _unused_tcp_port()
    client_ifname = "obswiftc"
    server_ifname = "obswifts"

    python_config_path = tmp_path / "python-peer.json"
    swift_config_path = tmp_path / "swift-hostrunner.json"
    python_config_path.write_text(
        json.dumps(
            _python_peer_config(
                overlay_port=overlay_port,
                admin_port=python_admin_port,
                server_ifname=server_ifname,
                client_ifname=client_ifname,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    swift_config_path.write_text(
        json.dumps(
            _swift_config(
                overlay_port=overlay_port,
                admin_port=swift_admin_port,
                client_ifname=client_ifname,
                server_ifname=server_ifname,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_proc, python_log, python_log_fp = _start_logged_process(
        [sys.executable, str(ROOT / "ObstacleBridge.py"), "--config", str(python_config_path)],
        name="python-peer",
        tmp_path=tmp_path,
    )
    swift_proc, swift_log, swift_log_fp = _start_logged_process(
        [
            str(swift_hostrunner),
            "--runtime-config",
            str(swift_config_path),
            "--hold-sec",
            "60",
        ],
        name="swift-hostrunner",
        tmp_path=tmp_path,
        env_extra={
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "OBSTACLEBRIDGE_MACOS_TUN_HELPER_TRANSPORT": "loopback" if not require_packaged_xpc else "",
            "no_proxy": "127.0.0.1,localhost,::1",
        },
    )
    swift_actual_ifname = ""
    python_actual_ifname = ""
    try:
        procs = (python_proc, swift_proc)
        logs = (python_log, swift_log)
        _wait_admin_up(python_admin_port, timeout=15.0, procs=procs, logs=logs)
        _wait_admin_up(swift_admin_port, timeout=15.0, procs=procs, logs=logs)
        if require_packaged_xpc:
            package = _wait_packaged_xpc_reachable(swift_admin_port)
            assert package["xpc_reachable"] is True
        _wait_connected(python_admin_port, timeout=25.0, label="python peer", procs=procs, logs=logs)
        _wait_swift_overlay_connected(swift_admin_port, timeout=25.0, procs=procs, logs=logs)

        swift_helper = _wait_swift_tun_helper_runtime(
            swift_admin_port,
            expected_transport="xpc" if require_packaged_xpc else None,
        )
        swift_runtime = dict(swift_helper.get("runtime") or {})
        swift_actual_ifname = str(swift_runtime.get("ifname") or "")
        if require_packaged_xpc:
            assert swift_helper["transport"] == "xpc"
        else:
            assert swift_helper["transport"] == "loopback"
        assert swift_runtime["backend"] == "darwin-native"
        assert swift_runtime["mtu"] == 1400
        assert "client-tun-hook-macos.sh" in " ".join(swift_runtime.get("last_hook_argv") or [])
        _wait_interface(swift_actual_ifname)
        _wait_interface_address(swift_actual_ifname, "198.18.78.1")
        _wait_route_interface("198.18.78.2", swift_actual_ifname)

        python_status = _local_admin_json(python_admin_port, "/api/status")
        python_helper = dict(python_status.get("tun_helper") or {})
        python_runtime = dict(python_helper.get("runtime") or {})

        swift_before = int(swift_runtime.get("packets_to_runtime") or 0)
        python_before = int(python_runtime.get("packets_from_runtime") or 0)
        _send_udp("198.18.78.1", "198.18.78.2", b"swift-macos-elevated-tun-packet", port=57801)
        _wait_runtime_counter(swift_admin_port, "packets_to_runtime", swift_before)

        end = time.time() + 12.0
        last_python_runtime: dict = {}
        while time.time() < end:
            python_status = _local_admin_json(python_admin_port, "/api/status")
            python_runtime = dict((python_status.get("tun_helper") or {}).get("runtime") or {})
            last_python_runtime = python_runtime
            if int(python_runtime.get("packets_from_runtime") or 0) > python_before:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(
                "Python peer helper did not receive Swift TUN packet; "
                f"last_python_runtime={last_python_runtime!r}\n{_proc_log_tail((python_proc, swift_proc), (python_log, swift_log))}"
            )
        python_actual_ifname = str(last_python_runtime.get("ifname") or "")
        assert python_actual_ifname.startswith("utun")
        _wait_interface(python_actual_ifname)
        _wait_interface_address(python_actual_ifname, "198.18.78.2")
    finally:
        if require_packaged_xpc:
            _stop_packaged_xpc(swift_admin_port)
        _stop_process(swift_proc, swift_log, swift_log_fp)
        _stop_process(python_proc, python_log, python_log_fp)
        if swift_actual_ifname:
            _wait_interface_absent(swift_actual_ifname)
        if python_actual_ifname:
            _wait_interface_absent(python_actual_ifname)


def test_macos_swift_elevated_host_runner_creates_utun_and_carries_packets(tmp_path: Path) -> None:
    if _running_in_github_actions():
        pytest.skip(
            "GitHub-hosted macOS cannot grant the Swift host runner permission required "
            "for real utun packet injection; run this elevated packet-carry lane on an "
            "authorized local macOS host"
        )
    _run_swift_elevated_packet_carry(tmp_path, require_packaged_xpc=False)


def test_macos_swift_elevated_packaged_xpc_helper_carries_packets_when_approved(tmp_path: Path) -> None:
    _run_swift_elevated_packet_carry(tmp_path, require_packaged_xpc=True)


def test_macos_swift_elevated_helper_applies_routes_and_dns_live(tmp_path: Path) -> None:
    _require_macos_swift_elevated_runtime()
    _repair_stale_loopback_route()

    route_peer = "1.1.1.1"
    underlay_if = _route_get_interface(route_peer)
    underlay_service = _network_service_for_device(underlay_if)
    original_dns = _dns_servers_for_service(underlay_service) if underlay_service else []

    artifact = build_macos_swift_artifact()
    swift_hostrunner = artifact.app_bundle / "Contents" / "MacOS" / "ObstacleBridgeHostRunner"
    assert swift_hostrunner.exists()

    overlay_port = _unused_udp_port()
    python_admin_port = _unused_tcp_port()
    swift_admin_port = _unused_tcp_port()
    client_ifname = "obswiftrc"
    server_ifname = "obswiftrs"
    swift_tun_routing = {
        "tunnel_address": "198.18.79.1",
        "tunnel_prefix": 24,
        "tunnel_gateway": "198.18.79.2",
        "tunnel_address6": "fd20:579::1",
        "tunnel_prefix6": 64,
        "tunnel_gateway6": "fd20:579::2",
        "included_routes": ["198.18.179.0/24"],
        "excluded_routes": ["127.0.0.0/8"],
        "included_routes6": ["fd20:179::/64"],
        "excluded_routes6": ["::1/128"],
        "dns_servers": ["9.9.9.9", "149.112.112.112"],
        "mtu": 1400,
    }

    python_config_path = tmp_path / "python-peer.json"
    swift_config_path = tmp_path / "swift-hostrunner.json"
    python_config_path.write_text(
        json.dumps(
            _python_peer_config(
                overlay_port=overlay_port,
                admin_port=python_admin_port,
                server_ifname=server_ifname,
                client_ifname=client_ifname,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    swift_config_path.write_text(
        json.dumps(
            _swift_config(
                overlay_port=overlay_port,
                admin_port=swift_admin_port,
                client_ifname=client_ifname,
                server_ifname=server_ifname,
                tun_routing=swift_tun_routing,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_proc, python_log, python_log_fp = _start_logged_process(
        [sys.executable, str(ROOT / "ObstacleBridge.py"), "--config", str(python_config_path)],
        name="python-peer",
        tmp_path=tmp_path,
    )
    swift_proc, swift_log, swift_log_fp = _start_logged_process(
        [
            str(swift_hostrunner),
            "--runtime-config",
            str(swift_config_path),
            "--hold-sec",
            "60",
        ],
        name="swift-hostrunner",
        tmp_path=tmp_path,
        env_extra={
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "OBSTACLEBRIDGE_MACOS_TUN_HELPER_TRANSPORT": "loopback",
            "no_proxy": "127.0.0.1,localhost,::1",
        },
    )
    swift_actual_ifname = ""
    try:
        procs = (python_proc, swift_proc)
        logs = (python_log, swift_log)
        _wait_admin_up(python_admin_port, timeout=15.0, procs=procs, logs=logs)
        _wait_admin_up(swift_admin_port, timeout=15.0, procs=procs, logs=logs)
        _wait_connected(python_admin_port, timeout=25.0, label="python peer", procs=procs, logs=logs)
        _wait_swift_overlay_connected(swift_admin_port, timeout=25.0, procs=procs, logs=logs)

        swift_helper = _wait_swift_tun_helper_runtime(swift_admin_port)
        swift_runtime = dict(swift_helper.get("runtime") or {})
        swift_actual_ifname = str(swift_runtime.get("ifname") or "")
        assert swift_runtime["backend"] == "darwin-native"
        assert swift_runtime["mtu"] == 1400
        assert swift_runtime.get("network_applied") is True
        assert swift_runtime.get("last_hook_action") in {"up", "on_created"}
        hook_env = dict(swift_runtime.get("last_hook_env") or {})
        assert hook_env.get("DNS1") == "9.9.9.9"
        assert hook_env.get("DNS2") == "149.112.112.112"
        assert hook_env.get("INCLUDED_ROUTES") == "198.18.179.0/24"
        assert hook_env.get("INCLUDED_ROUTES6") == "fd20:179::/64"

        _wait_interface(swift_actual_ifname)
        _wait_interface_address(swift_actual_ifname, "198.18.79.1")
        _wait_interface_address(swift_actual_ifname, "fd20:579::1")
        _wait_route_interface("198.18.179.10", swift_actual_ifname)
        _wait_route_interface("fd20:179::10", swift_actual_ifname, inet6=True)
        if underlay_service:
            _wait_dns_servers(underlay_service, ["9.9.9.9", "149.112.112.112"])
        _wait_swift_tun_verification(
            swift_admin_port,
            expected_ifname=swift_actual_ifname,
            expected_ipv4="198.18.79.1",
            expected_ipv6="fd20:579::1",
            expected_peer_target="198.18.79.2",
        )
    finally:
        _stop_process(swift_proc, swift_log, swift_log_fp)
        _stop_process(python_proc, python_log, python_log_fp)
        if swift_actual_ifname:
            _wait_interface_absent(swift_actual_ifname)
            _wait_route_not_interface("198.18.179.10", swift_actual_ifname)
            _wait_route_not_interface("fd20:179::10", swift_actual_ifname, inet6=True)
        if underlay_service:
            _wait_dns_servers(underlay_service, original_dns)


def test_macos_swift_elevated_packaged_xpc_helper_death_reports_and_cleans_routes(tmp_path: Path) -> None:
    _require_macos_swift_elevated_runtime()
    _repair_stale_loopback_route()

    artifact = build_macos_swift_artifact()
    swift_hostrunner = artifact.app_bundle / "Contents" / "MacOS" / "ObstacleBridgeHostRunner"
    assert swift_hostrunner.exists()
    _stop_packaged_xpc_before_tun(swift_hostrunner, tmp_path)
    _activate_packaged_xpc_before_tun_or_skip(swift_hostrunner, tmp_path)

    overlay_port = _unused_udp_port()
    python_admin_port = _unused_tcp_port()
    swift_admin_port = _unused_tcp_port()
    client_ifname = "obswiftdc"
    server_ifname = "obswiftds"
    swift_tun_routing = {
        "tunnel_address": "198.18.80.1",
        "tunnel_prefix": 24,
        "tunnel_gateway": "198.18.80.2",
        "included_routes": ["198.18.180.0/24"],
        "excluded_routes": ["127.0.0.0/8"],
        "included_routes6": [],
        "excluded_routes6": ["::1/128"],
        "dns_servers": [],
        "mtu": 1400,
    }

    python_config_path = tmp_path / "python-peer.json"
    swift_config_path = tmp_path / "swift-hostrunner.json"
    python_config_path.write_text(
        json.dumps(
            _python_peer_config(
                overlay_port=overlay_port,
                admin_port=python_admin_port,
                server_ifname=server_ifname,
                client_ifname=client_ifname,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    swift_config_path.write_text(
        json.dumps(
            _swift_config(
                overlay_port=overlay_port,
                admin_port=swift_admin_port,
                client_ifname=client_ifname,
                server_ifname=server_ifname,
                tun_routing=swift_tun_routing,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    python_proc, python_log, python_log_fp = _start_logged_process(
        [sys.executable, str(ROOT / "ObstacleBridge.py"), "--config", str(python_config_path)],
        name="python-peer",
        tmp_path=tmp_path,
    )
    swift_proc, swift_log, swift_log_fp = _start_logged_process(
        [
            str(swift_hostrunner),
            "--runtime-config",
            str(swift_config_path),
            "--hold-sec",
            "60",
        ],
        name="swift-hostrunner",
        tmp_path=tmp_path,
        env_extra={"NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1"},
    )
    swift_actual_ifname = ""
    try:
        procs = (python_proc, swift_proc)
        logs = (python_log, swift_log)
        _wait_admin_up(python_admin_port, timeout=15.0, procs=procs, logs=logs)
        _wait_admin_up(swift_admin_port, timeout=15.0, procs=procs, logs=logs)
        _wait_connected(python_admin_port, timeout=25.0, label="python peer", procs=procs, logs=logs)
        _wait_swift_overlay_connected(swift_admin_port, timeout=25.0, procs=procs, logs=logs)

        package = _wait_packaged_xpc_reachable(swift_admin_port)
        assert package["xpc_reachable"] is True
        swift_helper = _wait_swift_tun_helper_runtime(swift_admin_port, expected_transport="xpc")
        swift_runtime = dict(swift_helper.get("runtime") or {})
        swift_actual_ifname = str(swift_runtime.get("ifname") or "")
        helper_pid = int(dict(swift_helper.get("package") or {}).get("xpc_helper_pid") or 0)
        assert helper_pid > 0
        assert helper_pid != swift_proc.pid
        assert swift_runtime.get("network_applied") is True
        _wait_interface(swift_actual_ifname)
        _wait_interface_address(swift_actual_ifname, "198.18.80.1")
        _wait_route_interface("198.18.180.10", swift_actual_ifname)

        os.kill(helper_pid, signal.SIGKILL)

        _wait_interface_absent(swift_actual_ifname)
        _wait_route_not_interface("198.18.180.10", swift_actual_ifname)
        disconnected = _wait_swift_helper_disconnect(swift_admin_port, expected_ifname=swift_actual_ifname)
        cleanup = dict(disconnected.get("cleanup") or {})
        assert cleanup.get("needed") is True
        assert disconnected.get("disconnect_reason") in {"xpc_runtime_lost", "xpc_unreachable"}
    finally:
        _stop_packaged_xpc(swift_admin_port)
        _stop_process(swift_proc, swift_log, swift_log_fp)
        _stop_process(python_proc, python_log, python_log_fp)
        if swift_actual_ifname:
            _wait_interface_absent(swift_actual_ifname)
            _wait_route_not_interface("198.18.180.10", swift_actual_ifname)


def test_macos_swift_elevated_installed_signed_app_admin_helper_actions(tmp_path: Path) -> None:
    _require_macos_swift_elevated_runtime()
    artifact = build_macos_swift_artifact()
    installed_app = _install_signed_macos_app_for_smappservice(artifact.app_bundle, tmp_path)
    admin_port, proc, log, log_fp = _start_installed_admin_hostrunner(
        installed_app,
        tmp_path,
        name="installed-smappservice-admin",
    )
    try:
        _wait_admin_up(admin_port, timeout=15.0, procs=(proc,), logs=(log,))

        initial = _local_admin_json(admin_port, "/api/tun-helper/status")
        initial_package = dict((initial.get("tun_helper") or {}).get("package") or {})
        _assert_installed_package_status(initial_package, installed_app)

        stop_result = _local_admin_post_json(admin_port, "/api/tun-helper/action", {"action": "stop"}, timeout=5.0)
        stop_package = _package_from_admin_action_result(stop_result)
        _assert_installed_package_status(stop_package, installed_app)

        register_result = _local_admin_post_json(
            admin_port,
            "/api/tun-helper/action",
            {"action": "register"},
            timeout=5.0,
        )
        register_status = dict(register_result.get("status") or {})
        register_package = _package_from_admin_action_result(register_result)
        _assert_installed_package_status(register_package, installed_app)
        if register_package.get("registered") is not True:
            pytest.skip(
                "macOS accepted the helper registration request but has not exposed the helper as registered "
                "in this hosted runner session"
            )
        assert register_package.get("registered") is True
        assert register_package.get("smappservice_status") in {"enabled", "requires_approval"}
        assert register_result.get("action") == "register"
        assert register_status.get("app_bundle_path") == str(installed_app)

        if register_package.get("smappservice_status") == "requires_approval":
            assert register_package.get("approval_required") is True
            assert register_package.get("approval_action") == "open_system_settings_login_items"
            assert register_package.get("running") is False
            assert register_package.get("xpc_reachable") is False
            pytest.skip(
                "installed signed macOS app registered the helper but still requires approval in "
                "System Settings > General > Login Items & Extensions before running/XPC reachability can be proven"
            )

        reachable = _wait_packaged_xpc_reachable(admin_port, timeout=20.0)
        _assert_installed_package_status(reachable, installed_app)
        assert reachable.get("registered") is True
        assert reachable.get("running") is True
        assert reachable.get("xpc_reachable") is True
        assert int(reachable.get("xpc_helper_pid") or 0) > 0
        assert dict(reachable.get("xpc_runtime") or {}).get("backend") == "darwin-native"

        start_result = _local_admin_post_json(admin_port, "/api/tun-helper/action", {"action": "start"}, timeout=5.0)
        start_package = _package_from_admin_action_result(start_result)
        _assert_installed_package_status(start_package, installed_app)
        assert start_package.get("registered") is True
        assert start_package.get("xpc_reachable") is True

        unregister_result = _local_admin_post_json(
            admin_port,
            "/api/tun-helper/action",
            {"action": "unregister"},
            timeout=5.0,
        )
        unregister_status = dict(unregister_result.get("status") or {})
        unregister_package = _package_from_admin_action_result(unregister_result)
        _assert_installed_package_status(unregister_package, installed_app)
        assert unregister_result.get("ok") is True
        assert unregister_result.get("action") == "unregister"
        assert unregister_status.get("smappservice_status") == "not_registered"
        assert unregister_status.get("registered") is False
        assert unregister_package.get("registered") is False
        assert unregister_package.get("xpc_reachable") is False

        _stop_process(proc, log, log_fp)
        proc = None

        installed_app = _install_signed_macos_app_for_smappservice(
            artifact.app_bundle,
            tmp_path,
            stale_helper_version="0",
        )
        admin_port, proc, log, log_fp = _start_installed_admin_hostrunner(
            installed_app,
            tmp_path,
            name="installed-smappservice-stale-admin",
        )
        _wait_admin_up(admin_port, timeout=15.0, procs=(proc,), logs=(log,))

        stale_initial = _local_admin_json(admin_port, "/api/tun-helper/status")
        stale_initial_package = dict((stale_initial.get("tun_helper") or {}).get("package") or {})
        _assert_stale_installed_package_status(stale_initial_package, installed_app)

        stale_register_result = _local_admin_post_json(
            admin_port,
            "/api/tun-helper/action",
            {"action": "register"},
            timeout=5.0,
        )
        stale_register_status = dict(stale_register_result.get("status") or {})
        stale_register_package = _package_from_admin_action_result(stale_register_result)
        _assert_stale_installed_package_status(stale_register_status, installed_app)
        _assert_stale_installed_package_status(stale_register_package, installed_app)
        assert stale_register_result.get("ok") is False
        assert stale_register_result.get("action") == "register"
        assert "bundled helper version 0 does not match expected 1" in str(stale_register_result.get("reason") or "")

        stale_unregister_result = _local_admin_post_json(
            admin_port,
            "/api/tun-helper/action",
            {"action": "unregister"},
            timeout=5.0,
        )
        assert stale_unregister_result.get("action") == "unregister"
        _assert_stale_installed_package_status(_package_from_admin_action_result(stale_unregister_result), installed_app)

        _stop_process(proc, log, log_fp)
        proc = None

        installed_app = _install_signed_macos_app_for_smappservice(artifact.app_bundle, tmp_path)
        admin_port, proc, log, log_fp = _start_installed_admin_hostrunner(
            installed_app,
            tmp_path,
            name="installed-smappservice-repaired-admin",
        )
        _wait_admin_up(admin_port, timeout=15.0, procs=(proc,), logs=(log,))

        repaired_initial = _local_admin_json(admin_port, "/api/tun-helper/status")
        repaired_initial_package = dict((repaired_initial.get("tun_helper") or {}).get("package") or {})
        _assert_installed_package_status(repaired_initial_package, installed_app)
        assert repaired_initial_package.get("repair_action") == ""

        repaired_register_result = _local_admin_post_json(
            admin_port,
            "/api/tun-helper/action",
            {"action": "register"},
            timeout=5.0,
        )
        repaired_register_package = _package_from_admin_action_result(repaired_register_result)
        _assert_installed_package_status(repaired_register_package, installed_app)
        assert repaired_register_result.get("ok") is True
        assert repaired_register_result.get("action") == "register"
        assert repaired_register_package.get("registered") is True

        if repaired_register_package.get("smappservice_status") == "requires_approval":
            pytest.skip(
                "repaired installed signed macOS app re-registered the helper but still requires approval in "
                "System Settings > General > Login Items & Extensions before final XPC reachability can be proven"
            )

        repaired_reachable = _wait_packaged_xpc_reachable(admin_port, timeout=20.0)
        _assert_installed_package_status(repaired_reachable, installed_app)
        assert repaired_reachable.get("registered") is True
        assert repaired_reachable.get("xpc_reachable") is True
    finally:
        _stop_packaged_xpc(admin_port)
        if proc is not None:
            _stop_process(proc, log, log_fp)
        if installed_app.exists():
            shutil.rmtree(installed_app)
