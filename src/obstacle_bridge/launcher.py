"""
Supervisor-style runtime entrypoint for ``python -m obstacle_bridge``.

This module parses launcher-specific options and forwards unknown CLI options
to ``bridge.py``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple


PUBLIC_IP_DISCOVERY_SERVICES = (
    "https://4.ipw.cn",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
)
PUBLIC_IP_DISCOVERY_TIMEOUT_S = 1.0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ObstacleBridge and restart on project restart exit codes"
    )
    parser.add_argument(
        "--command",
        default=None,
        help=(
            "Command to run (single string; shell-split). "
            "When omitted, the launcher starts: "
            "python -m obstacle_bridge.bridge --config ObstacleBridge.cfg"
        ),
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=30,
        help="Seconds to wait before restarting when exit code == 77",
    )
    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="Do not redirect stdout/stderr to the OS null device (useful for debugging)",
    )
    return parser


def _default_bridge_command(forward_args: Sequence[str]) -> List[str]:
    return [
        sys.executable,
        "-m",
        "obstacle_bridge.bridge",
        "--config",
        "ObstacleBridge.cfg",
        *list(forward_args),
    ]


def _resolve_command(raw_command: Optional[str], forward_args: Sequence[str]) -> List[str]:
    if raw_command:
        return [*shlex.split(raw_command), *list(forward_args)]
    return _default_bridge_command(forward_args)


def _build_bridge_notice_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", "-c", default="ObstacleBridge.cfg")
    parser.add_argument("--dump-config", nargs="?")
    parser.add_argument("--save-config")
    parser.add_argument("--admin-web", action="store_true", default=True)
    parser.add_argument("--admin-web-bind", default="127.0.0.1")
    parser.add_argument("--admin-web-port", type=int, default=18080)
    parser.add_argument("--admin-web-path", default="/")
    return parser


def _flatten_config(config: Dict[str, Any]) -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def _load_config_defaults(config_path: pathlib.Path, explicit_config: bool) -> Dict[str, Any]:
    if not explicit_config and not config_path.exists():
        return {}
    try:
        raw = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return _flatten_config(payload)


def _clickable_host(bind: str) -> str:
    host = str(bind or "").strip()
    if host in {"", "0.0.0.0", "::", "*", "localhost"}:
        return "127.0.0.1"
    return host


def _is_wildcard_bind(bind: str) -> bool:
    return str(bind or "").strip() in {"", "0.0.0.0", "::", "*"}


def _normalize_ip_literal(host: str) -> Optional[str]:
    value = str(host or "").strip()
    if not value:
        return None
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _rank_local_ip(host: str) -> Tuple[int, str]:
    ip_obj = ipaddress.ip_address(host)
    if ip_obj.version == 4 and ip_obj.is_private:
        return (0, host)
    if ip_obj.version == 6 and ip_obj.is_private:
        return (1, host)
    if ip_obj.version == 4:
        return (2, host)
    return (3, host)


def _discover_local_network_host() -> Optional[str]:
    candidates = set()

    for family, remote in (
        (socket.AF_INET, ("192.0.2.1", 80)),
        (socket.AF_INET6, ("2001:db8::1", 80, 0, 0)),
    ):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.connect(remote)
            local_host = _normalize_ip_literal(sock.getsockname()[0])
            if local_host:
                candidates.add(local_host)
        except OSError:
            pass
        finally:
            sock.close()

    try:
        hostname = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            local_host = _normalize_ip_literal(sockaddr[0])
            if local_host:
                candidates.add(local_host)
    except socket.gaierror:
        pass

    filtered = []
    for host in candidates:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            continue
        filtered.append(host)

    if not filtered:
        return None
    return sorted(filtered, key=_rank_local_ip)[0]


def _format_url(host: str, port: int, path: str) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}{path}"


def _discover_public_network_host() -> Tuple[Optional[str], Optional[str]]:
    for service_url in PUBLIC_IP_DISCOVERY_SERVICES:
        request = urllib.request.Request(
            service_url,
            headers={"User-Agent": "ObstacleBridge/0.1 public-ip-check"},
        )
        try:
            with urllib.request.urlopen(request, timeout=PUBLIC_IP_DISCOVERY_TIMEOUT_S) as response:
                payload = response.read().decode("utf-8", errors="replace").strip()
        except (OSError, urllib.error.URLError, TimeoutError):
            continue

        public_ip = _normalize_ip_literal(payload)
        if not public_ip:
            continue

        public_dns = None
        try:
            reverse_name, _, _ = socket.gethostbyaddr(public_ip)
        except (OSError, socket.herror, socket.gaierror):
            reverse_name = None
        if reverse_name and reverse_name != public_ip:
            public_dns = reverse_name.rstrip(".")
        return public_ip, public_dns

    return None, None


def _format_admin_web_urls(forward_args: Sequence[str]) -> List[str]:
    parser = _build_bridge_notice_parser()
    argv = list(forward_args)
    explicit_config = any(arg in {"--config", "-c"} for arg in argv)
    bootstrap_args, _ = parser.parse_known_args(argv)

    if bootstrap_args.dump_config or bootstrap_args.save_config:
        return []

    config_defaults = _load_config_defaults(pathlib.Path(bootstrap_args.config), explicit_config)
    parser.set_defaults(
        admin_web=bool(config_defaults.get("admin_web", True)),
        admin_web_bind=str(config_defaults.get("admin_web_bind", "127.0.0.1") or "127.0.0.1"),
        admin_web_port=int(config_defaults.get("admin_web_port", 18080) or 18080),
        admin_web_path=str(config_defaults.get("admin_web_path", "/") or "/"),
    )
    effective_args, _ = parser.parse_known_args(argv)

    if not effective_args.admin_web:
        return []

    path = str(effective_args.admin_web_path or "/")
    if not path.startswith("/"):
        path = f"/{path}"

    urls = [_format_url(_clickable_host(effective_args.admin_web_bind), effective_args.admin_web_port, path)]
    if _is_wildcard_bind(effective_args.admin_web_bind):
        lan_host = _discover_local_network_host()
        if lan_host and lan_host != "127.0.0.1":
            lan_url = _format_url(lan_host, effective_args.admin_web_port, path)
            if lan_url not in urls:
                urls.append(lan_url)
        public_ip, public_dns = _discover_public_network_host()
        if public_ip:
            public_url = _format_url(public_ip, effective_args.admin_web_port, path)
            if public_url not in urls:
                urls.append(public_url)
            if public_dns:
                public_dns_url = _format_url(public_dns, effective_args.admin_web_port, path)
                if public_dns_url not in urls:
                    urls.append(public_dns_url)
    return urls


def _print_startup_notice(forward_args: Sequence[str]) -> None:
    admin_web_urls = _format_admin_web_urls(forward_args)
    if not admin_web_urls:
        return

    print(f"Open WebAdmin interface {admin_web_urls[0]}", flush=True)
    if len(admin_web_urls) > 1:
        print(f"Open WebAdmin from local network {admin_web_urls[1]}", flush=True)
    if len(admin_web_urls) > 2:
        print(
            f"Public WebAdmin candidate {admin_web_urls[2]} (requires inbound routing/firewall access)",
            flush=True,
        )
    if len(admin_web_urls) > 3:
        print(
            f"Public DNS candidate {admin_web_urls[3]} (if that name resolves externally)",
            flush=True,
        )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args, forward_args = parser.parse_known_args(argv)
    cmd = _resolve_command(args.command, forward_args)

    if args.command is None:
        _print_startup_notice(forward_args)

    devnull = None
    if not args.no_redirect:
        devnull = open(os.devnull, "wb")

    try:
        while True:
            try:
                if devnull is not None:
                    result = subprocess.run(cmd, stdout=devnull, stderr=devnull)
                else:
                    result = subprocess.run(cmd)
            except FileNotFoundError as exc:
                print(f"Command not found: {exc}", file=sys.stderr)
                return 127
            rc = int(result.returncode)
            if rc == 75:
                continue
            if rc == 77:
                time.sleep(args.interval)
                continue
            return rc
    finally:
        if devnull is not None:
            devnull.close()
