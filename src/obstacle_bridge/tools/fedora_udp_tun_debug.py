#!/usr/bin/env python3
"""Collect Fedora routing/firewall diagnostics for the iOS UDP/TUN experiment."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


def _iso_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass(frozen=True)
class CommandSpec:
    label: str
    argv: tuple[str, ...]
    optional: bool = False


def _run_command(spec: CommandSpec) -> str:
    if spec.optional and shutil.which(spec.argv[0]) is None:
        return f"$ {' '.join(spec.argv)}\n[skipped] command not found\n"
    try:
        proc = subprocess.run(
            spec.argv,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return f"$ {' '.join(spec.argv)}\n[error] command not found\n"
    output = proc.stdout
    if proc.stderr:
        output = f"{output}{proc.stderr}"
    if not output.strip():
        output = "[no output]\n"
    return f"$ {' '.join(spec.argv)}\n{output.rstrip()}\n[exit {proc.returncode}]\n"


def _build_specs(args: argparse.Namespace) -> list[CommandSpec]:
    specs = [
        CommandSpec("kernel", ("uname", "-a")),
        CommandSpec("interfaces", ("ip", "addr", "show", "dev", args.tun_if)),
        CommandSpec("uplink", ("ip", "addr", "show", "dev", args.uplink_if)),
        CommandSpec("routes_v4", ("ip", "route", "show")),
        CommandSpec("routes_v6", ("ip", "-6", "route", "show")),
        CommandSpec(
            "route_get_v4",
            ("ip", "route", "get", args.route_ipv4, "from", args.route_ipv4_src, "iif", args.tun_if),
        ),
        CommandSpec(
            "route_get_v6",
            ("ip", "-6", "route", "get", args.route_ipv6, "from", args.route_ipv6_src, "iif", args.tun_if),
        ),
        CommandSpec("ip_forward_v4", ("sysctl", "net.ipv4.ip_forward")),
        CommandSpec("ip_forward_v6", ("sysctl", "net.ipv6.conf.all.forwarding")),
        CommandSpec("rp_filter_all", ("sysctl", "net.ipv4.conf.all.rp_filter")),
        CommandSpec("rp_filter_default", ("sysctl", "net.ipv4.conf.default.rp_filter")),
        CommandSpec("rp_filter_tun", ("sysctl", f"net.ipv4.conf.{args.tun_if}.rp_filter")),
        CommandSpec("rp_filter_uplink", ("sysctl", f"net.ipv4.conf.{args.uplink_if}.rp_filter")),
        CommandSpec("iptables_forward", ("iptables", "-vnL", "FORWARD")),
        CommandSpec("iptables_nat", ("iptables", "-t", "nat", "-vnL", "POSTROUTING")),
        CommandSpec("ip6tables_forward", ("ip6tables", "-vnL", "FORWARD")),
        CommandSpec("ip6tables_nat", ("ip6tables", "-t", "nat", "-vnL", "POSTROUTING")),
        CommandSpec("nft_ruleset", ("nft", "list", "ruleset"), optional=True),
        CommandSpec("iptables_version", ("iptables", "--version")),
        CommandSpec("ip6tables_version", ("ip6tables", "--version")),
        CommandSpec("firewalld_state", ("firewall-cmd", "--state"), optional=True),
        CommandSpec("conntrack_summary", ("conntrack", "-S"), optional=True),
    ]
    return specs


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect a concise routing/firewall snapshot for the Fedora UDP/TUN experiment. "
            "This helps explain why traffic reaches FORWARD but never hits MASQUERADE."
        )
    )
    parser.add_argument("--tun-if", default="obexp0", help="Experiment TUN interface name")
    parser.add_argument("--uplink-if", default="wlp0s20f3", help="Fedora uplink interface name")
    parser.add_argument("--route-ipv4", default="1.1.1.1", help="IPv4 destination for route probing")
    parser.add_argument("--route-ipv4-src", default="192.168.105.1", help="IPv4 source for route probing")
    parser.add_argument("--route-ipv6", default="2606:4700:4700::1111", help="IPv6 destination for route probing")
    parser.add_argument("--route-ipv6-src", default="fd20:105::1", help="IPv6 source for route probing")
    parser.add_argument("--output", default="", help="Optional file path to write the report")
    return parser


def run(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    lines = [f"# fedora_udp_tun_debug {_iso_ts()}"]
    for spec in _build_specs(args):
        lines.append(f"\n## {spec.label}\n{_run_command(spec)}")
    report = "\n".join(lines).rstrip() + "\n"
    if str(args.output).strip():
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
