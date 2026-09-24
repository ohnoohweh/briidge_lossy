"""Issue a TLS server certificate for a Linux telemetry collector."""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from obstacle_bridge.bridge_telemetry_credentials import _write_private, issue_server_certificate


def _write_certificate(path: str, content: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _prompt_fqdn() -> str:
    while True:
        answer = input("Do you have an FQDN host name, for example telemetry.example.net? [y/N]: ").strip().lower()
        if answer in {"", "n", "no"}:
            return ""
        if answer in {"y", "yes"}:
            value = input("FQDN host name: ").strip()
            if value and not _is_ip_address(value):
                return value
            print("Enter a DNS host name, not an IP address.")
            continue
        print("Please answer y or n.")


def _prompt_ip(version: int) -> str:
    label = "IPv4" if version == 4 else "IPv6"
    while True:
        value = input(f"Static {label} address (press Enter to omit): ").strip()
        if not value:
            return ""
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            print(f"Enter a valid static {label} address or press Enter to omit.")
            continue
        if parsed.version == version:
            return value
        print(f"Enter a valid static {label} address or press Enter to omit.")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue an ObstacleBridge telemetry collector certificate")
    parser.add_argument("--ca-key", required=True, help="existing CA private-key PEM path")
    parser.add_argument("--ca-cert", required=True, help="existing CA certificate PEM path")
    parser.add_argument("--fqdn", help="collector DNS name; with --ipv4/--ipv6, bypasses interactive prompts")
    parser.add_argument("--ipv4", help="collector static IPv4 address; with --fqdn/--ipv6, bypasses interactive prompts")
    parser.add_argument("--ipv6", help="collector static IPv6 address; with --fqdn/--ipv4, bypasses interactive prompts")
    parser.add_argument("--key-out", required=True, help="new collector private-key PEM path")
    parser.add_argument("--cert-out", required=True, help="new collector certificate PEM path")
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()
    if Path(args.key_out) == Path(args.cert_out):
        parser.error("--key-out and --cert-out must differ")
    supplied_names = [value for value in (args.fqdn, args.ipv4, args.ipv6) if value]
    if supplied_names:
        fqdn, ipv4, ipv6 = args.fqdn or "", args.ipv4 or "", args.ipv6 or ""
        if fqdn and _is_ip_address(fqdn):
            parser.error("--fqdn must be a DNS name")
        for value, version, option in ((ipv4, 4, "--ipv4"), (ipv6, 6, "--ipv6")):
            if value:
                try:
                    if ipaddress.ip_address(value).version != version:
                        raise ValueError
                except ValueError:
                    parser.error(f"{option} must be a valid IPv{version} address")
    else:
        fqdn = _prompt_fqdn()
        ipv4 = _prompt_ip(4)
        ipv6 = _prompt_ip(6)
    names = [value for value in (fqdn, ipv4, ipv6) if value]
    if not names:
        parser.error("provide at least one FQDN, static IPv4 address, or static IPv6 address")
    key, certificate = issue_server_certificate(
        Path(args.ca_key).read_bytes(), Path(args.ca_cert).read_bytes(), names[0], args.days, names[1:]
    )
    _write_private(args.key_out, key)
    _write_certificate(args.cert_out, certificate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
