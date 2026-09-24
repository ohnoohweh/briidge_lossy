#!/usr/bin/env python3
"""Issue an iPhone telemetry identity and package it for device enrolment.

The output contains a password-protected PKCS#12 client identity and the
collector CA as DER. The private key is imported into the iPhone Keychain and
is never copied into ObstacleBridge Documents or its App Group container.
"""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from obstacle_bridge.bridge_telemetry_credentials import issue_client_certificate


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _password(args: argparse.Namespace) -> bytes:
    if args.p12_password_file:
        value = Path(args.p12_password_file).read_text(encoding="utf-8").strip()
    else:
        value = getpass.getpass("New PKCS#12 password: ")
        if value != getpass.getpass("Repeat PKCS#12 password: "):
            raise ValueError("PKCS#12 passwords do not match")
    if len(value) < 12:
        raise ValueError("PKCS#12 password must contain at least 12 characters")
    return value.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue and export an ObstacleBridge iPhone telemetry Keychain identity")
    parser.add_argument("--ca-key", required=True, help="existing telemetry CA private-key PEM path")
    parser.add_argument("--ca-cert", required=True, help="existing telemetry CA certificate PEM path")
    parser.add_argument("--installation-id", required=True, help="iPhone telemetry identity; becomes certificate CN")
    parser.add_argument("--out-dir", required=True, help="new, private output directory")
    parser.add_argument("--days", type=int, default=30, help="client certificate lifetime (1..365 days)")
    parser.add_argument("--p12-password-file", help="file holding the PKCS#12 password; use only in protected automation")
    args = parser.parse_args()
    output = Path(args.out_dir)
    if output.exists() and any(output.iterdir()):
        parser.error("--out-dir must be new or empty; refusing to overwrite credential material")
    password = _password(args)
    ca_pem = Path(args.ca_cert).read_bytes()
    key_pem, certificate_pem, serial = issue_client_certificate(Path(args.ca_key).read_bytes(), ca_pem, args.installation_id, args.days)
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    ca_certificate = x509.load_pem_x509_certificate(ca_pem)
    identity = pkcs12.serialize_key_and_certificates(
        args.installation_id.encode("utf-8"), private_key, certificate, [ca_certificate], serialization.BestAvailableEncryption(password)
    )
    safe_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in args.installation_id).strip("-")
    if not safe_name:
        parser.error("--installation-id contains no usable file-name characters")
    _write_new(output / f"obstaclebridge-telemetry-{safe_name}.p12", identity, 0o600)
    _write_new(output / "obstaclebridge-telemetry-collector-ca.cer", ca_certificate.public_bytes(serialization.Encoding.DER), 0o644)
    _write_new(
        output / "README.txt",
        (
            "ObstacleBridge iPhone telemetry enrolment\n\n"
            f"Installation ID / certificate CN: {args.installation_id}\nCertificate serial: {serial}\n\n"
            "Install the .cer first and enable full trust in Settings > General > About > Certificate Trust Settings. "
            "Install the password-protected .p12 next. Deliver both files only through a protected channel and delete local copies after installation.\n"
        ).encode("utf-8"),
        0o644,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
