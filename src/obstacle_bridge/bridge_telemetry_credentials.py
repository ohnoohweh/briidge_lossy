"""mTLS credential issuance and revocation helpers for telemetry/v1."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ipaddress
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_private(path: str, content: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def generate_ca(common_name: str) -> Tuple[bytes, bytes]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(common_name))])
    now = _now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, algorithm=None)
    )
    return (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        certificate.public_bytes(serialization.Encoding.PEM),
    )


def issue_client_certificate(ca_key_pem: bytes, ca_cert_pem: bytes, installation_id: str, days: int = 30) -> Tuple[bytes, bytes, int]:
    if not installation_id or len(installation_id) > 128:
        raise ValueError("invalid installation id")
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    key = ed25519.Ed25519PrivateKey.generate()
    now = _now()
    serial = x509.random_serial_number()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, installation_id)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=max(1, min(int(days), 365))))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier(authority_key_id.key_identifier, None, None), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:obstaclebridge:telemetry:" + installation_id)]), critical=False)
        .sign(ca_key, algorithm=None)
    )
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), certificate.public_bytes(serialization.Encoding.PEM), serial)


def issue_server_certificate(
    ca_key_pem: bytes,
    ca_cert_pem: bytes,
    hostname: str,
    days: int = 30,
    alternative_names: Iterable[str] = (),
) -> Tuple[bytes, bytes]:
    names = list(dict.fromkeys(str(name).strip() for name in (hostname, *alternative_names) if str(name).strip()))
    if not names:
        raise ValueError("at least one collector hostname or IP address is required")
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    key = ed25519.Ed25519PrivateKey.generate()
    now = _now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    subject_alternative_names = [
        x509.IPAddress(ipaddress.ip_address(name)) if _is_ip(name) else x509.DNSName(name)
        for name in names
    ]
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=max(1, min(int(days), 365))))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier(authority_key_id.key_identifier, None, None), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(subject_alternative_names), critical=False)
        .sign(ca_key, algorithm=None)
    )
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), certificate.public_bytes(serialization.Encoding.PEM))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class TelemetryRevocationList:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.path.exists():
            self._save(set())

    def _load(self) -> set[int]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return {int(value) for value in data.get("serials", [])}
        except Exception:
            return set()

    def _save(self, serials: set[int]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"serials": sorted(serials)}, separators=(",", ":")), encoding="utf-8")
        os.replace(str(temporary), str(self.path))

    def revoke(self, serial: int) -> None:
        serials = self._load()
        serials.add(int(serial))
        self._save(serials)

    def is_revoked(self, serial: int) -> bool:
        return int(serial) in self._load()


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Telemetry mTLS credential helper")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init-ca")
    init.add_argument("--common-name", required=True); init.add_argument("--key-out", required=True); init.add_argument("--cert-out", required=True)
    issue = subparsers.add_parser("issue-client")
    issue.add_argument("--ca-key", required=True); issue.add_argument("--ca-cert", required=True); issue.add_argument("--installation-id", required=True); issue.add_argument("--key-out", required=True); issue.add_argument("--cert-out", required=True); issue.add_argument("--days", type=int, default=30)
    revoke = subparsers.add_parser("revoke")
    revoke.add_argument("--revocations", required=True); revoke.add_argument("--serial", required=True, type=int)
    args = parser.parse_args(argv)
    if args.command == "init-ca":
        key, cert = generate_ca(args.common_name); _write_private(args.key_out, key); Path(args.cert_out).write_bytes(cert)
    elif args.command == "issue-client":
        key, cert, serial = issue_client_certificate(Path(args.ca_key).read_bytes(), Path(args.ca_cert).read_bytes(), args.installation_id, args.days); _write_private(args.key_out, key); Path(args.cert_out).write_bytes(cert); print(serial)
    else:
        TelemetryRevocationList(args.revocations).revoke(args.serial)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
