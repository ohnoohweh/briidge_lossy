from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def materialize_localhost_tls_fixture_set(target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ObstacleBridge Test TLS"),
    ])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    (target_dir / "key.pem").write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (target_dir / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return target_dir