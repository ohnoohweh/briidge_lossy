from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from obstacle_bridge.bridge_telemetry_credentials import generate_ca


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_ios_identity_generator_creates_password_protected_keychain_import_material(tmp_path):
    ca_key, ca_cert = generate_ca("telemetry-test-ca")
    ca_key_path, ca_cert_path, password_path = tmp_path / "ca.key.pem", tmp_path / "ca.cert.pem", tmp_path / "password"
    ca_key_path.write_bytes(ca_key); ca_cert_path.write_bytes(ca_cert); password_path.write_text("this-is-a-test-password", encoding="utf-8")
    output = tmp_path / "iphone-enrolment"
    completed = subprocess.run([
        sys.executable, str(REPO_ROOT / "scripts/generate_telemetry_ios_identity.py"),
        "--ca-key", str(ca_key_path), "--ca-cert", str(ca_cert_path),
        "--installation-id", "iphone-alice", "--out-dir", str(output), "--p12-password-file", str(password_path),
    ], check=True, capture_output=True, text=True)
    assert completed.stdout.strip() == str(output)
    p12_path = output / "obstaclebridge-telemetry-iphone-alice.p12"
    key, certificate, chain = pkcs12.load_key_and_certificates(p12_path.read_bytes(), b"this-is-a-test-password")
    assert key is not None and certificate is not None
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "iphone-alice"
    assert chain and chain[0].subject == x509.load_pem_x509_certificate(ca_cert).subject
    assert x509.load_der_x509_certificate((output / "obstaclebridge-telemetry-collector-ca.cer").read_bytes()).subject == x509.load_pem_x509_certificate(ca_cert).subject
    assert p12_path.stat().st_mode & 0o777 == 0o600


def test_ios_identity_generator_refuses_nonempty_output_directory(tmp_path):
    ca_key, ca_cert = generate_ca("telemetry-test-ca")
    ca_key_path, ca_cert_path, password_path = tmp_path / "ca.key.pem", tmp_path / "ca.cert.pem", tmp_path / "password"
    output = tmp_path / "iphone-enrolment"; output.mkdir(); (output / "existing").write_text("do not replace", encoding="utf-8")
    ca_key_path.write_bytes(ca_key); ca_cert_path.write_bytes(ca_cert); password_path.write_text("this-is-a-test-password", encoding="utf-8")
    completed = subprocess.run([
        sys.executable, str(REPO_ROOT / "scripts/generate_telemetry_ios_identity.py"),
        "--ca-key", str(ca_key_path), "--ca-cert", str(ca_cert_path),
        "--installation-id", "iphone-alice", "--out-dir", str(output), "--p12-password-file", str(password_path),
    ], capture_output=True, text=True)
    assert completed.returncode != 0
    assert "refusing to overwrite credential material" in completed.stderr


def test_ios_identity_wrapper_uses_standard_ca_paths_and_returns_output_to_operator():
    source = (REPO_ROOT / "ios/scripts/generate_telemetry_ios_identity.sh").read_text(encoding="utf-8")
    assert "TELEMETRY_INSTALLATION_ID" in source
    assert "/var/lib/obstaclebridge/telemetry-ca/ca.key.pem" in source
    assert "/var/lib/obstaclebridge/telemetry-ca/ca.cert.pem" in source
    assert "generate_telemetry_ios_identity.py" in source
    assert "sudo chown -R" in source


def test_ios_identity_upload_wrapper_uses_device_app_documents_copy_and_readback():
    source = (REPO_ROOT / "ios/scripts/upload_ios_telemetry_identity.sh").read_text(encoding="utf-8")
    assert "OB_IOS_DEVICE_ID is required" in source
    assert "--domain-type appDataContainer" in source
    assert "--domain-identifier" in source
    assert "Documents/ObstacleBridge-telemetry-identity.p12" in source
    assert "xcrun devicectl device copy to" in source
    assert "xcrun devicectl device copy from" in source
    assert "cmp -s" in source
    assert "not yet a Keychain identity" in source
    assert "PKCS#12 password:" in source
    assert "ObstacleBridge-telemetry-identity.password" in source
