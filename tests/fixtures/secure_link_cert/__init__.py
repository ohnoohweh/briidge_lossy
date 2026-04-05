from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from obstacle_bridge.bridge import _secure_link_canonical_cert_body_bytes


def _iso8601_z(value: dt.datetime) -> str:
    normalized = value.astimezone(dt.timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _public_key_der_b64(key: ed25519.Ed25519PublicKey) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def _write_private_key(path: Path, key: ed25519.Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _write_public_key(path: Path, key: ed25519.Ed25519PublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _write_signed_cert(
    path_root: Path,
    *,
    root_key: ed25519.Ed25519PrivateKey,
    subject_key: ed25519.Ed25519PrivateKey,
    cert_body_name: str,
    cert_sig_name: str,
    private_key_name: str,
    serial: str,
    subject_id: str,
    subject_name: str,
    deployment_id: str,
    roles: list[str],
    issued_at: dt.datetime,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> None:
    cert_body = {
        "version": 1,
        "serial": serial,
        "issuer_id": "deployment-admin-a" if serial != "client_root_b" else "deployment-admin-b",
        "subject_id": subject_id,
        "subject_name": subject_name,
        "deployment_id": deployment_id,
        "public_key_algorithm": "Ed25519",
        "public_key": _public_key_der_b64(subject_key.public_key()),
        "roles": list(roles),
        "issued_at": _iso8601_z(issued_at),
        "not_before": _iso8601_z(not_before),
        "not_after": _iso8601_z(not_after),
        "constraints": [],
        "signature_algorithm": "Ed25519",
    }
    signature = root_key.sign(_secure_link_canonical_cert_body_bytes(cert_body))
    (path_root / cert_body_name).write_text(json.dumps(cert_body, indent=2) + "\n", encoding="utf-8")
    (path_root / cert_sig_name).write_bytes(signature)
    _write_private_key(path_root / private_key_name, subject_key)


def materialize_secure_link_cert_fixture_set(target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    root_a_key = ed25519.Ed25519PrivateKey.generate()
    root_b_key = ed25519.Ed25519PrivateKey.generate()

    _write_public_key(target_dir / "root_a_pub.pem", root_a_key.public_key())
    _write_public_key(target_dir / "root_b_pub.pem", root_b_key.public_key())

    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_valid_cert_body.json",
        cert_sig_name="client_valid_cert.sig",
        private_key_name="client_valid_key.pem",
        serial="client_valid",
        subject_id="bridge-client-01",
        subject_name="Bridge Client 01",
        deployment_id="lab-a",
        roles=["client"],
        issued_at=now - dt.timedelta(days=1),
        not_before=now - dt.timedelta(days=2),
        not_after=now + dt.timedelta(days=365),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="server_valid_cert_body.json",
        cert_sig_name="server_valid_cert.sig",
        private_key_name="server_valid_key.pem",
        serial="server_valid",
        subject_id="bridge-server-01",
        subject_name="Bridge Server 01",
        deployment_id="lab-a",
        roles=["server"],
        issued_at=now - dt.timedelta(days=1),
        not_before=now - dt.timedelta(days=2),
        not_after=now + dt.timedelta(days=365),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_wrong_role_cert_body.json",
        cert_sig_name="client_wrong_role_cert.sig",
        private_key_name="client_wrong_role_key.pem",
        serial="client_wrong_role",
        subject_id="bridge-client-role-mismatch",
        subject_name="Bridge Client Wrong Role",
        deployment_id="lab-a",
        roles=["server"],
        issued_at=now - dt.timedelta(days=1),
        not_before=now - dt.timedelta(days=2),
        not_after=now + dt.timedelta(days=365),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_expired_cert_body.json",
        cert_sig_name="client_expired_cert.sig",
        private_key_name="client_expired_key.pem",
        serial="client_expired",
        subject_id="bridge-client-expired",
        subject_name="Bridge Client Expired",
        deployment_id="lab-a",
        roles=["client"],
        issued_at=now - dt.timedelta(days=30),
        not_before=now - dt.timedelta(days=30),
        not_after=now - dt.timedelta(days=1),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_future_cert_body.json",
        cert_sig_name="client_future_cert.sig",
        private_key_name="client_future_key.pem",
        serial="client_future",
        subject_id="bridge-client-future",
        subject_name="Bridge Client Future",
        deployment_id="lab-a",
        roles=["client"],
        issued_at=now,
        not_before=now + dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=366),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_a_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_other_deploy_cert_body.json",
        cert_sig_name="client_other_deploy_cert.sig",
        private_key_name="client_other_deploy_key.pem",
        serial="client_other_deploy",
        subject_id="bridge-client-other-deploy",
        subject_name="Bridge Client Other Deploy",
        deployment_id="lab-b",
        roles=["client"],
        issued_at=now - dt.timedelta(days=1),
        not_before=now - dt.timedelta(days=2),
        not_after=now + dt.timedelta(days=365),
    )
    _write_signed_cert(
        target_dir,
        root_key=root_b_key,
        subject_key=ed25519.Ed25519PrivateKey.generate(),
        cert_body_name="client_root_b_cert_body.json",
        cert_sig_name="client_root_b_cert.sig",
        private_key_name="client_root_b_key.pem",
        serial="client_root_b",
        subject_id="bridge-client-root-b",
        subject_name="Bridge Client Root B",
        deployment_id="lab-a",
        roles=["client"],
        issued_at=now - dt.timedelta(days=1),
        not_before=now - dt.timedelta(days=2),
        not_after=now + dt.timedelta(days=365),
    )

    (target_dir / "revoked_serials.json").write_text(json.dumps(["client_valid"], indent=2) + "\n", encoding="utf-8")
    return target_dir