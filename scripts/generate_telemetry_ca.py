"""Create a private CA for a Linux telemetry collector deployment."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from obstacle_bridge.bridge_telemetry_credentials import _write_private, generate_ca


def _write_certificate(path: str, content: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an ObstacleBridge telemetry root CA")
    parser.add_argument("--common-name", required=True)
    parser.add_argument("--key-out", required=True, help="new CA private-key PEM path")
    parser.add_argument("--cert-out", required=True, help="new CA certificate PEM path")
    args = parser.parse_args()
    if Path(args.key_out) == Path(args.cert_out):
        parser.error("--key-out and --cert-out must differ")
    key, certificate = generate_ca(args.common_name)
    _write_private(args.key_out, key)
    _write_certificate(args.cert_out, certificate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
