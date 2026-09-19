from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "scripts"))

from assign_testflight_group import der_ecdsa_to_raw


def test_der_ecdsa_to_raw_converts_es256_signature() -> None:
    der = bytes.fromhex("3006020101020102")

    assert der_ecdsa_to_raw(der) == (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
