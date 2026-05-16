from __future__ import annotations

import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.native_crypto import IOSNativeCryptoBackend, load_ios_native_crypto_backend


class _FakeBridge:
    def available_features(self):
        return {"aesgcm": True, "ed25519": True}

    def wrap(self, value: bytes) -> bytes:
        return bytes(value)

    def call_data(self, selector: str, *args, argtypes=None) -> bytes:
        if selector == "hkdfSHA256Salt:info:keyMaterial:lengthValue:":
            salt, info, key_material, length = args
            return b"hkdf:" + bytes([length]) + info[:2] + key_material[:2] + salt[:2]
        if selector == "pbkdf2SHA256Password:salt:iterationsValue:lengthValue:":
            password, salt, iterations, length = args
            return b"pbkdf2:" + bytes([iterations % 256, length % 256]) + password[:1] + salt[:1]
        if selector == "aesGCMEncryptKey:nonce:plaintext:aad:":
            key, nonce, plaintext, aad = args
            return b"aes-enc:" + key[:1] + nonce[:1] + plaintext + aad[:1]
        if selector == "aesGCMDecryptKey:nonce:ciphertext:aad:":
            key, nonce, ciphertext, aad = args
            return b"aes-dec:" + key[:1] + nonce[:1] + ciphertext[:2] + aad[:1]
        if selector == "chaCha20Poly1305EncryptKey:nonce:plaintext:aad:":
            _, _, plaintext, _ = args
            return b"chacha-enc:" + plaintext
        if selector == "chaCha20Poly1305DecryptKey:nonce:ciphertext:aad:":
            _, _, ciphertext, _ = args
            return b"chacha-dec:" + ciphertext[:2]
        if selector == "generateEd25519PrivateKey":
            return b"e" * 32
        if selector == "ed25519PublicKeyFromPrivateRaw:":
            return b"p" * 32
        if selector == "ed25519SignPrivateKey:message:":
            _, message = args
            return b"sig:" + message
        if selector == "generateX25519PrivateKey":
            return b"x" * 32
        if selector == "x25519PublicKeyFromPrivateRaw:":
            return b"q" * 32
        if selector == "x25519SharedSecretPrivateKey:peerPublicKey:":
            return b"shared"
        raise AssertionError(f"unexpected selector: {selector}")

    def call_bool(self, selector: str, *args, argtypes=None) -> bool:
        assert selector == "ed25519VerifyPublicKey:signature:message:"
        return True


def _backend() -> IOSNativeCryptoBackend:
    backend = object.__new__(IOSNativeCryptoBackend)
    backend._bridge = _FakeBridge()
    return backend


def test_load_ios_native_crypto_backend_returns_none_when_bridge_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("obstacle_bridge.ios_native_crypto._DirectObjCBridge", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert load_ios_native_crypto_backend() is None


def test_ios_native_crypto_backend_delegates_to_objc_bridge() -> None:
    backend = _backend()

    assert backend.available_features() == {"aesgcm": True, "ed25519": True}
    assert backend.hkdf_sha256(salt=b"sa", info=b"in", key_material=b"km", length=7).startswith(b"hkdf:")
    assert backend.pbkdf2_sha256(password=b"pw", salt=b"sa", iterations=2, length=16).startswith(b"pbkdf2:")
    assert backend.aesgcm_encrypt(key=b"k", nonce=b"n", plaintext=b"pt", aad=b"a").startswith(b"aes-enc:")
    assert backend.aesgcm_decrypt(key=b"k", nonce=b"n", ciphertext=b"ct", aad=b"a").startswith(b"aes-dec:")
    assert backend.chacha20poly1305_encrypt(key=b"k", nonce=b"n", plaintext=b"pt", aad=b"a") == b"chacha-enc:pt"
    assert backend.chacha20poly1305_decrypt(key=b"k", nonce=b"n", ciphertext=b"ct", aad=b"a") == b"chacha-dec:ct"
    assert backend.generate_ed25519_private_key() == b"e" * 32
    assert backend.ed25519_public_from_private(b"e" * 32) == b"p" * 32
    assert backend.ed25519_sign(private_key=b"e" * 32, message=b"msg") == b"sig:msg"
    assert backend.ed25519_verify(public_key=b"p" * 32, signature=b"s", message=b"m") is True
    assert backend.generate_x25519_private_key() == b"x" * 32
    assert backend.x25519_public_from_private(b"x" * 32) == b"q" * 32
    assert backend.x25519_shared_secret(private_key=b"x" * 32, peer_public_key=b"q" * 32) == b"shared"
