from __future__ import annotations

import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.native_crypto import IOSNativeCryptoBackend, load_ios_native_crypto_backend


class _FakeNSData:
    def __init__(self, payload: bytes) -> None:
        self._payload = bytes(payload)
        self._buf = ctypes.create_string_buffer(self._payload, len(self._payload))
        self.bytes = ctypes.addressof(self._buf)
        self.length = len(self._payload)


class _FakeNSDataClass:
    @staticmethod
    def dataWithBytes(data: bytes, length: int):
        return _FakeNSData(bytes(data[:length]))


class _FakeBridge:
    @staticmethod
    def _payload(data) -> bytes:
        return bytes(getattr(data, "_payload", b""))

    @staticmethod
    def availableFeatures():
        return {"aesgcm": True, "ed25519": True}

    @staticmethod
    def hkdfSHA256Salt_info_keyMaterial_length_(salt, info, key_material, length):
        return _FakeNSData(
            b"hkdf:"
            + bytes([length])
            + _FakeBridge._payload(info)[:2]
            + _FakeBridge._payload(key_material)[:2]
            + _FakeBridge._payload(salt)[:2]
        )

    @staticmethod
    def pbkdf2SHA256Password_salt_iterations_length_(password, salt, iterations, length):
        return _FakeNSData(
            b"pbkdf2:"
            + bytes([iterations % 256, length % 256])
            + _FakeBridge._payload(password)[:1]
            + _FakeBridge._payload(salt)[:1]
        )

    @staticmethod
    def aesGCMEncryptKey_nonce_plaintext_aad_(key, nonce, plaintext, aad):
        return _FakeNSData(
            b"aes-enc:"
            + _FakeBridge._payload(key)[:1]
            + _FakeBridge._payload(nonce)[:1]
            + _FakeBridge._payload(plaintext)
            + _FakeBridge._payload(aad)[:1]
        )

    @staticmethod
    def aesGCMDecryptKey_nonce_ciphertext_aad_(key, nonce, ciphertext, aad):
        return _FakeNSData(
            b"aes-dec:"
            + _FakeBridge._payload(key)[:1]
            + _FakeBridge._payload(nonce)[:1]
            + _FakeBridge._payload(ciphertext)[:2]
            + _FakeBridge._payload(aad)[:1]
        )

    @staticmethod
    def chaCha20Poly1305EncryptKey_nonce_plaintext_aad_(key, nonce, plaintext, aad):
        return _FakeNSData(b"chacha-enc:" + _FakeBridge._payload(plaintext))

    @staticmethod
    def chaCha20Poly1305DecryptKey_nonce_ciphertext_aad_(key, nonce, ciphertext, aad):
        return _FakeNSData(b"chacha-dec:" + _FakeBridge._payload(ciphertext)[:2])

    @staticmethod
    def generateEd25519PrivateKey():
        return _FakeNSData(b"e" * 32)

    @staticmethod
    def ed25519PublicKeyFromPrivateRaw_(private_key):
        return _FakeNSData(b"p" * 32)

    @staticmethod
    def ed25519SignPrivateKey_message_(private_key, message):
        return _FakeNSData(b"sig:" + _FakeBridge._payload(message))

    @staticmethod
    def ed25519VerifyPublicKey_signature_message_(public_key, signature, message):
        return True

    @staticmethod
    def generateX25519PrivateKey():
        return _FakeNSData(b"x" * 32)

    @staticmethod
    def x25519PublicKeyFromPrivateRaw_(private_key):
        return _FakeNSData(b"q" * 32)

    @staticmethod
    def x25519SharedSecretPrivateKey_peerPublicKey_(private_key, peer_public_key):
        return _FakeNSData(b"shared")


def _backend() -> IOSNativeCryptoBackend:
    backend = object.__new__(IOSNativeCryptoBackend)
    backend._nsdata_cls = _FakeNSDataClass
    backend._bridge = _FakeBridge
    return backend


def test_load_ios_native_crypto_backend_returns_none_when_bridge_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("obstacle_bridge.ios_native_crypto._load_rubicon", lambda: (None, None, None))
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
