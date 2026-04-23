"""Shared iOS native crypto bridge for ObstacleBridge packages.

This module lives under the shared ``obstacle_bridge`` package so both the
BeeWare iOS app and the standalone iOS E2E app can load it.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, c_char, cast
from typing import Any, Optional


def _load_rubicon():
    try:
        from rubicon.objc import ObjCClass
    except Exception:
        return None, None, None
    try:
        nsdata_cls = ObjCClass("NSData")
        bridge_cls = ObjCClass("ObstacleBridgeNativeCrypto")
    except Exception:
        return None, None, None
    return ObjCClass, nsdata_cls, bridge_cls


def _bytes_to_nsdata(nsdata_cls: Any, value: bytes) -> Any:
    payload = bytes(value or b"")
    return nsdata_cls.dataWithBytes(payload, length=len(payload))


def _nsdata_to_bytes(data: Any) -> bytes:
    if data is None:
        raise ValueError("native iOS crypto bridge returned nil data")
    return cast(data.bytes, POINTER(c_char))[: data.length]


class IOSNativeCryptoBackend:
    def __init__(self) -> None:
        _objc_class, nsdata_cls, bridge_cls = _load_rubicon()
        if bridge_cls is None or nsdata_cls is None:
            raise RuntimeError("ObstacleBridgeNativeCrypto is unavailable")
        self._nsdata_cls = nsdata_cls
        self._bridge = bridge_cls

    def _wrap(self, value: bytes) -> Any:
        return _bytes_to_nsdata(self._nsdata_cls, value)

    def _unwrap(self, value: Any) -> bytes:
        return _nsdata_to_bytes(value)

    def available_features(self) -> dict[str, Any]:
        try:
            payload = self._bridge.availableFeatures()
        except Exception:
            return {}
        out: dict[str, Any] = {}
        try:
            for key in payload:
                out[str(key)] = bool(payload[key])
        except Exception:
            return {}
        return out

    def hkdf_sha256(self, *, salt: bytes, info: bytes, key_material: bytes, length: int) -> bytes:
        data = self._bridge.hkdfSHA256Salt_info_keyMaterial_length_(
            self._wrap(salt),
            self._wrap(info),
            self._wrap(key_material),
            int(length),
        )
        return self._unwrap(data)

    def pbkdf2_sha256(self, *, password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
        data = self._bridge.pbkdf2SHA256Password_salt_iterations_length_(
            self._wrap(password),
            self._wrap(salt),
            int(iterations),
            int(length),
        )
        return self._unwrap(data)

    def aesgcm_encrypt(self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        data = self._bridge.aesGCMEncryptKey_nonce_plaintext_aad_(
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(plaintext),
            self._wrap(aad),
        )
        return self._unwrap(data)

    def aesgcm_decrypt(self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        data = self._bridge.aesGCMDecryptKey_nonce_ciphertext_aad_(
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(ciphertext),
            self._wrap(aad),
        )
        return self._unwrap(data)

    def chacha20poly1305_encrypt(self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        data = self._bridge.chaCha20Poly1305EncryptKey_nonce_plaintext_aad_(
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(plaintext),
            self._wrap(aad),
        )
        return self._unwrap(data)

    def chacha20poly1305_decrypt(self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        data = self._bridge.chaCha20Poly1305DecryptKey_nonce_ciphertext_aad_(
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(ciphertext),
            self._wrap(aad),
        )
        return self._unwrap(data)

    def generate_ed25519_private_key(self) -> bytes:
        return self._unwrap(self._bridge.generateEd25519PrivateKey())

    def ed25519_public_from_private(self, private_key: bytes) -> bytes:
        return self._unwrap(self._bridge.ed25519PublicKeyFromPrivateRaw_(self._wrap(private_key)))

    def ed25519_sign(self, *, private_key: bytes, message: bytes) -> bytes:
        data = self._bridge.ed25519SignPrivateKey_message_(self._wrap(private_key), self._wrap(message))
        return self._unwrap(data)

    def ed25519_verify(self, *, public_key: bytes, signature: bytes, message: bytes) -> bool:
        return bool(
            self._bridge.ed25519VerifyPublicKey_signature_message_(
                self._wrap(public_key),
                self._wrap(signature),
                self._wrap(message),
            )
        )

    def generate_x25519_private_key(self) -> bytes:
        return self._unwrap(self._bridge.generateX25519PrivateKey())

    def x25519_public_from_private(self, private_key: bytes) -> bytes:
        return self._unwrap(self._bridge.x25519PublicKeyFromPrivateRaw_(self._wrap(private_key)))

    def x25519_shared_secret(self, *, private_key: bytes, peer_public_key: bytes) -> bytes:
        data = self._bridge.x25519SharedSecretPrivateKey_peerPublicKey_(
            self._wrap(private_key),
            self._wrap(peer_public_key),
        )
        return self._unwrap(data)


def load_ios_native_crypto_backend() -> Optional[IOSNativeCryptoBackend]:
    try:
        return IOSNativeCryptoBackend()
    except Exception:
        return None
