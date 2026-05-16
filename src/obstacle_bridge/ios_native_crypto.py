"""Shared iOS native crypto bridge for ObstacleBridge packages.

This module lives under the shared ``obstacle_bridge`` package so both the
BeeWare iOS app and the standalone iOS E2E app can load it.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, c_bool, c_char, c_char_p, c_size_t, c_void_p, cast
from ctypes.util import find_library
from typing import Any, Optional

_LAST_LOAD_ERROR = ""


def _load_cdll(name: str) -> Any:
    path = find_library(name)
    if path:
        return ctypes.CDLL(path)
    for candidate in (
        f"/usr/lib/lib{name}.dylib",
        f"/System/Library/Frameworks/{name}.framework/{name}",
    ):
        try:
            return ctypes.CDLL(candidate)
        except OSError:
            continue
    raise OSError(f"library not found: {name}")


def _objc_callable(libobjc: Any, restype: Any, argtypes: list[Any]) -> Any:
    return ctypes.CFUNCTYPE(restype, c_void_p, c_void_p, *argtypes)(("objc_msgSend", libobjc))


class _DirectObjCBridge:
    _FEATURES = {
        "aesgcm": True,
        "chacha20poly1305": True,
        "hkdf_sha256": True,
        "pbkdf2_sha256": True,
        "ed25519": True,
        "x25519": True,
    }

    def __init__(self) -> None:
        global _LAST_LOAD_ERROR
        try:
            self._libobjc = _load_cdll("objc")
        except Exception as exc:
            _LAST_LOAD_ERROR = f"libobjc load failed: {type(exc).__name__}: {exc}"
            raise RuntimeError(_LAST_LOAD_ERROR) from exc
        self._libobjc.objc_getClass.restype = c_void_p
        self._libobjc.objc_getClass.argtypes = [c_char_p]
        self._libobjc.sel_registerName.restype = c_void_p
        self._libobjc.sel_registerName.argtypes = [c_char_p]

        self._nsdata_cls = self._class("NSData")
        self._bridge_cls = self._class("ObstacleBridgeNativeCrypto")
        _LAST_LOAD_ERROR = ""

    def _class(self, name: str) -> c_void_p:
        ptr = self._libobjc.objc_getClass(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C class not found: {name}")
        return ptr

    def _sel(self, name: str) -> c_void_p:
        ptr = self._libobjc.sel_registerName(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C selector not found: {name}")
        return ptr

    def _send(self, target: c_void_p, selector: str, restype: Any, *args: Any, argtypes: list[Any]) -> Any:
        fn = _objc_callable(self._libobjc, restype, argtypes)
        return fn(target, self._sel(selector), *args)

    def wrap(self, value: bytes) -> c_void_p:
        payload = bytes(value or b"")
        buf = ctypes.create_string_buffer(payload, len(payload))
        return self._send(
            self._nsdata_cls,
            "dataWithBytes:length:",
            c_void_p,
            cast(buf, c_void_p),
            c_size_t(len(payload)),
            argtypes=[c_void_p, c_size_t],
        )

    def unwrap(self, data: Any) -> bytes:
        if not data:
            raise ValueError("native iOS crypto bridge returned nil data")
        target = c_void_p(data) if not isinstance(data, c_void_p) else data
        length = self._send(target, "length", c_size_t, argtypes=[])
        bytes_ptr = self._send(target, "bytes", c_void_p, argtypes=[])
        return cast(bytes_ptr, POINTER(c_char))[: int(length)]

    def available_features(self) -> dict[str, Any]:
        return dict(self._FEATURES)

    def call_data(self, selector: str, *args: Any, argtypes: list[Any]) -> bytes:
        result = self._send(self._bridge_cls, selector, c_void_p, *args, argtypes=argtypes)
        return self.unwrap(result)

    def call_bool(self, selector: str, *args: Any, argtypes: list[Any]) -> bool:
        return bool(self._send(self._bridge_cls, selector, c_bool, *args, argtypes=argtypes))


class IOSNativeCryptoBackend:
    def __init__(self) -> None:
        self._bridge = _DirectObjCBridge()

    def _wrap(self, value: bytes) -> Any:
        return self._bridge.wrap(value)

    def available_features(self) -> dict[str, Any]:
        return self._bridge.available_features()

    def hkdf_sha256(self, *, salt: bytes, info: bytes, key_material: bytes, length: int) -> bytes:
        return self._bridge.call_data(
            "hkdfSHA256Salt:info:keyMaterial:lengthValue:",
            self._wrap(salt),
            self._wrap(info),
            self._wrap(key_material),
            int(length),
            argtypes=[c_void_p, c_void_p, c_void_p, ctypes.c_long],
        )

    def pbkdf2_sha256(self, *, password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
        return self._bridge.call_data(
            "pbkdf2SHA256Password:salt:iterationsValue:lengthValue:",
            self._wrap(password),
            self._wrap(salt),
            int(iterations),
            int(length),
            argtypes=[c_void_p, c_void_p, ctypes.c_long, ctypes.c_long],
        )

    def aesgcm_encrypt(self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._bridge.call_data(
            "aesGCMEncryptKey:nonce:plaintext:aad:",
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(plaintext),
            self._wrap(aad),
            argtypes=[c_void_p, c_void_p, c_void_p, c_void_p],
        )

    def aesgcm_decrypt(self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._bridge.call_data(
            "aesGCMDecryptKey:nonce:ciphertext:aad:",
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(ciphertext),
            self._wrap(aad),
            argtypes=[c_void_p, c_void_p, c_void_p, c_void_p],
        )

    def chacha20poly1305_encrypt(self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._bridge.call_data(
            "chaCha20Poly1305EncryptKey:nonce:plaintext:aad:",
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(plaintext),
            self._wrap(aad),
            argtypes=[c_void_p, c_void_p, c_void_p, c_void_p],
        )

    def chacha20poly1305_decrypt(self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._bridge.call_data(
            "chaCha20Poly1305DecryptKey:nonce:ciphertext:aad:",
            self._wrap(key),
            self._wrap(nonce),
            self._wrap(ciphertext),
            self._wrap(aad),
            argtypes=[c_void_p, c_void_p, c_void_p, c_void_p],
        )

    def generate_ed25519_private_key(self) -> bytes:
        return self._bridge.call_data("generateEd25519PrivateKey", argtypes=[])

    def ed25519_public_from_private(self, private_key: bytes) -> bytes:
        return self._bridge.call_data(
            "ed25519PublicKeyFromPrivateRaw:",
            self._wrap(private_key),
            argtypes=[c_void_p],
        )

    def ed25519_sign(self, *, private_key: bytes, message: bytes) -> bytes:
        return self._bridge.call_data(
            "ed25519SignPrivateKey:message:",
            self._wrap(private_key),
            self._wrap(message),
            argtypes=[c_void_p, c_void_p],
        )

    def ed25519_verify(self, *, public_key: bytes, signature: bytes, message: bytes) -> bool:
        return self._bridge.call_bool(
            "ed25519VerifyPublicKey:signature:message:",
            self._wrap(public_key),
            self._wrap(signature),
            self._wrap(message),
            argtypes=[c_void_p, c_void_p, c_void_p],
        )

    def generate_x25519_private_key(self) -> bytes:
        return self._bridge.call_data("generateX25519PrivateKey", argtypes=[])

    def x25519_public_from_private(self, private_key: bytes) -> bytes:
        return self._bridge.call_data(
            "x25519PublicKeyFromPrivateRaw:",
            self._wrap(private_key),
            argtypes=[c_void_p],
        )

    def x25519_shared_secret(self, *, private_key: bytes, peer_public_key: bytes) -> bytes:
        return self._bridge.call_data(
            "x25519SharedSecretPrivateKey:peerPublicKey:",
            self._wrap(private_key),
            self._wrap(peer_public_key),
            argtypes=[c_void_p, c_void_p],
        )


def load_ios_native_crypto_backend() -> Optional[IOSNativeCryptoBackend]:
    global _LAST_LOAD_ERROR
    try:
        return IOSNativeCryptoBackend()
    except Exception as exc:
        if not _LAST_LOAD_ERROR:
            _LAST_LOAD_ERROR = f"backend initialization failed: {type(exc).__name__}: {exc}"
        return None


def ios_native_crypto_load_error() -> str:
    return _LAST_LOAD_ERROR
