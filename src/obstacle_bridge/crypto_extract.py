"""Minimal crypto surface used by ObstacleBridge.

Desktop and server environments use ``cryptography`` directly. When that
package is unavailable, this module can fall back to an iOS-native backend that
exposes only the primitives ObstacleBridge needs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any, Optional


CRYPTO_EXTRACT_APIS = {
    "config_secrets": (
        "hashes.SHA256",
        "HKDF",
        "ChaCha20Poly1305",
    ),
    "admin_secret_reveal": (
        "hashes.SHA256",
        "PBKDF2HMAC",
        "AESGCM",
    ),
    "secure_link_cert": (
        "hashes.SHA256",
        "HKDF",
        "serialization.load_der_public_key",
        "serialization.load_pem_public_key",
        "serialization.load_pem_private_key",
        "serialization.Encoding.DER",
        "serialization.PublicFormat.SubjectPublicKeyInfo",
        "serialization.Encoding.Raw",
        "serialization.PublicFormat.Raw",
        "ed25519.Ed25519PublicKey",
        "ed25519.Ed25519PrivateKey",
        "x25519.X25519PrivateKey",
        "x25519.X25519PublicKey",
    ),
}


try:
    from cryptography.hazmat.primitives import hashes as hashes
    from cryptography.hazmat.primitives import serialization as serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2HMAC

    _BACKEND_NAME = "cryptography"
    _IOS_NATIVE_BACKEND = None
except Exception:
    @dataclass(frozen=True)
    class _SHA256:
        name: str = "sha256"
        digest_size: int = hashlib.sha256().digest_size
        block_size: int = hashlib.sha256().block_size

    class _HashesModule:
        @staticmethod
        def SHA256() -> _SHA256:
            return _SHA256()

    hashes = _HashesModule()

    def _load_ios_native_backend():
        try:
            from .ios_native_crypto import load_ios_native_crypto_backend
        except Exception:
            return None
        try:
            return load_ios_native_crypto_backend()
        except Exception:
            return None

    _IOS_NATIVE_BACKEND = _load_ios_native_backend()
    _BACKEND_NAME = "ios-native" if _IOS_NATIVE_BACKEND is not None else "unavailable"

    class HKDF:
        def __init__(self, *, algorithm: Any, length: int, salt: Optional[bytes], info: Optional[bytes]) -> None:
            self._algorithm = algorithm
            self._length = int(length)
            self._salt = bytes(salt or b"")
            self._info = bytes(info or b"")

        def derive(self, key_material: bytes) -> bytes:
            digest_name = getattr(self._algorithm, "name", "sha256")
            if digest_name != "sha256":
                raise ValueError(f"unsupported HKDF digest: {digest_name}")
            if _IOS_NATIVE_BACKEND is None:
                digest_size = hashlib.new(digest_name).digest_size
                salt = self._salt if self._salt else (b"\x00" * digest_size)
                prk = hmac.new(salt, bytes(key_material or b""), digest_name).digest()
                okm = b""
                previous = b""
                counter = 1
                while len(okm) < self._length:
                    previous = hmac.new(
                        prk,
                        previous + self._info + bytes([counter]),
                        digest_name,
                    ).digest()
                    okm += previous
                    counter += 1
                return okm[: self._length]
            return _IOS_NATIVE_BACKEND.hkdf_sha256(
                salt=self._salt,
                info=self._info,
                key_material=bytes(key_material or b""),
                length=self._length,
            )

    class PBKDF2HMAC:
        def __init__(self, *, algorithm: Any, length: int, salt: bytes, iterations: int) -> None:
            self._algorithm = algorithm
            self._length = int(length)
            self._salt = bytes(salt or b"")
            self._iterations = int(iterations)

        def derive(self, key_material: bytes) -> bytes:
            digest_name = getattr(self._algorithm, "name", "sha256")
            if digest_name != "sha256":
                raise ValueError(f"unsupported PBKDF2 digest: {digest_name}")
            if _IOS_NATIVE_BACKEND is None:
                return hashlib.pbkdf2_hmac(
                    digest_name,
                    bytes(key_material or b""),
                    self._salt,
                    self._iterations,
                    self._length,
                )
            return _IOS_NATIVE_BACKEND.pbkdf2_sha256(
                password=bytes(key_material or b""),
                salt=self._salt,
                iterations=self._iterations,
                length=self._length,
            )

    class AESGCM:
        def __init__(self, key: bytes) -> None:
            self._key = bytes(key or b"")

        def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("AESGCM requires cryptography or the iOS native crypto backend")
            return _IOS_NATIVE_BACKEND.aesgcm_encrypt(
                key=self._key,
                nonce=bytes(nonce or b""),
                plaintext=bytes(data or b""),
                aad=bytes(associated_data or b""),
            )

        def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("AESGCM requires cryptography or the iOS native crypto backend")
            return _IOS_NATIVE_BACKEND.aesgcm_decrypt(
                key=self._key,
                nonce=bytes(nonce or b""),
                ciphertext=bytes(data or b""),
                aad=bytes(associated_data or b""),
            )

        @staticmethod
        def generate_key(bit_length: int) -> bytes:
            bits = int(bit_length)
            if bits not in {128, 192, 256}:
                raise ValueError("bit_length must be 128, 192, or 256")
            return os.urandom(bits // 8)

    class ChaCha20Poly1305:
        def __init__(self, key: bytes) -> None:
            self._key = bytes(key or b"")

        def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("ChaCha20Poly1305 requires cryptography or the iOS native crypto backend")
            return _IOS_NATIVE_BACKEND.chacha20poly1305_encrypt(
                key=self._key,
                nonce=bytes(nonce or b""),
                plaintext=bytes(data or b""),
                aad=bytes(associated_data or b""),
            )

        def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("ChaCha20Poly1305 requires cryptography or the iOS native crypto backend")
            return _IOS_NATIVE_BACKEND.chacha20poly1305_decrypt(
                key=self._key,
                nonce=bytes(nonce or b""),
                ciphertext=bytes(data or b""),
                aad=bytes(associated_data or b""),
            )

        @staticmethod
        def generate_key() -> bytes:
            return os.urandom(32)

    _ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
    _X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")
    _ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
    _X25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
    _PEM_PUBLIC_BEGIN = b"-----BEGIN PUBLIC KEY-----"
    _PEM_PUBLIC_END = b"-----END PUBLIC KEY-----"
    _PEM_PRIVATE_BEGIN = b"-----BEGIN PRIVATE KEY-----"
    _PEM_PRIVATE_END = b"-----END PRIVATE KEY-----"

    def _der_to_pem(label: str, der: bytes) -> bytes:
        body = base64.encodebytes(bytes(der or b"")).replace(b"\n", b"")
        lines = [body[idx:idx + 64] for idx in range(0, len(body), 64)]
        return (
            f"-----BEGIN {label}-----\n".encode("ascii")
            + b"\n".join(lines)
            + f"\n-----END {label}-----\n".encode("ascii")
        )

    def _pem_to_der(data: bytes, begin: bytes, end: bytes) -> bytes:
        text = bytes(data or b"").strip()
        if not text.startswith(begin) or not text.endswith(end):
            raise ValueError("unsupported PEM payload")
        middle = text[len(begin): -len(end)]
        middle = b"".join(line.strip() for line in middle.splitlines() if line.strip())
        return base64.b64decode(middle)

    def _decode_public_der(data: bytes) -> tuple[str, bytes]:
        raw = bytes(data or b"")
        if raw.startswith(_ED25519_SPKI_PREFIX) and len(raw) == len(_ED25519_SPKI_PREFIX) + 32:
            return ("ed25519", raw[len(_ED25519_SPKI_PREFIX):])
        if raw.startswith(_X25519_SPKI_PREFIX) and len(raw) == len(_X25519_SPKI_PREFIX) + 32:
            return ("x25519", raw[len(_X25519_SPKI_PREFIX):])
        raise ValueError("unsupported DER public key payload")

    def _decode_private_der(data: bytes) -> tuple[str, bytes]:
        raw = bytes(data or b"")
        if raw.startswith(_ED25519_PKCS8_PREFIX) and len(raw) == len(_ED25519_PKCS8_PREFIX) + 32:
            return ("ed25519", raw[len(_ED25519_PKCS8_PREFIX):])
        if raw.startswith(_X25519_PKCS8_PREFIX) and len(raw) == len(_X25519_PKCS8_PREFIX) + 32:
            return ("x25519", raw[len(_X25519_PKCS8_PREFIX):])
        raise ValueError("unsupported DER private key payload")

    def _ed25519_public_der_from_raw(raw: bytes) -> bytes:
        return _ED25519_SPKI_PREFIX + bytes(raw or b"")

    def _x25519_public_der_from_raw(raw: bytes) -> bytes:
        return _X25519_SPKI_PREFIX + bytes(raw or b"")

    def _ed25519_private_der_from_raw(raw: bytes) -> bytes:
        return _ED25519_PKCS8_PREFIX + bytes(raw or b"")

    def _x25519_private_der_from_raw(raw: bytes) -> bytes:
        return _X25519_PKCS8_PREFIX + bytes(raw or b"")

    class _Encoding:
        DER = "DER"
        PEM = "PEM"
        Raw = "Raw"

    class _PublicFormat:
        SubjectPublicKeyInfo = "SubjectPublicKeyInfo"
        Raw = "Raw"

    class _PrivateFormat:
        PKCS8 = "PKCS8"

    class _NoEncryption:
        pass

    class _Ed25519PublicKey:
        def __init__(self, raw_public_key: bytes) -> None:
            self._raw = bytes(raw_public_key or b"")
            if len(self._raw) != 32:
                raise ValueError("Ed25519 public key must be 32 bytes")

        def verify(self, signature: bytes, data: bytes) -> None:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("Ed25519 verify requires the iOS native crypto backend")
            ok = _IOS_NATIVE_BACKEND.ed25519_verify(
                public_key=self._raw,
                signature=bytes(signature or b""),
                message=bytes(data or b""),
            )
            if not ok:
                raise ValueError("Ed25519 signature verification failed")

        def public_bytes(self, encoding: str, format: str) -> bytes:
            if encoding == _Encoding.Raw and format == _PublicFormat.Raw:
                return bytes(self._raw)
            if encoding == _Encoding.DER and format == _PublicFormat.SubjectPublicKeyInfo:
                return _ed25519_public_der_from_raw(self._raw)
            if encoding == _Encoding.PEM and format == _PublicFormat.SubjectPublicKeyInfo:
                return _der_to_pem("PUBLIC KEY", _ed25519_public_der_from_raw(self._raw))
            raise ValueError("unsupported Ed25519 public_bytes encoding/format")

    class _Ed25519PrivateKey:
        def __init__(self, raw_private_key: bytes) -> None:
            self._raw = bytes(raw_private_key or b"")
            if len(self._raw) != 32:
                raise ValueError("Ed25519 private key must be 32 bytes")

        @classmethod
        def generate(cls):
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("Ed25519 generate requires the iOS native crypto backend")
            return cls(_IOS_NATIVE_BACKEND.generate_ed25519_private_key())

        def sign(self, data: bytes) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("Ed25519 sign requires the iOS native crypto backend")
            return _IOS_NATIVE_BACKEND.ed25519_sign(
                private_key=self._raw,
                message=bytes(data or b""),
            )

        def public_key(self):
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("Ed25519 public key derivation requires the iOS native crypto backend")
            return _Ed25519PublicKey(_IOS_NATIVE_BACKEND.ed25519_public_from_private(self._raw))

        def private_bytes(self, encoding: str, format: str, encryption_algorithm: Any) -> bytes:
            if format != _PrivateFormat.PKCS8:
                raise ValueError("unsupported Ed25519 private_bytes format")
            der = _ed25519_private_der_from_raw(self._raw)
            if encoding == _Encoding.DER:
                return der
            if encoding == _Encoding.PEM:
                return _der_to_pem("PRIVATE KEY", der)
            raise ValueError("unsupported Ed25519 private_bytes encoding")

    class _X25519PublicKey:
        def __init__(self, raw_public_key: bytes) -> None:
            self._raw = bytes(raw_public_key or b"")
            if len(self._raw) != 32:
                raise ValueError("X25519 public key must be 32 bytes")

        @classmethod
        def from_public_bytes(cls, data: bytes):
            return cls(bytes(data or b""))

        def public_bytes(self, encoding: str, format: str) -> bytes:
            if encoding == _Encoding.Raw and format == _PublicFormat.Raw:
                return bytes(self._raw)
            if encoding == _Encoding.DER and format == _PublicFormat.SubjectPublicKeyInfo:
                return _x25519_public_der_from_raw(self._raw)
            if encoding == _Encoding.PEM and format == _PublicFormat.SubjectPublicKeyInfo:
                return _der_to_pem("PUBLIC KEY", _x25519_public_der_from_raw(self._raw))
            raise ValueError("unsupported X25519 public_bytes encoding/format")

    class _X25519PrivateKey:
        def __init__(self, raw_private_key: bytes) -> None:
            self._raw = bytes(raw_private_key or b"")
            if len(self._raw) != 32:
                raise ValueError("X25519 private key must be 32 bytes")

        @classmethod
        def generate(cls):
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("X25519 generate requires the iOS native crypto backend")
            return cls(_IOS_NATIVE_BACKEND.generate_x25519_private_key())

        def public_key(self):
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("X25519 public key derivation requires the iOS native crypto backend")
            return _X25519PublicKey(_IOS_NATIVE_BACKEND.x25519_public_from_private(self._raw))

        def exchange(self, peer_public_key: Any) -> bytes:
            if _IOS_NATIVE_BACKEND is None:
                raise RuntimeError("X25519 exchange requires the iOS native crypto backend")
            if not isinstance(peer_public_key, _X25519PublicKey):
                raise TypeError("peer_public_key must be X25519PublicKey")
            return _IOS_NATIVE_BACKEND.x25519_shared_secret(
                private_key=self._raw,
                peer_public_key=peer_public_key._raw,
            )

        def private_bytes(self, encoding: str, format: str, encryption_algorithm: Any) -> bytes:
            if format != _PrivateFormat.PKCS8:
                raise ValueError("unsupported X25519 private_bytes format")
            der = _x25519_private_der_from_raw(self._raw)
            if encoding == _Encoding.DER:
                return der
            if encoding == _Encoding.PEM:
                return _der_to_pem("PRIVATE KEY", der)
            raise ValueError("unsupported X25519 private_bytes encoding")

    class _SerializationModule:
        Encoding = _Encoding
        PublicFormat = _PublicFormat
        PrivateFormat = _PrivateFormat
        NoEncryption = _NoEncryption

        @staticmethod
        def load_der_public_key(data: bytes) -> Any:
            kind, raw = _decode_public_der(data)
            if kind == "ed25519":
                return _Ed25519PublicKey(raw)
            if kind == "x25519":
                return _X25519PublicKey(raw)
            raise ValueError("unsupported DER public key payload")

        @staticmethod
        def load_pem_public_key(data: bytes) -> Any:
            return _SerializationModule.load_der_public_key(_pem_to_der(data, _PEM_PUBLIC_BEGIN, _PEM_PUBLIC_END))

        @staticmethod
        def load_pem_private_key(data: bytes, password: Optional[bytes] = None) -> Any:
            if password is not None:
                raise ValueError("encrypted private keys are not supported")
            kind, raw = _decode_private_der(_pem_to_der(data, _PEM_PRIVATE_BEGIN, _PEM_PRIVATE_END))
            if kind == "ed25519":
                return _Ed25519PrivateKey(raw)
            if kind == "x25519":
                return _X25519PrivateKey(raw)
            raise ValueError("unsupported PEM private key payload")

    class _Ed25519Module:
        Ed25519PrivateKey = _Ed25519PrivateKey
        Ed25519PublicKey = _Ed25519PublicKey

    class _X25519Module:
        X25519PrivateKey = _X25519PrivateKey
        X25519PublicKey = _X25519PublicKey

    if _IOS_NATIVE_BACKEND is None:
        AESGCM = None
        ChaCha20Poly1305 = None
        serialization = None
        ed25519 = None
        x25519 = None
    else:
        serialization = _SerializationModule()
        ed25519 = _Ed25519Module()
        x25519 = _X25519Module()


def available_crypto_extract() -> dict[str, Any]:
    native_features = {}
    if _IOS_NATIVE_BACKEND is not None:
        try:
            native_features = dict(_IOS_NATIVE_BACKEND.available_features() or {})
        except Exception:
            native_features = {}
    return {
        "backend": _BACKEND_NAME,
        "hashes": hashes is not None,
        "hkdf": HKDF is not None,
        "pbkdf2": PBKDF2HMAC is not None,
        "aesgcm": AESGCM is not None,
        "chacha20poly1305": ChaCha20Poly1305 is not None,
        "serialization": serialization is not None,
        "ed25519": ed25519 is not None,
        "x25519": x25519 is not None,
        "ios_native_features": native_features,
        "api_groups": dict(CRYPTO_EXTRACT_APIS),
    }
