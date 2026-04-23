"""Compatibility wrapper for the shared iOS native crypto bridge."""

from __future__ import annotations

from obstacle_bridge.ios_native_crypto import IOSNativeCryptoBackend, load_ios_native_crypto_backend

__all__ = ["IOSNativeCryptoBackend", "load_ios_native_crypto_backend"]
