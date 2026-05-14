"""ObstacleBridge package."""

__all__ = [
    "bridge_main",
    "main",
    "ObstacleBridgeClient",
    "PacketIO",
    "MemoryPacketIO",
    "encode_invite_token",
    "decode_invite_token",
    "preview_import_text",
]


def __getattr__(name: str):
    """Load heavy runtime modules only when callers ask for them.

    The iOS Network Extension imports the package during early provider
    startup. Keeping the package import light avoids loading desktop/CLI
    runtime code before the extension has finished establishing the tunnel.
    """

    if name in {"bridge_main", "main"}:
        from .bridge import main as bridge_main

        return bridge_main
    if name == "ObstacleBridgeClient":
        from .core import ObstacleBridgeClient

        return ObstacleBridgeClient
    if name in {"MemoryPacketIO", "PacketIO"}:
        from .packet_io import MemoryPacketIO, PacketIO

        return {"MemoryPacketIO": MemoryPacketIO, "PacketIO": PacketIO}[name]
    if name in {"decode_invite_token", "encode_invite_token", "preview_import_text"}:
        from .onboarding import decode_invite_token, encode_invite_token, preview_import_text

        return {
            "decode_invite_token": decode_invite_token,
            "encode_invite_token": encode_invite_token,
            "preview_import_text": preview_import_text,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
