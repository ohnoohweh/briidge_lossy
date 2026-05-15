"""Bootstrap package that points imports at the src/ layout during in-repo use."""

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "obstacle_bridge"
__path__ = [str(_SRC_PACKAGE)]

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
    """Load runtime modules lazily so the shim mirrors the src package behavior."""

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
