"""Bootstrap package that points imports at the src/ layout during in-repo use."""

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "obstacle_bridge"
__path__ = [str(_SRC_PACKAGE)]
from .bridge import main as bridge_main
from .core import ObstacleBridgeClient
from .packet_io import MemoryPacketIO, PacketIO

main = bridge_main

__all__ = ["bridge_main", "main", "ObstacleBridgeClient", "PacketIO", "MemoryPacketIO"]
