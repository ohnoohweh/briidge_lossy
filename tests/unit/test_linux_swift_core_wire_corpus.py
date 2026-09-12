"""Python acceptance check for the shared Linux Swift Core wire corpus."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from obstacle_bridge.bridge import ChannelMux


CORPUS = Path(__file__).resolve().parents[2] / "swift/Tests/ObstacleBridgeCoreTests/Fixtures/python_wire_codec_corpus.json"


def test_core_wire_corpus_matches_python_protocol_layouts() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    tcp = corpus["tcp_application"]
    payload = bytes.fromhex(tcp["payload_hex"])
    assert struct.pack(">I", len(payload) + 1) + b"\x00" + payload == bytes.fromhex(tcp["wire_hex"])

    chunk = corpus["control_chunk"]
    payload = bytes.fromhex(chunk["payload_hex"])
    maximum = int(chunk["maximum_application_payload"])
    capacity = maximum - 8 - ChannelMux.CTRL_CHUNK_HDR.size
    expected = []
    for index in range((len(payload) + capacity - 1) // capacity):
        expected.append(ChannelMux.CTRL_CHUNK_HDR.pack(ChannelMux.CTRL_CHUNK_MAGIC, int(chunk["transaction_id"]), index, 3) + payload[index * capacity:(index + 1) * capacity])
    assert [item.hex() for item in expected] == chunk["chunks_hex"]
