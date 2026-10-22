from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from obstacle_bridge.worker_ipc import (
    WORKER_IPC_MAX_FRAME_BYTES,
    WorkerIPCFrameKind,
    decode_control,
    encode_control,
    encode_frame,
    hello,
    negotiated_capabilities,
    try_decode_frame,
)


ROOT = Path(__file__).resolve().parents[2]
SWIFT_SOURCE = ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeWorkerIPC.swift"


def test_common_worker_ipc_rejects_malformed_oversized_and_stale_frames() -> None:
    encoded = encode_control(WorkerIPCFrameKind.REQUEST, 3, {"id": "request-1"})
    frame, remainder = try_decode_frame(encoded)
    assert frame is not None and remainder == b""
    assert frame.generation == 3 and decode_control(frame) == {"id": "request-1"}
    assert try_decode_frame(encoded[:19]) is None
    with pytest.raises(ValueError, match="header"):
        try_decode_frame(b"NOPE" + encoded[4:])
    with pytest.raises(ValueError, match="maximum"):
        encode_frame(WorkerIPCFrameKind.DATA, 1, b"x" * (WORKER_IPC_MAX_FRAME_BYTES + 1))
    with pytest.raises(ValueError, match="generation"):
        encode_control(WorkerIPCFrameKind.REQUEST, 0, {})
    duplicate = encode_frame(WorkerIPCFrameKind.REQUEST, 1, b'{"id":"a","id":"b"}')
    duplicate_frame, _ = try_decode_frame(duplicate)
    assert duplicate_frame is not None
    with pytest.raises(ValueError, match="control"):
        decode_control(duplicate_frame)


def test_common_worker_ipc_negotiates_only_mutual_capabilities() -> None:
    frame, remainder = try_decode_frame(hello(9, "peer", ["binary.data", "events", "events"]))
    assert frame is not None and remainder == b""
    assert negotiated_capabilities(frame, {"binary.data", "requests"}) == ("peer", ("binary.data",))


def test_common_worker_ipc_swift_wire_parity(tmp_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        pytest.skip("swiftc is required for common worker IPC parity")
    probe = tmp_path / "WorkerIPCProbe.swift"
    probe.write_text(
        """
        import Foundation
        @main struct WorkerIPCProbe {
            static func main() throws {
                let encoded = try ObstacleBridgeWorkerIPC.hello(generation: 9, role: "peer", capabilities: ["events", "binary.data", "events"])
                let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(encoded)
                guard let frame, remainder.isEmpty else { throw ObstacleBridgeWorkerIPC.Failure.invalidFrame }
                let negotiated = try ObstacleBridgeWorkerIPC.negotiatedCapabilities(frame, supported: ["binary.data", "requests"])
                let hex = encoded.map { String(format: "%02x", $0) }.joined()
                print("\\(hex)|\\(frame.generation)|\\(negotiated.role)|\\(negotiated.capabilities.joined(separator: ","))")
            }
        }
        """,
        encoding="utf-8",
    )
    binary = tmp_path / "worker-ipc-probe"
    completed = subprocess.run([swiftc, str(SWIFT_SOURCE), str(probe), "-o", str(binary)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    swift_result = subprocess.run([str(binary)], capture_output=True, text=True, check=True).stdout.strip()
    python_wire = hello(9, "peer", ["events", "binary.data", "events"]).hex()
    assert swift_result == f"{python_wire}|9|peer|binary.data"
