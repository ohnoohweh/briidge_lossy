from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_linux_native_peer_worker_uses_readiness_decoder_after_bootstrap() -> None:
    source = (ROOT / "swift/Sources/ObstacleBridgeLinux/ObstacleBridgeLinuxNativePeerWorker.swift").read_text(encoding="utf-8")
    assert "import ObstacleBridgeDesktopShared" in source
    assert "DispatchSource.makeReadSource(fileDescriptor: descriptor" in source
    assert "ObstacleBridgeWorkerIPCStreamDecoder" in source
    assert "decoder.append(Data(bytes.prefix(Int(received))))" in source
    assert "dispatchMain()" in source
    assert "ObstacleBridgeWorkerIPC.headerBytes" in source
    assert "ObstacleBridgeWorkerIPC.frameSize(header)" in source
    assert "ObstacleBridgeWorkerIPC.decodeControl(frame)" in source
    assert "ObstacleBridgeWorkerIPC.encodeControl" in source
    assert '"kind"] as? String == "worker.hello"' in source
    assert '"peer.binary-data", "peer.control"' in source
    assert "frame.kind == .data" in source
    assert "writeData(handle, generation: generation, payload: frame.payload)" in source
    assert "generation == helloGeneration" in source
    assert "poll(&pollDescriptor, 1, 5_000)" in source
    assert "bounded inherited-descriptor bootstrap before readiness ownership" in source
    assert "poll(&pollDescriptor, 1, -1)" not in source
    assert "let h = try exact(handle, 4)" not in source
