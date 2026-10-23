from __future__ import annotations

import errno
import logging
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from obstacle_bridge.bridge_logging_ipc import NonBlockingUdpLogHandler, UdpLogQueryClient


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "swift/Sources/ObstacleBridgeLogCollector/main.swift"


@pytest.fixture(scope="module")
def native_collector(tmp_path_factory: pytest.TempPathFactory) -> Path:
    swiftc = shutil.which("swiftc")
    if not swiftc or sys.platform not in {"darwin", "linux"}:
        pytest.skip("native collector requires swiftc on macOS or Linux")
    binary = tmp_path_factory.mktemp("native-log-collector") / "collector"
    shared = ROOT / "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeWorkerIPC.swift"
    subprocess.run([swiftc, str(shared), str(SOURCE), "-o", str(binary)], check=True, capture_output=True, text=True)
    return binary


def test_native_collector_accepts_python_records_and_queries(native_collector: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    target = f"127.0.0.1:{port}"
    process = subprocess.Popen(
        [str(native_collector), "--bind", target],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    handler = None
    try:
        query = UdpLogQueryClient(target, timeout_sec=0.05)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not query.fetch(10)["available"]:
            assert process.poll() is None, "collector exited before binding"
            time.sleep(0.01)
        assert query.fetch(10)["available"]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as malformed:
            malformed.sendto(b"not-json", ("127.0.0.1", port))
            try:
                malformed.sendto(b"x" * (60 * 1024 + 1), ("127.0.0.1", port))
            except OSError as exc:
                if exc.errno != errno.EMSGSIZE:
                    raise
        handler = NonBlockingUdpLogHandler(target)
        record = logging.LogRecord("worker.test", logging.WARNING, __file__, 1, "cross-runtime %s", ("record",), None)
        handler.emit(record)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            lines = query.fetch(10)["lines"]
            if any("WARNING worker.test: cross-runtime record" in line for line in lines):
                break
            time.sleep(0.01)
        else:
            pytest.fail("native collector did not return Python log record")
        assert handler.dropped_records == 0
        assert len(query.fetch(1)["lines"]) == 1

        for index in range(15):
            handler.emit(logging.LogRecord("worker.test", logging.INFO, __file__, 1, f"{index}:" + "x" * 1000, (), None))
            time.sleep(0.003)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = query.fetch(100)
            lines = result["lines"]
            if result["available"] and any("worker.test: 14:" in line for line in lines):
                break
            time.sleep(0.01)
        else:
            pytest.fail("native collector did not return a bounded large log query")
        assert 0 < len(lines) < 15
    finally:
        if handler is not None:
            handler.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def test_native_collector_refuses_non_loopback_bind(native_collector: Path) -> None:
    result = subprocess.run(
        [str(native_collector), "--bind", "0.0.0.0:15140"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0
    assert "127.0.0.1:PORT" in result.stderr
