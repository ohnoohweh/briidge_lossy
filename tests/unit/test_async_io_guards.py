"""Regression coverage for repository-wide async-I/O diff guards."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_swift_guard_rejects_waits_in_every_product_source(monkeypatch) -> None:
    guard = _load("check_swift_async_io_guard")
    monkeypatch.setattr(guard, "changed_lines", lambda _args: [
        ("swift/Sources/ObstacleBridgeiOS/PacketTunnelProvider.swift", 10, "future.wait()"),
        ("swift/Sources/ObstacleBridgeMacOS/Host.swift", 11, "condition.wait()"),
        ("swift/Sources/ObstacleBridgeLinux/Adapter.swift", 12, "poll(&fd, 1, 1000)"),
    ])
    errors = guard.validate(["--staged"])
    assert len(errors) == 3
    assert all("synchronous wait" in error for error in errors)


def test_swift_guard_admits_readiness_and_explicit_bounded_exception(monkeypatch) -> None:
    guard = _load("check_swift_async_io_guard")
    monkeypatch.setattr(guard, "changed_lines", lambda _args: [
        ("swift/Sources/ObstacleBridgeiOS/PacketTunnelProvider.swift", 10, "recv(fd, &buffer, count, MSG_DONTWAIT)"),
        ("swift/Sources/ObstacleBridgeMacOS/Host.swift", 11, "poll(&fd, 1, 10) // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: bounded inherited bootstrap"),
    ])
    assert guard.validate(["--staged"]) == []


def test_python_guard_rejects_new_wait_without_exception(monkeypatch) -> None:
    guard = _load("check_python_async_io_guard")
    monkeypatch.setattr(guard, "changed_lines", lambda _args: [
        ("src/obstacle_bridge/bridge.py", 10, "ready.wait()"),
    ])
    assert len(guard.validate(["--staged"])) == 1
