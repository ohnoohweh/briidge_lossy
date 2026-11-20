"""Regression coverage for the Swift unchecked-sendable concurrency guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_swift_concurrency_guard",
        ROOT / "scripts" / "check_swift_concurrency_guard.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rejects_new_unchecked_sendable_conformance(monkeypatch) -> None:
    guard = _load()
    monkeypatch.setattr(
        guard,
        "changed_lines",
        lambda _args: {"swift/Sources/ObstacleBridgeLinux/Adapters/ObstacleBridgeLinuxTunHelperServer.swift": ["final class Owner: @unchecked Sendable {}"]},
    )
    errors = guard.validate(guard.changed_lines(["--staged"]))
    assert len(errors) == 1
    assert "forbidden" in errors[0]


def test_accepts_audited_serial_network_sender_sendable_conformances(monkeypatch) -> None:
    guard = _load()
    path = "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeNativeProxyConnections.swift"
    monkeypatch.setattr(
        guard,
        "changed_lines",
        lambda _args: {
            path: [
                "// OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_native_proxy_connections_keep_callbacks_on_owner_queue",
                "final class ObstacleBridgeBoundedConnectionDataSender: @unchecked Sendable {",
                "private struct PendingWrite: @unchecked Sendable {",
            ]
        },
    )
    assert guard.validate(guard.changed_lines(["--staged"])) == []


def test_accepts_lock_marker_with_named_test(monkeypatch) -> None:
    guard = _load()
    monkeypatch.setattr(
        guard,
        "changed_lines",
        lambda _args: {"swift/Sources/ObstacleBridgeLinux/Adapters/ObstacleBridgeLinuxTunHelperServer.swift": ["// OBSTACLEBRIDGE-CONCURRENCY: lock; test=ObstacleBridgeLinuxTunHelperAdapterTests", "private var clients: [Int32: Int] = [:]"]},
    )
    assert guard.validate(guard.changed_lines(["--staged"])) == []


def test_zero_before_sha_uses_the_branch_merge_base(monkeypatch) -> None:
    guard = _load()

    class Result:
        returncode = 0
        stdout = "merge-base-sha\n"

    monkeypatch.setattr(guard.subprocess, "run", lambda *_args, **_kwargs: Result())
    assert guard.effective_base(guard.NULL_GIT_SHA) == "merge-base-sha"


def test_rejects_new_synchronous_primitive_in_legacy_owner(monkeypatch) -> None:
    guard = _load()
    monkeypatch.setattr(
        guard,
        "changed_lines",
        lambda _args: {"swift/Sources/ObstacleBridgeLinux/Adapters/ObstacleBridgeLinuxTunHelperServer.swift": ["private let replacementLock = NSLock()"]},
    )
    errors = guard.validate(guard.changed_lines(["--staged"]))
    assert len(errors) == 1
    assert "synchronous coordination" in errors[0]
