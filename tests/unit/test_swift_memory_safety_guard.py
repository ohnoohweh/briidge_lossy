"""Regression coverage for the conservative Swift memory-safety diff gate."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("check_swift_memory_safety_guard", ROOT / "scripts" / "check_swift_memory_safety_guard.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rejects_new_unbounded_persistent_data_queue() -> None:
    guard = _load()
    errors, warnings = guard.validate([("swift/Sources/ObstacleBridgeiOS/Owner.swift", 12, "private var packets: [Data] = []")])
    assert len(errors) == 1 and "MEM009" in errors[0]
    assert warnings == []


def test_accepts_documented_bounded_data_queue() -> None:
    guard = _load()
    errors, _ = guard.validate([
        ("swift/Sources/ObstacleBridgeiOS/Owner.swift", 11, "// OBSTACLEBRIDGE-MEMORY-BOUNDS: items=64; bytes=524288; overflow=drop_newest; test=OwnerTests"),
        ("swift/Sources/ObstacleBridgeiOS/Owner.swift", 12, "private var packets: [Data] = []"),
    ])
    assert errors == []


def test_rejects_changed_stored_closure_that_strongly_captures_self(monkeypatch, tmp_path) -> None:
    guard = _load(); relative = "swift/Sources/ObstacleBridgeiOS/Owner.swift"
    source = tmp_path / relative; source.parent.mkdir(parents=True)
    source.write_text("final class Owner {\n  var callback: (() -> Void)?\n  func start() {\n    self.callback = {\n      self.run()\n    }\n  }\n  func run() {}\n}\n", encoding="utf-8")
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    errors, _ = guard.validate([(relative, 4, "    self.callback = {"), (relative, 5, "      self.run()")])
    assert len(errors) == 1 and "MEM002" in errors[0]


def test_reports_unowned_self_as_review_warning() -> None:
    guard = _load()
    errors, warnings = guard.validate([("swift/Sources/ObstacleBridgeiOS/Owner.swift", 12, "callback = { [unowned self] in self.run() }")])
    assert errors == []
    assert len(warnings) == 1 and "MEM008" in warnings[0]
