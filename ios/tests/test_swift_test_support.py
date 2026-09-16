from __future__ import annotations

from pathlib import Path

import swift_test_support


def test_core_crypto_flags_reuse_existing_swiftpm_module_build(
    monkeypatch, tmp_path: Path
) -> None:
    modules = tmp_path / ".build" / "arm64-apple-macosx" / "debug" / "Modules"
    modules.mkdir(parents=True)
    monkeypatch.setattr(swift_test_support, "ROOT", tmp_path)
    monkeypatch.setattr(swift_test_support.sys, "platform", "darwin")

    def unexpected_build(*_args, **_kwargs):
        raise AssertionError("an existing SwiftPM module build must be reused")

    monkeypatch.setattr(swift_test_support.subprocess, "run", unexpected_build)
    swift_test_support.swift_core_crypto_compile_flags.cache_clear()

    assert swift_test_support.swift_core_crypto_compile_flags() == (
        "-I",
        str(modules),
    )
