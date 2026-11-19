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
    swift_test_support.swift_core_crypto_compile_flags.cache_clear()


def test_linux_core_crypto_flags_include_swiftpm_link_closure(
    monkeypatch, tmp_path: Path
) -> None:
    build = tmp_path / ".build" / "x86_64-unknown-linux-gnu" / "debug"
    modules = build / "Modules"
    modules.mkdir(parents=True)
    expected_objects: list[Path] = []
    for target in ("Crypto", "CryptoBoringWrapper", "SwiftASN1", "CCryptoBoringSSL", "CXKCP", "CXKCPShims"):
        object_path = build / f"{target}.build" / f"{target}.o"
        object_path.parent.mkdir(parents=True)
        object_path.touch()
        expected_objects.append(object_path)
    monkeypatch.setattr(swift_test_support, "ROOT", tmp_path)
    monkeypatch.setattr(swift_test_support.sys, "platform", "linux")
    swift_test_support.swift_core_crypto_compile_flags.cache_clear()

    flags = swift_test_support.swift_core_crypto_compile_flags()

    assert flags[:4] == (
        "-I",
        str(modules),
        "-Xcc",
        f"-fmodule-map-file={tmp_path / 'Sources' / 'CZlib' / 'module.modulemap'}",
    )
    assert all(str(path) in flags for path in expected_objects)
    assert flags[-4:] == ("-Xlinker", "-lz", "-Xlinker", "-lstdc++")
    swift_test_support.swift_core_crypto_compile_flags.cache_clear()
