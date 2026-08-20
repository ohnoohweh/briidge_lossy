from __future__ import annotations

from scripts.check_swift_shared_parity_guard import (
    PARITY_TEST_FILES,
    classify_swift_shared_parity,
    validate_swift_shared_parity,
)


def test_classify_swift_shared_parity_buckets_changed_files() -> None:
    classified = classify_swift_shared_parity([
        "ios/native/ObstacleBridgeShared/SharedThing.swift",
        "ios/native/IPServer/PacketTunnelProvider.swift",
        "ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift",
        "ios/tests/test_m3_native_sources.py",
        "README.md",
    ])

    assert classified["shared_swift"] == ["ios/native/ObstacleBridgeShared/SharedThing.swift"]
    assert classified["ios_swift"] == ["ios/native/IPServer/PacketTunnelProvider.swift"]
    assert classified["macos_swift"] == ["ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift"]
    assert classified["parity_tests"] == ["ios/tests/test_m3_native_sources.py"]


def test_ios_only_swift_change_requires_shared_or_macos_peer_update() -> None:
    errors = validate_swift_shared_parity([
        "ios/native/IPServer/PacketTunnelProvider.swift",
        "ios/tests/test_m3_native_sources.py",
    ])

    assert len(errors) == 1
    assert "iOS-specific Swift runtime files changed" in errors[0]


def test_macos_only_swift_change_requires_shared_or_ios_peer_update() -> None:
    errors = validate_swift_shared_parity([
        "ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift",
        "ios/tests/test_macos_swift_host_runner.py",
    ])

    assert len(errors) == 1
    assert "macOS-specific Swift runtime files changed" in errors[0]


def test_shared_swift_change_requires_parity_source_tests() -> None:
    errors = validate_swift_shared_parity([
        "ios/native/ObstacleBridgeShared/ObstacleBridgeTunProbeDiagnosticsSupport.swift",
    ])

    assert len(errors) == 1
    assert "Swift shared/runtime edits must update the Swift parity source-guard tests." in errors[0]
    for path in sorted(PARITY_TEST_FILES):
        assert path in errors[0]


def test_shared_plus_ios_change_with_parity_tests_passes() -> None:
    errors = validate_swift_shared_parity([
        "ios/native/ObstacleBridgeShared/ObstacleBridgeTunProbeDiagnosticsSupport.swift",
        "ios/native/IPServer/PacketTunnelProvider.swift",
        "ios/tests/test_m3_native_sources.py",
    ])

    assert errors == []


def test_both_platform_specific_swift_changes_with_one_parity_test_pass() -> None:
    errors = validate_swift_shared_parity([
        "ios/native/IPServer/PacketTunnelProvider.swift",
        "ios/native/ObstacleBridgeApp/ObstacleBridgeHostRunner.swift",
        "ios/tests/test_macos_swift_host_runner.py",
    ])

    assert errors == []


def test_non_swift_changes_do_not_trigger_guard() -> None:
    errors = validate_swift_shared_parity([
        "README.md",
        "docs/README_TESTING.md",
        "scripts/check_requirements_guard.py",
    ])

    assert errors == []
