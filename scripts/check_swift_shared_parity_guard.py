#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHARED_SWIFT_PREFIX = "swift/Sources/ObstacleBridgeAppleShared/"
IOS_SWIFT_PREFIX = "swift/Sources/ObstacleBridgeiOS/"
MACOS_SWIFT_PREFIX = "swift/Sources/ObstacleBridgeMacOS/"
DESKTOP_PROXY_SUPERVISOR = "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeProxyWorkerSupervisor.swift"
DESKTOP_LOG_SUPERVISOR = "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeLogWorkerSupervisor.swift"
DESKTOP_WORKER_IPC = "swift/Sources/ObstacleBridgeDesktopShared/ObstacleBridgeWorkerIPC.swift"
LINUX_DESKTOP_HOST = "swift/Sources/ObstacleBridgeLinux/Adapters/ObstacleBridgeLinuxLiveRuntime.swift"
LINUX_LOG_ADAPTER = "swift/Sources/ObstacleBridgeLinux/Adapters/ObstacleBridgeLinuxObservability.swift"
MACOS_DESKTOP_HOST = "swift/Sources/ObstacleBridgeMacOS/ObstacleBridgeHostRunner.swift"
MACOS_NATIVE_PEER = "swift/Sources/ObstacleBridgeMacOS/ObstacleBridgeNativePeerWorker.swift"
LINUX_NATIVE_PEER = "swift/Sources/ObstacleBridgeLinux/ObstacleBridgeLinuxNativePeerWorker.swift"
SWIFT_SUFFIX = ".swift"
PARITY_TEST_FILES = {
    "ios/tests/test_m3_native_sources.py",
    "ios/tests/test_macos_swift_host_runner.py",
}


def _git_changed_files(*diff_args: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", *diff_args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _normalize(files: list[str]) -> list[str]:
    return sorted(set(f.replace("\\", "/") for f in files))


def _is_swift_under(path: str, prefix: str) -> bool:
    return path.startswith(prefix) and path.endswith(SWIFT_SUFFIX)


def classify_swift_shared_parity(changed: list[str]) -> dict[str, list[str]]:
    normalized = _normalize(changed)
    return {
        "shared_swift": [path for path in normalized if _is_swift_under(path, SHARED_SWIFT_PREFIX) or path == DESKTOP_WORKER_IPC],
        "ios_swift": [path for path in normalized if _is_swift_under(path, IOS_SWIFT_PREFIX)],
        "macos_swift": [path for path in normalized if _is_swift_under(path, MACOS_SWIFT_PREFIX)],
        "parity_tests": [path for path in normalized if path in PARITY_TEST_FILES],
    }


def validate_swift_shared_parity(changed: list[str]) -> list[str]:
    classified = classify_swift_shared_parity(changed)
    shared_swift = classified["shared_swift"]
    ios_swift = classified["ios_swift"]
    macos_swift = classified["macos_swift"]
    parity_tests = classified["parity_tests"]
    # Process spawning is a desktop-only boundary: iOS extensions cannot
    # inherit these workers. Admit this specific macOS host integration only
    # when the corresponding Linux host and their shared owner also change.
    desktop_pair = (
        set(macos_swift) == {MACOS_DESKTOP_HOST}
        and ((DESKTOP_PROXY_SUPERVISOR in _normalize(changed) and LINUX_DESKTOP_HOST in _normalize(changed))
             or (DESKTOP_LOG_SUPERVISOR in _normalize(changed) and LINUX_LOG_ADAPTER in _normalize(changed)))
    )
    native_peer_pair = (
        set(macos_swift) == {MACOS_NATIVE_PEER}
        and LINUX_NATIVE_PEER in _normalize(changed)
    )
    errors: list[str] = []

    if ios_swift and not (shared_swift or macos_swift):
        errors.append(
            "iOS-specific Swift runtime files changed without a shared Swift update or a mirrored macOS Swift update.\n"
            f"Changed iOS files: {', '.join(ios_swift)}\n"
            f"Expected one of: files under {SHARED_SWIFT_PREFIX} or files under {MACOS_SWIFT_PREFIX}"
        )

    if macos_swift and not (shared_swift or ios_swift or desktop_pair or native_peer_pair):
        errors.append(
            "macOS-specific Swift runtime files changed without a shared Swift update or a mirrored iOS Swift update.\n"
            f"Changed macOS files: {', '.join(macos_swift)}\n"
            f"Expected one of: files under {SHARED_SWIFT_PREFIX} or files under {IOS_SWIFT_PREFIX}"
        )

    if (shared_swift or ios_swift or macos_swift) and not parity_tests:
        errors.append(
            "Swift shared/runtime edits must update the Swift parity source-guard tests.\n"
            f"Changed shared files: {', '.join(shared_swift) if shared_swift else '(none)'}\n"
            f"Changed iOS files: {', '.join(ios_swift) if ios_swift else '(none)'}\n"
            f"Changed macOS files: {', '.join(macos_swift) if macos_swift else '(none)'}\n"
            f"Expected updated file(s): {', '.join(sorted(PARITY_TEST_FILES))}"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when Swift iOS/macOS runtime changes drift away from the shared Swift layer "
            "or skip the paired Swift parity source guards."
        )
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--base-ref",
        help="Compare changes against this git ref, for example origin/main or a commit SHA.",
    )
    scope.add_argument(
        "--staged",
        action="store_true",
        help="Check staged changes in the index.",
    )
    args = parser.parse_args()

    try:
        if args.staged:
            changed = _git_changed_files("--cached")
        else:
            changed = _git_changed_files(f"{args.base_ref}...HEAD")
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or str(exc))
        return 2

    errors = validate_swift_shared_parity(changed)
    if errors:
        sys.stderr.write("\n\n".join(errors) + "\n")
        return 1

    print("Swift shared parity guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
