#!/usr/bin/env python3
"""Reject unchecked Sendable additions and require evidence for legacy owners."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWIFT_SOURCE = "swift/Sources/"
UNCHECKED = "@unchecked Sendable"
SYNCHRONOUS_PRIMITIVES = ("NSLock", "DispatchSemaphore", "Mutex")
EVIDENCE = "OBSTACLEBRIDGE-CONCURRENCY:"
EVIDENCE_FORMAT = re.compile(
    r"OBSTACLEBRIDGE-CONCURRENCY:\s*(?:lock|actor|serial)\b.*\btest=\S+"
)
# This expanded rule cannot retroactively require evidence from earlier PR
# work. Every Swift product-source change after this adoption point is gated.
POLICY_BASELINE = "c4e994c4"
AUDITED_SYNCHRONOUS_OWNERS = (
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeTelemetryMTLSUploader.swift",
        "ObstacleBridgeTelemetryLockedUploadState: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: lock; test=test_macos_telemetry_uploader_uses_audited_synchronous_state",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeOverlayConnectionSupport.swift",
        "ObstacleBridgeUDPServerConnectionDriver: @unchecked Sendable",
        "ObstacleBridgeUDPClientConnectionDriver: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_overlay_connection_drivers_keep_callbacks_on_owner_queue",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeNativeProxyConnections.swift",
        "ObstacleBridgeTCPProxyConnection: @unchecked Sendable",
        "ObstacleBridgeUDPProxyConnection: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_native_proxy_connections_keep_callbacks_on_owner_queue",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeWebAdminServer.swift",
        "ObstacleBridgeWebAdminServer: @unchecked Sendable",
        "LiveSession: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_web_admin_server_callbacks_keep_owner_queue",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeTunHelperXPCTransport.swift",
        "ObstacleBridgeTunHelperReachabilityState: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: lock; test=test_tun_helper_xpc_reachability_state_is_synchronous_and_owned",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeTunHelperXPCTransport.swift",
        "ObstacleBridgeTunHelperPingRequestState: @unchecked Sendable",
        "ObstacleBridgeTunHelperCommandRequestState: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: lock; test=test_tun_helper_xpc_request_state_completes_once",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeTcpOverlayTransportOwner.swift",
        "ObstacleBridgeTcpOverlayTransportOwner: @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_tcp_overlay_owner_serializes_public_and_network_callbacks",
    ),
    (
        "swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeWebSocketOverlayTransportOwner.swift",
        "ObstacleBridgeWebSocketOverlayTransportOwner: NSObject, URLSessionWebSocketDelegate, URLSessionTaskDelegate, @unchecked Sendable",
        "OBSTACLEBRIDGE-CONCURRENCY: serial; test=test_websocket_overlay_owner_serializes_public_and_delegate_callbacks",
    ),
)

def is_audited_synchronous_owner(path: str, added: list[str]) -> bool:
    """Allow the one documented synchronous Apple bridge, never a broad exemption."""
    additions = "\n".join(added)
    return any(path == owner[0] and all(marker in additions for marker in owner[1:]) for owner in AUDITED_SYNCHRONOUS_OWNERS)

def effective_base(base_ref: str) -> str:
    if subprocess.run(["git", "merge-base", "--is-ancestor", base_ref, POLICY_BASELINE], cwd=ROOT).returncode == 0:
        return POLICY_BASELINE
    return base_ref

def changed_lines(args: list[str]) -> dict[str, list[str]]:
    proc = subprocess.run(["git", "diff", "--unified=0", *args], cwd=ROOT, check=True, capture_output=True, text=True)
    path = ""; result: dict[str, list[str]] = {}
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif path and line.startswith("+") and not line.startswith("+++"):
            result.setdefault(path, []).append(line[1:])
    return result

def validate(changes: dict[str, list[str]]) -> list[str]:
    errors = []
    for path, added in changes.items():
        if not path.startswith(SWIFT_SOURCE) or not path.endswith(".swift"):
            continue
        audited_synchronous_owner = is_audited_synchronous_owner(path, added)
        if any(UNCHECKED in line for line in added):
            if not audited_synchronous_owner:
                errors.append(
                    f"{path}: new {UNCHECKED} conformances are forbidden; use actor isolation, a serial executor, or a proven Sendable value type."
                )
                continue
        source_path = ROOT / path
        if not source_path.exists() or UNCHECKED not in source_path.read_text(encoding="utf-8"):
            continue
        introduced = [primitive for primitive in SYNCHRONOUS_PRIMITIVES if any(primitive in line for line in added)]
        if introduced and not audited_synchronous_owner:
            errors.append(
                f"{path}: legacy {UNCHECKED} owners may not introduce synchronous coordination "
                f"({', '.join(introduced)}); migrate the owner to actor or serial asynchronous ownership."
            )
            continue
        evidence = "\n".join(added)
        if not EVIDENCE_FORMAT.search(evidence):
            errors.append(
                f"{path}: changes to a source containing an @unchecked Sendable owner require a changed-line "
                f"{EVIDENCE} lock|actor|serial; test=<concurrency test> marker."
            )
    return errors

def main() -> int:
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--base-ref"); scope.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    try:
        errors = validate(changed_lines(["--cached"] if args.staged else [f"{effective_base(args.base_ref)}...HEAD"]))
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.stderr.write(str(exc)); return 2
    if errors:
        sys.stderr.write("\n".join(errors) + "\n"); return 1
    print("Swift concurrency guard passed.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
