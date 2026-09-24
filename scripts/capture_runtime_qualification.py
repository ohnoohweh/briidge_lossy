#!/usr/bin/env python3
"""Capture a redacted, reproducible R007 runtime-qualification evidence bundle.

The collector deliberately generates no traffic and never reads application
logs, credentials, or packet contents.  It records only the existing Admin
JSON projections needed to qualify bounded packet admission on a physical
owner.  The traffic generator and platform termination report remain explicit
operator inputs, which keeps their provenance outside the tunnel protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen


SnapshotFetcher = Callable[[str, Mapping[str, str]], dict[str, Any]]
ENDPOINTS = ("/api/status", "/api/peers", "/api/tun-routing/status")


def fetch_json(url: str, headers: Mapping[str, str]) -> dict[str, Any]:
    request = Request(url, headers=dict(headers))
    with urlopen(request, timeout=10) as response:  # noqa: S310 -- explicit operator endpoint
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError(f"{url} returned {type(payload).__name__}, not a JSON object")
    return payload


def packet_counters(status: Mapping[str, Any]) -> dict[str, int] | None:
    """Return the owner packet-direction counters exposed by Admin status."""
    candidates = [
        status.get("swift_udp_bridge_state"),
        status.get("packetflow_bridge"),
        (status.get("tun_helper") or {}).get("runtime") if isinstance(status.get("tun_helper"), Mapping) else None,
    ]
    field_pairs = (
        ("packets_from_system", "packets_to_system"),
        ("packets_from_runtime", "packets_to_runtime"),
    )
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        for incoming, outgoing in field_pairs:
            left, right = candidate.get(incoming), candidate.get(outgoing)
            if isinstance(left, int) and isinstance(right, int):
                return {"from_owner": left, "to_owner": right}
    return None


def secure_link_authenticated(status: Mapping[str, Any]) -> bool:
    bridge = status.get("swift_udp_bridge_state")
    runtime = bridge.get("myudp_runtime") if isinstance(bridge, Mapping) else None
    layers = runtime.get("connection_layers") if isinstance(runtime, Mapping) else status.get("connection_layers")
    if not isinstance(layers, list):
        return False
    for entry in layers:
        nested = entry.get("layers") if isinstance(entry, Mapping) else None
        for layer in nested if isinstance(nested, list) else [entry]:
            if isinstance(layer, Mapping) and layer.get("layer") == "secure_link":
                return layer.get("state") == "authenticated" and layer.get("app_ready") is True
    return False


def preflight(status: Mapping[str, Any], *, require_authenticated: bool) -> dict[str, int]:
    health_count = status.get("runtime_health_record_count")
    if not isinstance(health_count, int) or health_count <= 0:
        raise ValueError("Admin status has no retained runtime-health evidence")
    counters = packet_counters(status)
    if counters is None:
        raise ValueError("Admin status has no owner packet-direction counters")
    if require_authenticated and not secure_link_authenticated(status):
        raise ValueError("Admin status does not report an authenticated, ready SecureLink")
    return counters


def current_revision() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def capture(
    *,
    base_url: str,
    output_dir: Path,
    build_identifier: str,
    traffic_source: str,
    termination_report_location: str,
    samples: int,
    interval_seconds: float,
    headers: Mapping[str, str],
    require_authenticated: bool,
    fetcher: SnapshotFetcher = fetch_json,
) -> dict[str, Any]:
    if samples < 2:
        raise ValueError("samples must be at least two")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    if not build_identifier.strip():
        raise ValueError("build_identifier must not be empty")
    if not traffic_source.strip():
        raise ValueError("traffic_source must not be empty")
    if not termination_report_location.strip():
        raise ValueError("termination_report_location must not be empty")
    normalized_base = base_url.rstrip("/")
    output_dir.mkdir(parents=True, exist_ok=False)

    collected: list[dict[str, Any]] = []
    for index in range(samples):
        snapshot = {path: fetcher(f"{normalized_base}{path}", headers) for path in ENDPOINTS}
        status = snapshot["/api/status"]
        counters = preflight(status, require_authenticated=require_authenticated)
        collected.append({
            "sample_index": index,
            "captured_unix_ts": time.time(),
            "packet_counters": counters,
            "status": status,
            "peers": snapshot["/api/peers"],
            "tun_routing": snapshot["/api/tun-routing/status"],
        })
        if index + 1 < samples:
            time.sleep(interval_seconds)

    first, last = collected[0]["packet_counters"], collected[-1]["packet_counters"]
    manifest = {
        "schema_version": 1,
        "purpose": "R007 physical runtime-load qualification evidence",
        "repository_revision": current_revision(),
        "build_identifier": build_identifier,
        "admin_base_url": normalized_base,
        "admin_authentication": "bearer" if "Authorization" in headers else "not_recorded",
        "traffic_source": traffic_source,
        "sample_count": samples,
        "sample_interval_seconds": interval_seconds,
        "packet_counter_delta": {key: last[key] - first[key] for key in first},
        "snapshot_file": "snapshots.json",
        "termination_report_location": termination_report_location,
    }
    (output_dir / "snapshots.json").write_text(json.dumps(collected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-base-url", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--build-identifier", required=True,
                        help="signed build/version identifier; never a credential")
    parser.add_argument("--traffic-source", required=True,
                        help="controlled traffic-generator identifier or report location")
    parser.add_argument("--termination-report-location", required=True,
                        help="platform termination/watchdog report location")
    parser.add_argument("--samples", type=int, default=60)
    parser.add_argument("--interval-seconds", type=float, default=10.0)
    parser.add_argument("--bearer-token-env", default="OB_QUALIFICATION_ADMIN_TOKEN")
    args = parser.parse_args(argv)
    headers: dict[str, str] = {"Accept": "application/json"}
    token = os.environ.get(args.bearer_token_env, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        manifest = capture(
            base_url=args.admin_base_url,
            output_dir=args.output_dir,
            build_identifier=args.build_identifier,
            traffic_source=args.traffic_source,
            termination_report_location=args.termination_report_location,
            samples=args.samples,
            interval_seconds=args.interval_seconds,
            headers=headers,
            require_authenticated=True,
        )
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        print(f"runtime qualification capture failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
