#!/usr/bin/env python3
"""Assign a processed App Store Connect build to a TestFlight beta group."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_ROOT = "https://api.appstoreconnect.apple.com/v1"


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _read_der_length(value: bytes, offset: int) -> tuple[int, int]:
    first = value[offset]
    if first < 0x80:
        return first, offset + 1
    width = first & 0x7F
    if width == 0 or width > 2:
        raise ValueError("unsupported ECDSA DER length")
    end = offset + 1 + width
    return int.from_bytes(value[offset + 1 : end], "big"), end


def der_ecdsa_to_raw(signature: bytes) -> bytes:
    """Convert OpenSSL's DER ECDSA result to JWT's 64-byte ES256 form."""
    if not signature or signature[0] != 0x30:
        raise ValueError("invalid ECDSA DER sequence")
    sequence_length, offset = _read_der_length(signature, 1)
    if offset + sequence_length != len(signature):
        raise ValueError("invalid ECDSA DER sequence length")
    numbers: list[int] = []
    for _ in range(2):
        if offset >= len(signature) or signature[offset] != 0x02:
            raise ValueError("invalid ECDSA DER integer")
        number_length, offset = _read_der_length(signature, offset + 1)
        end = offset + number_length
        if end > len(signature):
            raise ValueError("truncated ECDSA DER integer")
        numbers.append(int.from_bytes(signature[offset:end], "big"))
        offset = end
    if offset != len(signature) or any(number >= 1 << 256 for number in numbers):
        raise ValueError("invalid ES256 signature")
    return b"".join(number.to_bytes(32, "big") for number in numbers)


def authorization_token(key_id: str, issuer_id: str, private_key: Path) -> str:
    now = int(time.time())
    header = base64url(json.dumps({"alg": "ES256", "kid": key_id, "typ": "JWT"}, separators=(",", ":")).encode())
    payload = base64url(json.dumps({"iss": issuer_id, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=signing_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return f"{header}.{payload}.{base64url(der_ecdsa_to_raw(result.stdout))}"


def api_request(token: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
    request = Request(
        f"{API_ROOT}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            response_body = response.read()
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"App Store Connect {method} {path} failed ({error.code}): {detail}") from error
    except URLError as error:
        raise RuntimeError(f"App Store Connect {method} {path} failed: {error.reason}") from error
    return json.loads(response_body) if response_body else None


def find_one(token: str, path: str, resource: str) -> dict[str, Any]:
    response = api_request(token, "GET", path)
    matches = response.get("data", []) if response else []
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {resource}, found {len(matches)}")
    return matches[0]


def find_processed_build(token: str, app_id: str, build_number: str, poll_seconds: int, timeout_seconds: int) -> dict[str, Any]:
    query = urlencode({"filter[app]": app_id, "filter[version]": build_number, "fields[builds]": "version,processingState", "limit": "200"})
    deadline = time.monotonic() + timeout_seconds
    while True:
        response = api_request(token, "GET", f"/builds?{query}")
        matches = response.get("data", []) if response else []
        valid = [item for item in matches if item["attributes"].get("processingState") == "VALID"]
        if valid:
            return valid[0]
        states = sorted({item.get("attributes", {}).get("processingState", "UNKNOWN") for item in matches})
        if any(state in {"FAILED", "INVALID"} for state in states):
            raise RuntimeError(f"build {build_number} processing failed with state(s): {', '.join(states)}")
        if time.monotonic() >= deadline:
            observed = ", ".join(states) if states else "not yet visible"
            raise RuntimeError(f"timed out waiting for build {build_number}; last state: {observed}")
        print(f"[assign_testflight_group] build {build_number} processing ({', '.join(states) if states else 'not yet visible'}); retrying")
        time.sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--issuer-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    if not args.private_key.is_file():
        raise SystemExit("App Store Connect private key file is missing")
    if args.poll_seconds <= 0 or args.timeout_seconds <= 0:
        raise SystemExit("poll and timeout values must be positive")

    token = authorization_token(args.key_id, args.issuer_id, args.private_key)
    app = find_one(token, f"/apps?{urlencode({'filter[bundleId]': args.bundle_id})}", "app")
    group = find_one(token, f"/betaGroups?{urlencode({'filter[app]': app['id'], 'filter[name]': args.group_name})}", "beta group")
    build = find_processed_build(token, app["id"], args.build_number, args.poll_seconds, args.timeout_seconds)
    api_request(
        token,
        "POST",
        f"/builds/{build['id']}/relationships/betaGroups",
        {"data": [{"type": "betaGroups", "id": group["id"]}]},
    )
    print(f"[assign_testflight_group] assigned build {args.build_number} to {args.group_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
