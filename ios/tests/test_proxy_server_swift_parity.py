from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from obstacle_bridge.bridge_proxy_server import (
    ObstacleBridgeProxyProtocolCodec,
    ProxyCredentials,
)


ROOT = Path(__file__).resolve().parents[2]
SWIFT_PROXY_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeProxyServer.swift"
SWIFT_PROXY_RUNNER_SOURCE = ROOT / "tests" / "fixtures" / "proxy_protocol_runner.swift"


@pytest.fixture(scope="session")
def swift_proxy_protocol_runner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        pytest.skip("swiftc is required for Swift proxy protocol parity tests")
    output_dir = tmp_path_factory.mktemp("swift_proxy_protocol")
    binary = output_dir / "proxy_protocol_runner"
    completed = subprocess.run(
        [
            swiftc,
            "-o",
            str(binary),
            str(SWIFT_PROXY_SOURCE),
            str(SWIFT_PROXY_RUNNER_SOURCE),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "failed to compile Swift proxy protocol runner\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return binary


def _run_swift(binary: Path, request: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        [str(binary)],
        input=json.dumps(request),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "Swift proxy protocol runner failed\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _pproxy_http_origin_request(raw: bytes) -> bytes:
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1")
    first, *headers = head.split("\r\n")
    method, target, version = first.split(" ", 2)
    parsed = urlsplit(target)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    kept_headers = [line for line in headers if not line.startswith("Proxy-")]
    return (f"{method} {path} {version}\r\n" + "\r\n".join(kept_headers) + "\r\n\r\n").encode()


def _python_parse_http(raw: bytes) -> dict[str, object]:
    parsed = ObstacleBridgeProxyProtocolCodec.parse_http_request_head(raw)
    assert parsed is not None
    authority = ObstacleBridgeProxyProtocolCodec.parse_authority(parsed.target, default_port=443)
    return {
        "method": parsed.method,
        "target": parsed.target,
        "version": parsed.version,
        "host_header": parsed.headers.get("host"),
        "header_length": parsed.header_length,
        "rewritten_hex": ObstacleBridgeProxyProtocolCodec.rewrite_http_request_for_origin_server(parsed).hex(),
        "authorized": ObstacleBridgeProxyProtocolCodec.authorized(
            parsed.headers,
            ProxyCredentials(username="obproxy", password="secret"),
        ),
        "authority_host": authority[0] if authority is not None else None,
        "authority_port": authority[1] if authority is not None else None,
    }


def _python_parse_socks5(raw: bytes) -> dict[str, object]:
    parsed = ObstacleBridgeProxyProtocolCodec.parse_socks5_connect_request(raw)
    assert parsed is not None
    return {
        "address_type": parsed.address_type,
        "command": parsed.command,
        "consumed": parsed.consumed,
        "host": parsed.host,
        "port": parsed.port,
    }


def _socks5_domain_connect(host: str, port: int) -> bytes:
    encoded = host.encode()
    return bytes([0x05, 0x01, 0x00, 0x03, len(encoded)]) + encoded + port.to_bytes(2, "big")


def test_swift_proxy_http_absolute_form_matches_pproxy_rewrite(swift_proxy_protocol_runner: Path) -> None:
    raw = (
        b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\n"
        b"Host: example.com:8080\r\n"
        b"Proxy-Authorization: Basic abc\r\n"
        b"Proxy-Connection: keep-alive\r\n"
        b"User-Agent: parity\r\n"
        b"\r\n"
    )

    swift = _run_swift(swift_proxy_protocol_runner, {"action": "parse_http", "request_hex": raw.hex()})
    python = _python_parse_http(raw)

    assert swift == python
    assert swift["method"] == "GET"
    assert swift["target"] == "http://example.com:8080/path?q=1"
    assert bytes.fromhex(swift["rewritten_hex"]) == _pproxy_http_origin_request(raw)
    assert b"Proxy-Authorization" not in bytes.fromhex(swift["rewritten_hex"])
    assert b"Proxy-Connection" not in bytes.fromhex(swift["rewritten_hex"])


def test_swift_proxy_http_connect_authority_and_basic_auth_match_pproxy(
    swift_proxy_protocol_runner: Path,
) -> None:
    auth = "Basic " + base64.b64encode(b"obproxy:secret").decode()
    raw = (
        f"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
        f"Host: [2001:db8::1]:443\r\n"
        f"Proxy-Authorization: {auth}\r\n"
        f"\r\n"
    ).encode()

    swift = _run_swift(swift_proxy_protocol_runner, {"action": "parse_http", "request_hex": raw.hex()})
    generated_auth = _run_swift(swift_proxy_protocol_runner, {"action": "basic_auth"})
    python = _python_parse_http(raw)

    assert swift == python
    assert swift["method"] == "CONNECT"
    assert swift["authority_host"] == "2001:db8::1"
    assert swift["authority_port"] == 443
    assert swift["authorized"] is True
    assert generated_auth["header"] == auth
    assert ObstacleBridgeProxyProtocolCodec.basic_authorization_header("obproxy", "secret") == auth


@pytest.mark.parametrize(
    ("request_bytes", "expected_host", "expected_port", "expected_type"),
    [
        (bytes([0x05, 0x01, 0x00, 0x01, 192, 0, 2, 9]) + (443).to_bytes(2, "big"), "192.0.2.9", 443, 1),
        (_socks5_domain_connect("example.com", 8443), "example.com", 8443, 3),
        (
            bytes([0x05, 0x01, 0x00, 0x04])
            + bytes.fromhex("20010db8000000000000000000000001")
            + (443).to_bytes(2, "big"),
            "2001:db8:0:0:0:0:0:1",
            443,
            4,
        ),
    ],
)
def test_swift_proxy_socks5_connect_forms_match_pproxy_address_parser(
    swift_proxy_protocol_runner: Path,
    request_bytes: bytes,
    expected_host: str,
    expected_port: int,
    expected_type: int,
) -> None:
    swift = _run_swift(swift_proxy_protocol_runner, {"action": "parse_socks5", "request_hex": request_bytes.hex()})
    python = _python_parse_socks5(request_bytes)

    assert swift == python
    assert swift == {
        "address_type": expected_type,
        "command": 1,
        "consumed": len(request_bytes),
        "host": expected_host,
        "port": expected_port,
    }
