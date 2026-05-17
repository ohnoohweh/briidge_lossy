"""Headless probes executed by the standalone iOS E2E application."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Mapping
import urllib.error
import urllib.request
from urllib.parse import urlparse

from obstacle_bridge.core import ObstacleBridgeClient
from obstacle_bridge.crypto_extract import available_crypto_extract
from obstacle_bridge_ios.app import ObstacleBridgeIOSApp, _default_ios_grouped_config


REPORT_DIRNAME = ".obstaclebridge-ios-e2e"
HOST_WEBSOCKET_REPORT_NAME = "host-websocket-latest.json"
WS_UDP_ECHO_REPORT_NAME = "ws-udp-echo-latest.json"
WS_SECURE_LINK_REPORT_NAME = "ws-secure-link-latest.json"
RUNTIME_CONFIG_REPORT_NAME = "runtime-config-latest.json"
EMBEDDED_WEBADMIN_REPORT_NAME = "embedded-webadmin-latest.json"
WEBADMIN_HTTP_REPORT_NAME = "webadmin-http-latest.json"


def _report_root(root: Path | None = None) -> Path:
    if root is not None:
        base = root
    elif sys.platform == "ios":
        base = Path.home() / "Documents" / REPORT_DIRNAME
    else:
        base = Path.home() / REPORT_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def _probe_logging_config(*, root: Path | None, name: str) -> dict[str, Any]:
    log_path = _report_root(root) / f"{name}.log"
    return {
        "log": "DEBUG",
        "console_level": "DEBUG",
        "file_level": "DEBUG",
        "log_file": str(log_path),
        "debug_stderr": True,
        "log_secure_link": "DEBUG",
        "log_ws_session": "DEBUG",
        "log_runner": "DEBUG",
        "log_admin_web": "DEBUG",
    }


def _webadmin_url_from_config(config: Mapping[str, Any]) -> str | None:
    if not isinstance(config, Mapping) or not bool(config.get("admin_web")):
        return None
    bind = str(config.get("admin_web_bind") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(config.get("admin_web_port") or 18080)
    path = str(config.get("admin_web_path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    host = "127.0.0.1" if bind in {"0.0.0.0", "::", "*", "localhost"} else bind
    return f"http://{host}:{port}{path}"


def _default_webadmin_probe_urls() -> list[str]:
    return [
        "http://192.168.105.1:18080/",
        "http://127.0.0.1:18080/",
    ]


def _shared_app_group_root() -> str | None:
    if sys.platform != "ios":
        return None
    try:
        from rubicon.objc import ObjCClass
    except Exception:
        return None
    try:
        file_manager = ObjCClass("NSFileManager").defaultManager
        url = file_manager.containerURLForSecurityApplicationGroupIdentifier_("group.com.obstaclebridge.shared")
    except Exception:
        return None
    if url is None:
        return None
    try:
        path = str(url.path)
    except Exception:
        return None
    return path or None


def _shared_log_snapshot(max_tail_chars: int = 3000) -> dict[str, Any]:
    root = _shared_app_group_root()
    if not root:
        return {"ok": False, "error": "shared app-group container unavailable"}
    root_path = Path(root)
    logs_dir = root_path / "logs"
    config_path = root_path / "config" / "ObstacleBridge.cfg"
    snapshot: dict[str, Any] = {
        "ok": True,
        "root": str(root_path),
        "logs_dir": str(logs_dir),
        "config_path": str(config_path),
        "config_exists": config_path.is_file(),
        "files": [],
    }
    if not logs_dir.is_dir():
        snapshot["ok"] = False
        snapshot["error"] = "shared logs directory missing"
        return snapshot
    for path in sorted(logs_dir.iterdir()):
        if not path.is_file():
            continue
        info: dict[str, Any] = {
            "name": path.name,
            "size": path.stat().st_size,
        }
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            info["tail"] = text[-max_tail_chars:]
        except Exception as exc:
            info["tail_error"] = f"{type(exc).__name__}: {exc}"
        snapshot["files"].append(info)
    return snapshot


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _http_json_sync(
    url: str,
    *,
    method: str = "GET",
    payload: Mapping[str, Any] | None = None,
    timeout_sec: float = 2.0,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(dict(payload)).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            doc = json.loads(response.read().decode("utf-8"))
            if isinstance(doc, dict):
                doc.setdefault("http_status", int(getattr(response, "status", 0) or 0))
            return doc
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            doc = json.loads(raw)
            if isinstance(doc, dict):
                doc.setdefault("http_status", int(exc.code))
                return doc
        except Exception:
            pass
        return {"ok": False, "http_status": int(exc.code), "error": raw}


async def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: Mapping[str, Any] | None = None,
    timeout_sec: float = 2.0,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _http_json_sync,
        url,
        method=method,
        payload=payload,
        timeout_sec=timeout_sec,
    )


def _http_probe_sync(
    url: str,
    *,
    timeout_sec: float = 2.0,
) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            body = response.read()
            text = body.decode("utf-8", errors="replace")
            payload: Any = None
            if text:
                with contextlib.suppress(Exception):
                    payload = json.loads(text)
            return {
                "ok": True,
                "url": url,
                "http_status": int(getattr(response, "status", 0) or 0),
                "content_type": str(response.headers.get("Content-Type") or ""),
                "body_preview": text[:400],
                "json": payload if isinstance(payload, (dict, list)) else None,
                "latency_ms": int((time.perf_counter() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        payload: Any = None
        if raw:
            with contextlib.suppress(Exception):
                payload = json.loads(raw)
        return {
            "ok": False,
            "url": url,
            "http_status": int(exc.code),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "body_preview": raw[:400],
            "json": payload if isinstance(payload, (dict, list)) else None,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "http_status": None,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }


async def _http_probe(
    url: str,
    *,
    timeout_sec: float = 2.0,
) -> dict[str, Any]:
    return await asyncio.to_thread(_http_probe_sync, url, timeout_sec=timeout_sec)


async def _wait_for_json(url: str, *, timeout_sec: float = 10.0) -> dict[str, Any]:
    deadline = time.perf_counter() + float(timeout_sec)
    last_error = "unknown"
    while time.perf_counter() < deadline:
        try:
            return await _http_json(url, timeout_sec=min(1.5, max(0.5, deadline - time.perf_counter())))
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(0.25)
    raise TimeoutError(f"timed out waiting for JSON from {url}: {last_error}")


async def _wait_for_uptime_reset(url: str, *, previous_uptime: int, timeout_sec: float = 10.0) -> dict[str, Any]:
    deadline = time.perf_counter() + float(timeout_sec)
    last_doc: dict[str, Any] | None = None
    while time.perf_counter() < deadline:
        try:
            doc = await _http_json(url, timeout_sec=min(1.5, max(0.5, deadline - time.perf_counter())))
        except Exception:
            await asyncio.sleep(0.25)
            continue
        last_doc = doc
        uptime = int(doc.get("uptime_sec") or 0)
        if uptime < int(previous_uptime):
            return doc
        await asyncio.sleep(0.25)
    raise TimeoutError(f"uptime did not reset before timeout; last_meta={last_doc!r}")


async def run_host_websocket_probe(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    """Connect from the iOS E2E app process to a host WebSocket echo endpoint."""

    started = time.perf_counter()
    try:
        import websockets
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "detail": f"websockets import failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }

    payload = {
        "app": "obstacle_bridge_ios_e2e",
        "probe": "host-websocket",
        "message": "obstaclebridge-ios-e2e-probe",
    }
    try:
        async with websockets.connect(url, open_timeout=timeout_sec, close_timeout=timeout_sec) as ws:
            await asyncio.wait_for(ws.send(json.dumps(payload, sort_keys=True)), timeout=timeout_sec)
            reply_text = await asyncio.wait_for(ws.recv(), timeout=timeout_sec)
        reply = json.loads(reply_text)
        ok = reply.get("message") == payload["message"] and reply.get("probe") == payload["probe"]
        return {
            "ok": bool(ok),
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "sent": payload,
            "received": reply,
            "detail": "host WebSocket echo succeeded" if ok else "host WebSocket echo payload mismatch",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "host-websocket",
            "url": url,
            "detail": f"host WebSocket probe failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }


def run_host_websocket_probe_sync(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    return asyncio.run(run_host_websocket_probe(url, timeout_sec=timeout_sec))


class _UDPProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self.response.done():
            self.response.set_result(bytes(data))

    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)


async def _send_udp_and_wait(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout_sec: float,
) -> bytes:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _UDPProbeProtocol,
        remote_addr=(str(host), int(port)),
    )
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(protocol.response, timeout=timeout_sec)
    finally:
        transport.close()


def _ws_peer_from_url(ws_url: str) -> tuple[str, int]:
    parsed = urlparse(ws_url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError(f"ws_url must use ws:// or wss://: {ws_url}")
    if not parsed.hostname:
        raise ValueError(f"ws_url must include a host: {ws_url}")
    if parsed.port is None:
        return parsed.hostname, 443 if parsed.scheme == "wss" else 80
    return parsed.hostname, int(parsed.port)


def _ios_ws_udp_bridge_config(
    *,
    ws_url: str,
    local_udp_port: int,
    target_udp_host: str,
    target_udp_port: int,
    report_root: Path | None = None,
) -> dict[str, Any]:
    peer_host, peer_port = _ws_peer_from_url(ws_url)
    return {
        "overlay_transport": "ws",
        "ws_peer": peer_host,
        "ws_peer_port": int(peer_port),
        "ws_bind": "127.0.0.1",
        "ws_own_port": 0,
        "secure_link_mode": "off",
        "admin_web": False,
        "status": False,
        "own_servers": [
            {
                "name": "ios-e2e-local-udp",
                "listen": {"protocol": "udp", "bind": "127.0.0.1", "port": int(local_udp_port)},
                "target": {
                    "protocol": "udp",
                    "host": str(target_udp_host),
                    "port": int(target_udp_port),
                },
            }
        ],
        **_probe_logging_config(root=report_root, name="ws-udp-echo-runtime"),
    }


def _ios_ws_secure_link_config(
    *,
    ws_url: str,
    secure_link_psk: str,
    report_root: Path | None = None,
) -> dict[str, Any]:
    peer_host, peer_port = _ws_peer_from_url(ws_url)
    return {
        "overlay_transport": "ws",
        "ws_peer": peer_host,
        "ws_peer_port": int(peer_port),
        "ws_bind": "127.0.0.1",
        "ws_own_port": 0,
        "secure_link": True,
        "secure_link_mode": "psk",
        "secure_link_psk": str(secure_link_psk),
        "admin_web": False,
        "status": False,
        **_probe_logging_config(root=report_root, name="ws-secure-link-runtime"),
    }


def _extract_secure_link_peer_doc(client: ObstacleBridgeClient) -> dict[str, Any] | None:
    runner = getattr(client, "runner", None)
    getter = getattr(runner, "get_peer_connections_snapshot", None) if runner is not None else None
    if not callable(getter):
        return None
    try:
        doc = dict(getter() or {})
    except Exception:
        return None
    peers = list(doc.get("peers") or [])
    for row in peers:
        if str(row.get("state") or "").strip().lower() == "listening":
            continue
        secure_link = row.get("secure_link") or {}
        if bool(secure_link.get("authenticated")):
            return {
                "peer": dict(row),
                "count": int(doc.get("count") or len(peers)),
            }
    return None


async def run_ws_udp_echo_probe(
    *,
    ws_url: str,
    local_udp_port: int,
    target_udp_host: str,
    target_udp_port: int,
    payload: bytes,
    expected: bytes | None = None,
    timeout_sec: float = 12.0,
) -> dict[str, Any]:
    """Run an iOS-side UDP service over a WS ObstacleBridge peer and validate the reply."""

    started = time.perf_counter()
    report_root = _report_root()
    expected_payload = payload if expected is None else expected
    config = _ios_ws_udp_bridge_config(
        ws_url=ws_url,
        local_udp_port=local_udp_port,
        target_udp_host=target_udp_host,
        target_udp_port=target_udp_port,
        report_root=report_root,
    )
    client = ObstacleBridgeClient(config, apply_logging=True)
    last_detail = ""
    try:
        await client.start()
        deadline = time.perf_counter() + float(timeout_sec)
        while time.perf_counter() < deadline:
            try:
                response = await _send_udp_and_wait(
                    "127.0.0.1",
                    int(local_udp_port),
                    payload,
                    timeout_sec=min(2.0, max(0.5, deadline - time.perf_counter())),
                )
                ok = response == expected_payload
                return {
                    "ok": bool(ok),
                    "app": "obstacle_bridge_ios_e2e",
                    "probe": "ws-udp-echo",
                    "ws_url": ws_url,
                    "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
                    "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
                    "payload_hex": payload.hex(),
                    "expected_hex": expected_payload.hex(),
                    "response_hex": response.hex(),
                    "detail": "UDP response matched" if ok else "UDP response did not match expected payload",
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                }
            except Exception as exc:
                last_detail = f"{type(exc).__name__}: {exc}"
                await asyncio.sleep(0.25)
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-udp-echo",
            "ws_url": ws_url,
            "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
            "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
            "payload_hex": payload.hex(),
            "expected_hex": expected_payload.hex(),
            "response_hex": "",
            "detail": f"UDP probe timed out: {last_detail}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-udp-echo",
            "ws_url": ws_url,
            "local_udp": {"host": "127.0.0.1", "port": int(local_udp_port)},
            "target_udp": {"host": str(target_udp_host), "port": int(target_udp_port)},
            "payload_hex": payload.hex(),
            "expected_hex": expected_payload.hex(),
            "response_hex": "",
            "detail": f"bridge startup/probe failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_ws_udp_echo_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_ws_udp_echo_probe(**kwargs))


async def run_ws_secure_link_probe(
    *,
    ws_url: str,
    secure_link_psk: str,
    timeout_sec: float = 12.0,
    hold_after_success_sec: float = 3.0,
) -> dict[str, Any]:
    """Connect from the iOS E2E app process to a WS peer using SecureLink PSK."""

    started = time.perf_counter()
    report_root = _report_root()
    config = _ios_ws_secure_link_config(ws_url=ws_url, secure_link_psk=secure_link_psk, report_root=report_root)
    client = ObstacleBridgeClient(config, apply_logging=True)
    last_doc: dict[str, Any] | None = None
    crypto_status = available_crypto_extract()
    log_file = str(report_root / "ws-secure-link-runtime.log")
    try:
        await client.start()
        deadline = time.perf_counter() + float(timeout_sec)
        while time.perf_counter() < deadline:
            match = _extract_secure_link_peer_doc(client)
            if match is not None:
                peer_row = dict(match.get("peer") or {})
                secure_link = dict(peer_row.get("secure_link") or {})
                if hold_after_success_sec > 0:
                    await asyncio.sleep(float(hold_after_success_sec))
                return {
                    "ok": True,
                    "app": "obstacle_bridge_ios_e2e",
                    "probe": "ws-secure-link",
                    "ws_url": ws_url,
                    "crypto_extract": crypto_status,
                    "runtime_log_file": log_file,
                    "secure_link_mode": "psk",
                    "peer_count": int(match.get("count") or 0),
                    "peer_transport": str(peer_row.get("transport") or ""),
                    "peer_state": str(peer_row.get("state") or ""),
                    "secure_link_state": str(secure_link.get("state") or ""),
                    "secure_link_authenticated": bool(secure_link.get("authenticated")),
                    "detail": "SecureLink authenticated over WebSocket",
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                }
            runner = getattr(client, "runner", None)
            getter = getattr(runner, "get_peer_connections_snapshot", None) if runner is not None else None
            if callable(getter):
                with contextlib.suppress(Exception):
                    last_doc = dict(getter() or {})
            await asyncio.sleep(0.25)
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-secure-link",
            "ws_url": ws_url,
            "crypto_extract": crypto_status,
            "runtime_log_file": log_file,
            "secure_link_mode": "psk",
            "detail": "SecureLink did not authenticate before timeout",
            "last_peer_doc": last_doc,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "ws-secure-link",
            "ws_url": ws_url,
            "crypto_extract": crypto_status,
            "runtime_log_file": log_file,
            "secure_link_mode": "psk",
            "detail": f"SecureLink probe failed: {type(exc).__name__}: {exc}",
            "last_peer_doc": last_doc,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_ws_secure_link_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_ws_secure_link_probe(**kwargs))


async def run_runtime_config(
    *,
    config: Mapping[str, Any],
    hold_sec: float = 600.0,
) -> dict[str, Any]:
    """Start an ObstacleBridge runtime from config and keep it alive for inspection."""

    started = time.perf_counter()
    report_root = _report_root()
    runtime_config = dict(config)
    if not any(key in runtime_config for key in ("log", "console_level", "log_file")):
        runtime_config.update(_probe_logging_config(root=report_root, name="runtime-config"))
    client = ObstacleBridgeClient(runtime_config, apply_logging=True)
    runtime_log_file = str(runtime_config.get("log_file") or "")
    try:
        await client.start()
        snapshot = dict(client.snapshot() or {})
        await asyncio.sleep(max(0.0, float(hold_sec)))
        final_snapshot = dict(client.snapshot() or {})

        return {
            "ok": True,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "runtime-config",
            "hold_sec": float(hold_sec),
            "crypto_extract": available_crypto_extract(),
            "runtime_log_file": runtime_log_file,
            "started": bool(final_snapshot.get("started")),
            "webadmin_url": _webadmin_url_from_config(runtime_config),
            "config": runtime_config,
            "initial_snapshot": snapshot,
            "final_snapshot": final_snapshot,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "runtime-config",
            "hold_sec": float(hold_sec),
            "crypto_extract": available_crypto_extract(),
            "runtime_log_file": runtime_log_file,
            "webadmin_url": _webadmin_url_from_config(runtime_config),
            "config": runtime_config,
            "detail": f"runtime-config failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        await client.stop()


def run_runtime_config_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_runtime_config(**kwargs))


async def run_webadmin_http_probe(
    *,
    urls: list[str] | None = None,
    timeout_sec: float = 3.0,
    attempts: int = 3,
    delay_sec: float = 0.75,
) -> dict[str, Any]:
    """Probe candidate WebAdmin URLs from the standalone iOS E2E app process."""

    started = time.perf_counter()
    probe_urls = [str(url).strip() for url in (urls or _default_webadmin_probe_urls()) if str(url).strip()]
    if not probe_urls:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "webadmin-http",
            "detail": "no probe URLs configured",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }

    tunnel_status_before: dict[str, Any] | None = None
    tunnel_status_after: dict[str, Any] | None = None
    shared_logs_before = _shared_log_snapshot()
    with contextlib.suppress(Exception):
        from obstacle_bridge_ios.tunnel_control import ipserver_tunnel_status

        tunnel_status_before = dict(ipserver_tunnel_status() or {})

    probes: list[dict[str, Any]] = []
    success_urls: list[str] = []
    for base_url in probe_urls:
        root_url = base_url.rstrip("/") + "/"
        meta_url = root_url.rstrip("/") + "/api/meta"
        status_url = root_url.rstrip("/") + "/api/status"
        attempts_doc: list[dict[str, Any]] = []
        succeeded = False
        for attempt in range(1, max(1, int(attempts)) + 1):
            meta_doc = await _http_probe(meta_url, timeout_sec=timeout_sec)
            status_doc = await _http_probe(status_url, timeout_sec=timeout_sec)
            root_doc = await _http_probe(root_url, timeout_sec=timeout_sec)
            attempt_doc = {
                "attempt": attempt,
                "meta": meta_doc,
                "status": status_doc,
                "root": root_doc,
            }
            attempts_doc.append(attempt_doc)
            if bool(meta_doc.get("ok")) or bool(status_doc.get("ok")) or bool(root_doc.get("ok")):
                succeeded = True
                success_urls.append(base_url)
                break
            if attempt < max(1, int(attempts)):
                await asyncio.sleep(max(0.0, float(delay_sec)))
        probes.append(
            {
                "url": base_url,
                "ok": succeeded,
                "attempts": attempts_doc,
            }
        )

    with contextlib.suppress(Exception):
        from obstacle_bridge_ios.tunnel_control import ipserver_tunnel_status

        tunnel_status_after = dict(ipserver_tunnel_status() or {})

    return {
        "ok": bool(success_urls),
        "app": "obstacle_bridge_ios_e2e",
        "probe": "webadmin-http",
        "probe_urls": probe_urls,
        "success_urls": success_urls,
        "attempt_count": max(1, int(attempts)),
        "timeout_sec": float(timeout_sec),
        "delay_sec": float(delay_sec),
        "tunnel_status_before": tunnel_status_before,
        "tunnel_status_after": tunnel_status_after,
        "shared_logs_before": shared_logs_before,
        "shared_logs_after": _shared_log_snapshot(),
        "probes": probes,
        "latency_ms": int((time.perf_counter() - started) * 1000),
    }


def run_webadmin_http_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_webadmin_http_probe(**kwargs))


async def run_embedded_webadmin_probe(
    *,
    timeout_sec: float = 20.0,
    restart_timeout_sec: float = 10.0,
) -> dict[str, Any]:
    """Exercise the app-style embedded WebAdmin stack through its local HTTP API."""

    started = time.perf_counter()
    os.environ["OBSTACLEBRIDGE_ADMIN_UI_PLATFORM"] = "ios"
    app = ObstacleBridgeIOSApp()
    baseline_config = _default_ios_grouped_config(app.DOCUMENTS_ROOT)
    baseline_config.setdefault("admin_web", {})
    baseline_config["admin_web"]["admin_web_auth_disable"] = True
    baseline_config["admin_web"]["admin_web_name"] = ""
    _write_json(app.CONFIG_FILE, baseline_config)
    first_app_closed = False
    second_app: ObstacleBridgeIOSApp | None = None
    persisted_name = "Embedded E2E Persisted"
    persisted_psk = "embedded-e2e-secure-link-psk"

    def _stop_embedded_app(target: ObstacleBridgeIOSApp) -> None:
        if getattr(target.client, "runner", None) is not None:
            target._run_async_sync(target.client.stop())
        target.close()

    try:
        start_snapshot = app.start_embedded_webadmin()
        webadmin_url = str(start_snapshot.get("webadmin_url") or "http://127.0.0.1:18080/")
        meta_url = webadmin_url.rstrip("/") + "/api/meta"
        status_url = webadmin_url.rstrip("/") + "/api/status"
        config_url = webadmin_url.rstrip("/") + "/api/config"

        meta_ready = await _wait_for_json(meta_url, timeout_sec=timeout_sec)
        status_ready = await _wait_for_json(status_url, timeout_sec=timeout_sec)
        config_ready = await _wait_for_json(config_url, timeout_sec=timeout_sec)
        crypto_before = dict(meta_ready.get("crypto_extract") or {})
        build_before = dict(meta_ready.get("build") or {})

        uptime_before = int(meta_ready.get("uptime_sec") or 0)
        if uptime_before < 2:
            deadline = time.perf_counter() + float(timeout_sec)
            while uptime_before < 2 and time.perf_counter() < deadline:
                await asyncio.sleep(0.5)
                meta_ready = await _wait_for_json(meta_url, timeout_sec=2.0)
                uptime_before = int(meta_ready.get("uptime_sec") or 0)

        save_doc = await _http_json(
            config_url,
            method="POST",
            payload={"updates": {"admin_web_name": persisted_name, "secure_link_psk": persisted_psk}},
            timeout_sec=3.0,
        )
        config_after_save = await _wait_for_json(config_url, timeout_sec=timeout_sec)

        restart_doc = await _http_json(
            webadmin_url.rstrip("/") + "/api/restart",
            method="POST",
            payload={},
            timeout_sec=3.0,
        )
        meta_after_restart = await _wait_for_uptime_reset(
            meta_url,
            previous_uptime=uptime_before,
            timeout_sec=restart_timeout_sec,
        )
        status_after_restart = await _wait_for_json(status_url, timeout_sec=timeout_sec)

        _stop_embedded_app(app)
        first_app_closed = True

        second_app = ObstacleBridgeIOSApp()
        second_app.start_embedded_webadmin()
        config_after_relaunch = await _wait_for_json(config_url, timeout_sec=timeout_sec)
        uptime_after_restart = int(meta_after_restart.get("uptime_sec") or 0)
        relaunch_name = str((((config_after_relaunch.get("config") or {}).get("admin_web_name")) or ""))
        save_ok = bool(save_doc.get("ok"))
        uptime_reset = uptime_after_restart < uptime_before
        config_persisted = relaunch_name == persisted_name

        return {
            "ok": bool(save_ok and uptime_reset and config_persisted),
            "app": "obstacle_bridge_ios_e2e",
            "probe": "embedded-webadmin",
            "webadmin_url": webadmin_url,
            "config_file": str(app.CONFIG_FILE),
            "uptime_before_restart_sec": uptime_before,
            "uptime_after_restart_sec": uptime_after_restart,
            "uptime_reset": uptime_reset,
            "status_platform": str(((status_ready.get("admin_ui") or {}).get("platform") or "")),
            "restart_doc": restart_doc,
            "save_doc": save_doc,
            "save_ok": save_ok,
            "saved_admin_web_name": str((((config_after_save.get("config") or {}).get("admin_web_name")) or "")),
            "saved_secure_link_psk_hidden": str((((config_after_save.get("config") or {}).get("secure_link_psk")) or "")) == "",
            "relaunch_admin_web_name": relaunch_name,
            "config_persisted_after_relaunch": config_persisted,
            "crypto_extract": crypto_before,
            "build": build_before,
            "runtime_log_file": str(app.LOG_FILE),
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "meta_before_restart": meta_ready,
            "meta_after_restart": meta_after_restart,
            "status_before_restart": status_ready,
            "status_after_restart": status_after_restart,
            "config_before_save": config_ready,
            "config_after_save": config_after_save,
            "config_after_relaunch": config_after_relaunch,
        }
    except Exception as exc:
        return {
            "ok": False,
            "app": "obstacle_bridge_ios_e2e",
            "probe": "embedded-webadmin",
            "config_file": str(app.CONFIG_FILE),
            "runtime_log_file": str(app.LOG_FILE),
            "crypto_extract": available_crypto_extract(),
            "detail": f"embedded-webadmin failed: {type(exc).__name__}: {exc}",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    finally:
        if second_app is not None:
            with contextlib.suppress(Exception):
                _stop_embedded_app(second_app)
        if not first_app_closed:
            with contextlib.suppress(Exception):
                _stop_embedded_app(app)


def run_embedded_webadmin_probe_sync(**kwargs: Any) -> dict[str, Any]:
    return asyncio.run(run_embedded_webadmin_probe(**kwargs))


def write_report(report: dict[str, Any], root: Path | None = None) -> Path:
    base = _report_root(root)
    if report.get("probe") == "ws-udp-echo":
        report_name = WS_UDP_ECHO_REPORT_NAME
    elif report.get("probe") == "ws-secure-link":
        report_name = WS_SECURE_LINK_REPORT_NAME
    elif report.get("probe") == "runtime-config":
        report_name = RUNTIME_CONFIG_REPORT_NAME
    elif report.get("probe") == "embedded-webadmin":
        report_name = EMBEDDED_WEBADMIN_REPORT_NAME
    elif report.get("probe") == "webadmin-http":
        report_name = WEBADMIN_HTTP_REPORT_NAME
    else:
        report_name = HOST_WEBSOCKET_REPORT_NAME
    target = base / report_name
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target
