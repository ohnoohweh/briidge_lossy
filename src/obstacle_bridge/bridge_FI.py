"""Test-only failure-injection entrypoint for secure-link integration scenarios."""

from __future__ import annotations

import base64
import json
import time

from . import bridge as base


class SecureLinkPskSessionFI(base.SecureLinkPskSession):
    def __init__(self, inner: base.ISession, args, transport_name: str):
        super().__init__(inner, args, transport_name)
        self._debug_recent_accepted_frames = base.deque(maxlen=16)

    def _remember_debug_accepted_frame(self, peer_id, session_id: int, counter: int, wire_payload: bytes) -> None:
        self._debug_recent_accepted_frames.append(
            {
                "peer_id": None if peer_id is None else int(peer_id),
                "session_id": int(session_id or 0),
                "counter": int(counter or 0),
                "payload": bytes(wire_payload or b""),
                "accepted_unix_ts": time.time(),
            }
        )

    def _current_authenticated_peer_id(self):
        if self._client_mode:
            return None
        active = [int(peer_id) for peer_id, state in self._peer_states.items() if state.authenticated]
        if len(active) == 1:
            return active[0]
        return None

    def debug_replay_recent_frame(self, *, session_id=None):
        selected = None
        if session_id is None:
            if self._debug_recent_accepted_frames:
                selected = self._debug_recent_accepted_frames[-1]
        else:
            target_session_id = int(session_id or 0)
            for row in reversed(self._debug_recent_accepted_frames):
                if int(row.get("session_id") or 0) == target_session_id:
                    selected = row
                    break
        if selected is None:
            return (False, "frame_not_found")
        inject_peer_id = self._current_authenticated_peer_id() if not self._client_mode else None
        if not self._client_mode and inject_peer_id is None:
            stored_peer_id = selected.get("peer_id")
            if stored_peer_id is not None and int(stored_peer_id) in self._peer_states:
                inject_peer_id = int(stored_peer_id)
        if not self._client_mode and inject_peer_id is None:
            return (False, "no_active_authenticated_peer")
        self._on_inner_payload(bytes(selected.get("payload") or b""), peer_id=inject_peer_id)
        return (True, "replayed")

    def debug_inject_raw_frame(self, payload: bytes, *, peer_id=None):
        wire = bytes(payload or b"")
        if not wire:
            return (False, "empty_payload")
        inject_peer_id = peer_id
        if not self._client_mode and inject_peer_id is None:
            inject_peer_id = self._current_authenticated_peer_id()
            if inject_peer_id is None:
                return (False, "no_active_authenticated_peer")
        self._on_inner_payload(wire, peer_id=inject_peer_id)
        return (True, "injected")

    def _handle_data(self, peer_id, session_id: int, counter: int, body: bytes, aad: bytes) -> None:
        super()._handle_data(peer_id, session_id, counter, body, aad)
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if state is None:
            return
        if int(state.session_id or 0) != int(session_id):
            return
        if int(state.rx_counter or 0) != int(counter):
            return
        self._remember_debug_accepted_frame(peer_id, session_id, counter, aad + bytes(body or b""))


class RunnerFI(base.Runner):
    def debug_secure_link_frame_action(self, action: str, **kwargs) -> dict:
        requested = 0
        skipped = 0
        results: list[dict] = []
        action_name = str(action or "").strip().lower()
        for idx, session in enumerate(self._sessions):
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            if action_name == "replay_recent":
                func = getattr(session, "debug_replay_recent_frame", None)
                call_kwargs = {"session_id": kwargs.get("session_id")}
            elif action_name == "inject_raw":
                func = getattr(session, "debug_inject_raw_frame", None)
                call_kwargs = {"payload": kwargs.get("payload", b""), "peer_id": kwargs.get("peer_id")}
            else:
                return {"ok": False, "requested": 0, "skipped": len(self._sessions), "results": [], "error": "unknown_action"}
            if not callable(func):
                skipped += 1
                results.append({"transport": label, "ok": False, "reason": "secure_link_not_enabled"})
                continue
            try:
                ok, reason = func(**call_kwargs)
            except Exception as exc:
                skipped += 1
                results.append({"transport": label, "ok": False, "reason": f"error:{exc}"})
                continue
            if ok:
                requested += 1
            else:
                skipped += 1
            results.append({"transport": label, "ok": bool(ok), "reason": str(reason or "")})
        return {
            "ok": requested > 0,
            "requested": requested,
            "skipped": skipped,
            "results": results,
            "action": action_name,
        }


class AdminWebUIFI(base.AdminWebUI):
    async def _handle_client(self, reader, writer):
        self.log.debug("Admin web UI handling")
        try:
            reqline = await reader.readline()
            if not reqline:
                return

            self.log.debug("Request %s", reqline)
            parts = reqline.decode("utf-8", "replace").strip().split()
            if len(parts) != 3:
                await self._send(writer, 400, b"Bad Request", "text/plain; charset=utf-8")
                return

            method, raw_path, _httpver = parts
            headers = {}
            content_length = 0
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                text = line.decode("utf-8", "replace")
                if ":" in text:
                    k, v = text.split(":", 1)
                    hk = k.strip().lower()
                    hv = v.strip()
                    headers[hk] = hv
                    if hk == "content-length":
                        with base.contextlib.suppress(Exception):
                            content_length = max(0, int(hv))

            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)

            path = raw_path.split("?", 1)[0]
            self.log.info("ADMIN REQUEST method=%s path=%s", method, path)

            if (
                method == "GET"
                and path == "/api/live"
                and str(headers.get("upgrade", "")).strip().lower() == "websocket"
            ):
                if not self._is_authenticated(headers):
                    payload = {"ok": False, "authenticated": False, "error": "authentication required"}
                    self._log_api_response(path, 401, payload, summary="auth required")
                    await self._send_json(writer, 401, payload)
                    return
                await self._handle_live_websocket(reader, writer, headers)
                return

            if path == "/api/auth/state":
                await self._handle_auth_state(writer, headers)
                return
            if path == "/api/auth/challenge":
                await self._handle_auth_challenge(writer, method)
                return
            if path == "/api/auth/login":
                await self._handle_auth_login(writer, method, body)
                return
            if path == "/api/auth/logout":
                await self._handle_auth_logout(writer, method, headers)
                return

            if path.startswith("/api/") and not self._is_authenticated(headers):
                payload = {"ok": False, "authenticated": False, "error": "authentication required"}
                self._log_api_response(path, 401, payload, summary="auth required")
                await self._send_json(writer, 401, payload)
                return

            if path == "/api/health":
                payload = {"ok": True}
                self._log_api_response("/api/health", 200, payload)
                await self._send_json(writer, 200, payload)
                return
            if path == "/api/meta":
                await self._handle_meta(writer)
                return
            if path == "/api/restart":
                await self._handle_restart(writer, method, headers)
                return
            if path == "/api/shutdown":
                await self._handle_shutdown(writer, method, headers)
                return
            if path == "/api/secure-link/rekey":
                await self._handle_secure_link_rekey(writer, method)
                return
            if path == "/api/secure-link/debug":
                await self._handle_secure_link_debug(writer, method, body)
                return
            if path == "/api/status":
                await self._handle_status(writer)
                return
            if path == "/api/connections":
                await self._handle_connections(writer)
                return
            if path == "/api/config":
                await self._handle_config(writer, method, body)
                return
            if path == "/api/logs":
                await self._handle_logs(writer, raw_path)
                return
            if path == "/api/peers":
                await self._handle_peers(writer)
                return

            await self._handle_static(writer, path)
        except Exception:
            self.log.exception("Admin web request failed")
            with base.contextlib.suppress(Exception):
                await self._send(writer, 500, b"Internal Server Error", "text/plain; charset=utf-8")
        finally:
            with base.contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _handle_secure_link_debug(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        action = str(req.get("action") or "").strip().lower()
        if action == "replay_recent":
            payload = self.runner.debug_secure_link_frame_action("replay_recent", session_id=req.get("session_id"))
        elif action == "inject_raw":
            raw_b64 = str(req.get("payload_b64") or "")
            try:
                raw = base64.b64decode(raw_b64.encode("ascii"), validate=True)
            except Exception:
                await self._send_json(writer, 400, {"ok": False, "error": "invalid payload_b64"})
                return
            payload = self.runner.debug_secure_link_frame_action("inject_raw", payload=raw, peer_id=req.get("peer_id"))
        else:
            await self._send_json(writer, 400, {"ok": False, "error": "unknown action"})
            return
        code = 200 if bool(payload.get("ok")) else 409
        self._log_api_response(
            "/api/secure-link/debug",
            code,
            payload,
            summary=f"action={action} requested={payload.get('requested', 0)} skipped={payload.get('skipped', 0)}",
        )
        await self._send_json(writer, code, payload)


def main(argv=None) -> None:
    base.SecureLinkPskSession = SecureLinkPskSessionFI
    base.Runner = RunnerFI
    base.AdminWebUI = AdminWebUIFI
    base.main(argv)


if __name__ == "__main__":
    main()
