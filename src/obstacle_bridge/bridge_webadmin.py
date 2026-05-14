from __future__ import annotations

from . import bridge as _bridge

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

class AdminWebUI:
    AUTH_CHALLENGE_TTL_SEC = 90
    AUTH_SESSION_TTL_SEC = 8 * 60 * 60
    CONFIG_CHALLENGE_TTL_SEC = 90
    LIVE_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    LIVE_TOPICS = ("status", "connections", "peers", "meta")
    ONBOARDING_TOKEN_PREFIX = "ob1."

    @staticmethod
    def _transport_attr_prefix(transport: str) -> str:
        t = str(transport or "").strip().lower()
        return "udp" if t in {"udp", "myudp"} else t

    @staticmethod
    def register_cli(p):
        g = p.add_argument_group("admin_web")
        g.add_argument(
            "--admin-web",
            action="store_true",
            default=True,
            help="Enable admin web interface",
        )
        g.add_argument(
            "--admin-web-bind",
            default="127.0.0.1",
            help="Bind address for admin web interface",
        )
        g.add_argument(
            "--admin-web-port",
            type=int,
            default=18080,
            help="Port for admin web interface",
        )
        g.add_argument(
            "--admin-web-path",
            default="/",
            help="Base path for admin web interface",
        )
        g.add_argument(
            "--admin-web-dir",
            default="./admin_web",
            help="Directory containing admin web files",
        )
        g.add_argument(
            "--admin-web-name",
            default="",
            help="Optional instance name shown in the admin web title and headline",
        )
        g.add_argument(
            "--admin-web-landing-page-disable",
            action="store_true",
            default=False,
            help="Disable the Admin Web landing/quick-start panel for advanced users.",
        )
        g.add_argument(
            "--admin-web-security-advisor-disable",
            action="store_true",
            default=False,
            help="Disable the Admin Web startup security advisor panel for advanced users.",
        )
        g.add_argument(
            "--admin-web-security-advisor-startup-disable",
            action="store_true",
            default=False,
            help="Do not auto-open the security advisor on first page load.",
        )
        g.add_argument(
            "--admin-web-first-tab",
            choices=["home", "status", "secure-link", "configuration", "logs", "misc"],
            default="home",
            help="Initial Admin Web tab. Use status for an advanced/operator-focused default.",
        )
        g.add_argument(
            "--admin-web-token",
            default="",
            help="Optional bearer token for admin restart endpoint",
        )
        g.add_argument(
            "--admin-web-auth-disable",
            action="store_true",
            default=False,
            help="Disable username/password challenge for admin web access",
        )
        g.add_argument(
            "--admin-web-username",
            default="",
            help="Username for admin web access when challenge-based authentication is enabled",
        )
        g.add_argument(
            "--admin-web-password",
            default="",
            help="Password for admin web access when challenge-based authentication is enabled",
        )

    def __init__(self, args, runner):
        self.args = args
        self.runner = runner
        self.server = None
        self.log = logging.getLogger("admin_web")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self.started_monotonic = time.monotonic()
        self._auth_challenges: Dict[str, dict] = {}
        self._auth_sessions: Dict[str, float] = {}
        self._config_challenges: Dict[str, dict] = {}
        self._secret_reveal_challenges: Dict[str, dict] = {}

    async def start(self):
        if not getattr(self.args, "admin_web", False):
            return

        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.args.admin_web_bind,
            port=self.args.admin_web_port,
        )

        self.log.info(
            "Admin web UI listening on http://%s:%d%s",
            self.args.admin_web_bind,
            self.args.admin_web_port,
            self.args.admin_web_path,
        )

    async def stop(self):
        self.log.info(
            "Admin web UI stopping")
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle_client(self, reader, writer):
        self.log.info("Admin web UI incoming connection %s", format_stream_endpoints(writer))
        self.log.debug("Admin web UI handling")
        try:
            reqline = await reader.readline()
            if not reqline:
                return

            self.log.debug(
                "Request %s",reqline)

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
                        with contextlib.suppress(Exception):
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

            if path == "/api/config/challenge":
                await self._handle_config_challenge(writer, method, headers, body)
                return

            if path == "/api/config/secret/secure-link-psk/challenge":
                await self._handle_config_secret_secure_link_psk_challenge(writer, method, headers)
                return

            if path.startswith("/api/") and not self._is_authenticated(headers):
                payload = {"ok": False, "authenticated": False, "error": "authentication required"}
                self._log_api_response(path, 401, payload, summary="auth required")
                await self._send_json(writer, 401, payload)
                return

            if path == "/api/health":
                payload={"ok": True}
                self._log_api_response("/api/health", 200, payload)
                await self._send_json(writer, 200, payload)
                return

            if path == "/api/meta":                
                await self._handle_meta(writer)
                return

            if path == "/api/restart":
                await self._handle_restart(writer, method, headers)
                return

            if path == "/api/reconnect":
                await self._handle_reconnect(writer, method, headers, body)
                return

            if path == "/api/shutdown":
                await self._handle_shutdown(writer, method, headers)
                return

            if path == "/api/secure-link/rekey":
                await self._handle_secure_link_rekey(writer, method, body)
                return

            if path == "/api/secure-link/reload":
                await self._handle_secure_link_reload(writer, method, body)
                return

            if path == "/api/config/secret/secure-link-psk":
                await self._handle_config_secret_secure_link_psk(writer, method, body)
                return

            if path == "/api/status":
                await self._handle_status(writer)
                return

            if path == "/api/connections":
                await self._handle_connections(writer)
                return

            if path == "/api/onboarding/connection-profiles":
                await self._handle_onboarding_connection_profiles(writer, method)
                return

            if path == "/api/onboarding/invite/generate":
                await self._handle_onboarding_invite_generate(writer, method, body)
                return

            if path == "/api/onboarding/invite/preview":
                await self._handle_onboarding_invite_preview(writer, method, body)
                return

            if path == "/api/onboarding/blueprints":
                await self._handle_onboarding_blueprints(writer, method)
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
            with contextlib.suppress(Exception):
                await self._send(writer, 500, b"Internal Server Error", "text/plain; charset=utf-8")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    def _build_connections_payload(self) -> dict:
        payload = self.runner.get_connections_snapshot()
        payload["app"] = "udp-bidirectional-mux"
        payload["milestone"] = "C"
        return payload

    async def _handle_connections(self, writer):
        payload = self._build_connections_payload()
        self._log_api_response("/api/connections", 200, payload)
        await self._send_json(writer, 200, payload)

    @staticmethod
    def _sanitize_onboarding_services(value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []
        out: list[dict] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            listen = item.get("listen")
            target = item.get("target")
            if not isinstance(listen, dict) or not isinstance(target, dict):
                continue
            l_proto = str(listen.get("protocol", "") or "").strip().lower()
            t_proto = str(target.get("protocol", "") or "").strip().lower()
            if l_proto not in {"udp", "tcp", "tun"} or t_proto not in {"udp", "tcp", "tun"}:
                continue
            spec: dict = {"listen": {"protocol": l_proto}, "target": {"protocol": t_proto}}
            name = str(item.get("name", "") or "").strip()
            if name:
                spec["name"] = name
            if l_proto == "tun":
                ifname = str(listen.get("ifname", "") or "").strip()
                if ifname:
                    spec["listen"]["ifname"] = ifname
                mtu = listen.get("mtu")
                if mtu is not None:
                    with contextlib.suppress(Exception):
                        mtu_i = int(mtu)
                        if 1 <= mtu_i <= 65535:
                            spec["listen"]["mtu"] = mtu_i
            else:
                bind = str(listen.get("bind", "") or "").strip()
                with contextlib.suppress(Exception):
                    port_i = int(listen.get("port"))
                    if bind and 1 <= port_i <= 65535:
                        spec["listen"]["bind"] = bind
                        spec["listen"]["port"] = port_i
            if t_proto == "tun":
                ifname = str(target.get("ifname", "") or "").strip()
                if ifname:
                    spec["target"]["ifname"] = ifname
                mtu = target.get("mtu")
                if mtu is not None:
                    with contextlib.suppress(Exception):
                        mtu_i = int(mtu)
                        if 1 <= mtu_i <= 65535:
                            spec["target"]["mtu"] = mtu_i
            else:
                host = str(target.get("host", "") or "").strip()
                with contextlib.suppress(Exception):
                    port_i = int(target.get("port"))
                    if host and 1 <= port_i <= 65535:
                        spec["target"]["host"] = host
                        spec["target"]["port"] = port_i
            hooks = item.get("lifecycle_hooks")
            if isinstance(hooks, dict):
                spec["lifecycle_hooks"] = hooks
            opts = item.get("options")
            if isinstance(opts, dict):
                spec["options"] = opts
            out.append(spec)
        return out

    @staticmethod
    def _decode_host_port(value: Any) -> Tuple[str, Optional[int]]:
        if isinstance(value, dict):
            host = str(value.get("host", "") or "").strip()
            with contextlib.suppress(Exception):
                port_i = int(value.get("port"))
                if host and 1 <= port_i <= 65535:
                    return host, port_i
            return host, None
        if isinstance(value, (list, tuple)) and len(value) >= 2:
            host = str(value[0] or "").strip()
            with contextlib.suppress(Exception):
                port_i = int(value[1])
                if host and 1 <= port_i <= 65535:
                    return host, port_i
            return host, None
        text = str(value or "").strip()
        if not text:
            return "", None
        if text.startswith("[") and "]:" in text:
            host, _, port_text = text[1:].partition("]:")
            with contextlib.suppress(Exception):
                port_i = int(port_text)
                if 1 <= port_i <= 65535:
                    return host, port_i
            return host, None
        if ":" in text:
            host, _, port_text = text.rpartition(":")
            with contextlib.suppress(Exception):
                port_i = int(port_text)
                if host and 1 <= port_i <= 65535:
                    return host, port_i
        return text, None

    def _normalized_overlay_transports(self) -> list[str]:
        raw = getattr(self.args, "overlay_transport", None)
        values: list[str]
        if isinstance(raw, str):
            values = [item.strip().lower() for item in raw.split(",")]
        elif isinstance(raw, (list, tuple, set)):
            values = [str(item or "").strip().lower() for item in raw]
        else:
            values = []
        out: list[str] = []
        for item in values:
            if item in {"udp", "myudp", "tcp", "quic", "ws"} and item not in out:
                out.append(item)
        if not out:
            out = ["myudp"]
        out = ["myudp" if item == "udp" else item for item in out]
        return out

    def _build_onboarding_connection_profiles(self) -> list[dict]:
        profiles: list[dict] = []
        secure_mode = str(getattr(self.args, "secure_link_mode", "off") or "off").strip().lower()
        overlay_transports = self._normalized_overlay_transports()
        for transport in overlay_transports:
            attr_prefix = self._transport_attr_prefix(transport)
            bind = str(getattr(self.args, f"{attr_prefix}_bind", "") or "").strip()
            own_port = getattr(self.args, f"{attr_prefix}_own_port", None)
            peer = str(getattr(self.args, f"{attr_prefix}_peer", "") or "").strip()
            peer_port = getattr(self.args, f"{attr_prefix}_peer_port", None)
            with contextlib.suppress(Exception):
                own_port = int(own_port)
            with contextlib.suppress(Exception):
                peer_port = int(peer_port)
            role = "client" if peer else "server"
            endpoint_host = peer if role == "client" else bind
            endpoint_port = peer_port if role == "client" else own_port
            profile = {
                "id": f"cfg:{transport}:{len(profiles)}",
                "source": "config",
                "transport": transport,
                "role": role,
                "endpoint_host": str(endpoint_host or ""),
                "endpoint_port": endpoint_port if isinstance(endpoint_port, int) else None,
                "listen_bind": bind,
                "listen_port": own_port if isinstance(own_port, int) else None,
                "peer_host": peer,
                "peer_port": peer_port if isinstance(peer_port, int) else None,
                "secure_link_mode": secure_mode,
                "label": (
                    f"{transport.upper()} peer {peer}:{peer_port}"
                    if role == "client"
                    else f"{transport.upper()} listen {bind}:{own_port}"
                ),
            }
            if transport == "ws":
                profile["ws_path"] = str(getattr(self.args, "ws_path", "/") or "/")
                profile["ws_tls"] = bool(getattr(self.args, "ws_tls", False))
            profiles.append(profile)
        try:
            peers_payload = self.runner.get_peer_connections_snapshot() or {}
            for row in list(peers_payload.get("peers") or []):
                transport = str(row.get("transport", "") or "").strip().lower()
                if transport not in {"udp", "tcp", "quic", "ws", "myudp"}:
                    continue
                role = "server" if str(row.get("state", "")).strip().lower() == "listening" else "client"
                endpoint_raw = row.get("listen") if role == "server" else row.get("peer")
                host, port = self._decode_host_port(endpoint_raw)
                profiles.append(
                    {
                        "id": f"live:{transport}:{row.get('id')}",
                        "source": "live",
                        "transport": "myudp" if transport == "udp" else transport,
                        "role": role,
                        "endpoint_host": host,
                        "endpoint_port": port,
                        "listen_bind": "",
                        "listen_port": None,
                        "peer_host": "",
                        "peer_port": None,
                        "secure_link_mode": secure_mode,
                        "label": f"{transport.upper()} {role} {host}:{port}" if host and port else f"{transport.upper()} {role}",
                    }
                )
        except Exception:
            self.log.exception("failed to derive live onboarding connection profiles")
        return profiles

    def _build_onboarding_blueprints(self) -> list[dict]:
        grouped: Dict[str, list[dict]] = {}
        snapshot = self.runner.get_connections_snapshot() or {}
        for proto in ("udp", "tcp"):
            for row in list(snapshot.get(proto) or []):
                state = str(row.get("state", "") or "").strip().lower()
                if state == "listening":
                    continue
                peer_id = str(row.get("peer_id", "") or "").strip()
                if not peer_id:
                    continue
                local_port = row.get("local_port")
                with contextlib.suppress(Exception):
                    local_port = int(local_port)
                if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
                    continue
                host, port = self._decode_host_port(row.get("remote_destination"))
                if not host or not isinstance(port, int):
                    continue
                spec = {
                    "name": f"bp-{peer_id}-{proto}-{local_port}",
                    "listen": {"protocol": proto, "bind": "0.0.0.0", "port": local_port},
                    "target": {"protocol": proto, "host": host, "port": port},
                }
                grouped.setdefault(peer_id, [])
                token = json.dumps(spec, sort_keys=True, ensure_ascii=False)
                if token not in {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in grouped[peer_id]}:
                    grouped[peer_id].append(spec)
        out = [{"peer_id": peer_id, "own_servers": specs} for peer_id, specs in sorted(grouped.items()) if specs]
        return out

    @classmethod
    def _encode_onboarding_token(cls, payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return cls.ONBOARDING_TOKEN_PREFIX + body

    @classmethod
    def _decode_onboarding_token(cls, token: str) -> dict:
        text = str(token or "").strip()
        if text.startswith(cls.ONBOARDING_TOKEN_PREFIX):
            text = text[len(cls.ONBOARDING_TOKEN_PREFIX):]
        if not text:
            raise ValueError("invite token is empty")
        padding = "=" * ((4 - (len(text) % 4)) % 4)
        try:
            raw = base64.urlsafe_b64decode((text + padding).encode("ascii"))
        except Exception as exc:
            raise ValueError(f"invite token is not valid base64url: {exc}") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"invite token has invalid JSON payload: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("invite token payload must be a JSON object")
        return payload

    @staticmethod
    def _onboarding_updates_from_invite(payload: dict) -> dict:
        updates: dict = {}
        conn = payload.get("connection")
        if not isinstance(conn, dict):
            return updates
        transport = str(conn.get("transport", "") or "").strip().lower()
        if transport == "udp":
            transport = "myudp"
        host = str(conn.get("endpoint_host", "") or "").strip()
        port = conn.get("endpoint_port")
        if transport in {"myudp", "tcp", "quic", "ws"} and host:
            updates["overlay_transport"] = transport
            attr_prefix = AdminWebUI._transport_attr_prefix(transport)
            updates[f"{attr_prefix}_peer"] = host
            with contextlib.suppress(Exception):
                port_i = int(port)
                if 1 <= port_i <= 65535:
                    updates[f"{attr_prefix}_peer_port"] = port_i
        secure_mode = str(payload.get("secure_link_mode", "") or "").strip().lower()
        if secure_mode in {"off", "none", "psk", "cert"}:
            updates["secure_link_mode"] = "off" if secure_mode in {"off", "none"} else secure_mode
            updates["secure_link"] = secure_mode not in {"off", "none"}
        psk_value = payload.get("secure_link_psk")
        if isinstance(psk_value, str) and psk_value.strip():
            with contextlib.suppress(Exception):
                updates["secure_link_psk"] = str(_decrypt_config_secret(psk_value) or "")
        own = AdminWebUI._sanitize_onboarding_services(payload.get("own_servers"))
        remote = AdminWebUI._sanitize_onboarding_services(payload.get("remote_servers"))
        if own:
            updates["own_servers"] = own
        if remote:
            updates["remote_servers"] = remote
        return updates

    async def _handle_onboarding_connection_profiles(self, writer, method: str):
        if method != "GET":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        profiles = self._build_onboarding_connection_profiles()
        payload = {"ok": True, "count": len(profiles), "profiles": profiles}
        self._log_api_response("/api/onboarding/connection-profiles", 200, payload, summary=f"count={len(profiles)}")
        await self._send_json(writer, 200, payload)

    async def _handle_onboarding_invite_generate(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        profiles = self._build_onboarding_connection_profiles()
        connection_id = str(req.get("connection_id", "") or "").strip()
        selected = None
        if len(profiles) > 1 and not connection_id:
            await self._send_json(
                writer,
                409,
                {"ok": False, "error": "multiple connection profiles available; select connection_id", "profiles": profiles},
            )
            return
        if connection_id:
            for item in profiles:
                if str(item.get("id", "") or "") == connection_id:
                    selected = item
                    break
            if selected is None:
                await self._send_json(writer, 400, {"ok": False, "error": f"unknown connection_id: {connection_id}"})
                return
        elif profiles:
            selected = profiles[0]
        secure_mode = str(getattr(self.args, "secure_link_mode", "off") or "off").strip().lower()
        own_services = self._sanitize_onboarding_services(req.get("own_servers", getattr(self.args, "own_servers", [])))
        remote_services = self._sanitize_onboarding_services(req.get("remote_servers", getattr(self.args, "remote_servers", [])))
        payload_doc = {
            "version": 1,
            "generated_unix_ts": int(time.time()),
            "generated_by": str(getattr(self.args, "admin_web_name", "") or ""),
            "connection": selected or {},
            "secure_link_mode": secure_mode if secure_mode in {"off", "none", "psk", "cert"} else "off",
            "secure_link_psk": _encrypt_config_secret(str(getattr(self.args, "secure_link_psk", "") or "")),
            "secure_link_required": bool(getattr(self.args, "secure_link_require", False)),
            "admin_auth_recommended": True,
            "own_servers": own_services,
            "remote_servers": remote_services,
        }
        token = self._encode_onboarding_token(payload_doc)
        payload = {"ok": True, "invite_token": token, "preview": payload_doc}
        self._log_api_response("/api/onboarding/invite/generate", 200, {"ok": True}, summary=f"connection_id={connection_id or '-'}")
        await self._send_json(writer, 200, payload)

    async def _handle_onboarding_invite_preview(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        token = str(req.get("invite_token", "") or "").strip()
        if not token:
            await self._send_json(writer, 400, {"ok": False, "error": "invite_token is required"})
            return
        try:
            payload_doc = self._decode_onboarding_token(token)
        except Exception as exc:
            await self._send_json(writer, 400, {"ok": False, "error": str(exc)})
            return
        updates = self._onboarding_updates_from_invite(payload_doc)
        preview_doc = dict(payload_doc)
        if isinstance(preview_doc.get("secure_link_psk"), str) and preview_doc.get("secure_link_psk"):
            preview_doc["secure_link_psk"] = "***hidden***"
            preview_doc["secure_link_psk_present"] = True
        payload = {"ok": True, "preview": preview_doc, "suggested_updates": updates}
        self._log_api_response("/api/onboarding/invite/preview", 200, {"ok": True}, summary=f"updates={len(updates)}")
        await self._send_json(writer, 200, payload)

    async def _handle_onboarding_blueprints(self, writer, method: str):
        if method != "GET":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        blueprints = self._build_onboarding_blueprints()
        payload = {"ok": True, "count": len(blueprints), "blueprints": blueprints}
        self._log_api_response("/api/onboarding/blueprints", 200, payload, summary=f"count={len(blueprints)}")
        await self._send_json(writer, 200, payload)

    def _build_meta_payload(self) -> dict:
        platform = _admin_ui_platform()
        return {
            "app": "udp-bidirectional-mux",
            "pid": os.getpid(),
            "uptime_sec": int(time.monotonic() - self.started_monotonic),
            "admin_web_name": str(getattr(self.runner.args, "admin_web_name", "") or ""),
            "overlay_transport": getattr(self.runner.args, "overlay_transport", None),
            "dashboard_enabled": getattr(self.runner.args, "dashboard", None),
            "milestone": "C",
            "build": _detect_build_info(),
            "runtime_dependencies": _runtime_dependency_status_for_platform(platform),
            "crypto_extract": available_crypto_extract(),
        }

    async def _handle_meta(self, writer):
        payload = self._build_meta_payload()
        self._log_api_response("/api/meta", 200, payload)
        await self._send_json(writer, 200, payload)

    async def _handle_config(self, writer, method: str, body: bytes):
        if method == "GET":
            payload = {
                "ok": True,
                "config": self.runner.get_config_snapshot(),
                "schema": self.runner.get_config_schema_snapshot(),
            }
            self._log_api_response("/api/config", 200, payload, summary="config snapshot")
            await self._send_json(writer, 200, payload)
            return

        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        updates = req.get("updates", {})
        restart_after_save = bool(req.get("restart_after_save", False))
        if self.auth_required():
            challenge_id = str(req.get("challenge_id", "") or "").strip()
            proof = str(req.get("proof", "") or "").strip().lower()
            if not challenge_id or not proof:
                await self._send_json(writer, 428, {"ok": False, "error": "configuration change confirmation required"})
                return
            self._prune_auth_state()
            challenge = self._config_challenges.pop(challenge_id, None)
            if not challenge:
                await self._send_json(writer, 403, {"ok": False, "error": "invalid or expired configuration change challenge"})
                return
            if not isinstance(updates, dict):
                await self._send_json(writer, 400, {"ok": False, "error": "updates must be an object"})
                return
            updates_digest = self._build_config_update_digest(updates)
            if updates_digest != str(challenge.get("updates_digest", "") or ""):
                await self._send_json(writer, 403, {"ok": False, "error": "configuration update payload mismatch"})
                return
            expected = self._build_config_change_response(
                str(challenge.get("seed", "") or ""),
                str(getattr(self.args, "admin_web_username", "") or ""),
                str(getattr(self.args, "admin_web_password", "") or ""),
                updates_digest,
            )
            if proof != expected:
                await self._send_json(writer, 403, {"ok": False, "error": "configuration change confirmation failed"})
                return
        ok, err = self.runner.update_config(updates)
        if not ok:
            logging.getLogger("obstacle_bridge.admin_web").error(
                "configuration update failed error=%s updates_keys=%s crypto_extract=%r build=%r",
                err,
                sorted(updates.keys()) if isinstance(updates, dict) else [],
                available_crypto_extract(),
                _detect_build_info(),
            )
            await self._send_json(writer, 400, {"ok": False, "error": err})
            return
        if any(key in AdminWebUI._secret_config_keys() or key in {"admin_web_auth_disable", "admin_web_username"} for key in updates.keys()):
            self.reset_auth_state()
        delay_restart = bool(self.runner._restart_requires_delay()) if restart_after_save else False
        payload = {
            "ok": True,
            "config": self.runner.get_config_snapshot(),
            "restart_requested": bool(restart_after_save),
            "restart_mode": "delayed" if delay_restart else ("immediate" if restart_after_save else ""),
            "restart_delay_sec": 40 if delay_restart else 0,
        }
        self._log_api_response(
            "/api/config",
            200,
            payload,
            summary=f"updated keys={list(updates.keys())} restart_after_save={restart_after_save}",
        )
        await self._send_json(writer, 200, payload)
        if restart_after_save:
            self.runner.request_restart()

    async def _handle_logs(self, writer, raw_path: str):
        limit = 400
        with contextlib.suppress(Exception):
            if "?" in raw_path:
                query = raw_path.split("?", 1)[1]
                for pair in query.split("&"):
                    if not pair:
                        continue
                    k, _, v = pair.partition("=")
                    if k == "limit":
                        limit = int(v)
                        break
        lines = self.runner.get_debug_logs(limit=limit)
        payload = {"ok": True, "lines": lines, "count": len(lines)}
        self._log_api_response("/api/logs", 200, payload, summary=f"count={len(lines)}")
        await self._send_json(writer, 200, payload)

    async def _handle_secure_link_rekey(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        target_peer_id = str(req.get("peer_id", "") or "").strip()
        if not target_peer_id:
            await self._send_json(writer, 400, {"ok": False, "error": "peer_id is required"})
            return
        payload = self.runner.request_secure_link_rekey(target_peer_id=target_peer_id)
        code = 200 if bool(payload.get("ok")) else 409
        self._log_api_response(
            "/api/secure-link/rekey",
            code,
            payload,
            summary=f"peer_id={target_peer_id} requested={payload.get('requested', 0)} skipped={payload.get('skipped', 0)}",
        )
        await self._send_json(writer, code, payload)

    async def _handle_secure_link_reload(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        scope = str(req.get("scope", "") or "").strip().lower()
        if scope not in {"revocation", "local_identity", "all"}:
            await self._send_json(writer, 400, {"ok": False, "error": "scope must be one of revocation, local_identity, all"})
            return
        target_peer_id = str(req.get("peer_id", "") or "").strip()
        payload = self.runner.request_secure_link_reload(scope=scope, target_peer_id=target_peer_id or None)
        code = 200 if bool(payload.get("ok")) else 409
        self._log_api_response(
            "/api/secure-link/reload",
            code,
            payload,
            summary=f"scope={scope} target_peer_id={target_peer_id or '-'} reloaded={payload.get('reloaded', 0)} dropped={payload.get('dropped', 0)} failed={payload.get('failed', 0)}",
        )
        await self._send_json(writer, code, payload)

    def _build_peers_payload(self) -> dict:
        payload = self.runner.get_peer_connections_snapshot()
        payload["ok"] = True
        return payload

    async def _handle_peers(self, writer):
        payload = self._build_peers_payload()
        self._log_api_response("/api/peers", 200, payload, summary=f"count={payload.get('count', 0)}")
        await self._send_json(writer, 200, payload)

    async def _handle_restart(self, writer, method, headers):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        token = getattr(self.args, "admin_web_token", "") or ""
        if token:
            auth = headers.get("authorization", "")
            expected = f"Bearer {token}"
            if auth != expected:
                await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
                return

        embedded_restart = callable(getattr(self.runner, "_embedded_restart_callback", None))
        delay_restart = False if embedded_restart else bool(self.runner._restart_requires_delay())
        payload = {
            "ok": True,
            "restarting": True,
            "restart_embedded": embedded_restart,
            "restart_mode": "delayed" if delay_restart else "immediate",
            "restart_delay_sec": 40 if delay_restart else 0,
        }
        self._log_api_response("/api/restart", 200, payload)
        logging.getLogger("obstacle_bridge.admin_web").warning(
            "restart requested embedded=%s mode=%s build=%r",
            embedded_restart,
            payload.get("restart_mode"),
            _detect_build_info(),
        )
        await self._send_json(writer, 200, payload)
        self.runner.request_restart()

    async def _handle_reconnect(self, writer, method, headers, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        token = getattr(self.args, "admin_web_token", "") or ""
        if token:
            auth = headers.get("authorization", "")
            expected = f"Bearer {token}"
            if auth != expected:
                await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
                return

        req = {}
        if body:
            try:
                req = json.loads((body or b"{}").decode("utf-8"))
            except Exception:
                await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
                return
        target_peer_id = str(req.get("peer_id", "") or "").strip() or None
        payload = self.runner.request_overlay_reconnect(target_peer_id=target_peer_id)
        code = 200 if bool(payload.get("ok")) else (404 if payload.get("reason") == "unknown_peer_id" else 409)
        self._log_api_response(
            "/api/reconnect",
            code,
            payload,
            summary=(
                f"target_peer_id={target_peer_id or '-'} "
                f"requested={payload.get('requested', 0)} sessions={payload.get('sessions', 0)} "
                f"transports={','.join(payload.get('transports', []))}"
            ),
        )
        await self._send_json(writer, code, payload)

    async def _handle_shutdown(self, writer, method, headers):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        token = getattr(self.args, "admin_web_token", "") or ""
        if token:
            auth = headers.get("authorization", "")
            expected = f"Bearer {token}"
            if auth != expected:
                await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
                return

        payload = {"ok": True, "shutting_down": True}
        self._log_api_response("/api/shutdown", 200, payload)
        await self._send_json(writer, 200, payload)

        # let response flush before stopping (non-restart exit code)
        asyncio.get_running_loop().call_soon(self.runner.request_shutdown, 76)

    @staticmethod
    def _secret_config_keys() -> Set[str]:
        return {"admin_web_password", "secure_link_psk"}

    @staticmethod
    def _readonly_config_keys() -> Set[str]:
        # Keep this set minimal: `secure_link_psk` is intentionally secret
        # but it should be settable (write-only) by the admin UI like
        # `admin_web_password`. Returning an empty set keeps keys writable
        # while secret keys are still masked in GET snapshots.
        return set()

    def auth_required(self) -> bool:
        if bool(getattr(self.args, "admin_web_auth_disable", False)):
            return False
        username = str(getattr(self.args, "admin_web_username", "") or "")
        password = str(getattr(self.args, "admin_web_password", "") or "")
        return bool(username and password)

    def reset_auth_state(self) -> None:
        self._auth_challenges.clear()
        self._auth_sessions.clear()
        self._config_challenges.clear()
        self._secret_reveal_challenges.clear()

    def _prune_auth_state(self) -> None:
        now = time.time()
        expired_challenges = [key for key, item in self._auth_challenges.items() if float(item.get("expires_at", 0.0)) <= now]
        for key in expired_challenges:
            self._auth_challenges.pop(key, None)
        expired_sessions = [key for key, expires_at in self._auth_sessions.items() if float(expires_at) <= now]
        for key in expired_sessions:
            self._auth_sessions.pop(key, None)
        expired_config_challenges = [key for key, item in self._config_challenges.items() if float(item.get("expires_at", 0.0)) <= now]
        for key in expired_config_challenges:
            self._config_challenges.pop(key, None)
        expired_config_challenges = [key for key, item in self._config_challenges.items() if float(item.get("expires_at", 0.0)) <= now]
        for key in expired_config_challenges:
            self._config_challenges.pop(key, None)
        expired_reveal_challenges = [key for key, item in self._secret_reveal_challenges.items() if float(item.get("expires_at", 0.0)) <= now]
        for key in expired_reveal_challenges:
            self._secret_reveal_challenges.pop(key, None)

    def _parse_cookie_header(self, headers: dict) -> Dict[str, str]:
        raw = str(headers.get("cookie", "") or "")
        cookies: Dict[str, str] = {}
        for part in raw.split(";"):
            item = part.strip()
            if not item or "=" not in item:
                continue
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()
        return cookies

    def _session_cookie_name(self) -> str:
        scope = "|".join([
            str(getattr(self.args, "admin_web_bind", "") or ""),
            str(getattr(self.args, "admin_web_port", "") or ""),
            str(getattr(self.args, "admin_web_path", "") or ""),
        ])
        suffix = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:12]
        return f"admin_web_session_{suffix}"

    @staticmethod
    def _is_loopback_host(value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        lowered = text.lower().strip("[]")
        if lowered in {"localhost", "ip6-localhost"}:
            return True
        try:
            return bool(ipaddress.ip_address(lowered).is_loopback)
        except Exception:
            return False

    def _build_security_advisor_payload(self) -> dict:
        enabled = not bool(getattr(self.args, "admin_web_security_advisor_disable", False))
        bind = str(getattr(self.args, "admin_web_bind", "") or "").strip()
        admin_local_only = self._is_loopback_host(bind)
        secure_mode = str(getattr(self.args, "secure_link_mode", "off") or "off").strip().lower()
        secure_psk = str(getattr(self.args, "secure_link_psk", "") or "")
        auth_disabled = bool(getattr(self.args, "admin_web_auth_disable", False))
        findings: List[dict] = []
        if enabled:
            if bool(getattr(self.args, "admin_web", False)):
                if auth_disabled:
                    admin_message = (
                        "Admin Web password protection is recommended even on localhost-only setups. Enable admin authentication in the configuration unless you intentionally want friction-free local access."
                        if admin_local_only
                        else "Admin Web is reachable beyond localhost and admin authentication is disabled in the configuration. This should be treated as a warning. Enable admin authentication or bind Admin Web to localhost."
                    )
                    findings.append({
                        "id": "admin_auth_disabled",
                        "severity": "warning" if not admin_local_only else "recommended",
                        "title": "Protect Admin Web",
                        "message": admin_message,
                        "action_label": "Open Configuration",
                        "action_target": "configuration",
                    })
            if secure_mode in {"", "off", "none"}:
                findings.append({
                    "id": "secure_link_disabled",
                    "severity": "warning" if not admin_local_only else "recommended",
                    "title": "Enable SecureLink",
                    "message": (
                        "SecureLink is currently disabled. That can be acceptable for localhost-only or lab-style setups, but enabling SecureLink is still recommended."
                        if admin_local_only
                        else "This node is not localhost-only and SecureLink is currently disabled. Running without SecureLink should be treated as a warning. Start with PSK for quick protection or move to certificates for deployment-grade trust."
                    ),
                    "action_label": "Open Secure-Link",
                    "action_target": "secure-link",
                })
            elif secure_mode == "psk":
                if len(secure_psk.strip()) < 12:
                    findings.append({
                        "id": "secure_link_psk_weak",
                        "severity": "recommended",
                        "title": "Strengthen PSK",
                        "message": "SecureLink PSK is enabled, but the configured secret looks short. Use a stronger shared secret for better protection.",
                        "action_label": "Open Configuration",
                        "action_target": "configuration",
                    })
                findings.append({
                    "id": "secure_link_cert_followup",
                    "severity": "informational",
                    "title": "Plan Certificate Trust",
                    "message": "PSK is a good quick-start protection mode. For longer-lived deployments, certificate-based SecureLink provides a stronger operational trust model.",
                    "action_label": "Open Secure-Link",
                    "action_target": "secure-link",
                })
        highest = "informational"
        for level in ("critical", "warning", "recommended", "informational"):
            if any(str(item.get("severity", "")).lower() == level for item in findings):
                highest = level
                break
        summary = "Security advisor disabled."
        if enabled:
            if not findings:
                summary = "Current settings look reasonably hardened for this first implementation slice."
            else:
                if highest == "critical":
                    summary = "Security advisor found settings that should be addressed before wider exposure."
                elif highest == "warning":
                    summary = "Security advisor found warning-level hardening issues for this node."
                elif highest == "recommended":
                    summary = "Security advisor found recommended hardening steps for this node."
                else:
                    summary = "Security advisor found optional follow-up improvements."
        return {
            "enabled": enabled,
            "summary": summary,
            "highest_severity": highest,
            "findings": findings,
        }

    def _build_admin_ui_payload(self) -> dict:
        platform = _admin_ui_platform()
        return {
            "home_tab_enabled": True,
            "landing_page_enabled": False,
            "security_advisor_enabled": not bool(getattr(self.args, "admin_web_security_advisor_disable", False)),
            "security_advisor_startup_enabled": not bool(getattr(self.args, "admin_web_security_advisor_startup_disable", False)),
            "first_tab": str(getattr(self.args, "admin_web_first_tab", "home") or "home"),
            "first_start_detected": bool(getattr(self.args, "_first_start_detected", False)),
            "config_file_state": str(getattr(self.args, "_config_file_state", "unknown") or "unknown"),
            "platform": platform,
            "runtime_dependencies": _runtime_dependency_status_for_platform(platform),
        }

    def _is_authenticated(self, headers: dict) -> bool:
        if not self.auth_required():
            return True
        self._prune_auth_state()
        token = self._parse_cookie_header(headers).get(self._session_cookie_name(), "")
        return bool(token and token in self._auth_sessions)

    def _build_auth_seed(self, challenge_id: str) -> str:
        return secrets.token_hex(32) + challenge_id

    def _build_auth_response(self, seed: str, username: str, password: str) -> str:
        msg = f"{seed}:{username}:{password}".encode("utf-8")
        return hashlib.sha256(msg).hexdigest()

    @staticmethod
    def _canonical_config_update_json(updates: dict) -> str:
        return json.dumps(updates, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _build_config_update_digest(self, updates: dict) -> str:
        canonical = self._canonical_config_update_json(updates if isinstance(updates, dict) else {})
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _build_config_change_seed(self, challenge_id: str) -> str:
        return secrets.token_hex(32) + challenge_id

    def _build_config_change_response(self, seed: str, username: str, password: str, updates_digest: str) -> str:
        msg = f"{seed}:{username}:{password}:{updates_digest}".encode("utf-8")
        return hashlib.sha256(msg).hexdigest()

    def _build_secret_reveal_seed(self, challenge_id: str) -> str:
        return secrets.token_hex(32) + challenge_id

    def _build_secret_reveal_response(self, seed: str, username: str, password: str, secret_name: str) -> str:
        msg = f"{seed}:{username}:{password}:{secret_name}".encode("utf-8")
        return hashlib.sha256(msg).hexdigest()

    def _issue_config_challenge(self, updates: dict) -> dict:
        self._prune_auth_state()
        challenge_id = secrets.token_hex(16)
        seed = self._build_config_change_seed(challenge_id)
        updates_digest = self._build_config_update_digest(updates)
        self._config_challenges[challenge_id] = {
            "seed": seed,
            "updates_digest": updates_digest,
            "expires_at": time.time() + self.CONFIG_CHALLENGE_TTL_SEC,
        }
        return {
            "challenge_id": challenge_id,
            "seed": seed,
            "updates_digest": updates_digest,
        }

    def _issue_secret_reveal_challenge(self, secret_name: str) -> dict:
        self._prune_auth_state()
        challenge_id = secrets.token_hex(16)
        seed = self._build_secret_reveal_seed(challenge_id)
        self._secret_reveal_challenges[challenge_id] = {
            "seed": seed,
            "secret_name": secret_name,
            "expires_at": time.time() + self.CONFIG_CHALLENGE_TTL_SEC,
        }
        return {
            "challenge_id": challenge_id,
            "seed": seed,
            "secret_name": secret_name,
        }

    def _encrypt_admin_secret_for_reveal(self, secret_name: str, secret_value: str) -> dict:
        password = str(getattr(self.args, "admin_web_password", "") or "")
        if AESGCM is None or hashes is None or PBKDF2HMAC is None:
            raise RuntimeError("admin secret reveal encryption requires cryptography")
        if not self.auth_required() or not password:
            raise ValueError("admin password authentication is required to reveal secrets")
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ADMIN_SECRET_REVEAL_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        aad = ADMIN_SECRET_REVEAL_AAD + b":" + secret_name.encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, str(secret_value or "").encode("utf-8"), aad)
        return {
            "algorithm": "AES-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": ADMIN_SECRET_REVEAL_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "aad": base64.b64encode(aad).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _issue_session_headers(self) -> List[Tuple[str, str]]:
        token = secrets.token_hex(32)
        self._auth_sessions[token] = time.time() + self.AUTH_SESSION_TTL_SEC
        cookie = f"{self._session_cookie_name()}={token}; Path=/; HttpOnly; SameSite=Strict"
        return [("Set-Cookie", cookie)]

    async def _handle_auth_state(self, writer, headers: dict):
        payload = {
            "ok": True,
            "auth_required": self.auth_required(),
            "authenticated": self._is_authenticated(headers),
        }
        self._log_api_response("/api/auth/state", 200, payload)
        await self._send_json(writer, 200, payload)

    async def _handle_auth_challenge(self, writer, method: str):
        if method != "GET":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": True, "auth_required": False}
            self._log_api_response("/api/auth/challenge", 200, payload, summary="auth disabled")
            await self._send_json(writer, 200, payload)
            return
        self._prune_auth_state()
        challenge_id = secrets.token_hex(16)
        seed = self._build_auth_seed(challenge_id)
        self._auth_challenges[challenge_id] = {
            "seed": seed,
            "expires_at": time.time() + self.AUTH_CHALLENGE_TTL_SEC,
        }
        payload = {
            "ok": True,
            "auth_required": True,
            "challenge_id": challenge_id,
            "seed": seed,
            "algorithm": "sha256(seed:username:password)",
        }
        self._log_api_response("/api/auth/challenge", 200, {"ok": True, "auth_required": True}, summary="issued challenge")
        await self._send_json(writer, 200, payload)

    async def _handle_auth_login(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": True, "auth_required": False, "authenticated": True}
            await self._send_json(writer, 200, payload, headers=self._issue_session_headers())
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        challenge_id = str(req.get("challenge_id", "") or "")
        proof = str(req.get("proof", "") or "").strip().lower()
        self._prune_auth_state()
        challenge = self._auth_challenges.pop(challenge_id, None)
        if not challenge:
            payload = {"ok": False, "authenticated": False, "error": "invalid or expired challenge"}
            self._log_api_response("/api/auth/login", 403, payload, summary="invalid challenge")
            await self._send_json(writer, 403, payload)
            return
        expected = self._build_auth_response(
            str(challenge.get("seed", "") or ""),
            str(getattr(self.args, "admin_web_username", "") or ""),
            str(getattr(self.args, "admin_web_password", "") or ""),
        )
        if proof != expected:
            payload = {"ok": False, "authenticated": False, "error": "authentication failed"}
            self._log_api_response("/api/auth/login", 403, payload, summary="bad proof")
            await self._send_json(writer, 403, payload)
            return
        payload = {"ok": True, "authenticated": True}
        self._log_api_response("/api/auth/login", 200, payload, summary="authenticated")
        await self._send_json(writer, 200, payload, headers=self._issue_session_headers())

    async def _handle_config_challenge(self, writer, method: str, headers: dict, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": True, "auth_required": False}
            self._log_api_response("/api/config/challenge", 200, payload, summary="auth disabled")
            await self._send_json(writer, 200, payload)
            return
        if not self._is_authenticated(headers):
            payload = {"ok": False, "authenticated": False, "error": "authentication required"}
            self._log_api_response("/api/config/challenge", 401, payload, summary="auth required")
            await self._send_json(writer, 401, payload)
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        updates = req.get("updates", {})
        if not isinstance(updates, dict):
            await self._send_json(writer, 400, {"ok": False, "error": "updates must be an object"})
            return
        payload = {"ok": True, "auth_required": True, **self._issue_config_challenge(updates)}
        self._log_api_response(
            "/api/config/challenge",
            200,
            {"ok": True, "auth_required": True, "updates_digest": payload["updates_digest"]},
            summary="issued config change challenge",
        )
        await self._send_json(writer, 200, payload)

    async def _handle_config_secret_secure_link_psk_challenge(self, writer, method: str, headers: dict):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": False, "error": "admin password authentication is required to reveal secure_link_psk"}
            self._log_api_response("/api/config/secret/secure-link-psk/challenge", 403, payload, summary="auth disabled")
            await self._send_json(writer, 403, payload)
            return
        if not self._is_authenticated(headers):
            payload = {"ok": False, "authenticated": False, "error": "authentication required"}
            self._log_api_response("/api/config/secret/secure-link-psk/challenge", 401, payload, summary="auth required")
            await self._send_json(writer, 401, payload)
            return
        payload = {"ok": True, "auth_required": True, **self._issue_secret_reveal_challenge("secure_link_psk")}
        self._log_api_response(
            "/api/config/secret/secure-link-psk/challenge",
            200,
            {"ok": True, "auth_required": True, "secret_name": "secure_link_psk"},
            summary="issued secret reveal challenge",
        )
        await self._send_json(writer, 200, payload)

    async def _handle_config_secret_secure_link_psk(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": False, "error": "admin password authentication is required to reveal secure_link_psk"}
            self._log_api_response("/api/config/secret/secure-link-psk", 403, payload, summary="auth disabled")
            await self._send_json(writer, 403, payload)
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        challenge_id = str(req.get("challenge_id", "") or "").strip()
        proof = str(req.get("proof", "") or "").strip().lower()
        if not challenge_id or not proof:
            await self._send_json(writer, 428, {"ok": False, "error": "secure_link_psk reveal confirmation required"})
            return
        self._prune_auth_state()
        challenge = self._secret_reveal_challenges.pop(challenge_id, None)
        if not challenge:
            await self._send_json(writer, 403, {"ok": False, "error": "invalid or expired secure_link_psk reveal challenge"})
            return
        secret_name = str(challenge.get("secret_name", "") or "")
        if secret_name != "secure_link_psk":
            await self._send_json(writer, 403, {"ok": False, "error": "secret reveal payload mismatch"})
            return
        expected = self._build_secret_reveal_response(
            str(challenge.get("seed", "") or ""),
            str(getattr(self.args, "admin_web_username", "") or ""),
            str(getattr(self.args, "admin_web_password", "") or ""),
            secret_name,
        )
        if proof != expected:
            await self._send_json(writer, 403, {"ok": False, "error": "secure_link_psk reveal confirmation failed"})
            return
        try:
            envelope = self._encrypt_admin_secret_for_reveal(secret_name, str(getattr(self.args, "secure_link_psk", "") or ""))
        except Exception as e:
            await self._send_json(writer, 500, {"ok": False, "error": str(e)})
            return
        payload = {"ok": True, "secret_name": secret_name, "encrypted": envelope}
        self._log_api_response(
            "/api/config/secret/secure-link-psk",
            200,
            {"ok": True, "secret_name": secret_name, "encrypted": {"algorithm": envelope.get("algorithm")}},
            summary="encrypted secret reveal",
        )
        await self._send_json(writer, 200, payload)

    async def _handle_auth_logout(self, writer, method: str, headers: dict):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        token = self._parse_cookie_header(headers).get(self._session_cookie_name(), "")
        if token:
            self._auth_sessions.pop(token, None)
        payload = {"ok": True, "authenticated": False}
        self._log_api_response("/api/auth/logout", 200, payload)
        await self._send_json(
            writer,
            200,
            payload,
            headers=[("Set-Cookie", f"{self._session_cookie_name()}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")],
        )

    def _resolve_static_base(self) -> pathlib.Path:
        configured = pathlib.Path(str(getattr(self.args, "admin_web_dir", "") or "./admin_web")).expanduser()
        candidates = [configured]

        package_static = pathlib.Path(__file__).resolve().parent / "admin_web"
        if package_static not in candidates:
            candidates.append(package_static)

        repo_static = pathlib.Path(__file__).resolve().parents[2] / "admin_web"
        if repo_static not in candidates:
            candidates.append(repo_static)

        for candidate in candidates:
            resolved = candidate.resolve()
            index = resolved / "index.html"
            if resolved.is_dir() and index.is_file():
                return resolved

        return configured.resolve()

    async def _handle_static(self, writer, req_path):
        base = self._resolve_static_base()

        if req_path in ("", "/"):
            req_path = "/index.html"

        # Milestone A: admin_web_path is accepted as CLI/config, but static routing
        # is intentionally kept simple. If you later want to support mounting below
        # /admin/ or similar, normalize req_path here.

        rel = req_path.lstrip("/")
        full = (base / rel).resolve()

        if not str(full).startswith(str(base)):
            await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
            return

        if not full.exists() or not full.is_file():
            await self._send(writer, 404, b"Not Found", "text/plain; charset=utf-8")
            return

        data = full.read_bytes()
        ctype, _ = mimetypes.guess_type(str(full))
        await self._send(
            writer,
            200,
            data,
            ctype or "application/octet-stream",
        )

    def _build_status_payload(self) -> dict:
        payload = self.runner.get_status_snapshot()
        for aggregate_key in ("open_connections", "traffic", "compress_layer"):
            payload.pop(aggregate_key, None)
        payload["admin_web_name"] = str(getattr(self.runner.args, "admin_web_name", "") or "")
        payload["uptime_sec"] = int(time.monotonic() - self.started_monotonic)
        payload["app"] = "udp-bidirectional-mux"
        payload["milestone"] = "B"
        payload["admin_ui"] = self._build_admin_ui_payload()
        payload["security_advisor"] = self._build_security_advisor_payload()
        payload["build"] = _detect_build_info()
        return payload

    async def _handle_status(self, writer):
        payload = self._build_status_payload()
        self._log_api_response("/api/status", 200, payload)
        await self._send_json(writer, 200, payload)

    def _live_topic_interval_s(self, topic: str) -> float:
        t = str(topic or "").strip().lower()
        if t == "meta":
            return 5.0
        return 1.0

    def _live_topic_payload(self, topic: str) -> Optional[dict]:
        t = str(topic or "").strip().lower()
        if t == "status":
            return self._build_status_payload()
        if t == "connections":
            return self._build_connections_payload()
        if t == "peers":
            return self._build_peers_payload()
        if t == "meta":
            return self._build_meta_payload()
        return None

    def _parse_live_topics(self, value: Any) -> Set[str]:
        topics: Set[str] = set()
        if isinstance(value, str):
            value = [value]
        if isinstance(value, (list, tuple, set)):
            for item in value:
                topic = str(item or "").strip().lower()
                if topic in self.LIVE_TOPICS:
                    topics.add(topic)
        return topics

    async def _handle_live_websocket(self, reader, writer, headers: dict) -> None:
        key = str(headers.get("sec-websocket-key", "") or "").strip()
        version = str(headers.get("sec-websocket-version", "") or "").strip()
        if not key or version != "13":
            await self._send(writer, 400, b"Bad WebSocket Request", "text/plain; charset=utf-8")
            return
        accept = base64.b64encode(
            hashlib.sha1((key + self.LIVE_WS_GUID).encode("utf-8")).digest()
        ).decode("ascii")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(response)
        await writer.drain()

        topics: Set[str] = {"status", "connections", "peers", "meta"}
        next_due: Dict[str, float] = {topic: 0.0 for topic in self.LIVE_TOPICS}
        await self._send_ws_json(
            writer,
            {
                "type": "hello",
                "topics": sorted(topics),
                "intervals_sec": {topic: self._live_topic_interval_s(topic) for topic in self.LIVE_TOPICS},
            },
        )
        while True:
            now = time.monotonic()
            if topics:
                wait_s = min(max(0.0, next_due.get(topic, 0.0) - now) for topic in topics)
            else:
                wait_s = 30.0
            incoming = None
            try:
                incoming = await asyncio.wait_for(self._recv_ws_message(reader, writer), timeout=wait_s)
            except asyncio.TimeoutError:
                incoming = None
            if incoming is False:
                return
            if isinstance(incoming, str):
                try:
                    msg = json.loads(incoming)
                except Exception:
                    msg = {}
                requested = self._parse_live_topics(msg.get("subscribe"))
                if requested:
                    topics = requested
                active_tabs = set(str(item or "").strip().lower() for item in (msg.get("active_tabs") or []))
                if active_tabs:
                    next_topics: Set[str] = {"status"}
                    if "status" in active_tabs:
                        next_topics.update({"connections", "peers"})
                    if "misc" in active_tabs:
                        next_topics.add("meta")
                    topics = next_topics
                request_topics = self._parse_live_topics(msg.get("request"))
                for topic in sorted(request_topics):
                    payload = self._live_topic_payload(topic)
                    if payload is None:
                        continue
                    await self._send_ws_json(writer, {"type": topic, "data": payload})
                    next_due[topic] = time.monotonic() + self._live_topic_interval_s(topic)
            now = time.monotonic()
            for topic in sorted(topics):
                if now < next_due.get(topic, 0.0):
                    continue
                payload = self._live_topic_payload(topic)
                if payload is None:
                    continue
                await self._send_ws_json(writer, {"type": topic, "data": payload})
                next_due[topic] = now + self._live_topic_interval_s(topic)

    async def _recv_ws_message(self, reader, writer) -> Any:
        try:
            hdr = await reader.readexactly(2)
        except asyncio.IncompleteReadError:
            return False
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            ext = await reader.readexactly(2)
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = await reader.readexactly(8)
            length = struct.unpack("!Q", ext)[0]
        mask_key = await reader.readexactly(4) if masked else b""
        payload = await reader.readexactly(length) if length else b""
        if masked and mask_key:
            payload = bytes(b ^ mask_key[idx % 4] for idx, b in enumerate(payload))
        if opcode == 0x8:
            with contextlib.suppress(Exception):
                await self._send_ws_frame(writer, 0x8, payload)
            return False
        if opcode == 0x9:
            with contextlib.suppress(Exception):
                await self._send_ws_frame(writer, 0xA, payload)
            return None
        if opcode == 0xA:
            return None
        if opcode != 0x1:
            return None
        return payload.decode("utf-8", "replace")

    async def _send_ws_json(self, writer, obj: dict) -> None:
        await self._send_ws_frame(
            writer,
            0x1,
            json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        )

    async def _send_ws_frame(self, writer, opcode: int, payload: bytes = b"") -> None:
        data = payload or b""
        first = 0x80 | (opcode & 0x0F)
        length = len(data)
        if length < 126:
            header = bytes([first, length])
        elif length < (1 << 16):
            header = bytes([first, 126]) + struct.pack("!H", length)
        else:
            header = bytes([first, 127]) + struct.pack("!Q", length)
        writer.write(header + data)
        await writer.drain()

    def _json_one_line(self, payload) -> str:
        try:
            txt = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception as e:
            txt = f"<json-encode-failed {e!r}>"
        if len(txt) > 4000:
            txt = txt[:4000] + "...<truncated>"
        return txt

    def _log_api_response(self, path: str, status: int, payload, *, summary: Optional[str] = None) -> None:
        if summary:
            self.log.info(
                "ADMIN RESPONSE path=%s status=%d summary=%s payload=%s",
                path,
                status,
                summary,
                self._json_one_line(payload),
            )
        else:
            self.log.info(
                "ADMIN RESPONSE path=%s status=%d payload=%s",
                path,
                status,
                self._json_one_line(payload),
            )

    async def _send_json(self, writer, code, obj, headers: Optional[List[Tuple[str, str]]] = None):
        data = json.dumps(obj, indent=2).encode("utf-8")
        await self._send(writer, code, data, "application/json; charset=utf-8", headers=headers)

    async def _send(self, writer, code, data, content_type, headers: Optional[List[Tuple[str, str]]] = None):
        reason = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(code, "OK")

        hdr = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"Connection: close\r\n"
            f"Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
            f"Pragma: no-cache\r\n"
            f"Expires: 0\r\n"
        )
        extra = ""
        for key, value in (headers or []):
            extra += f"{key}: {value}\r\n"
        hdr = (hdr + extra + "\r\n").encode("utf-8")

        writer.write(hdr + data)
        await writer.drain()


# ------------ Runtime argument helpers / CLI ------------
# ============================ ConfigAwareCLI (JSON) ===========================
import os, json, argparse, pathlib, sys
from typing import Any, Dict, List, Tuple, Callable, Optional, Set, Mapping, Sequence

