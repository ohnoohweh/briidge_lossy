from __future__ import annotations

from ._bridge_import import export_bridge_globals

_bridge = export_bridge_globals(globals())

if sys.platform.startswith("linux"):
    from . import bridge_tun_linux as _bridge_tun_platform
elif sys.platform.startswith("win"):
    from . import bridge_tun_windows as _bridge_tun_platform
elif sys.platform.startswith("darwin"):
    from . import bridge_tun_macos as _bridge_tun_platform
elif sys.platform == "ios":
    from . import bridge_tun_ios as _bridge_tun_platform
else:
    _bridge_tun_platform = None

from .bridge_tun_routing import TunRoutingSettings

class _ChanCtr:
    msgs_in: int = 0
    msgs_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    crc_in: int = 0
    crc_out: int = 0

# ============================================================================
# ============================
# Multi-service ChannelMux (v3 control payloads)
# ============================
# Single source of truth for front-end servers:
# --own-servers "tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666"
#
# OPEN v4 binary payload (no backward compatibility):
# +------+--------+----------+----------+-----------+----------+
# | 'O4' | instance_id | conn_seq | svc_id | l_proto | bind_len | bind[...] | l_port | r_proto | host_len | host[...] | r_port |
# +------+--------+----------+----------+-----------+----------+
#   2B       u64         u32      u16      u8        u8        bytes       u16
#
# Features retained and extended:
# - Unconnected UDP server socket per service (AF_UNSPEC), serve many remote (addr,port)
# - UDP idle timeout 20s (no RX or TX) per (svc_id, addr) and per client-side chan
# - TCP backpressure per channel (size/time-based drain)
# - Per-channel counters (msgs/bytes + CRC32 in/out), detailed DEBUG logs
# - Safe read sizes (<= SAFE_TCP_READ == 65535-8)
# - Listener self-healing (_ensure_servers_task): auto-restart closed/broken servers
#
# Dependencies assumed available above in file:
#   Proto, MType, MUX_HDR, SAFE_TCP_READ, _pack_mux, _unpack_mux
#   plus imports: asyncio, logging, socket, struct, time, zlib


class ChannelMux:
    """Catalog-based multiplexer with multiple TCP/UDP/TUN services and peer-side dynamic dialers."""
    ProtoName = Literal["tcp", "udp", "tun"]
    ServiceOrigin = Literal["local", "peer"]
    ServiceKey = Tuple[ServiceOrigin, int, int]  # (origin, peer_id, svc_id)

    class Proto(enum.IntEnum):
        UDP = 0
        TCP = 1
        TUN = 2

    class MType(enum.IntEnum):
        DATA = 0
        OPEN = 1  # TCP only
        CLOSE = 2  # TCP only
        REMOTE_SERVICES_SET_V1 = 3  # legacy control plane
        REMOTE_SERVICES_SET_V2 = 4  # control plane: peer installs listener catalog
        DATA_FRAG = 5  # UDP service datagram fragment
        REMOTE_SERVICES_SET_V2_CHUNK = 6  # chunked control payload for oversized REMOTE_SERVICES_SET_V2
        OPEN_CHUNK = 7  # chunked control payload for oversized OPEN

    @dataclass(frozen=True)
    class ServiceSpec:
        svc_id: int
        l_proto: "ChannelMux.ProtoName"
        l_bind: str
        l_port: int
        r_proto: "ChannelMux.ProtoName"
        r_host: str
        r_port: int
        name: Optional[str] = None
        lifecycle_hooks: Optional[dict] = None
        options: Optional[dict] = None

    @dataclass
    class TunDevice:
        fd: int
        ifname: str
        mtu: int
        service_key: Optional["ChannelMux.ServiceKey"] = None
        reader_registered: bool = False
        chan_id: Optional[int] = None

    UDP_MIN_ID = 1
    UDP_MAX_ID = 65535
    TCP_MIN_ID = 1
    TCP_MAX_ID = 65535
    TUN_MIN_ID = 1
    TUN_MAX_ID = 65535
    UDP_IDLE_S = 20.0
    TUN_READ_SIZE_MAX = 65535
    TUN_DEFAULT_MTU = 1500
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    SIOCSIFMTU = 0x8922
    IFF_UP = 0x1
    IFF_RUNNING = 0x40
    HOOK_DEFAULT_TIMEOUT_MS = 10000
    CTRL_CHUNK_HDR = struct.Struct(">4sIHH")
    CTRL_CHUNK_MAGIC = b"CKV1"
    CTRL_CHUNK_REASSEMBLY_TTL_S = 20.0
    CTRL_CHUNK_MAX_INFLIGHT = 512
    TUN_INFLOW_THROTTLE_WINDOW_NS = 100_000_000
    TUN_INFLOW_THROTTLE_RATIO = 0.9
    SHARED_TUN_RECENT_DROP_LIMIT = 16

    @staticmethod
    def _proto_name_to_code(name: "ChannelMux.ProtoName") -> int:
        name_l = str(name).lower()
        if name_l == "udp":
            return int(ChannelMux.Proto.UDP)
        if name_l == "tcp":
            return int(ChannelMux.Proto.TCP)
        if name_l == "tun":
            return int(ChannelMux.Proto.TUN)
        raise ValueError(f"unsupported protocol name: {name}")

    @staticmethod
    def _proto_code_to_name(code: int) -> "ChannelMux.ProtoName":
        if int(code) == int(ChannelMux.Proto.UDP):
            return "udp"
        if int(code) == int(ChannelMux.Proto.TCP):
            return "tcp"
        if int(code) == int(ChannelMux.Proto.TUN):
            return "tun"
        raise ValueError(f"unsupported protocol code: {code}")

    # ---------------- CLI ----------------
    @staticmethod
    def register_cli(p) -> None:
        """Only the new catalog flag + optional mux TCP backpressure."""
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False
        if not _has('--own-servers'):
            p.add_argument(
                '--own-servers', nargs='*', default=None,
                help=("Service catalog (client mode only). "
                      "Use structured JSON service objects with listen/target fields. "
                      "Listener instances ignore --own-servers because multiple overlay peers make the target ambiguous. "
                        "Example JSON item: "
                        """'{"listen":{"protocol":"tcp","bind":"0.0.0.0","port":80},"target":{"protocol":"tcp","host":"127.0.0.1","port":88}}'""")
            )
        if not _has('--remote-servers'):
            p.add_argument(
                '--remote-servers', nargs='*', default=None,
                help=("Service catalog applied on the connected peer (client mode only). "
                      "Use structured JSON service objects with listen/target fields. "
                      "Listener instances ignore --remote-servers because multiple overlay peers make the target ambiguous. "
                        "Example JSON item: "
                        """'{"listen":{"protocol":"udp","bind":"::","port":16666},"target":{"protocol":"udp","host":"127.0.0.1","port":16666}}'""")
            )
        # Keep backpressure knobs (apply to local TCP writers we own)
        if not _has('--mux-tcp-bp-threshold'):
            p.add_argument('--mux-tcp-bp-threshold', type=int, default=1,
                           help='Mux TCP: size threshold (bytes) to trigger drain() (default 1).')
        if not _has('--mux-tcp-bp-latency-ms'):
            p.add_argument('--mux-tcp-bp-latency-ms', type=int, default=300,
                           help='Mux TCP: if > 0, drain writers after this ms when bytes pending.')
        if not _has('--mux-tcp-bp-poll-interval-ms'):
            p.add_argument('--mux-tcp-bp-poll-interval-ms', type=int, default=50,
                           help='Mux TCP: polling interval for time-based backpressure (ms).')

    @staticmethod
    def from_args(session, loop: asyncio.AbstractEventLoop, args,
                  on_local_rx_bytes: Optional[Callable[[int], None]] = None,
                  on_local_tx_bytes: Optional[Callable[[int], None]] = None) -> "ChannelMux":
        mux = ChannelMux(session, loop, on_local_rx_bytes, on_local_tx_bytes)
        mux.args = args
        with contextlib.suppress(Exception):
            mux._tun_routing_settings = TunRoutingSettings.from_mapping(vars(args))
        # Parse catalog
        services = ChannelMux._parse_own_servers(getattr(args, 'own_servers', None))
        remote_services = ChannelMux._parse_remote_servers(getattr(args, 'remote_servers', None))
        active_transport = str(getattr(args, "overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
        mux._overlay_transport = active_transport
        bind_attr, peer_attr, peer_port_attr, _listen_port_attr = _overlay_cli_attrs(active_transport)
        raw_overlay_peer = str(getattr(args, peer_attr, None) or getattr(args, "peer", None) or "").strip()
        raw_overlay_port = getattr(args, peer_port_attr, None)
        if raw_overlay_port is None and peer_port_attr != "peer_port":
            raw_overlay_port = getattr(args, "peer_port", None)
        mux._overlay_peer_name = raw_overlay_peer
        mux._overlay_peer_host = raw_overlay_peer
        mux._overlay_peer_port = int(raw_overlay_port if raw_overlay_port is not None else 443) if raw_overlay_peer else 0
        if raw_overlay_peer:
            socktype = socket.SOCK_STREAM if active_transport in ("tcp", "ws") else socket.SOCK_DGRAM
            with contextlib.suppress(Exception):
                resolved = _resolve_cli_peer(
                    args,
                    peer_attr=peer_attr,
                    peer_port_attr=peer_port_attr,
                    resolve_attr=f"{'udp' if active_transport == 'myudp' else active_transport}_peer_resolve_family",
                    bind_host=str(getattr(args, bind_attr, "") or ""),
                    socktype=socktype,
                )
                if resolved is not None:
                    mux._overlay_peer_host = str(resolved[0])
                    mux._overlay_peer_port = int(resolved[1])
        listener_mode = not _has_configured_overlay_peer(args, active_transport)
        # Split channel-id space by role to avoid bidirectional OPEN collisions:
        # listener uses even ids, peer/client uses odd ids.
        mux._chan_id_start = 2 if listener_mode else 1
        mux._chan_id_stride = 2
        mux._next_udp_id = mux._chan_id_start
        mux._next_tcp_id = mux._chan_id_start
        if listener_mode and services:
            retained_services = [s for s in services if ChannelMux._is_server_shared_tun_service(s)]
            ignored_count = len(services) - len(retained_services)
            if ignored_count:
                mux.log.info(
                    "[MUX] listener mode detected: ignoring %d --own-servers entries; "
                    "the listening peer must not expose ambiguous local services when multiple overlay peers connect",
                    ignored_count,
                )
            if retained_services:
                mux.log.info(
                    "[MUX] listener mode retaining %d prestarted server-owned shared TUN service(s)",
                    len(retained_services),
                )
            services = retained_services
        if listener_mode and remote_services:
            mux.log.info(
                "[MUX] listener mode detected: ignoring %d --remote-servers entries; "
                "the listening peer must not expose ambiguous local services when multiple overlay peers connect",
                len(remote_services),
            )
            remote_services = []
        #if not services:
         #   raise ValueError("No services defined. Provide --own-servers \"proto,port,bind,proto,host,port ...\"")
        for s in services:
            mux._local_services[("local", 0, s.svc_id)] = s
        mux._remote_services_requested = remote_services
        # Backpressure knobs
        try: mux._tcp_drain_threshold = int(getattr(args, 'mux_tcp_bp_threshold', 1))
        except Exception: pass
        try: mux._tcp_bp_latency_ms = int(getattr(args, 'mux_tcp_bp_latency_ms', 300))
        except Exception: mux._tcp_bp_latency_ms = 300
        try: mux._tcp_bp_poll_interval_s = float(getattr(args, 'mux_tcp_bp_poll_interval_ms', 50)) / 1000.0
        except Exception: mux._tcp_bp_poll_interval_s = 0.05
        with contextlib.suppress(Exception):
            config_path = str(getattr(args, "_config_path", "") or getattr(args, "config", "") or "")
            if config_path:
                mux._hook_base_dir = str(pathlib.Path(config_path).expanduser().resolve().parent)
        return mux

    @staticmethod
    def _parse_own_servers(specs: Optional[list[str]]) -> list[ChannelMux.ServiceSpec]:
        """Parse --own-servers spec(s) into ServiceSpec list."""
        return ChannelMux._parse_service_specs(specs, "--own-servers")

    @staticmethod
    def _parse_remote_servers(specs: Optional[list[str]]) -> list[ChannelMux.ServiceSpec]:
        """Parse --remote-servers spec(s) into ServiceSpec list."""
        return ChannelMux._parse_service_specs(specs, "--remote-servers")

    @staticmethod
    def _parse_service_specs(specs: Optional[list[str]], arg_name: str) -> list[ChannelMux.ServiceSpec]:
        """Parse service spec(s) into ServiceSpec list."""
        if not specs:
            return []
        out: list[ChannelMux.ServiceSpec] = []
        sid = 1
        for item in specs:
            if item is None:
                continue
            parsed_items: list[dict] = []
            if isinstance(item, dict):
                parsed_items = [item]
            elif isinstance(item, str) and item.strip():
                try:
                    decoded = json.loads(item)
                except Exception as exc:
                    raise ValueError(
                        f"{arg_name} requires structured JSON service objects; legacy tuple syntax is no longer accepted. "
                        f"Migrate existing config with scripts/migrate_service_definitions.py. Offending value: {item}"
                    ) from exc
                if isinstance(decoded, dict):
                    parsed_items = [decoded]
                elif isinstance(decoded, list):
                    if not all(isinstance(entry, dict) for entry in decoded):
                        raise ValueError(f"{arg_name} JSON arrays must contain only service objects: {item}")
                    parsed_items = list(decoded)
                else:
                    raise ValueError(f"{arg_name} JSON value must be a service object or array of service objects: {item}")
            else:
                continue
            for parsed_item in parsed_items:
                out.append(ChannelMux._parse_structured_service_spec(parsed_item, arg_name, sid))
                sid += 1
        return out

    @staticmethod
    def _validate_service_proto(name: str, arg_name: str, tok: str, side: str) -> str:
        lowered = str(name or "").strip().lower()
        if lowered not in {"udp", "tcp", "tun"}:
            raise ValueError(f"{arg_name} {side} protocol must be udp, tcp or tun: {tok}")
        return lowered

    @staticmethod
    def _validate_service_port(value: Any, arg_name: str, tok: str, field_name: str) -> int:
        try:
            port = int(value)
        except Exception:
            raise ValueError(f"{arg_name} {field_name} must be an integer in 1..65535: {tok}")
        if not (1 <= port <= 65535):
            raise ValueError(f"{arg_name} {field_name} must be an integer in 1..65535: {tok}")
        return port

    @staticmethod
    def _normalize_shared_tun_owned_ip(raw: Any, *, token: str, arg_name: str, field_name: str) -> tuple[str, str]:
        text = str(raw or "").strip()
        if not text:
            raise ValueError(f"{arg_name} {field_name} address entries must be non-empty: {token}")
        try:
            if "/" in text:
                iface = ipaddress.ip_interface(text)
                if iface.version == 4 and int(iface.network.prefixlen) != 32:
                    raise ValueError
                if iface.version == 6 and int(iface.network.prefixlen) != 128:
                    raise ValueError
                return str(iface.ip), f"ipv{iface.version}"
            addr = ipaddress.ip_address(text)
            return str(addr), f"ipv{addr.version}"
        except Exception:
            raise ValueError(
                f"{arg_name} {field_name} addresses must be exact host IPv4/IPv6 values "
                f"(optionally /32 or /128 only): {token}"
            )

    @staticmethod
    def _validate_shared_tun_ownership_options(options: dict, arg_name: str, token: str) -> None:
        shared = options.get("shared_tun_ownership")
        if shared is None:
            return
        if not isinstance(shared, dict):
            raise ValueError(f"{arg_name} structured tun option shared_tun_ownership must be an object: {token}")

        mode = str(shared.get("mode") or "").strip().lower()
        if mode != "server_shared":
            raise ValueError(
                f"{arg_name} structured tun option shared_tun_ownership.mode must be server_shared: {token}"
            )

        peers = shared.get("peers")
        if not isinstance(peers, list) or not peers:
            raise ValueError(
                f"{arg_name} structured tun option shared_tun_ownership.peers must be a non-empty array: {token}"
            )

        seen_peer_refs: set[str] = set()
        seen_ipv4: set[str] = set()
        seen_ipv6: set[str] = set()

        for entry in peers:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"{arg_name} structured tun option shared_tun_ownership.peers entries must be objects: {token}"
                )
            peer_ref = str(entry.get("peer_ref") or "").strip()
            if not peer_ref:
                raise ValueError(
                    f"{arg_name} structured tun option shared_tun_ownership peer_ref must be non-empty: {token}"
                )
            if peer_ref in seen_peer_refs:
                raise ValueError(
                    f"{arg_name} structured tun option shared_tun_ownership peer_ref values must be unique: {token}"
                )
            seen_peer_refs.add(peer_ref)

            ipv4_values = entry.get("ipv4", [])
            ipv6_values = entry.get("ipv6", [])
            if ipv4_values is None:
                ipv4_values = []
            if ipv6_values is None:
                ipv6_values = []
            if not isinstance(ipv4_values, list) or not isinstance(ipv6_values, list):
                raise ValueError(
                    f"{arg_name} structured tun option shared_tun_ownership ipv4/ipv6 values must be arrays: {token}"
                )
            if not ipv4_values and not ipv6_values:
                raise ValueError(
                    f"{arg_name} structured tun option shared_tun_ownership each peer must own at least one address: {token}"
                )

            for raw_addr in ipv4_values:
                normalized, family = ChannelMux._normalize_shared_tun_owned_ip(
                    raw_addr,
                    token=token,
                    arg_name=arg_name,
                    field_name="shared_tun_ownership.ipv4",
                )
                if family != "ipv4":
                    raise ValueError(
                        f"{arg_name} structured tun option shared_tun_ownership.ipv4 accepts only IPv4 addresses: {token}"
                    )
                if normalized in seen_ipv4:
                    raise ValueError(
                        f"{arg_name} structured tun option shared_tun_ownership IPv4 addresses must be unique: {token}"
                    )
                seen_ipv4.add(normalized)

            for raw_addr in ipv6_values:
                normalized, family = ChannelMux._normalize_shared_tun_owned_ip(
                    raw_addr,
                    token=token,
                    arg_name=arg_name,
                    field_name="shared_tun_ownership.ipv6",
                )
                if family != "ipv6":
                    raise ValueError(
                        f"{arg_name} structured tun option shared_tun_ownership.ipv6 accepts only IPv6 addresses: {token}"
                    )
                if normalized in seen_ipv6:
                    raise ValueError(
                        f"{arg_name} structured tun option shared_tun_ownership IPv6 addresses must be unique: {token}"
                    )
                seen_ipv6.add(normalized)

    @staticmethod
    def _shared_tun_ownership_snapshot_for_spec(spec: "ChannelMux.ServiceSpec") -> Optional[dict[str, Any]]:
        options = spec.options if isinstance(spec.options, dict) else None
        shared = options.get("shared_tun_ownership") if isinstance(options, dict) else None
        if not isinstance(shared, dict):
            return None
        peers_raw = shared.get("peers")
        if not isinstance(peers_raw, list) or not peers_raw:
            return None

        peers: list[dict[str, Any]] = []
        owner_by_ipv4: dict[str, str] = {}
        owner_by_ipv6: dict[str, str] = {}
        address_count = 0

        for entry in peers_raw:
            if not isinstance(entry, dict):
                continue
            peer_ref = str(entry.get("peer_ref") or "").strip()
            if not peer_ref:
                continue
            ipv4_values: list[str] = []
            ipv6_values: list[str] = []
            for raw_addr in list(entry.get("ipv4") or []):
                normalized, family = ChannelMux._normalize_shared_tun_owned_ip(
                    raw_addr,
                    token=str(spec.name or spec.svc_id),
                    arg_name="shared_tun_ownership",
                    field_name="shared_tun_ownership.ipv4",
                )
                if family == "ipv4":
                    ipv4_values.append(normalized)
                    owner_by_ipv4[normalized] = peer_ref
            for raw_addr in list(entry.get("ipv6") or []):
                normalized, family = ChannelMux._normalize_shared_tun_owned_ip(
                    raw_addr,
                    token=str(spec.name or spec.svc_id),
                    arg_name="shared_tun_ownership",
                    field_name="shared_tun_ownership.ipv6",
                )
                if family == "ipv6":
                    ipv6_values.append(normalized)
                    owner_by_ipv6[normalized] = peer_ref
            peer_address_count = len(ipv4_values) + len(ipv6_values)
            address_count += peer_address_count
            peers.append(
                {
                    "peer_ref": peer_ref,
                    "ipv4": ipv4_values,
                    "ipv6": ipv6_values,
                    "address_count": peer_address_count,
                }
            )

        if not peers:
            return None
        return {
            "mode": str(shared.get("mode") or "server_shared"),
            "peer_count": len(peers),
            "address_count": address_count,
            "peer_refs": [str(entry["peer_ref"]) for entry in peers],
            "peers": peers,
            "owner_by_ipv4": owner_by_ipv4,
            "owner_by_ipv6": owner_by_ipv6,
        }

    @staticmethod
    def _shared_tun_runtime_snapshot(
        ownership: Optional[dict[str, Any]],
        active_peer_bindings: Optional[list[dict[str, Any]]] = None,
        throttle_scopes: Optional[list[dict[str, Any]]] = None,
        drop_state: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        if not isinstance(ownership, dict):
            return None
        snapshot = {
            "mode": str(ownership.get("mode") or "server_shared"),
            "peer_count": int(ownership.get("peer_count", 0) or 0),
            "address_count": int(ownership.get("address_count", 0) or 0),
            "peer_refs": [str(v) for v in list(ownership.get("peer_refs") or [])],
            "peers": [
                {
                    "peer_ref": str(entry.get("peer_ref") or ""),
                    "ipv4": [str(v) for v in list(entry.get("ipv4") or [])],
                    "ipv6": [str(v) for v in list(entry.get("ipv6") or [])],
                    "address_count": int(entry.get("address_count", 0) or 0),
                }
                for entry in list(ownership.get("peers") or [])
                if isinstance(entry, dict)
            ],
            "owner_by_ipv4": {str(k): str(v) for k, v in dict(ownership.get("owner_by_ipv4") or {}).items()},
            "owner_by_ipv6": {str(k): str(v) for k, v in dict(ownership.get("owner_by_ipv6") or {}).items()},
            "active_peer_bindings": [],
            "throttle_scopes": [],
            "drop_counters": {"total": 0, "by_reason": {}},
            "recent_drops": [],
        }
        if isinstance(active_peer_bindings, list):
            snapshot["active_peer_bindings"] = [
                {
                    "peer_id": int(entry.get("peer_id", 0) or 0),
                    "preferred_chan_id": (
                        None if entry.get("preferred_chan_id") is None else int(entry.get("preferred_chan_id"))
                    ),
                    "bound_chan_ids": [int(v) for v in list(entry.get("bound_chan_ids") or [])],
                    "throttle_prev_window_bytes": int(entry.get("throttle_prev_window_bytes", 0) or 0),
                    "throttle_curr_window_bytes": int(entry.get("throttle_curr_window_bytes", 0) or 0),
                    "throttle_drop_count": int(entry.get("throttle_drop_count", 0) or 0),
                }
                for entry in active_peer_bindings
                if isinstance(entry, dict)
            ]
        if isinstance(throttle_scopes, list):
            snapshot["throttle_scopes"] = [
                {
                    "scope_id": str(entry.get("scope_id") or ""),
                    "route_class": str(entry.get("route_class") or ""),
                    "selected_peer_ids": [int(v) for v in list(entry.get("selected_peer_ids") or [])],
                    "selected_chan_ids": [int(v) for v in list(entry.get("selected_chan_ids") or [])],
                    "prev_window_bytes": int(entry.get("prev_window_bytes", 0) or 0),
                    "curr_window_bytes": int(entry.get("curr_window_bytes", 0) or 0),
                    "throttle_drop_count": int(entry.get("throttle_drop_count", 0) or 0),
                }
                for entry in throttle_scopes
                if isinstance(entry, dict)
            ]
        if isinstance(drop_state, dict):
            snapshot["drop_counters"] = {
                "total": int(drop_state.get("total", 0) or 0),
                "by_reason": {
                    str(k): int(v or 0)
                    for k, v in dict(drop_state.get("by_reason") or {}).items()
                },
            }
            snapshot["recent_drops"] = [
                {
                    "reason": str(entry.get("reason") or ""),
                    "direction": str(entry.get("direction") or ""),
                    "peer_id": None if entry.get("peer_id") is None else int(entry.get("peer_id")),
                    "chan_id": None if entry.get("chan_id") is None else int(entry.get("chan_id")),
                    "ip_version": None if entry.get("ip_version") is None else int(entry.get("ip_version")),
                    "source_ip": None if entry.get("source_ip") is None else str(entry.get("source_ip")),
                    "destination_ip": None if entry.get("destination_ip") is None else str(entry.get("destination_ip")),
                    "route_class": None if entry.get("route_class") is None else str(entry.get("route_class")),
                    "packet_bytes": None if entry.get("packet_bytes") is None else int(entry.get("packet_bytes")),
                }
                for entry in list(drop_state.get("recent_drops") or [])
                if isinstance(entry, dict)
            ]
        return snapshot

    @staticmethod
    def _is_server_shared_tun_service(spec: "ChannelMux.ServiceSpec") -> bool:
        if str(getattr(spec, "l_proto", "") or "").lower() != "tun":
            return False
        if str(getattr(spec, "r_proto", "") or "").lower() != "tun":
            return False
        return ChannelMux._shared_tun_ownership_snapshot_for_spec(spec) is not None

    @staticmethod
    def _parse_structured_service_spec(item: dict, arg_name: str, sid: int) -> "ChannelMux.ServiceSpec":
        token = json.dumps(item, sort_keys=True, ensure_ascii=False)
        listen = item.get("listen")
        target = item.get("target")
        if not isinstance(listen, dict):
            raise ValueError(f"{arg_name} structured item requires object field listen: {token}")
        if not isinstance(target, dict):
            raise ValueError(f"{arg_name} structured item requires object field target: {token}")
        l_proto = ChannelMux._validate_service_proto(listen.get("protocol"), arg_name, token, "listen")
        r_proto = ChannelMux._validate_service_proto(target.get("protocol"), arg_name, token, "target")

        if l_proto == "tun":
            l_bind = str(listen.get("ifname", "") or "").strip()
            l_port_i = ChannelMux._validate_service_port(listen.get("mtu"), arg_name, token, "listen mtu")
            if not l_bind:
                raise ValueError(f"{arg_name} structured tun listen requires ifname: {token}")
        else:
            l_bind = str(listen.get("bind", "") or "").strip()
            l_port_i = ChannelMux._validate_service_port(listen.get("port"), arg_name, token, "listen port")
            if not l_bind:
                raise ValueError(f"{arg_name} structured {l_proto} listen requires bind: {token}")

        if r_proto == "tun":
            r_host = str(target.get("ifname", "") or "").strip()
            r_port_i = ChannelMux._validate_service_port(target.get("mtu"), arg_name, token, "target mtu")
            if not r_host:
                raise ValueError(f"{arg_name} structured tun target requires ifname: {token}")
        else:
            r_host = str(target.get("host", "") or "").strip().strip("[]")
            r_port_i = ChannelMux._validate_service_port(target.get("port"), arg_name, token, "target port")
            if not r_host:
                raise ValueError(f"{arg_name} structured {r_proto} target requires host: {token}")

        lifecycle_hooks = item.get("lifecycle_hooks")
        if lifecycle_hooks is not None and not isinstance(lifecycle_hooks, dict):
            raise ValueError(f"{arg_name} structured item lifecycle_hooks must be an object when provided: {token}")
        options = item.get("options")
        if options is not None and not isinstance(options, dict):
            raise ValueError(f"{arg_name} structured item options must be an object when provided: {token}")
        if isinstance(options, dict):
            if "shared_tun_ownership" in options and not (l_proto == "tun" and r_proto == "tun"):
                raise ValueError(
                    f"{arg_name} structured item option shared_tun_ownership is supported only on tun->tun services: {token}"
                )
            if l_proto == "tun" and r_proto == "tun":
                ChannelMux._validate_shared_tun_ownership_options(options, arg_name, token)

        return ChannelMux.ServiceSpec(
            svc_id=sid,
            l_proto=l_proto,
            l_bind=l_bind,
            l_port=l_port_i,
            r_proto=r_proto,
            r_host=r_host,
            r_port=r_port_i,
            name=str(item.get("name", "") or "").strip() or None,
            lifecycle_hooks=lifecycle_hooks if isinstance(lifecycle_hooks, dict) else None,
            options=options if isinstance(options, dict) else None,
        )

    # -------------- lifecycle --------------
    def __init__(self, session, loop: asyncio.AbstractEventLoop,
                 on_local_rx_bytes: Optional[Callable[[int], None]] = None,
                 on_local_tx_bytes: Optional[Callable[[int], None]] = None):
        self.session = session
        self.log = logging.getLogger("channel_mux")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self.loop = loop
        self._on_local_rx = on_local_rx_bytes  # local->peer (overlay direction) counters hook
        self._on_local_tx = on_local_tx_bytes  # peer->local counters hook
        self.args = None
        self._tun_routing_settings = TunRoutingSettings()
        self._hook_base_dir = os.getcwd()
        self._overlay_transport = ""
        self._overlay_peer_name = ""
        self._overlay_peer_host = ""
        self._overlay_peer_port = 0

        # Overlay state gate
        self._overlay_connected: bool = self.session.is_connected()
        self._accepting_enabled: bool = self._overlay_connected

        # Services
        self._local_services: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        self._remote_services_requested: list[ChannelMux.ServiceSpec] = []
        self._peer_installed_services: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        self._pending_peer_service_catalogs: dict[int, dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec]] = {}
        self._svc_tcp_servers: dict[ChannelMux.ServiceKey, asyncio.base_events.Server] = {}
        self._svc_udp_servers: dict[ChannelMux.ServiceKey, asyncio.DatagramTransport] = {}
        self._svc_tun_devices: dict[ChannelMux.ServiceKey, ChannelMux.TunDevice] = {}

        # Channel id allocators
        self._chan_id_start: int = 1
        self._chan_id_stride: int = 1
        self._next_udp_id: int = self.UDP_MIN_ID
        self._next_tcp_id: int = self.TCP_MIN_ID
        self._next_tun_id: int = self.TUN_MIN_ID

        # UDP server-side maps
        # (svc_id, (host,port)) -> (chan, last_ts)
        self._udp_by_client: dict[tuple[ChannelMux.ServiceKey, tuple[str,int]], tuple[int,float]] = {}
        # chan -> (svc_key, (host,port))
        self._udp_by_chan: dict[int, tuple[ChannelMux.ServiceKey, tuple[str,int]]] = {}

        # UDP peer client-side transports
        self._udp_client_transports: dict[int, asyncio.DatagramTransport] = {}
        self._udp_client_last_ts: dict[int, float] = {}

        # UDP client early-buffer (per channel, preserves datagram boundaries)
        self._udp_client_pending: Dict[int, list[bytes]] = {}
        self._udp_client_pending_cap: int = 1024  # max queued datagrams per channel (tweak as needed)
        self._udp_frag_next_datagram_id: int = 1
        self._udp_frag_rx: dict[tuple[int, int], dict[str, Any]] = {}
        self._peer_app_payload_yield_count: int = 0
        self._peer_app_payload_last_yield_gap_ms: float = 0.0
        self._peer_app_payload_max_yield_gap_ms: float = 0.0

        # TCP maps
        # chan -> (svc_id, writer)
        self._tcp_by_chan: dict[int, tuple[int, asyncio.StreamWriter]] = {}
        # writer -> (svc_id, chan)
        self._tcp_by_writer: dict[asyncio.StreamWriter, tuple[int,int]] = {}
        self._tcp_pending_data: dict[int, list[bytes]] = {}

        # Backpressure machinery (per TCP writer)
        self._tcp_send_locks: dict[int, asyncio.Lock] = {}
        self._tcp_backpressure_evt: dict[int, asyncio.Event] = {}
        self._tcp_backpressure_tasks: dict[int, asyncio.Task] = {}
        self._tcp_drain_threshold: int = 1
        self._tcp_bp_latency_ms: int = 300
        self._tcp_bp_poll_interval_s: float = 0.05

        # Rolling MUX counters (per (chan, proto))
        self._mux_counters: dict[tuple[int,int], int] = {}

        # MUX sender identity/epoch tracking
        self._mux_instance_id: int = random.getrandbits(64)
        self._mux_connection_seq: int = 1
        self._peer_mux_epochs: dict[int, tuple[int, int]] = {}
        # OPEN dedupe maps (full tuple keying)
        # key: (peer_id, chan_id, svc_id, l_proto_i, l_bind, l_port, r_proto_i, r_host, r_port)
        self._udp_open_key_by_chan: dict[int, tuple[int, int, int, int, str, int, int, str, int]] = {}
        self._udp_chan_by_open_key: dict[tuple[int, int, int, int, str, int, int, str, int], int] = {}
        self._tcp_open_key_by_chan: dict[int, tuple[int, int, int, str, int, int, str, int]] = {}
        self._tcp_chan_by_open_key: dict[tuple[int, int, int, str, int, int, str, int], int] = {}
        self._tun_open_key_by_chan: dict[int, tuple[int, int, int, str, int, int, str, int]] = {}
        self._tun_chan_by_open_key: dict[tuple[int, int, int, str, int, int, str, int], int] = {}
        self._tun_by_chan: dict[int, ChannelMux.TunDevice] = {}
        self._tun_chan_by_service: dict[ChannelMux.ServiceKey, int] = {}
        self._tun_frag_rx: dict[tuple[int, int], dict[str, Any]] = {}
        self._shared_tun_ownership_by_service: dict[ChannelMux.ServiceKey, dict[str, Any]] = {}
        self._shared_tun_runtime_by_peer: dict[tuple[ChannelMux.ServiceKey, int], dict[str, Any]] = {}
        self._shared_tun_peer_ref_by_peer: dict[tuple[ChannelMux.ServiceKey, int], str] = {}
        self._shared_tun_peer_id_by_ref: dict[tuple[ChannelMux.ServiceKey, str], int] = {}
        self._shared_tun_drop_state_by_service: dict[ChannelMux.ServiceKey, dict[str, Any]] = {}
        self._tun_inflow_scope_state: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._chan_owner_peer_id: dict[int, int] = {}
        self._ctrl_chunk_rx: dict[tuple[int, int, int, int, int], dict[str, Any]] = {}
        self._ctrl_chunk_next_txid: int = 1

        # Per-channel stats (readable counters + CRC)
        self._chan_stats: dict[tuple[int, ChannelMux.Proto], _ChanCtr] = {}
        self._peer_closed_channel_stats: dict[int, _ChanCtr] = {}

        # Tasks
        self._sweeper_task: Optional[asyncio.Task] = None
        self._ensure_task: Optional[asyncio.Task] = None

        self._session_max_app_payload = max(
            ChannelMux.MUX_HDR.size,
            self._resolve_session_max_app_payload(self.session),
        )
        self._SAFE_TCP_READ = max(1, self._session_max_app_payload - ChannelMux.MUX_HDR.size)
        self._udp_service_datagram_cap, self._udp_service_datagram_diag = self._resolve_udp_service_datagram_cap(self.session)
        self.log.info(
            "[MUX] session_max_app_payload=%s safe_tcp_read=%s udp_service_datagram_cap=%s (%s)",
            self._session_max_app_payload,
            self._SAFE_TCP_READ,
            self._udp_service_datagram_cap,
            self._udp_service_datagram_diag,
        )

        # Dashboard interface
        self._udp_client_svc_id: Dict[int, int] = {}
        self._tcp_role_by_chan: Dict[int, str] = {}
        self._warn_dumped_channel_config: bool = False
        self._peer_app_payload_pending: Deque[Tuple[bytes, Optional[int]]] = deque()
        self._peer_app_payload_scheduled: bool = False
        self._peer_app_payload_dispatching: bool = False

        # Session payload hook
        try:
            self.session.set_on_app_payload(self.on_app_payload_from_peer)
            self.log.debug("[MUX] on_app_payload_from_peer wired")
        except Exception as e:
            self.log.error("[MUX] failed to wire on_app_payload_from_peer: %r", e)
        try:
            self.session.set_on_peer_disconnect(self.on_peer_disconnected)
            self.log.debug("[MUX] on_peer_disconnected wired")
        except Exception:
            pass
    
    @staticmethod
    def _hook_platform_key() -> str:
        platform = str(sys.platform or "").lower()
        if platform.startswith("win"):
            return "windows"
        if platform.startswith("linux"):
            return "linux"
        if platform.startswith("darwin"):
            return "darwin"
        return platform or "unknown"

    def _tun_packet_debug_enabled(self) -> bool:
        checker = getattr(self.log, "isEnabledFor", None)
        if callable(checker):
            try:
                return bool(checker(logging.DEBUG))
            except Exception:
                return False
        return False

    def _log_tun_packet_debug(
        self,
        *,
        stage: str,
        packet: bytes,
        ifname: str = "",
        chan: Optional[int] = None,
    ) -> None:
        if not self._tun_packet_debug_enabled():
            return
        payload = bytes(packet or b"")
        ip_version = (payload[0] >> 4) if payload else -1
        self.log.debug(
            "[TUN/PKT] stage=%s if=%s chan=%s len=%s ipver=%s hex=%s",
            stage,
            ifname,
            "" if chan is None else chan,
            len(payload),
            ip_version,
            payload.hex(),
        )

    @staticmethod
    def _render_hook_value(value: Any, context: Dict[str, Any]) -> str:
        class _SafeMap(dict):
            def __missing__(self, key):  # type: ignore[override]
                return ""
        return str(value).format_map(_SafeMap({k: "" if v is None else str(v) for k, v in context.items()}))

    @staticmethod
    def _select_hook_argv(command_spec: dict, platform_key: Optional[str] = None) -> list[str]:
        selected: Optional[Any] = None
        pk = str(platform_key or ChannelMux._hook_platform_key())
        argv = command_spec.get("argv")
        if isinstance(argv, list):
            selected = argv
        elif isinstance(argv, dict):
            selected = argv.get(pk)
            if selected is None and pk == "windows":
                selected = argv.get("win32")
            if selected is None:
                selected = argv.get("default")
        if selected is None:
            argv_by_os = command_spec.get("argv_by_os")
            if isinstance(argv_by_os, dict):
                selected = argv_by_os.get(pk)
                if selected is None and pk == "windows":
                    selected = argv_by_os.get("win32")
                if selected is None:
                    selected = argv_by_os.get("default")
        if not isinstance(selected, list):
            raise ValueError("hook command must resolve to argv list")
        out = [str(v) for v in selected if str(v)]
        if not out:
            raise ValueError("hook command argv list must not be empty")
        return out

    def _resolve_hook_argv(self, argv: list[str]) -> list[str]:
        if not argv:
            return argv
        exe = str(argv[0])
        has_path_separator = any(sep and sep in exe for sep in (os.sep, os.altsep))
        if has_path_separator and not os.path.isabs(exe):
            base = pathlib.Path(str(self._hook_base_dir or os.getcwd())).expanduser()
            return [str((base / exe).resolve()), *argv[1:]]
        return argv

    def _hook_command_spec_for(self, spec: "ChannelMux.ServiceSpec", role: str, event: str) -> Optional[dict]:
        hooks = spec.lifecycle_hooks
        if not isinstance(hooks, dict):
            return None
        role_hooks = hooks.get(str(role))
        if not isinstance(role_hooks, dict):
            return None
        command_spec = role_hooks.get(str(event))
        if not isinstance(command_spec, dict):
            return None
        return command_spec

    def _current_overlay_peer_endpoint(self) -> tuple[str, int]:
        host = str(self._overlay_peer_host or "")
        port = int(self._overlay_peer_port or 0)

        session = getattr(self, "session", None)
        live_host = str(getattr(session, "_peer_host", "") or "") if session is not None else ""
        live_port = getattr(session, "_peer_port", 0) if session is not None else 0
        if live_host:
            host = live_host
        try:
            live_port_i = int(live_port or 0)
        except Exception:
            live_port_i = 0
        if live_port_i > 0:
            port = live_port_i
        return host, port

    def _hook_context(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
        event: str,
        role: str,
        channel_id: Optional[int] = None,
        peer_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        catalog = ""
        if svc_key is not None:
            catalog = "own_servers" if str(svc_key[0]) == "local" else "remote_servers"
        overlay_peer_host, overlay_peer_port = self._current_overlay_peer_endpoint()
        ifname = str(spec.l_bind) if str(spec.l_proto) == "tun" else ""
        if str(spec.l_proto) == "tun" and svc_key is not None:
            dev = self._svc_tun_devices.get(svc_key)
            if dev is not None:
                realized_ifname = str(getattr(dev, "ifname", "") or "").strip()
                if realized_ifname:
                    ifname = realized_ifname
        return {
            "service_id": int(spec.svc_id),
            "service_name": str(spec.name or f"svc-{spec.svc_id}"),
            "catalog": catalog,
            "event": str(event),
            "protocol": str(spec.l_proto),
            "channel_id": "" if channel_id is None else int(channel_id),
            "bind": str(spec.l_bind),
            "listen_port": int(spec.l_port),
            "target_host": str(spec.r_host),
            "target_port": int(spec.r_port),
            "ifname": ifname,
            "peer_id": "" if peer_id is None else int(peer_id),
            "peer_endpoint": "",
            "overlay_transport": str(self._overlay_transport or ""),
            "overlay_peer_name": str(self._overlay_peer_name or ""),
            "overlay_peer_host": overlay_peer_host,
            "overlay_peer_port": "" if not overlay_peer_port else overlay_peer_port,
            "role": str(role),
        }

    def _tunnel_hook_env_defaults(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> Dict[str, str]:
        if str(spec.l_proto) != "tun" or self.args is None:
            return {}
        try:
            config = TunRoutingSettings.from_mapping(vars(self.args))
        except Exception:
            return {}
        origin = "" if svc_key is None else str(svc_key[0])
        if origin == "local":
            return config.local_hook_env()
        if origin == "peer":
            return config.remote_hook_env()
        return {}

    def _tun_routing_config(self) -> TunRoutingSettings:
        if self.args is None:
            return self._tun_routing_settings
        with contextlib.suppress(Exception):
            self._tun_routing_settings = TunRoutingSettings.from_mapping(
                vars(self.args),
                base=self._tun_routing_settings,
            )
        return self._tun_routing_settings

    @staticmethod
    def _merge_hook_env_defaults(
        lifecycle_hooks: Optional[dict],
        env_defaults: Dict[str, str],
    ) -> Optional[dict]:
        if not isinstance(lifecycle_hooks, dict) or not env_defaults:
            return lifecycle_hooks
        listener_hooks = lifecycle_hooks.get("listener")
        if not isinstance(listener_hooks, dict):
            return lifecycle_hooks
        merged_hooks = dict(lifecycle_hooks)
        merged_listener = dict(listener_hooks)
        changed = False
        for event, command_spec in listener_hooks.items():
            if not isinstance(command_spec, dict):
                continue
            merged_command = dict(command_spec)
            existing_env = merged_command.get("env")
            merged_env = dict(env_defaults)
            if isinstance(existing_env, dict):
                for key, value in existing_env.items():
                    merged_env[str(key)] = str(value)
            if existing_env != merged_env:
                merged_command["env"] = merged_env
                changed = True
            merged_listener[event] = merged_command
        if not changed:
            return lifecycle_hooks
        merged_hooks["listener"] = merged_listener
        return merged_hooks

    def _service_spec_with_hook_env_defaults(
        self,
        spec: "ChannelMux.ServiceSpec",
        *,
        remote_install: bool,
    ) -> "ChannelMux.ServiceSpec":
        if str(spec.l_proto) != "tun" or self.args is None:
            return spec
        try:
            config = TunRoutingSettings.from_mapping(vars(self.args))
        except Exception:
            return spec
        env_defaults = config.remote_hook_env() if remote_install else config.local_hook_env()
        lifecycle_hooks = self._merge_hook_env_defaults(spec.lifecycle_hooks, env_defaults)
        if lifecycle_hooks is spec.lifecycle_hooks:
            return spec
        return ChannelMux.ServiceSpec(
            svc_id=int(spec.svc_id),
            l_proto=str(spec.l_proto),
            l_bind=str(spec.l_bind),
            l_port=int(spec.l_port),
            r_proto=str(spec.r_proto),
            r_host=str(spec.r_host),
            r_port=int(spec.r_port),
            name=spec.name,
            lifecycle_hooks=lifecycle_hooks if isinstance(lifecycle_hooks, dict) else None,
            options=spec.options if isinstance(spec.options, dict) else None,
        )

    async def _run_service_hook(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
        role: str,
        event: str,
        *,
        channel_id: Optional[int] = None,
        peer_id: Optional[int] = None,
    ) -> None:
        command_spec = self._hook_command_spec_for(spec, role, event)
        if command_spec is None:
            return
        context = self._hook_context(spec, svc_key, event, role, channel_id=channel_id, peer_id=peer_id)
        try:
            argv_raw = self._select_hook_argv(command_spec)
            argv = self._resolve_hook_argv([self._render_hook_value(v, context) for v in argv_raw])
            timeout_ms_raw = command_spec.get("timeout_ms", self.HOOK_DEFAULT_TIMEOUT_MS)
            timeout_ms = int(timeout_ms_raw)
            if timeout_ms <= 0:
                timeout_ms = self.HOOK_DEFAULT_TIMEOUT_MS
            env = dict(os.environ)
            env["OB_OVERLAY_TRANSPORT"] = str(context.get("overlay_transport") or "")
            env["OB_OVERLAY_PEER_NAME"] = str(context.get("overlay_peer_name") or "")
            env["OB_OVERLAY_PEER_HOST"] = str(context.get("overlay_peer_host") or "")
            env["OB_OVERLAY_PEER_PORT"] = str(context.get("overlay_peer_port") or "")
            env.update(self._tunnel_hook_env_defaults(spec, svc_key))
            env_extra = command_spec.get("env")
            if isinstance(env_extra, dict):
                for k, v in env_extra.items():
                    env[str(k)] = self._render_hook_value(v, context)
            self.log.info(
                "[HOOK] start role=%s event=%s svc=%s argv=%r timeout_ms=%s",
                role,
                event,
                spec.svc_id,
                argv,
                timeout_ms,
            )
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=max(0.1, timeout_ms / 1000.0))
            except asyncio.TimeoutError:
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                self.log.warning(
                    "[HOOK] timeout role=%s event=%s svc=%s timeout_ms=%s argv=%r",
                    role,
                    event,
                    spec.svc_id,
                    timeout_ms,
                    argv,
                )
                return
            stdout_tail = (stdout_b or b"").decode("utf-8", "replace")[-400:]
            stderr_tail = (stderr_b or b"").decode("utf-8", "replace")[-400:]
            level_fn = self.log.info if int(proc.returncode or 0) == 0 else self.log.warning
            level_fn(
                "[HOOK] done role=%s event=%s svc=%s rc=%s stdout_tail=%r stderr_tail=%r",
                role,
                event,
                spec.svc_id,
                proc.returncode,
                stdout_tail,
                stderr_tail,
            )
        except Exception as e:
            self.log.warning(
                "[HOOK] failed role=%s event=%s svc=%s err=%r",
                role,
                event,
                spec.svc_id,
                e,
            )

    def _schedule_service_hook(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
        role: str,
        event: str,
        *,
        channel_id: Optional[int] = None,
        peer_id: Optional[int] = None,
    ) -> None:
        if not self.loop.is_running():
            self.log.debug(
                "[HOOK] schedule skipped role=%s event=%s svc=%s: event loop not running",
                role,
                event,
                spec.svc_id,
            )
            return
        coro = self._run_service_hook(
            spec,
            svc_key,
            role,
            event,
            channel_id=channel_id,
            peer_id=peer_id,
        )
        try:
            task = self.loop.create_task(coro)
        except Exception as e:
            with contextlib.suppress(Exception):
                coro.close()
            self.log.debug(
                "[HOOK] schedule skipped role=%s event=%s svc=%s err=%r",
                role,
                event,
                spec.svc_id,
                e,
            )
            return
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)

    # ---------- public counters ----------
    def udp_open_count(self) -> int:
        # Both sides: server mappings + live client transports
        return len(self._udp_by_chan) + len(self._udp_client_transports)

    def tcp_open_count(self) -> int:
        return len(self._tcp_by_chan)

    def tun_open_count(self) -> int:
        return len({id(dev) for dev in self._tun_by_chan.values()})

    # OPEN v4 binary payload (no backward compatibility):
    # +------+-------------+----------+--------+----------+----------+-----------+----------+----------+----------+-----------+----------+
    # | 'O4' | instance_id | conn_seq | svc_id | l_proto  | bind_len | bind[...] | l_port   | r_proto  | host_len | host[...] | r_port   |
    # +------+-------------+----------+--------+----------+----------+-----------+----------+----------+----------+-----------+----------+
    #   2B       u64          u32       u16       u8         u8         bytes       u16        u8         u8         bytes       u16
    #
    # ---------------------------------------------------------------------------
    # MUX v2 wire header and helpers (module scope; used by ChannelMux)
    # ---------------------------------------------------------------------------
    # MUX v2 header: chan_id(2) | proto(1) | counter(2) | mtype(1) | data_len(2)
    MUX_HDR = struct.Struct(">HBHBH")
    UDP_FRAG_HDR = struct.Struct(">IHH")
    UDP_FRAG_REASSEMBLY_TTL_S = 10.0
    UDP_FRAG_MAX_INFLIGHT = 256

    @staticmethod
    def _resolve_session_max_app_payload(session: ISession) -> int:
        getter = getattr(session, "get_max_app_payload_size", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                return max(0, int(getter() or 0))
        return 65535
    
    def _pack_mux(self, chan_id: int, proto: ChannelMux.Proto, counter: int, mtype: ChannelMux.MType, data: bytes) -> bytes:
        if not (0 <= chan_id <= 0xFFFF):
            raise ValueError("chan_id out of range")
        if data is None:
            data = b""
        return ChannelMux.MUX_HDR.pack(chan_id, int(proto), counter & 0xFFFF, int(mtype), len(data)) + data

    def _unpack_mux(self, buf: bytes) -> Optional[Tuple[int, ChannelMux.Proto, int, ChannelMux.MType, memoryview]]:
        if not isinstance(buf, (bytes, bytearray, memoryview)) or len(buf) < ChannelMux.MUX_HDR.size:
            self.log.warning("[MUX] type or len error %i %i < %i", not isinstance(buf, (bytes, bytearray, memoryview)), len(buf), ChannelMux.MUX_HDR.size)
            return None
        mv = memoryview(buf)
        chan_id, proto, counter, mtype, dlen = ChannelMux.MUX_HDR.unpack(mv[:ChannelMux.MUX_HDR.size])
        if mv.nbytes < ChannelMux.MUX_HDR.size + dlen:
            self.log.warning("[MUX] unpack mux failed : too little data %i < %i", mv.nbytes, ChannelMux.MUX_HDR.size + dlen)
            return None
        try:
            return chan_id, ChannelMux.Proto(proto), counter, ChannelMux.MType(mtype), mv[ChannelMux.MUX_HDR.size:ChannelMux.MUX_HDR.size + dlen]
        except Exception as e:
            self.log.warning("[MUX] unpack mux failed : %r", e)
            return None

    @staticmethod
    def _service_spec_wire_obj(spec: "ChannelMux.ServiceSpec") -> dict[str, Any]:
        return {
            "svc_id": int(spec.svc_id),
            "l_proto": str(spec.l_proto),
            "l_bind": str(spec.l_bind),
            "l_port": int(spec.l_port),
            "r_proto": str(spec.r_proto),
            "r_host": str(spec.r_host),
            "r_port": int(spec.r_port),
            "name": spec.name,
            "lifecycle_hooks": spec.lifecycle_hooks,
            "options": spec.options,
        }

    @staticmethod
    def _service_spec_from_wire_obj(obj: Any) -> Optional["ChannelMux.ServiceSpec"]:
        if not isinstance(obj, dict):
            return None
        try:
            l_proto = str(obj.get("l_proto") or "").strip().lower()
            r_proto = str(obj.get("r_proto") or "").strip().lower()
            if l_proto not in {"udp", "tcp", "tun"}:
                return None
            if r_proto not in {"udp", "tcp", "tun"}:
                return None
            lifecycle_hooks = obj.get("lifecycle_hooks")
            if lifecycle_hooks is not None and not isinstance(lifecycle_hooks, dict):
                return None
            options = obj.get("options")
            if options is not None and not isinstance(options, dict):
                return None
            return ChannelMux.ServiceSpec(
                svc_id=int(obj.get("svc_id")),
                l_proto=l_proto,
                l_bind=str(obj.get("l_bind") or ""),
                l_port=int(obj.get("l_port")),
                r_proto=r_proto,
                r_host=str(obj.get("r_host") or ""),
                r_port=int(obj.get("r_port")),
                name=str(obj.get("name") or "").strip() or None,
                lifecycle_hooks=lifecycle_hooks if isinstance(lifecycle_hooks, dict) else None,
                options=options if isinstance(options, dict) else None,
            )
        except Exception:
            return None

    # ---------- OPEN payload ----------
    # O4 (legacy): compact fields only.
    # O5 (extended): same base fields + metadata JSON {name,lifecycle_hooks,options}.
    def _build_open_v4(self, spec: ChannelMux.ServiceSpec) -> bytes:
        lb = spec.l_bind.encode("utf-8", "ignore")
        hb = spec.r_host.encode("utf-8", "ignore")
        meta_obj = {
            "name": spec.name,
            "lifecycle_hooks": spec.lifecycle_hooks,
            "options": spec.options,
        }
        meta = json.dumps(meta_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(lb) > 0xFFFF or len(hb) > 0xFFFF:
            raise ValueError("OPEN v5 host/bind too long")
        return (
            b"O5"
            + struct.pack(
                ">QIHBH",
                self._mux_instance_id & 0xFFFFFFFFFFFFFFFF,
                self._mux_connection_seq & 0xFFFFFFFF,
                int(spec.svc_id),
                self._proto_name_to_code(spec.l_proto),
                len(lb),
            )
            + lb
            + struct.pack(">HBH", int(spec.l_port), self._proto_name_to_code(spec.r_proto), len(hb))
            + hb
            + struct.pack(">HI", int(spec.r_port), len(meta))
            + meta
        )

    def _parse_open_with_meta(self, buf: bytes) -> Optional[tuple[int, int, int, int, str, int, int, str, int, Optional[str], Optional[dict], Optional[dict]]]:
        try:
            if len(buf) < 2:
                return None
            # O5 extended payload
            if buf[:2] == b"O5":
                if len(buf) < 2 + 8 + 4 + 2 + 1 + 2 + 2 + 1 + 2 + 2 + 4:
                    return None
                instance_id, connection_seq, svc_id, l_proto, l_bind_len = struct.unpack(">QIHBH", buf[2:19])
                off = 19
                if len(buf) < off + l_bind_len + 2 + 1 + 2 + 2 + 4:
                    return None
                l_bind = buf[off:off + l_bind_len].decode("utf-8", "ignore")
                off += l_bind_len
                l_port, r_proto, host_len = struct.unpack(">HBH", buf[off:off + 5])
                off += 5
                if len(buf) < off + host_len + 2 + 4:
                    return None
                host = buf[off:off + host_len].decode("utf-8", "ignore")
                off += host_len
                r_port, meta_len = struct.unpack(">HI", buf[off:off + 6])
                off += 6
                if len(buf) < off + meta_len:
                    return None
                meta: dict[str, Any] = {}
                if meta_len > 0:
                    meta_raw = buf[off:off + meta_len].decode("utf-8", "ignore")
                    parsed_meta = json.loads(meta_raw)
                    if isinstance(parsed_meta, dict):
                        meta = parsed_meta
                off += meta_len
                if off != len(buf):
                    return None
                lifecycle_hooks = meta.get("lifecycle_hooks")
                options = meta.get("options")
                return (
                    int(instance_id),
                    int(connection_seq),
                    int(svc_id),
                    int(l_proto),
                    l_bind,
                    int(l_port),
                    int(r_proto),
                    host,
                    int(r_port),
                    str(meta.get("name") or "").strip() or None,
                    lifecycle_hooks if isinstance(lifecycle_hooks, dict) else None,
                    options if isinstance(options, dict) else None,
                )

            # O4 legacy payload
            if len(buf) < 2 + 8 + 4 + 2 + 1 + 1 + 2 + 1 + 1 + 2:
                return None
            if buf[0:2] != b"O4":
                return None
            instance_id, connection_seq, svc_id, l_proto, l_bind_len = struct.unpack(">QIHBB", buf[2:18])
            off = 18
            if len(buf) < off + l_bind_len + 2 + 1 + 1 + 2:
                return None
            l_bind = buf[off:off + l_bind_len].decode("utf-8", "ignore")
            off += l_bind_len
            l_port, r_proto = struct.unpack(">HB", buf[off:off + 3])
            off += 3
            (hlen,) = struct.unpack(">B", buf[off:off + 1])
            off += 1
            if len(buf) < off + hlen + 2:
                return None
            host = buf[off:off + hlen].decode("utf-8", "ignore")
            off += hlen
            (r_port,) = struct.unpack(">H", buf[off:off + 2])
            off += 2
            if off != len(buf):
                return None
            return (
                int(instance_id),
                int(connection_seq),
                int(svc_id),
                int(l_proto),
                l_bind,
                int(l_port),
                int(r_proto),
                host,
                int(r_port),
                None,
                None,
                None,
            )
        except Exception:
            return None

    def _parse_open_v4(self, buf: bytes):
        parsed = self._parse_open_with_meta(buf)
        if parsed is None:
            return None
        return parsed[:9]

    # ---------- REMOTE_SERVICES_SET v2 payload ----------
    # RS2 legacy: compact fields.
    # RS3 extended: JSON entries preserving name/lifecycle_hooks/options.
    def _encode_remote_services_set_v2(self, services: list["ChannelMux.ServiceSpec"]) -> bytes:
        rows = [
            self._service_spec_wire_obj(
                self._service_spec_with_hook_env_defaults(s, remote_install=True)
            )
            for s in services
        ]
        blob = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        out = bytearray(b"RS3")
        out += struct.pack(
            ">QII",
            self._mux_instance_id & 0xFFFFFFFFFFFFFFFF,
            self._mux_connection_seq & 0xFFFFFFFF,
            len(blob),
        )
        out += blob
        return bytes(out)

    def _decode_remote_services_set_v2(self, payload: bytes) -> Optional[tuple[int, int, list["ChannelMux.ServiceSpec"]]]:
        try:
            # RS3 extended
            if len(payload) >= 19 and payload[:3] == b"RS3":
                instance_id, connection_seq, blob_len = struct.unpack(">QII", payload[3:19])
                if int(blob_len) < 0 or len(payload) != 19 + int(blob_len):
                    return None
                rows_raw = payload[19:19 + int(blob_len)].decode("utf-8", "ignore")
                parsed_rows = json.loads(rows_raw)
                if not isinstance(parsed_rows, list):
                    return None
                out_rs3: list[ChannelMux.ServiceSpec] = []
                for row in parsed_rows:
                    spec = self._service_spec_from_wire_obj(row)
                    if spec is None:
                        return None
                    out_rs3.append(spec)
                return int(instance_id), int(connection_seq), out_rs3

            # RS2 legacy
            if len(payload) < 17 or payload[:3] != b"RS2":
                return None
            off = 3
            instance_id, connection_seq, count = struct.unpack(">QIH", payload[off:off + 14])
            off += 14
            out: list[ChannelMux.ServiceSpec] = []
            for _ in range(int(count)):
                if off + 5 > len(payload):
                    return None
                svc_id, l_proto_i, l_len = struct.unpack(">HBB", payload[off:off + 4])
                off += 4
                if off + l_len + 4 > len(payload):
                    return None
                l_bind = payload[off:off + l_len].decode("utf-8", "ignore")
                off += l_len
                l_port, r_proto_i = struct.unpack(">HB", payload[off:off + 3])
                off += 3
                (r_len,) = struct.unpack(">B", payload[off:off + 1])
                off += 1
                if off + r_len + 2 > len(payload):
                    return None
                r_host = payload[off:off + r_len].decode("utf-8", "ignore")
                off += r_len
                (r_port,) = struct.unpack(">H", payload[off:off + 2])
                off += 2
                l_proto = self._proto_code_to_name(int(l_proto_i))
                r_proto = self._proto_code_to_name(int(r_proto_i))
                out.append(ChannelMux.ServiceSpec(
                    svc_id=int(svc_id),
                    l_proto=l_proto,
                    l_bind=l_bind,
                    l_port=int(l_port),
                    r_proto=r_proto,
                    r_host=r_host,
                    r_port=int(r_port),
                ))
            if off != len(payload):
                return None
            return int(instance_id), int(connection_seq), out
        except Exception:
            return None

    def _peer_epoch_is_new(self, peer_id: Optional[int], instance_id: int, connection_seq: int) -> bool:
        peer_key = int(peer_id or 0)
        prev = self._peer_mux_epochs.get(peer_key)
        if prev is None:
            self._peer_mux_epochs[peer_key] = (int(instance_id), int(connection_seq))
            return True
        prev_instance, prev_seq = prev
        if int(instance_id) == prev_instance and int(connection_seq) <= prev_seq:
            return False
        self._peer_mux_epochs[peer_key] = (int(instance_id), int(connection_seq))
        return True

    def _forget_udp_open_key(self, chan: int) -> None:
        key = self._udp_open_key_by_chan.pop(chan, None)
        if key is not None and self._udp_chan_by_open_key.get(key) == chan:
            self._udp_chan_by_open_key.pop(key, None)

    def _forget_tcp_open_key(self, chan: int) -> None:
        key = self._tcp_open_key_by_chan.pop(chan, None)
        if key is not None and self._tcp_chan_by_open_key.get(key) == chan:
            self._tcp_chan_by_open_key.pop(key, None)

    def _forget_tun_open_key(self, chan: int) -> None:
        key = self._tun_open_key_by_chan.pop(chan, None)
        if key is not None and self._tun_chan_by_open_key.get(key) == chan:
            self._tun_chan_by_open_key.pop(key, None)

    def _reset_peer_open_channels(self, peer_key: int) -> None:
        # UDP channels created from OPEN
        for key, chan in list(self._udp_chan_by_open_key.items()):
            if int(key[0]) != int(peer_key):
                continue
            tr = self._udp_client_transports.pop(chan, None)
            self._udp_client_last_ts.pop(chan, None)
            self._udp_client_pending.pop(chan, None)
            self._udp_client_svc_id.pop(chan, None)
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass
            self._drop_udp_fragment_reassembly(chan)
            self._finalize_channel_stats(chan, ChannelMux.Proto.UDP, peer_id=peer_key)
            self._chan_owner_peer_id.pop(chan, None)
            self._forget_udp_open_key(chan)
            self.log.info("[MUX] peer=%s epoch reset -> drop UDP chan=%s", peer_key, chan)

        # TCP channels created from OPEN
        for key, chan in list(self._tcp_chan_by_open_key.items()):
            if int(key[0]) != int(peer_key):
                continue
            tup = self._tcp_by_chan.pop(chan, None)
            self._tcp_pending_data.pop(chan, None)
            self._tcp_role_by_chan.pop(chan, None)
            if tup:
                _, writer = tup
                self._tcp_by_writer.pop(writer, None)
                try:
                    writer.close()
                except Exception:
                    pass
            self._finalize_channel_stats(chan, ChannelMux.Proto.TCP, peer_id=peer_key)
            self._chan_owner_peer_id.pop(chan, None)
            self._forget_tcp_open_key(chan)
            self.log.info("[MUX] peer=%s epoch reset -> drop TCP chan=%s", peer_key, chan)

        # TUN channels created from OPEN
        for key, chan in list(self._tun_chan_by_open_key.items()):
            if int(key[0]) != int(peer_key):
                continue
            self._rx_tun_close(chan)
            self.log.info("[MUX] peer=%s epoch reset -> drop TUN chan=%s", peer_key, chan)
    # ---------- start/stop ----------
    async def start(self) -> None:
        self.log.info("[MUX] start; overlay_connected=%s accepting=%s", self._overlay_connected, self._accepting_enabled)
        effective_services = self._effective_services_by_id()
        if effective_services:
            specs = "; ".join(f"{s.svc_id}:{s.l_proto} {s.l_bind}:{s.l_port} -> {s.r_proto} {s.r_host}:{s.r_port}" for s in effective_services.values())
            self.log.info("[MUX] services: %s", specs)
        else:
            self.log.info("[MUX] services: (none)")
        self.log.info("[MUX] start; overlay_connected=%s accepting=%s", self._overlay_connected, self._accepting_enabled)
        await self._start_prestaged_listener_shared_tun_services()
        if self._overlay_connected and self._accepting_enabled:
            await self._start_all_services()
            self._send_remote_services_catalog_if_any()
        self._sweeper_task = self.loop.create_task(self._udp_idle_sweeper())
        self._ensure_task = self.loop.create_task(self._ensure_servers_task())

    async def stop(self, reason: str = "") -> None:
        self.log.info("[MUX] stopping reason=%s", str(reason or "unspecified"))
        for t in (self._ensure_task, self._sweeper_task):
            if t:
                try: t.cancel()
                except Exception: pass
        self._ensure_task = self._sweeper_task = None
        await self._stop_all_services()
        await self._close_all_channels()
        await self._drop_peer_installed_services(peer_id=None)

    # ---------- overlay state ----------
    async def on_overlay_state(self, connected: bool):
        was_connected = self._overlay_connected
        self._overlay_connected = connected
        self.log.info("[MUX] overlay -> %s", "CONNECTED" if connected else "DISCONNECTED")
        if not connected:
            self._accepting_enabled = False
            await self._stop_all_services()
            await self._close_all_channels()
            return
        # Re-enable and (re)start
        if not was_connected:
            self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        self._accepting_enabled = True
        await self._start_all_services()
        self._replay_tun_listener_created_hooks()
        self._send_remote_services_catalog_if_any()

    async def on_transport_epoch_change(self, epoch: int) -> None:
        self.log.info("[MUX] transport epoch changed -> %s (hard resync)", epoch)
        self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        await self._close_all_channels()
        if self._overlay_connected and self._accepting_enabled:
            await self._start_all_services()
            self._replay_tun_listener_created_hooks()
        self._send_remote_services_catalog_if_any()

    def _replay_tun_listener_created_hooks(self) -> None:
        for svc_key, spec in self._effective_services_by_id().items():
            if str(spec.l_proto) != "tun":
                continue
            if svc_key not in self._svc_tun_devices:
                continue
            if self._hook_command_spec_for(spec, "listener", "on_created") is None:
                continue
            self._schedule_service_hook(spec, svc_key, "listener", "on_created")

    async def _start_prestaged_listener_shared_tun_services(self) -> None:
        for svc_key, spec in self._local_services.items():
            if svc_key in self._svc_tun_devices:
                continue
            if not self._is_server_shared_tun_service(spec):
                continue
            try:
                await self._start_tun_server_for(spec, svc_key)
            except Exception as e:
                self.log.warning(
                    "[MUX] prestarted shared TUN service %s:%s start failed: %r",
                    svc_key[0],
                    spec.svc_id,
                    e,
                )

    def on_overlay_peer_set(self, host: str, port: int) -> None:
        self._overlay_peer_host = str(host or self._overlay_peer_host or "")
        try:
            self._overlay_peer_port = int(port or self._overlay_peer_port or 0)
        except Exception:
            self._overlay_peer_port = int(self._overlay_peer_port or 0)
        if self._overlay_connected and self._accepting_enabled:
            self._replay_tun_listener_created_hooks()

    # ---------- service lifecycle ----------
    async def _start_all_services(self):
        for svc_key, svc in self._effective_services_by_id().items():
            try:
                if svc.l_proto == "tcp" and svc_key not in self._svc_tcp_servers:
                    await self._start_tcp_server_for(svc, svc_key)
                elif svc.l_proto == "udp" and svc_key not in self._svc_udp_servers:
                    await self._start_udp_server_for(svc, svc_key)
                elif svc.l_proto == "tun" and svc_key not in self._svc_tun_devices:
                    await self._start_tun_server_for(svc, svc_key)
            except Exception as e:
                self.log.warning("[MUX] service %s:%s start failed: %r", svc_key[0], svc.svc_id, e)

    async def _stop_all_services(self):
        effective = self._effective_services_by_id()
        # UDP first
        for sid in list(self._svc_udp_servers.keys()):
            spec = effective.get(sid)
            await self._stop_listener_for_service_id(sid, spec.l_proto if spec else "udp", spec=spec)
        # TCP
        for sid in list(self._svc_tcp_servers.keys()):
            spec = effective.get(sid)
            await self._stop_listener_for_service_id(sid, spec.l_proto if spec else "tcp", spec=spec)
        # TUN
        for sid in list(self._svc_tun_devices.keys()):
            spec = effective.get(sid)
            await self._stop_listener_for_service_id(sid, spec.l_proto if spec else "tun", spec=spec)

    async def _close_all_channels(self):
        # TCP
        for chan, (sid, w) in list(self._tcp_by_chan.items()):
            try:
                self.log.info("[TCP/CLI] chan=%s svc=%s close (global shutdown)", chan, sid)
                w.close()
                aw = getattr(w, "wait_closed", None)
                if callable(aw): await aw()
            except Exception: pass
        self._tcp_by_chan.clear()
        self._tcp_by_writer.clear()
        self._tcp_pending_data.clear()
        self._tcp_role_by_chan.clear()
        self._tcp_open_key_by_chan.clear()
        self._tcp_chan_by_open_key.clear()
        self._chan_owner_peer_id.clear()
        self._chan_stats.clear()
        # UDP server maps
        self._udp_by_client.clear()
        self._udp_by_chan.clear()
        # UDP client transports
        for chan, tr in list(self._udp_client_transports.items()):
            try: tr.close()
            except Exception: pass
        self._udp_client_transports.clear()
        self._udp_client_last_ts.clear()
        self._udp_client_pending.clear()
        self._udp_client_svc_id.clear()
        self._udp_open_key_by_chan.clear()
        self._udp_chan_by_open_key.clear()
        self._udp_frag_rx.clear()
        closed_tun_devices: set[int] = set()
        for chan, dev in list(self._tun_by_chan.items()):
            if dev.service_key is not None and self._svc_tun_devices.get(dev.service_key) is dev:
                dev.chan_id = None
            elif id(dev) not in closed_tun_devices:
                closed_tun_devices.add(id(dev))
                try:
                    self._close_tun_device(dev)
                except Exception:
                    pass
        self._tun_by_chan.clear()
        self._tun_chan_by_service.clear()
        self._tun_open_key_by_chan.clear()
        self._tun_chan_by_open_key.clear()
        self._tun_frag_rx.clear()
        self._ctrl_chunk_rx.clear()
        # Backpressure tasks
        for t in list(self._tcp_backpressure_tasks.values()):
            try: t.cancel()
            except Exception: pass
        self._tcp_backpressure_tasks.clear()
        self._tcp_backpressure_evt.clear()

    # ---------- UDP server (unconnected; multi-origin) ----------
    async def _start_udp_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        parent = self
        class _UDPServer(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                parent._svc_udp_servers[svc_key] = transport
                parent.log.info("[UDP/SRV] service=%s:%s listening on %s:%s", svc_key[0], spec.svc_id, spec.l_bind, spec.l_port)
            def datagram_received(self, data: bytes, addr):
                parent._on_local_udp_datagram(spec, svc_key, data, addr)
            def error_received(self, exc):
                parent.log.info("[UDP/SRV] service=%s:%s transport error: %r", svc_key[0], spec.svc_id, exc)
            def connection_lost(self, exc):
                parent.log.info("[UDP/SRV] service=%s:%s transport lost: %r", svc_key[0], spec.svc_id, exc)
                # Remove so _ensure_servers_task will respawn
                parent._svc_udp_servers.pop(svc_key, None)

        family = _listener_family_for_host(spec.l_bind)
        await self.loop.create_datagram_endpoint(
            lambda: _UDPServer(),
            local_addr=(spec.l_bind, spec.l_port),
            family=family
        )
        self._schedule_service_hook(spec, svc_key, "listener", "on_created")

    def _on_local_udp_datagram(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey", data: bytes, addr: tuple[str,int]) -> None:
        if not (self._overlay_connected and self._accepting_enabled):
            self.log.debug(f"[NET] package dropping  : ")
            return
        if len(data) > self._udp_service_datagram_cap:
            self.log.warning(
                "[UDP/SRV] drop oversize local UDP datagram len=%s cap=%s (%s)",
                len(data),
                self._udp_service_datagram_cap,
                self._udp_service_datagram_diag,
            )
            return
        now = time.time()
        key = (svc_key, addr)

        # --- NEW: resolve local server socket address once for this service ---
        srv_tr = self._svc_udp_servers.get(svc_key)
        l_sock = srv_tr.get_extra_info("sockname") if srv_tr else None
        l_ep = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else (spec.l_bind, int(spec.l_port))
        src = (addr[0], int(addr[1]))
        dst = l_ep

        if key not in self._udp_by_client:
            chan = self._alloc_udp_id()
            self._udp_by_client[key] = (chan, now)
            self._udp_by_chan[chan] = (svc_key, addr)
            self._chan_owner_peer_id[chan] = int(svc_key[1]) if str(svc_key[0]) == "peer" else 0
            self._schedule_service_hook(spec, svc_key, "listener", "on_channel_connected", channel_id=chan)
            self.log.debug("[UDP/SRV] learn %s -> chan=%s svc=%s:%s", addr, chan, svc_key[0], spec.svc_id)
            try:
                self._send_open_for_service(chan, ChannelMux.Proto.UDP, spec)
            except Exception:
                pass
        else:
            chan, _ = self._udp_by_client[key]

        # --- Enhanced per-datagram log with endpoints ---
        ctr = self._ctr(ChannelMux.Proto.UDP, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(data)
        try:
            self._log_conn("<-", "UDP", chan, data, src=src, dst=dst)
        except Exception as e:
            self.log.debug(f"[NET] logging failed : %r",e)
            pass

        # Touch activity & forward DATA to overlay
        self._udp_by_client[key] = (chan, now)
        self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, data)

    # ---------- UDP idle sweeper (both roles) ----------
    async def _udp_idle_sweeper(self):
        try:
            while True:
                await asyncio.sleep(1.0)
                now = time.time()
                # Server role mappings (per svc_id,addr)
                stale_srv: list[tuple[int, tuple[str,int]]] = []
                for key, (chan, ts) in list(self._udp_by_client.items()):
                    if (now - ts) >= self.UDP_IDLE_S:
                        stale_srv.append(key)
                for key in stale_srv:
                    chan, _ = self._udp_by_client.pop(key, (None, None))
                    if chan is None:
                        continue
                    self._udp_by_chan.pop(chan, None)
                    self._finalize_channel_stats(chan, ChannelMux.Proto.UDP)
                    self.log.info("[UDP/SRV] chan=%s idle >= %.0fs -> CLOSE", chan, self.UDP_IDLE_S)
                    self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.CLOSE, b"")
                # Client role transports (per chan)
                stale_cli: list[int] = []
                for chan, ts in list(self._udp_client_last_ts.items()):
                    if (now - ts) >= self.UDP_IDLE_S:
                        stale_cli.append(chan)
                for chan in stale_cli:
                    tr = self._udp_client_transports.pop(chan, None)
                    self._udp_client_last_ts.pop(chan, None)
                    self._finalize_channel_stats(chan, ChannelMux.Proto.UDP)
                    self._chan_owner_peer_id.pop(chan, None)
                    if tr:
                        try: tr.close()
                        except Exception: pass
                    self.log.info("[UDP/CLI] chan=%s idle >= %.0fs -> CLOSE", chan, self.UDP_IDLE_S)
                    self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.CLOSE, b"")
                self._prune_udp_fragment_reassembly()
                self._prune_tun_fragment_reassembly()
                self._prune_control_chunk_reassembly()
        except asyncio.CancelledError:
            return

    # ---------- Ensure servers task (self-healing) ----------
    async def _ensure_servers_task(self):
        try:
            while True:
                await asyncio.sleep(1.0)
                if not (self._overlay_connected and self._accepting_enabled):
                    continue
                for svc_key, spec in self._effective_services_by_id().items():
                    if spec.l_proto == "tcp":
                        srv = self._svc_tcp_servers.get(svc_key)
                        if srv is None or getattr(srv, "sockets", None) in (None, []):
                            self.log.info("[MUX] TCP service %s:%s ensure-listen (re)start", svc_key[0], spec.svc_id)
                            try:
                                await self._start_tcp_server_for(spec, svc_key)
                            except Exception as e:
                                self.log.info("[MUX] TCP service %s:%s restart failed: %r", svc_key[0], spec.svc_id, e)
                    elif spec.l_proto == "udp":
                        tr = self._svc_udp_servers.get(svc_key)
                        if tr is None:
                            self.log.info("[MUX] UDP service %s:%s ensure-listen (re)start", svc_key[0], spec.svc_id)
                            try:
                                await self._start_udp_server_for(spec, svc_key)
                            except Exception as e:
                                self.log.info("[MUX] UDP service %s:%s restart failed: %r", svc_key[0], spec.svc_id, e)
                    else:
                        dev = self._svc_tun_devices.get(svc_key)
                        if dev is None:
                            self.log.info("[MUX] TUN service %s:%s ensure-listen (re)start", svc_key[0], spec.svc_id)
                            try:
                                await self._start_tun_server_for(spec, svc_key)
                            except Exception as e:
                                self.log.info("[MUX] TUN service %s:%s restart failed: %r", svc_key[0], spec.svc_id, e)
        except asyncio.CancelledError:
            return

    def _effective_services_by_id(self) -> dict["ChannelMux.ServiceKey", "ChannelMux.ServiceSpec"]:
        out: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        out.update(self._local_services)
        out.update(self._peer_installed_services)
        return out

    def _install_shared_tun_ownership_for_service(
        self,
        svc_key: "ChannelMux.ServiceKey",
        spec: "ChannelMux.ServiceSpec",
    ) -> None:
        self._drop_shared_tun_state_for_service(svc_key)
        if str(spec.l_proto) != "tun" or str(spec.r_proto) != "tun":
            return
        snapshot = self._shared_tun_ownership_snapshot_for_spec(spec)
        if snapshot is None:
            return
        self._shared_tun_ownership_by_service[svc_key] = snapshot

    def _drop_shared_tun_state_for_service(self, svc_key: "ChannelMux.ServiceKey") -> None:
        self._shared_tun_ownership_by_service.pop(svc_key, None)
        self._shared_tun_drop_state_by_service.pop(svc_key, None)
        self._shared_tun_runtime_by_peer = {
            key: value
            for key, value in self._shared_tun_runtime_by_peer.items()
            if key[0] != svc_key
        }
        self._shared_tun_peer_ref_by_peer = {
            key: value
            for key, value in self._shared_tun_peer_ref_by_peer.items()
            if key[0] != svc_key
        }
        self._shared_tun_peer_id_by_ref = {
            key: value
            for key, value in self._shared_tun_peer_id_by_ref.items()
            if key[0] != svc_key
        }
        self._tun_inflow_scope_state = {
            key: value
            for key, value in self._tun_inflow_scope_state.items()
            if not (len(key) >= 3 and key[0] == "shared" and key[1] == svc_key)
        }

    def _drop_shared_tun_state_for_peer(self, peer_id: int) -> None:
        self._shared_tun_runtime_by_peer = {
            key: value
            for key, value in self._shared_tun_runtime_by_peer.items()
            if int(key[1]) != int(peer_id)
        }
        removed = [
            key
            for key in self._shared_tun_peer_ref_by_peer
            if int(key[1]) == int(peer_id)
        ]
        for key in removed:
            peer_ref = self._shared_tun_peer_ref_by_peer.pop(key, None)
            if peer_ref is None:
                continue
            ref_key = (key[0], str(peer_ref))
            if self._shared_tun_peer_id_by_ref.get(ref_key) == int(peer_id):
                self._shared_tun_peer_id_by_ref.pop(ref_key, None)
        self._tun_inflow_scope_state = {
            key: value
            for key, value in self._tun_inflow_scope_state.items()
            if not (len(key) >= 4 and key[0] == "shared" and int(peer_id) in set(key[3]))
        }

    def _record_shared_tun_peer_binding(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        peer_id: Optional[int],
        chan_id: int,
    ) -> None:
        if svc_key is None or peer_id is None:
            return
        if svc_key not in self._shared_tun_ownership_by_service:
            return
        key = (svc_key, int(peer_id))
        state = self._shared_tun_runtime_by_peer.setdefault(
            key,
            {"preferred_chan_id": None, "bound_chan_ids": []},
        )
        bound_chan_ids = [int(v) for v in list(state.get("bound_chan_ids") or []) if int(v) != int(chan_id)]
        bound_chan_ids.append(int(chan_id))
        bound_chan_ids.sort()
        state["bound_chan_ids"] = bound_chan_ids
        preferred = state.get("preferred_chan_id")
        state["preferred_chan_id"] = int(preferred) if preferred in bound_chan_ids else bound_chan_ids[0]

    def _drop_shared_tun_peer_binding(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        peer_id: Optional[int],
        chan_id: int,
    ) -> None:
        if svc_key is None or peer_id is None:
            return
        key = (svc_key, int(peer_id))
        state = self._shared_tun_runtime_by_peer.get(key)
        if not isinstance(state, dict):
            return
        bound_chan_ids = [int(v) for v in list(state.get("bound_chan_ids") or []) if int(v) != int(chan_id)]
        if not bound_chan_ids:
            self._shared_tun_runtime_by_peer.pop(key, None)
            return
        state["bound_chan_ids"] = bound_chan_ids
        preferred = state.get("preferred_chan_id")
        state["preferred_chan_id"] = int(preferred) if preferred in bound_chan_ids else bound_chan_ids[0]

    def _shared_tun_runtime_snapshot_for_service(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> Optional[dict[str, Any]]:
        if svc_key is None:
            return None
        ownership = self._shared_tun_ownership_by_service.get(svc_key)
        if not isinstance(ownership, dict):
            return None
        active_peer_bindings = [
            {
                "peer_id": int(key[1]),
                "preferred_chan_id": state.get("preferred_chan_id"),
                "bound_chan_ids": [int(v) for v in list(state.get("bound_chan_ids") or [])],
                "throttle_prev_window_bytes": 0,
                "throttle_curr_window_bytes": 0,
                "throttle_drop_count": 0,
            }
            for key, state in self._shared_tun_runtime_by_peer.items()
            if key[0] == svc_key and isinstance(state, dict)
        ]
        throttle_scopes = self._shared_tun_throttle_scope_snapshots_for_service(svc_key)
        throttle_by_peer: dict[int, dict[str, Any]] = {}
        for scope in throttle_scopes:
            selected_peer_ids = [int(v) for v in list(scope.get("selected_peer_ids") or [])]
            if len(selected_peer_ids) == 1:
                throttle_by_peer[int(selected_peer_ids[0])] = scope
        for entry in active_peer_bindings:
            scope = throttle_by_peer.get(int(entry.get("peer_id", 0) or 0))
            if not isinstance(scope, dict):
                continue
            entry["throttle_prev_window_bytes"] = int(scope.get("prev_window_bytes", 0) or 0)
            entry["throttle_curr_window_bytes"] = int(scope.get("curr_window_bytes", 0) or 0)
            entry["throttle_drop_count"] = int(scope.get("throttle_drop_count", 0) or 0)
        active_peer_bindings.sort(key=lambda entry: int(entry.get("peer_id", 0)))
        drop_state = self._shared_tun_drop_state_by_service.get(svc_key)
        return self._shared_tun_runtime_snapshot(ownership, active_peer_bindings, throttle_scopes, drop_state)

    def _record_shared_tun_drop(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        *,
        reason: str,
        direction: str,
        peer_id: Optional[int] = None,
        chan_id: Optional[int] = None,
        ip_version: Optional[int] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        route_class: Optional[str] = None,
        packet_bytes: Optional[int] = None,
    ) -> None:
        if svc_key is None or svc_key not in self._shared_tun_ownership_by_service:
            return
        state = self._shared_tun_drop_state_by_service.setdefault(
            svc_key,
            {"total": 0, "by_reason": {}, "recent_drops": []},
        )
        reason_key = str(reason or "unknown")
        state["total"] = int(state.get("total", 0) or 0) + 1
        by_reason = dict(state.get("by_reason") or {})
        by_reason[reason_key] = int(by_reason.get(reason_key, 0) or 0) + 1
        state["by_reason"] = by_reason
        recent = list(state.get("recent_drops") or [])
        recent.append(
            {
                "reason": reason_key,
                "direction": str(direction or ""),
                "peer_id": None if peer_id is None else int(peer_id),
                "chan_id": None if chan_id is None else int(chan_id),
                "ip_version": None if ip_version is None else int(ip_version),
                "source_ip": None if source_ip is None else str(source_ip),
                "destination_ip": None if destination_ip is None else str(destination_ip),
                "route_class": None if route_class is None else str(route_class),
                "packet_bytes": None if packet_bytes is None else int(packet_bytes),
            }
        )
        if len(recent) > self.SHARED_TUN_RECENT_DROP_LIMIT:
            recent = recent[-self.SHARED_TUN_RECENT_DROP_LIMIT :]
        state["recent_drops"] = recent

    @staticmethod
    def _direct_tun_inflow_scope_key(
        svc_key: Optional["ChannelMux.ServiceKey"],
        chan_id: Optional[int],
    ) -> tuple[Any, ...]:
        return ("direct", svc_key)

    @staticmethod
    def _shared_tun_inflow_scope_key(
        svc_key: Optional["ChannelMux.ServiceKey"],
        route: Optional[dict[str, Any]],
    ) -> Optional[tuple[Any, ...]]:
        if svc_key is None or not isinstance(route, dict) or not bool(route.get("routed")):
            return None
        return (
            "shared",
            svc_key,
            str(route.get("route_class") or ""),
            tuple(int(v) for v in list(route.get("selected_peer_ids") or [])),
            tuple(int(v) for v in list(route.get("selected_chan_ids") or [])),
        )

    @staticmethod
    def _tun_inflow_scope_id(scope_key: tuple[Any, ...]) -> str:
        if not scope_key:
            return ""
        if scope_key[0] == "shared" and len(scope_key) >= 5:
            _, svc_key, route_class, peer_ids, chan_ids = scope_key[:5]
            return (
                f"shared:{svc_key[0]}:{svc_key[1]}:{svc_key[2]}:{route_class}:"
                f"peers={','.join(str(int(v)) for v in peer_ids)}:"
                f"chans={','.join(str(int(v)) for v in chan_ids)}"
            )
        if scope_key[0] == "direct" and len(scope_key) >= 3:
            _, svc_key, chan_id = scope_key[:3]
            return f"direct:{svc_key}:{'' if chan_id is None else int(chan_id)}"
        if scope_key[0] == "direct" and len(scope_key) >= 2:
            _, svc_key = scope_key[:2]
            return f"direct:{svc_key}"
        return str(scope_key)

    def _shared_tun_throttle_scope_snapshots_for_service(
        self,
        svc_key: "ChannelMux.ServiceKey",
    ) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        for key, state in self._tun_inflow_scope_state.items():
            if len(key) < 5 or key[0] != "shared" or key[1] != svc_key or not isinstance(state, dict):
                continue
            snapshots.append(
                {
                    "scope_id": self._tun_inflow_scope_id(key),
                    "route_class": str(key[2] or ""),
                    "selected_peer_ids": [int(v) for v in key[3]],
                    "selected_chan_ids": [int(v) for v in key[4]],
                    "prev_window_bytes": int(state.get("prev_bytes", 0) or 0),
                    "curr_window_bytes": int(state.get("curr_bytes", 0) or 0),
                    "throttle_drop_count": int(state.get("throttle_drop_count", 0) or 0),
                }
            )
        snapshots.sort(key=lambda entry: str(entry.get("scope_id") or ""))
        return snapshots

    def _shared_tun_bound_peer_ref_for_packet(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        peer_id: Optional[int],
        source_ip: str,
    ) -> Optional[str]:
        if svc_key is None or peer_id is None or not source_ip:
            return None
        ownership = self._shared_tun_ownership_by_service.get(svc_key)
        if not isinstance(ownership, dict):
            return None
        owner_by_ipv4 = dict(ownership.get("owner_by_ipv4") or {})
        owner_by_ipv6 = dict(ownership.get("owner_by_ipv6") or {})
        owner_ref = owner_by_ipv4.get(str(source_ip)) or owner_by_ipv6.get(str(source_ip))
        if not owner_ref:
            return None
        peer_key = (svc_key, int(peer_id))
        existing_ref = self._shared_tun_peer_ref_by_peer.get(peer_key)
        if existing_ref is not None:
            if str(existing_ref) != str(owner_ref):
                return None
            return str(existing_ref)
        self._shared_tun_peer_ref_by_peer[peer_key] = str(owner_ref)
        self._shared_tun_peer_id_by_ref[(svc_key, str(owner_ref))] = int(peer_id)
        return str(owner_ref)

    @staticmethod
    def _shared_tun_plan_outbound_route(
        ownership: dict[str, Any],
        peer_id_by_ref: dict[str, int],
        active_peer_bindings: list[dict[str, Any]],
        packet: bytes,
    ) -> dict[str, Any]:
        parsed, parse_error = ChannelMux._parse_tun_packet_endpoints(packet)
        if parse_error is not None:
            return {
                "routed": False,
                "route_class": None,
                "selected_peer_ids": [],
                "selected_chan_ids": [],
                "ip_version": None,
                "destination_ip": None,
                "drop_reason": parse_error,
            }
        destination_ip = str(parsed.get("destination_ip") or "")
        active_by_peer_id: dict[int, dict[str, Any]] = {
            int(entry.get("peer_id", 0)): entry
            for entry in active_peer_bindings
            if isinstance(entry, dict)
        }
        if int(parsed.get("ip_version", 0) or 0) == 4 and destination_ip == "255.255.255.255":
            selected = [
                entry
                for entry in active_peer_bindings
                if entry.get("preferred_chan_id") is not None
            ]
            selected.sort(key=lambda entry: int(entry.get("peer_id", 0) or 0))
            return {
                "routed": bool(selected),
                "route_class": "broadcast",
                "selected_peer_ids": [int(entry.get("peer_id", 0) or 0) for entry in selected],
                "selected_chan_ids": [int(entry.get("preferred_chan_id")) for entry in selected],
                "ip_version": int(parsed.get("ip_version", 0) or 0),
                "destination_ip": destination_ip,
                "drop_reason": None if selected else "broadcast_no_active_peers",
            }
        owner_ref = (
            dict(ownership.get("owner_by_ipv4") or {}).get(destination_ip)
            or dict(ownership.get("owner_by_ipv6") or {}).get(destination_ip)
        )
        if not owner_ref:
            return {
                "routed": False,
                "route_class": "unicast",
                "selected_peer_ids": [],
                "selected_chan_ids": [],
                "ip_version": int(parsed.get("ip_version", 0) or 0),
                "destination_ip": destination_ip,
                "drop_reason": "unknown_destination",
            }
        peer_id = peer_id_by_ref.get(str(owner_ref))
        if peer_id is None:
            return {
                "routed": False,
                "route_class": "unicast",
                "selected_peer_ids": [],
                "selected_chan_ids": [],
                "ip_version": int(parsed.get("ip_version", 0) or 0),
                "destination_ip": destination_ip,
                "drop_reason": "destination_peer_unmapped",
            }
        binding = active_by_peer_id.get(int(peer_id))
        preferred_chan_id = None if binding is None else binding.get("preferred_chan_id")
        if preferred_chan_id is None:
            return {
                "routed": False,
                "route_class": "unicast",
                "selected_peer_ids": [int(peer_id)],
                "selected_chan_ids": [],
                "ip_version": int(parsed.get("ip_version", 0) or 0),
                "destination_ip": destination_ip,
                "drop_reason": "destination_peer_inactive",
            }
        return {
            "routed": True,
            "route_class": "unicast",
            "selected_peer_ids": [int(peer_id)],
            "selected_chan_ids": [int(preferred_chan_id)],
            "ip_version": int(parsed.get("ip_version", 0) or 0),
            "destination_ip": destination_ip,
            "drop_reason": None,
        }

    def _shared_tun_plan_local_delivery(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        packet: bytes,
    ) -> Optional[dict[str, Any]]:
        if self._tun_routing_config().shared_tun_disable_outflow_filter:
            return None
        if svc_key is None:
            return None
        ownership = self._shared_tun_ownership_by_service.get(svc_key)
        if not isinstance(ownership, dict):
            return None
        peer_id_by_ref = {
            str(peer_ref): int(peer_id)
            for (mapped_svc_key, peer_ref), peer_id in self._shared_tun_peer_id_by_ref.items()
            if mapped_svc_key == svc_key
        }
        active_peer_bindings = [
            {
                "peer_id": int(key[1]),
                "preferred_chan_id": state.get("preferred_chan_id"),
                "bound_chan_ids": [int(v) for v in list(state.get("bound_chan_ids") or [])],
            }
            for key, state in self._shared_tun_runtime_by_peer.items()
            if key[0] == svc_key and isinstance(state, dict)
        ]
        return self._shared_tun_plan_outbound_route(ownership, peer_id_by_ref, active_peer_bindings, packet)

    def _shared_tun_plan_inbound_peer_relay(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        source_peer_id: Optional[int],
        packet: bytes,
    ) -> Optional[dict[str, Any]]:
        if self._tun_routing_config().shared_tun_disable_outflow_filter:
            return None
        route = self._shared_tun_plan_local_delivery(svc_key, packet)
        if route is None:
            return None
        route = dict(route)
        selected_peer_ids = [int(v) for v in list(route.get("selected_peer_ids") or [])]
        if (
            str(route.get("route_class") or "") == "unicast"
            and bool(route.get("routed"))
            and selected_peer_ids
            and source_peer_id is not None
            and int(selected_peer_ids[0]) != int(source_peer_id)
        ):
            route["relay_to_peer"] = True
            route["deliver_local"] = False
            return route
        route["relay_to_peer"] = False
        route["deliver_local"] = True
        return route

    @staticmethod
    def _parse_tun_packet_endpoints(packet: bytes) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        payload = bytes(packet or b"")
        if not payload:
            return None, "empty"
        version = (payload[0] >> 4) & 0x0F
        if version == 4:
            if len(payload) < 20:
                return None, "ipv4_too_short"
            ihl = (payload[0] & 0x0F) * 4
            if ihl < 20 or len(payload) < ihl:
                return None, "ipv4_header_truncated"
            return (
                {
                    "ip_version": 4,
                    "source_ip": str(ipaddress.IPv4Address(payload[12:16])),
                    "destination_ip": str(ipaddress.IPv4Address(payload[16:20])),
                },
                None,
            )
        if version == 6:
            if len(payload) < 40:
                return None, "ipv6_too_short"
            return (
                {
                    "ip_version": 6,
                    "source_ip": str(ipaddress.IPv6Address(payload[8:24])),
                    "destination_ip": str(ipaddress.IPv6Address(payload[24:40])),
                },
                None,
            )
        return None, "unsupported_ip_version"

    def _shared_tun_allowed_source_ips_for_peer(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        peer_id: Optional[int],
    ) -> Optional[set[str]]:
        if svc_key is None or peer_id is None:
            return None
        ownership = self._shared_tun_ownership_by_service.get(svc_key)
        if not isinstance(ownership, dict):
            return None
        peers = [entry for entry in list(ownership.get("peers") or []) if isinstance(entry, dict)]
        if len(peers) != 1:
            return None
        entry = peers[0]
        return {
            str(addr)
            for addr in list(entry.get("ipv4") or []) + list(entry.get("ipv6") or [])
            if str(addr)
        }

    def _shared_tun_guard_inbound_packet(
        self,
        *,
        dev: "ChannelMux.TunDevice",
        chan: int,
        packet: bytes,
    ) -> tuple[bool, Optional[dict[str, Any]], Optional[str]]:
        svc_key = getattr(dev, "service_key", None)
        ownership = self._shared_tun_ownership_by_service.get(svc_key) if svc_key is not None else None
        if not isinstance(ownership, dict):
            return True, None, None
        parsed, parse_error = self._parse_tun_packet_endpoints(packet)
        if parse_error is not None:
            return False, None, parse_error
        if self._tun_routing_config().shared_tun_disable_inflow_filter:
            return True, parsed, None
        peer_id = self._chan_owner_peer_id.get(int(chan))
        source_ip = str(parsed.get("source_ip") or "")
        bound_peer_ref = self._shared_tun_bound_peer_ref_for_packet(svc_key, peer_id, source_ip)
        if bound_peer_ref is None:
            return False, parsed, "source_not_owned_by_peer"
        return True, parsed, None

    def _next_ctrl_chunk_txid(self) -> int:
        txid = int(self._ctrl_chunk_next_txid) & 0xFFFFFFFF
        if txid <= 0:
            txid = 1
        self._ctrl_chunk_next_txid = 1 if txid == 0xFFFFFFFF else txid + 1
        return txid

    def _max_mux_data_len(self) -> int:
        return max(0, self._session_max_app_payload - ChannelMux.MUX_HDR.size)

    def _send_chunked_control_payload(
        self,
        *,
        chan_id: int,
        proto: "ChannelMux.Proto",
        chunk_mtype: "ChannelMux.MType",
        payload: bytes,
    ) -> None:
        max_data_len = self._max_mux_data_len()
        chunk_payload_cap = max_data_len - ChannelMux.CTRL_CHUNK_HDR.size
        if chunk_payload_cap <= 0:
            self.log.error(
                "[MUX/CTRL] cannot send chunked payload mtype=%s: no room for chunk header (session_max=%s)",
                int(chunk_mtype),
                self._session_max_app_payload,
            )
            return
        if not payload:
            payload = b""
        total_chunks = max(1, (len(payload) + chunk_payload_cap - 1) // chunk_payload_cap)
        if total_chunks > 0xFFFF:
            self.log.error(
                "[MUX/CTRL] cannot send chunked payload mtype=%s: too many chunks=%s",
                int(chunk_mtype),
                total_chunks,
            )
            return
        txid = self._next_ctrl_chunk_txid()
        self.log.info(
            "[MUX/CTRL] chunked send mtype=%s txid=%s chan=%s proto=%s bytes=%s chunks=%s cap=%s",
            int(chunk_mtype),
            txid,
            chan_id,
            int(proto),
            len(payload),
            total_chunks,
            chunk_payload_cap,
        )
        for idx in range(total_chunks):
            part = payload[idx * chunk_payload_cap:(idx + 1) * chunk_payload_cap]
            frame_data = ChannelMux.CTRL_CHUNK_HDR.pack(
                ChannelMux.CTRL_CHUNK_MAGIC,
                txid,
                idx,
                total_chunks,
            ) + part
            self._send_mux(chan_id, proto, chunk_mtype, frame_data)

    def _consume_control_chunk(
        self,
        *,
        chan_id: int,
        proto: "ChannelMux.Proto",
        mtype: "ChannelMux.MType",
        payload: bytes,
        peer_id: Optional[int],
    ) -> Optional[bytes]:
        if len(payload) < ChannelMux.CTRL_CHUNK_HDR.size:
            return None
        magic, txid, chunk_idx, chunk_total = ChannelMux.CTRL_CHUNK_HDR.unpack(payload[:ChannelMux.CTRL_CHUNK_HDR.size])
        if magic != ChannelMux.CTRL_CHUNK_MAGIC:
            return None
        if int(chunk_total) <= 0 or int(chunk_total) > 0xFFFF or int(chunk_idx) >= int(chunk_total):
            return None
        chunk = bytes(payload[ChannelMux.CTRL_CHUNK_HDR.size:])
        key = (int(peer_id or 0), int(chan_id), int(proto), int(mtype), int(txid))
        state = self._ctrl_chunk_rx.get(key)
        now = time.time()
        if state is None:
            if len(self._ctrl_chunk_rx) >= self.CTRL_CHUNK_MAX_INFLIGHT:
                self._prune_control_chunk_reassembly()
                if len(self._ctrl_chunk_rx) >= self.CTRL_CHUNK_MAX_INFLIGHT:
                    self.log.warning("[MUX/CTRL] drop chunk txid=%s: reassembly table full", txid)
                    return None
            state = {"total": int(chunk_total), "parts": {}, "received": 0, "updated": now}
            self._ctrl_chunk_rx[key] = state
        elif int(state.get("total", 0)) != int(chunk_total):
            self._ctrl_chunk_rx.pop(key, None)
            return None
        parts = state.setdefault("parts", {})
        if int(chunk_idx) not in parts:
            parts[int(chunk_idx)] = chunk
            state["received"] = int(state.get("received", 0)) + len(chunk)
        state["updated"] = now
        if len(parts) < int(chunk_total):
            return None
        assembled = bytearray()
        for idx in range(int(chunk_total)):
            piece = parts.get(idx)
            if piece is None:
                return None
            assembled.extend(piece)
        self._ctrl_chunk_rx.pop(key, None)
        return bytes(assembled)

    def _prune_control_chunk_reassembly(self) -> None:
        now = time.time()
        expired = [
            key
            for key, state in self._ctrl_chunk_rx.items()
            if (now - float(state.get("updated", now))) >= self.CTRL_CHUNK_REASSEMBLY_TTL_S
        ]
        for key in expired:
            self._ctrl_chunk_rx.pop(key, None)

    def _send_open_for_service(self, chan_id: int, proto: "ChannelMux.Proto", spec: "ChannelMux.ServiceSpec") -> None:
        payload = self._build_open_v4(spec)
        if ChannelMux.MUX_HDR.size + len(payload) <= self._session_max_app_payload:
            self._send_mux(chan_id, proto, ChannelMux.MType.OPEN, payload)
            return
        self._send_chunked_control_payload(
            chan_id=chan_id,
            proto=proto,
            chunk_mtype=ChannelMux.MType.OPEN_CHUNK,
            payload=payload,
        )

    def _send_remote_services_catalog_if_any(self) -> None:
        if not self._remote_services_requested:
            return
        try:
            payload = self._encode_remote_services_set_v2(self._remote_services_requested)
            if ChannelMux.MUX_HDR.size + len(payload) <= self._session_max_app_payload:
                self._send_mux(0, ChannelMux.Proto.UDP, ChannelMux.MType.REMOTE_SERVICES_SET_V2, payload)
                self.log.info("[MUX/CTRL] sent REMOTE_SERVICES_SET_V2 with %d service(s)", len(self._remote_services_requested))
            else:
                self._send_chunked_control_payload(
                    chan_id=0,
                    proto=ChannelMux.Proto.UDP,
                    chunk_mtype=ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
                    payload=payload,
                )
                self.log.info(
                    "[MUX/CTRL] sent chunked REMOTE_SERVICES_SET_V2 with %d service(s)",
                    len(self._remote_services_requested),
                )
        except Exception as e:
            self.log.warning("[MUX/CTRL] failed sending REMOTE_SERVICES_SET_V2: %r", e)

    async def _stop_listener_for_service_id(
        self,
        svc_key: "ChannelMux.ServiceKey",
        proto_name: str,
        *,
        spec: Optional["ChannelMux.ServiceSpec"] = None,
    ) -> None:
        if spec is None:
            spec = self._effective_services_by_id().get(svc_key)
        if spec is not None:
            await self._run_service_hook(spec, svc_key, "listener", "on_stopped")
        if proto_name == "udp":
            tr = self._svc_udp_servers.pop(svc_key, None)
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass
            return
        if proto_name == "tun":
            dev = self._svc_tun_devices.pop(svc_key, None)
            if dev is not None:
                self._unbind_all_tun_channels_for_device(dev)
                self._close_tun_device(dev)
            self._drop_shared_tun_state_for_service(svc_key)
            return
        srv = self._svc_tcp_servers.pop(svc_key, None)
        if srv:
            try:
                srv.close()
                await srv.wait_closed()
            except Exception:
                pass

    async def _apply_peer_installed_services(self, services: list["ChannelMux.ServiceSpec"], peer_id: Optional[int]) -> None:
        owner_peer_id = int(peer_id or 0)
        new_map: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {
            ("peer", owner_peer_id, int(s.svc_id)): s for s in services
        }
        old_map = {k: v for k, v in self._peer_installed_services.items() if k[0] == "peer" and int(k[1]) == owner_peer_id}
        to_stop: set[ChannelMux.ServiceKey] = set()
        to_start: set[ChannelMux.ServiceKey] = set()

        for sid in set(old_map.keys()) - set(new_map.keys()):
            to_stop.add(sid)
        for sid in set(new_map.keys()) - set(old_map.keys()):
            to_start.add(sid)
        for sid in set(new_map.keys()) & set(old_map.keys()):
            if new_map[sid] != old_map[sid]:
                to_stop.add(sid)
                to_start.add(sid)

        for svc_key in sorted(to_stop):
            old = old_map.get(svc_key)
            if old:
                await self._stop_listener_for_service_id(svc_key, old.l_proto, spec=old)

        for svc_key in set(old_map.keys()) - set(new_map.keys()):
            self._peer_installed_services.pop(svc_key, None)
        for svc_key, old in old_map.items():
            if svc_key in new_map and svc_key in to_stop:
                self._peer_installed_services.pop(svc_key, None)
        for svc_key, spec in new_map.items():
            self._peer_installed_services[svc_key] = spec

        if self._overlay_connected and self._accepting_enabled:
            for svc_key in sorted(to_start):
                spec = new_map.get(svc_key)
                if not spec:
                    continue
                try:
                    if spec.l_proto == "tcp" and svc_key not in self._svc_tcp_servers:
                        await self._start_tcp_server_for(spec, svc_key)
                    elif spec.l_proto == "udp" and svc_key not in self._svc_udp_servers:
                        await self._start_udp_server_for(spec, svc_key)
                    elif spec.l_proto == "tun" and svc_key not in self._svc_tun_devices:
                        await self._start_tun_server_for(spec, svc_key)
                except Exception as e:
                    self.log.warning("[MUX/CTRL] peer-installed service %s:%s start failed: %r", svc_key[0], spec.svc_id, e)

    async def _drop_peer_installed_services(self, peer_id: Optional[int]) -> None:
        if peer_id is None:
            to_stop = {k: v for k, v in self._peer_installed_services.items() if k[0] == "peer"}
        else:
            owner_peer_id = int(peer_id)
            to_stop = {
                k: v for k, v in self._peer_installed_services.items()
                if k[0] == "peer" and int(k[1]) == owner_peer_id
            }
        for svc_key, spec in list(to_stop.items()):
            await self._stop_listener_for_service_id(svc_key, spec.l_proto, spec=spec)
            self._peer_installed_services.pop(svc_key, None)

    def on_peer_disconnected(self, peer_id: int) -> None:
        self._pending_peer_service_catalogs.pop(int(peer_id), None)
        self._peer_mux_epochs.pop(int(peer_id), None)
        self._reset_peer_open_channels(int(peer_id))
        self._drop_shared_tun_state_for_peer(int(peer_id))
        try:
            self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_id))
        except Exception as e:
            self.log.debug("[MUX/CTRL] failed scheduling peer disconnect cleanup for peer_id=%s: %r", peer_id, e)

    # ---------- MUX send ----------
    def _send_mux(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType, data: bytes) -> None:
        if not self.session.is_connected():
            return
        if proto == ChannelMux.Proto.UDP and mtype == ChannelMux.MType.DATA:
            payload = bytes(data or b"")
            if ChannelMux.MUX_HDR.size + len(payload) > self._session_max_app_payload:
                self._send_udp_mux_fragments(chan_id, payload)
                return
        if proto == ChannelMux.Proto.TUN and mtype == ChannelMux.MType.DATA:
            payload = bytes(data or b"")
            if ChannelMux.MUX_HDR.size + len(payload) > self._session_max_app_payload:
                self._send_tun_mux_fragments(chan_id, payload)
                return
        # Enforce the effective session payload budget so transport wrappers such as
        # secure-link over WS cannot emit oversized outer frames.
        if data is None:
            data = b""
        wire = self._pack_mux(chan_id, proto, self._next_ctr(chan_id, proto, mtype), mtype, data)
        if len(wire) > self._session_max_app_payload:
            self.log.error(
                "[MUX] drop oversized app message: %d bytes > %d",
                len(wire),
                self._session_max_app_payload,
            )
            return
        # Local->peer counter hook
        if self._on_local_rx:
            try: self._on_local_rx(len(wire))
            except Exception: pass
        try:
            owner_peer_id = self._chan_owner_peer_id.get(int(chan_id))
            try:
                self.session.send_app(wire, peer_id=owner_peer_id)
            except TypeError:
                self.session.send_app(wire)
        except Exception as e:
            self.log.debug("[MUX] send_app error: %r", e)
        try:
            self._log_app_msg("->",wire)
        except Exception as e:
            self.log.debug("[MUX] logging error: %r", e)

    def _warning_with_channel_dump(self, msg: str, *args) -> None:
        self.log.warning(msg, *args)
        if self._warn_dumped_channel_config:
            return
        self._warn_dumped_channel_config = True
        try:
            self.log.warning(
                "[MUX/CFG] channel-config local=%d requested_remote=%d peer_installed=%d tcp_live=%d udp_srv_map=%d udp_cli_live=%d",
                len(self._local_services),
                len(self._remote_services_requested),
                len(self._peer_installed_services),
                len(self._tcp_by_chan),
                len(self._udp_by_chan),
                len(self._udp_client_transports),
            )
            self.log.warning(
                "[MUX/CFG] local_services=%s requested_remote=%s peer_installed=%s",
                [f"{k[0]}:{k[2]}:{v.l_proto}:{v.l_bind}:{v.l_port}->{v.r_proto}:{v.r_host}:{v.r_port}" for k, v in self._local_services.items()],
                [f"{s.svc_id}:{s.l_proto}:{s.l_bind}:{s.l_port}->{s.r_proto}:{s.r_host}:{s.r_port}" for s in self._remote_services_requested],
                [f"{k[0]}:{k[1]}:{k[2]}:{v.l_proto}:{v.l_bind}:{v.l_port}->{v.r_proto}:{v.r_host}:{v.r_port}" for k, v in self._peer_installed_services.items()],
            )
        except Exception as e:
            self.log.warning("[MUX/CFG] failed to dump channel-config: %r", e)

    def _next_ctr(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType) -> int:
        key = (chan_id, int(proto))
        if mtype == ChannelMux.MType.OPEN:
            self._mux_counters[key] = 0
            return 0
        prev = self._mux_counters.get(key, 0)
        nxt = (prev + 1) & 0xFFFF
        self._mux_counters[key] = nxt
        return nxt

    def _next_udp_fragment_datagram_id(self) -> int:
        datagram_id = int(self._udp_frag_next_datagram_id) & 0xFFFFFFFF
        if datagram_id <= 0:
            datagram_id = 1
        self._udp_frag_next_datagram_id = 1 if datagram_id == 0xFFFFFFFF else datagram_id + 1
        return datagram_id

    def _udp_fragment_payload_limit(self) -> int:
        return max(0, self._session_max_app_payload - ChannelMux.MUX_HDR.size - ChannelMux.UDP_FRAG_HDR.size)

    @staticmethod
    def _describe_session_stack(session: ISession) -> str:
        parts: list[str] = []
        seen: set[int] = set()
        current: Any = session
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            parts.append(type(current).__name__)
            next_session = getattr(current, "_inner", None)
            if next_session is None:
                next_session = getattr(current, "_real", None)
            if next_session is current:
                break
            current = next_session
        return " -> ".join(parts)

    @staticmethod
    def _resolve_udp_service_datagram_cap(session: ISession) -> tuple[int, str]:
        local_udp_payload_cap = 65507
        fragment_header_cap = 0xFFFF
        cap = min(local_udp_payload_cap, fragment_header_cap)
        stack = ChannelMux._describe_session_stack(session)
        diag = (
            f"stack={stack}; local_udp_payload_cap={local_udp_payload_cap}; "
            f"mux_fragment_total_len_cap={fragment_header_cap}"
        )
        return cap, diag

    def _send_udp_mux_fragments(self, chan_id: int, payload: bytes) -> None:
        frag_payload_limit = self._udp_fragment_payload_limit()
        if frag_payload_limit <= 0:
            self.log.error(
                "[MUX] drop oversized UDP datagram: no fragment payload fits within session budget %d",
                self._session_max_app_payload,
            )
            return
        datagram_id = self._next_udp_fragment_datagram_id()
        total_len = len(payload)
        self.log.info(
            "[MUX] fragment UDP datagram chan=%s len=%s datagram_id=%s frag_payload_limit=%s",
            chan_id,
            total_len,
            datagram_id,
            frag_payload_limit,
        )
        for offset in range(0, total_len, frag_payload_limit):
            frag_payload = ChannelMux.UDP_FRAG_HDR.pack(
                datagram_id,
                total_len & 0xFFFF,
                offset & 0xFFFF,
            ) + payload[offset:offset + frag_payload_limit]
            self._send_mux(chan_id, ChannelMux.Proto.UDP, ChannelMux.MType.DATA_FRAG, frag_payload)

    def _drop_udp_fragment_reassembly(self, chan: int) -> None:
        for key in [key for key in self._udp_frag_rx if key[0] == chan]:
            self._udp_frag_rx.pop(key, None)

    def _prune_udp_fragment_reassembly(self) -> None:
        now = time.time()
        expired = [
            key
            for key, state in self._udp_frag_rx.items()
            if (now - float(state.get("updated", now))) >= self.UDP_FRAG_REASSEMBLY_TTL_S
        ]
        for key in expired:
            self._udp_frag_rx.pop(key, None)

    def _prune_tun_fragment_reassembly(self) -> None:
        now = time.time()
        expired = [
            key
            for key, state in self._tun_frag_rx.items()
            if (now - float(state.get("updated", now))) >= self.UDP_FRAG_REASSEMBLY_TTL_S
        ]
        for key in expired:
            self._tun_frag_rx.pop(key, None)

    @classmethod
    def _require_tun_support(cls) -> None:
        if _bridge_tun_platform is None:
            raise RuntimeError("TUN services are supported only on Linux, macOS, Windows and iOS")
        _bridge_tun_platform.require_tun_support(cls)

    def _open_tun_device(self, ifname: str, mtu: int, svc_key: Optional["ChannelMux.ServiceKey"] = None) -> "ChannelMux.TunDevice":
        self._require_tun_support()
        try:
            return _bridge_tun_platform.open_tun_device(self, ifname, mtu, svc_key=svc_key)
        except Exception as exc:
            if sys.platform.startswith("win"):
                raise RuntimeError(
                    "Windows TUN device creation failed. Install a WinTun wrapper (e.g. 'wintun') and the Wintun driver, "
                    "or adapt the Windows TUN adapter. Original error: " + str(exc)
                ) from exc
            raise

    def _register_tun_reader(self, dev: "ChannelMux.TunDevice") -> None:
        if dev.reader_registered:
            return
        _bridge_tun_platform.register_tun_reader(self, dev)

    def _close_tun_device(self, dev: "ChannelMux.TunDevice") -> None:
        _bridge_tun_platform.close_tun_device(self, dev)

    def _write_tun_packet(self, dev: "ChannelMux.TunDevice", data: bytes) -> None:
        if _bridge_tun_platform is not None:
            writer = getattr(_bridge_tun_platform, "write_tun_packet", None)
            if callable(writer):
                writer(self, dev, data)
                return
        adapter = getattr(dev, "wintun_adapter", None)
        if adapter is not None:
            write_names = ["write", "send", "send_packet", "write_packet"]
            for name in write_names:
                if hasattr(adapter, name):
                    result = getattr(adapter, name)(data)
                    if asyncio.iscoroutine(result):
                        self.loop.create_task(result)
                    return
            if callable(adapter):
                result = adapter(data)
                if asyncio.iscoroutine(result):
                    self.loop.create_task(result)
                return
            raise RuntimeError("No write method on WinTun adapter")
        os.write(dev.fd, data)

    def _find_service_tun_device(self, ifname: str, mtu: int) -> Optional["ChannelMux.TunDevice"]:
        for dev in self._svc_tun_devices.values():
            if dev.ifname == ifname and int(dev.mtu) == int(mtu):
                return dev
        return None

    async def _start_tun_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        self._start_tun_server_for_sync(spec, svc_key)

    def _start_tun_server_for_sync(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey") -> "ChannelMux.TunDevice":
        mtu = max(68, int(spec.l_port or self.TUN_DEFAULT_MTU))
        dev = self._open_tun_device(spec.l_bind, mtu, svc_key=svc_key)
        self._svc_tun_devices[svc_key] = dev
        self._install_shared_tun_ownership_for_service(svc_key, spec)
        self._register_tun_reader(dev)
        self.log.info("[TUN/SRV] service=%s:%s opened if=%s mtu=%s", svc_key[0], spec.svc_id, dev.ifname, dev.mtu)
        self._schedule_service_hook(spec, svc_key, "listener", "on_created")
        return dev

    def _tun_fragment_payload_limit(self) -> int:
        return max(0, self._session_max_app_payload - ChannelMux.MUX_HDR.size - ChannelMux.UDP_FRAG_HDR.size)

    def _send_tun_mux_fragments(self, chan_id: int, payload: bytes) -> None:
        frag_payload_limit = self._tun_fragment_payload_limit()
        if frag_payload_limit <= 0:
            self.log.error("[MUX] drop oversized TUN packet: no fragment payload fits within session budget %d", self._session_max_app_payload)
            return
        datagram_id = self._next_udp_fragment_datagram_id()
        total_len = len(payload)
        self.log.info(
            "[MUX] fragment TUN packet chan=%s len=%s datagram_id=%s frag_payload_limit=%s",
            chan_id,
            total_len,
            datagram_id,
            frag_payload_limit,
        )
        for offset in range(0, total_len, frag_payload_limit):
            frag_payload = ChannelMux.UDP_FRAG_HDR.pack(datagram_id, total_len & 0xFFFF, offset & 0xFFFF) + payload[offset:offset + frag_payload_limit]
            self._send_mux(chan_id, ChannelMux.Proto.TUN, ChannelMux.MType.DATA_FRAG, frag_payload)

    def _bind_tun_channel(self, chan: int, dev: "ChannelMux.TunDevice") -> None:
        # A full-duplex TUN pair can temporarily create symmetric OPENs from both
        # peers. Keep every inbound channel routable; dev.chan_id is only the
        # preferred outbound channel for locally-read packets.
        self._tun_by_chan[chan] = dev
        self._record_shared_tun_peer_binding(
            getattr(dev, "service_key", None),
            self._chan_owner_peer_id.get(int(chan)),
            int(chan),
        )
        if dev.chan_id is None:
            dev.chan_id = chan
        if dev.service_key is not None:
            self._tun_chan_by_service.setdefault(dev.service_key, chan)

    def _tun_channels_for_device(self, dev: "ChannelMux.TunDevice") -> list[int]:
        return [chan for chan, mapped in self._tun_by_chan.items() if mapped is dev]

    def _unbind_tun_channel(self, chan: int) -> Optional["ChannelMux.TunDevice"]:
        dev = self._tun_by_chan.pop(chan, None)
        if dev is None:
            return None
        self._drop_shared_tun_peer_binding(
            getattr(dev, "service_key", None),
            self._chan_owner_peer_id.get(int(chan)),
            int(chan),
        )
        remaining = self._tun_channels_for_device(dev)
        if dev.chan_id == chan:
            dev.chan_id = remaining[0] if remaining else None
        if dev.service_key is not None and self._tun_chan_by_service.get(dev.service_key) == chan:
            if dev.chan_id is not None:
                self._tun_chan_by_service[dev.service_key] = dev.chan_id
            else:
                self._tun_chan_by_service.pop(dev.service_key, None)
        return dev

    def _unbind_all_tun_channels_for_device(self, dev: "ChannelMux.TunDevice") -> None:
        for chan in list(self._tun_by_chan.keys()):
            if self._tun_by_chan.get(chan) is dev:
                self._drop_shared_tun_peer_binding(
                    getattr(dev, "service_key", None),
                    self._chan_owner_peer_id.get(int(chan)),
                    int(chan),
                )
                self._tun_by_chan.pop(chan, None)
                self._tun_frag_rx = {key: state for key, state in self._tun_frag_rx.items() if key[0] != chan}
                self._forget_tun_open_key(chan)
                self._finalize_channel_stats(chan, ChannelMux.Proto.TUN)
                self._chan_owner_peer_id.pop(chan, None)
        service_key = getattr(dev, "service_key", None)
        if service_key is not None:
            self._tun_chan_by_service.pop(service_key, None)
        with contextlib.suppress(Exception):
            dev.chan_id = None

    def _peer_tun_listener_for_target(
        self,
        peer_key: int,
        ifname: str,
        mtu: int,
    ) -> Optional[tuple["ChannelMux.ServiceKey", "ChannelMux.ServiceSpec"]]:
        mirrored_match: Optional[tuple["ChannelMux.ServiceKey", "ChannelMux.ServiceSpec"]] = None
        catalogs = (
            self._peer_installed_services,
            self._pending_peer_service_catalogs.get(int(peer_key), {}),
        )
        for catalog in catalogs:
            for svc_key, spec in catalog.items():
                if svc_key[0] != "peer" or int(svc_key[1]) != int(peer_key):
                    continue
                if spec.l_proto != "tun":
                    continue
                if str(spec.l_bind) == str(ifname) and int(spec.l_port) == int(mtu):
                    return svc_key, spec
                if (
                    spec.r_proto == "tun"
                    and str(spec.r_host) == str(ifname)
                    and int(spec.r_port) == int(mtu)
                ):
                    mirrored_match = (svc_key, spec)
        return mirrored_match

    def _ensure_peer_tun_listener_for_target(
        self,
        peer_key: int,
        ifname: str,
        mtu: int,
    ) -> Optional["ChannelMux.TunDevice"]:
        found = self._peer_tun_listener_for_target(peer_key, ifname, mtu)
        if found is None:
            return None
        svc_key, spec = found
        self._peer_installed_services.setdefault(svc_key, spec)
        dev = self._svc_tun_devices.get(svc_key)
        if dev is not None:
            return dev
        return self._start_tun_server_for_sync(spec, svc_key)

    def _session_buffered_frames(self) -> int:
        getter = getattr(self.session, "get_metrics", None)
        if not callable(getter):
            return 0
        try:
            metrics = getter()
        except Exception:
            return 0
        waiting_count = getattr(metrics, "waiting_count", None)
        try:
            return max(0, int(waiting_count or 0))
        except (TypeError, ValueError):
            return 0

    def _advance_tun_inflow_window(self, scope_key: tuple[Any, ...], now_ns: int) -> dict[str, Any]:
        state = self._tun_inflow_scope_state.setdefault(
            tuple(scope_key),
            {
                "window_start_ns": None,
                "prev_bytes": 0,
                "curr_bytes": 0,
                "throttle_drop_count": 0,
            },
        )
        start_ns = state.get("window_start_ns")
        if start_ns is None:
            state["window_start_ns"] = int(now_ns)
            return state
        elapsed = int(now_ns) - int(start_ns)
        if elapsed < self.TUN_INFLOW_THROTTLE_WINDOW_NS:
            return state
        windows = elapsed // self.TUN_INFLOW_THROTTLE_WINDOW_NS
        if windows == 1:
            state["prev_bytes"] = int(state.get("curr_bytes", 0) or 0)
        else:
            state["prev_bytes"] = 0
        state["curr_bytes"] = 0
        state["window_start_ns"] = int(start_ns + windows * self.TUN_INFLOW_THROTTLE_WINDOW_NS)
        return state

    def _local_tun_send_allowed(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> bool:
        if self._tun_routing_config().shared_tun_disable_scoped_throttle:
            return True
        state = self._advance_tun_inflow_window(scope_key, now_ns)
        buffered_frames = self._session_buffered_frames()
        if buffered_frames <= 0:
            return True
        allowance_bytes = int(float(int(state.get("prev_bytes", 0) or 0)) * self.TUN_INFLOW_THROTTLE_RATIO)
        if allowance_bytes <= 0:
            return False
        return (int(state.get("curr_bytes", 0) or 0) + int(packet_len)) <= allowance_bytes

    def _record_local_tun_forward(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> None:
        state = self._advance_tun_inflow_window(scope_key, now_ns)
        state["curr_bytes"] = int(state.get("curr_bytes", 0) or 0) + max(0, int(packet_len))

    def _on_local_tun_packet(self, dev: "ChannelMux.TunDevice", packet: bytes) -> None:
        self._log_tun_packet_debug(stage="from_local_tun", packet=packet, ifname=dev.ifname, chan=dev.chan_id)
        if not (self._overlay_connected and self._accepting_enabled):
            return
        if len(packet) > int(dev.mtu):
            self.log.warning("[TUN] if=%s drop oversize local packet len=%s mtu=%s", dev.ifname, len(packet), dev.mtu)
            self._record_shared_tun_drop(
                getattr(dev, "service_key", None),
                reason="oversize_local_packet",
                direction="local_to_peer",
                chan_id=dev.chan_id,
                packet_bytes=len(packet),
            )
            return
        now_ns = time.monotonic_ns()
        shared_route = self._shared_tun_plan_local_delivery(getattr(dev, "service_key", None), packet)
        scope_key = self._shared_tun_inflow_scope_key(getattr(dev, "service_key", None), shared_route)
        if scope_key is None:
            scope_key = self._direct_tun_inflow_scope_key(getattr(dev, "service_key", None), dev.chan_id)
        if not self._local_tun_send_allowed(len(packet), now_ns=now_ns, scope_key=scope_key):
            scope_state = self._advance_tun_inflow_window(scope_key, now_ns)
            scope_state["throttle_drop_count"] = int(scope_state.get("throttle_drop_count", 0) or 0) + 1
            self._record_shared_tun_drop(
                getattr(dev, "service_key", None),
                reason="throttled_local_tun",
                direction="local_to_peer",
                chan_id=dev.chan_id,
                route_class=None if shared_route is None else str(shared_route.get("route_class") or ""),
                destination_ip=None if shared_route is None else shared_route.get("destination_ip"),
                packet_bytes=len(packet),
            )
            self.log.debug(
                "[TUN] if=%s throttle local packet scope=%s buffered_frames=%s prev_window_bytes=%s curr_window_bytes=%s packet_bytes=%s",
                dev.ifname,
                self._tun_inflow_scope_id(scope_key),
                self._session_buffered_frames(),
                int(scope_state.get("prev_bytes", 0) or 0),
                int(scope_state.get("curr_bytes", 0) or 0),
                len(packet),
            )
            return
        if shared_route is not None:
            if not bool(shared_route.get("routed")):
                self._record_shared_tun_drop(
                    getattr(dev, "service_key", None),
                    reason=str(shared_route.get("drop_reason") or "shared_route_drop"),
                    direction="local_to_peer",
                    chan_id=dev.chan_id,
                    ip_version=shared_route.get("ip_version"),
                    destination_ip=shared_route.get("destination_ip"),
                    route_class=shared_route.get("route_class"),
                    packet_bytes=len(packet),
                )
                self.log.debug(
                    "[TUN] if=%s drop shared route class=%s dst=%s reason=%s",
                    dev.ifname,
                    shared_route.get("route_class"),
                    shared_route.get("destination_ip"),
                    shared_route.get("drop_reason"),
                )
                return
            selected_chan_ids = [int(v) for v in list(shared_route.get("selected_chan_ids") or [])]
            for chan in selected_chan_ids:
                ctr = self._ctr(ChannelMux.Proto.TUN, chan)
                ctr.msgs_in += 1
                ctr.bytes_in += len(packet)
                self._send_mux(chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet)
            self._record_local_tun_forward(len(packet), now_ns=now_ns, scope_key=scope_key)
            return
        chan = dev.chan_id
        if chan is None:
            svc_key = dev.service_key
            if svc_key is None:
                self.log.warning("[TUN] if=%s drop packet: no mux channel bound", dev.ifname)
                return
            spec = self._effective_services_by_id().get(svc_key)
            if spec is None:
                self.log.warning("[TUN] if=%s drop packet: missing service spec", dev.ifname)
                return
            chan = self._alloc_tun_id()
            self._bind_tun_channel(chan, dev)
            self._chan_owner_peer_id[chan] = int(svc_key[1]) if str(svc_key[0]) == "peer" else 0
            self._schedule_service_hook(spec, svc_key, "listener", "on_channel_connected", channel_id=chan)
            self._send_open_for_service(chan, ChannelMux.Proto.TUN, spec)
        ctr = self._ctr(ChannelMux.Proto.TUN, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(packet)
        self._send_mux(chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet)
        self._record_local_tun_forward(len(packet), now_ns=now_ns, scope_key=scope_key)

    def _rx_tun(self, chan: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            self._rx_tun_open(chan, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.OPEN_CHUNK:
            self._rx_open_chunk(chan, ChannelMux.Proto.TUN, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.DATA:
            self._rx_tun_data(chan, data)
        elif mtype == ChannelMux.MType.DATA_FRAG:
            self._rx_tun_fragment(chan, data)
        elif mtype == ChannelMux.MType.CLOSE:
            self._rx_tun_close(chan)
        else:
            self.log.warning("[APP] Unknown mtype to dispatch TUN:%s", mtype)

    def _rx_tun_open(self, chan: int, payload: bytes, peer_id: Optional[int] = None) -> None:
        p = self._parse_open_with_meta(payload)
        if not p:
            self.log.debug("[TUN/CLI] chan=%s OPEN parse failed", chan)
            return
        (
            instance_id,
            connection_seq,
            svc_id,
            l_proto,
            l_bind,
            l_port,
            r_proto,
            host,
            r_port,
            svc_name,
            lifecycle_hooks,
            options,
        ) = p
        peer_key = int(peer_id or 0)
        self._chan_owner_peer_id[chan] = peer_key
        prev_epoch = self._peer_mux_epochs.get(peer_key)
        if not self._peer_epoch_is_new(peer_id, instance_id, connection_seq):
            self.log.debug("[TUN/CLI] chan=%s duplicate/replay OPEN instance_id=%s connection_seq=%s", chan, instance_id, connection_seq)
        else:
            if prev_epoch is not None:
                self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
        if int(l_proto) != int(ChannelMux.Proto.TUN):
            self.log.warning("[TUN/CLI] chan=%s OPEN declares non-TUN l_proto=%s", chan, l_proto)
            return
        if int(r_proto) != int(ChannelMux.Proto.TUN):
            self.log.warning("[TUN/CLI] chan=%s OPEN requests non-TUN r_proto=%s", chan, r_proto)
            return
        open_key = (peer_key, int(svc_id), int(l_proto), str(l_bind), int(l_port), int(r_proto), str(host), int(r_port))
        self._forget_tun_open_key(chan)
        self._tun_open_key_by_chan[chan] = open_key
        self._tun_chan_by_open_key[open_key] = chan
        peer_spec = ChannelMux.ServiceSpec(
            svc_id=int(svc_id),
            l_proto="tun",
            l_bind=str(l_bind),
            l_port=int(l_port),
            r_proto="tun",
            r_host=str(host),
            r_port=int(r_port),
            name=svc_name,
            lifecycle_hooks=lifecycle_hooks,
            options=options,
        )
        self._schedule_service_hook(peer_spec, None, "client", "before_connect", channel_id=chan, peer_id=peer_id)
        dev = self._find_service_tun_device(str(host), int(r_port))
        if dev is None:
            shared_tun_requested = self._shared_tun_ownership_snapshot_for_spec(peer_spec) is not None
            if shared_tun_requested:
                self.log.info(
                    "[TUN/CLI] chan=%s shared TUN attach rejected: no prestarted server-owned service if=%s mtu=%s",
                    chan,
                    host,
                    r_port,
                )
                self._forget_tun_open_key(chan)
                return
            try:
                dev = self._ensure_peer_tun_listener_for_target(peer_key, str(host), int(r_port))
            except Exception as e:
                self.log.info(
                    "[TUN/CLI] chan=%s peer listener start failed if=%s mtu=%s: %r",
                    chan,
                    host,
                    r_port,
                    e,
                )
                self._forget_tun_open_key(chan)
                return
        if dev is None:
            try:
                dev = self._open_tun_device(str(host), max(68, int(r_port or self.TUN_DEFAULT_MTU)))
                self._register_tun_reader(dev)
            except Exception as e:
                self.log.info("[TUN/CLI] chan=%s open failed if=%s mtu=%s: %r", chan, host, r_port, e)
                self._forget_tun_open_key(chan)
                return
        self._bind_tun_channel(chan, dev)
        self._schedule_service_hook(peer_spec, None, "client", "on_connected", channel_id=chan, peer_id=peer_id)
        self.log.info("[TUN/CLI] chan=%s bound if=%s mtu=%s svc=%s", chan, dev.ifname, dev.mtu, svc_id)

    def _rx_tun_data(self, chan: int, data: bytes) -> None:
        dev = self._tun_by_chan.get(chan)
        if dev is None:
            self.log.warning("[TUN] chan=%s DATA not routed yet (no device)", chan)
            return
        allowed, parsed, drop_reason = self._shared_tun_guard_inbound_packet(dev=dev, chan=chan, packet=data)
        if not allowed:
            self._record_shared_tun_drop(
                getattr(dev, "service_key", None),
                reason=str(drop_reason or "inbound_guard_drop"),
                direction="peer_to_local",
                peer_id=self._chan_owner_peer_id.get(int(chan)),
                chan_id=chan,
                ip_version=None if parsed is None else parsed.get("ip_version"),
                source_ip=None if parsed is None else parsed.get("source_ip"),
                destination_ip=None if parsed is None else parsed.get("destination_ip"),
                packet_bytes=len(data),
            )
            self.log.warning(
                "[TUN] chan=%s drop inbound packet if=%s reason=%s src=%s dst=%s",
                chan,
                dev.ifname,
                drop_reason,
                None if parsed is None else parsed.get("source_ip"),
                None if parsed is None else parsed.get("destination_ip"),
            )
            return
        self._log_tun_packet_debug(stage="to_local_tun", packet=data, ifname=dev.ifname, chan=chan)
        ctr = self._ctr(ChannelMux.Proto.TUN, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(data)
        if len(data) > int(dev.mtu):
            self.log.warning("[TUN] chan=%s drop oversize packet len=%s mtu=%s", chan, len(data), dev.mtu)
            self._record_shared_tun_drop(
                getattr(dev, "service_key", None),
                reason="oversize_inbound_packet",
                direction="peer_to_local",
                peer_id=self._chan_owner_peer_id.get(int(chan)),
                chan_id=chan,
                ip_version=None if parsed is None else parsed.get("ip_version"),
                source_ip=None if parsed is None else parsed.get("source_ip"),
                destination_ip=None if parsed is None else parsed.get("destination_ip"),
                packet_bytes=len(data),
            )
            return
        shared_relay = self._shared_tun_plan_inbound_peer_relay(
            getattr(dev, "service_key", None),
            self._chan_owner_peer_id.get(int(chan)),
            data,
        )
        if shared_relay is not None and bool(shared_relay.get("relay_to_peer")):
            selected_chan_ids = [int(v) for v in list(shared_relay.get("selected_chan_ids") or [])]
            for selected_chan in selected_chan_ids:
                target_ctr = self._ctr(ChannelMux.Proto.TUN, selected_chan)
                target_ctr.msgs_in += 1
                target_ctr.bytes_in += len(data)
                self._send_mux(selected_chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, data)
            self.log.debug(
                "[TUN] chan=%s relay shared peer packet if=%s dst=%s relay_peers=%s relay_chans=%s",
                chan,
                dev.ifname,
                shared_relay.get("destination_ip"),
                shared_relay.get("selected_peer_ids"),
                shared_relay.get("selected_chan_ids"),
            )
            return
        try:
            self._write_tun_packet(dev, data)
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
        except Exception as e:
            self.log.info("[TUN] chan=%s write failed if=%s: %r", chan, dev.ifname, e)

    def _rx_tun_fragment(self, chan: int, payload: bytes) -> None:
        dev = self._tun_by_chan.get(chan)
        if dev is None:
            self.log.warning("[TUN] chan=%s fragment not routed yet (no device)", chan)
            return
        if len(payload) < ChannelMux.UDP_FRAG_HDR.size:
            self.log.warning("[TUN] chan=%s fragment too short (%d bytes)", chan, len(payload))
            return
        datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(payload[:ChannelMux.UDP_FRAG_HDR.size])
        chunk = bytes(payload[ChannelMux.UDP_FRAG_HDR.size:])
        if total_len <= 0 or total_len > int(dev.mtu):
            self.log.warning("[TUN] chan=%s drop fragment datagram_id=%s total_len=%s mtu=%s", chan, datagram_id, total_len, dev.mtu)
            self._tun_frag_rx.pop((chan, int(datagram_id)), None)
            return
        if offset > total_len or (offset + len(chunk)) > total_len or not chunk:
            self.log.warning("[TUN] chan=%s invalid fragment datagram_id=%s total=%s offset=%s chunk=%s", chan, datagram_id, total_len, offset, len(chunk))
            return
        key = (chan, int(datagram_id))
        now = time.time()
        state = self._tun_frag_rx.get(key)
        if state is None:
            state = {"total": int(total_len), "parts": {}, "received": 0, "updated": now}
            self._tun_frag_rx[key] = state
        elif int(state.get("total", 0)) != int(total_len):
            self._tun_frag_rx.pop(key, None)
            return
        parts = state.setdefault("parts", {})
        if offset not in parts:
            parts[offset] = chunk
            state["received"] = int(state.get("received", 0)) + len(chunk)
        state["updated"] = now
        if int(state.get("received", 0)) < int(total_len):
            return
        assembled = bytearray(int(total_len))
        cursor = 0
        for frag_offset, frag_chunk in sorted(parts.items()):
            frag_offset_i = int(frag_offset)
            if frag_offset_i != cursor:
                return
            next_cursor = frag_offset_i + len(frag_chunk)
            if next_cursor > int(total_len):
                self._tun_frag_rx.pop(key, None)
                return
            assembled[frag_offset_i:next_cursor] = frag_chunk
            cursor = next_cursor
        if cursor != int(total_len):
            return
        self._tun_frag_rx.pop(key, None)
        self._rx_tun_data(chan, bytes(assembled))

    def _rx_tun_close(self, chan: int) -> None:
        dev = self._unbind_tun_channel(chan)
        self._finalize_channel_stats(chan, ChannelMux.Proto.TUN)
        self._chan_owner_peer_id.pop(chan, None)
        self._tun_frag_rx = {key: state for key, state in self._tun_frag_rx.items() if key[0] != chan}
        self._forget_tun_open_key(chan)
        if dev is None:
            return
        if dev.service_key is not None and self._svc_tun_devices.get(dev.service_key) is dev:
            spec = self._effective_services_by_id().get(dev.service_key)
            if spec is not None:
                self._schedule_service_hook(spec, dev.service_key, "listener", "on_channel_closed", channel_id=chan)
        else:
            self._close_tun_device(dev)
            spec = ChannelMux.ServiceSpec(svc_id=0, l_proto="tun", l_bind=dev.ifname, l_port=int(dev.mtu), r_proto="tun", r_host=dev.ifname, r_port=int(dev.mtu))
            self._schedule_service_hook(spec, None, "client", "after_closed", channel_id=chan)
        self.log.info("[TUN] chan=%s CLOSE => local teardown", chan)

    def _rx_open_chunk(
        self,
        chan: int,
        proto: "ChannelMux.Proto",
        payload: bytes,
        *,
        peer_id: Optional[int] = None,
    ) -> None:
        assembled = self._consume_control_chunk(
            chan_id=chan,
            proto=proto,
            mtype=ChannelMux.MType.OPEN_CHUNK,
            payload=payload,
            peer_id=peer_id,
        )
        if assembled is None:
            return
        if proto == ChannelMux.Proto.UDP:
            self._rx_udp_open(chan, assembled, peer_id=peer_id)
            return
        if proto == ChannelMux.Proto.TCP:
            self._rx_tcp_open(chan, assembled, peer_id=peer_id)
            return
        if proto == ChannelMux.Proto.TUN:
            self._rx_tun_open(chan, assembled, peer_id=peer_id)
            return

    def _on_remote_services_payload(self, payload: bytes, peer_id: Optional[int]) -> bool:
        decoded = self._decode_remote_services_set_v2(payload)
        if decoded is None:
            self.log.warning("[MUX/CTRL] invalid REMOTE_SERVICES_SET_V2 payload (%d bytes)", len(payload))
            return False
        instance_id, connection_seq, services = decoded
        peer_key = int(peer_id or 0)
        prev_epoch = self._peer_mux_epochs.get(peer_key)
        if not self._peer_epoch_is_new(peer_id, instance_id, connection_seq):
            self.log.debug("[MUX/CTRL] duplicate/replay REMOTE_SERVICES_SET_V2 peer_id=%s instance_id=%s connection_seq=%s", peer_key, instance_id, connection_seq)
        else:
            if prev_epoch is not None:
                self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
        self._pending_peer_service_catalogs[peer_key] = {
            ("peer", peer_key, int(s.svc_id)): s for s in services
        }
        self.loop.create_task(self._apply_peer_installed_services(services, peer_id=peer_id))
        self.log.info(
            "[MUX/CTRL] received REMOTE_SERVICES_SET_V2 with %d service(s) from peer_id=%s instance_id=%s connection_seq=%s",
            len(services),
            peer_key,
            instance_id,
            connection_seq,
        )
        return True

    # ---------- MUX RX demux ----------
    def _schedule_peer_app_payload_dispatch(self) -> None:
        if self._peer_app_payload_scheduled:
            return
        self._peer_app_payload_scheduled = True
        scheduled_at = time.perf_counter()

        def _run() -> None:
            self._peer_app_payload_scheduled = False
            self._record_yield_gap("peer_app_payload", scheduled_at, "channelmux_peer_app_payload")
            self._dispatch_one_peer_app_payload()

        self.loop.call_soon(_run)

    def _record_yield_gap(self, prefix: str, scheduled_at: float, stage: str) -> None:
        gap_ms = max(0.0, (time.perf_counter() - float(scheduled_at)) * 1000.0)
        count_attr = f"_{prefix}_yield_count"
        last_attr = f"_{prefix}_last_yield_gap_ms"
        max_attr = f"_{prefix}_max_yield_gap_ms"
        count = int(getattr(self, count_attr, 0) or 0) + 1
        setattr(self, count_attr, count)
        setattr(self, last_attr, gap_ms)
        setattr(self, max_attr, max(float(getattr(self, max_attr, 0.0) or 0.0), gap_ms))
        if gap_ms >= 20.0 or count <= 3 or (count % 256) == 0:
            self.log.info("[MUX/YIELD] stage=%s count=%s gap_ms=%.3f", stage, count, gap_ms)

    def _dispatch_one_peer_app_payload(self) -> None:
        if self._peer_app_payload_dispatching:
            return
        self._peer_app_payload_dispatching = True
        try:
            if not self._peer_app_payload_pending:
                return
            buf, peer_id = self._peer_app_payload_pending.popleft()
            self._handle_app_payload_from_peer(buf, peer_id=peer_id)
        finally:
            self._peer_app_payload_dispatching = False
        if self._peer_app_payload_pending:
            self._schedule_peer_app_payload_dispatch()

    def on_app_payload_from_peer(self, buf: bytes, peer_id: Optional[int] = None) -> bool:
        self._peer_app_payload_pending.append((bytes(buf), peer_id))
        if self._peer_app_payload_dispatching:
            self._schedule_peer_app_payload_dispatch()
            return True
        if not self.loop.is_running():
            while self._peer_app_payload_pending:
                self._dispatch_one_peer_app_payload()
            return True
        self._dispatch_one_peer_app_payload()
        return True

    def _handle_app_payload_from_peer(self, buf: bytes, peer_id: Optional[int] = None) -> bool:
        self.log.debug(f"[MUX] APP data receiving on session id=%x", id(self))
        try:
            self._log_app_msg("<-",buf)
        except Exception as e:
            self.log.debug("[MUX] logging error: %r", e)
        parsed = self._unpack_mux(buf)        
        if not parsed:
            self.log.warning(f"[APP] unpack failed len={len(buf)}: {buf[:16].hex().upper()}")
            return False
        chan_id, proto, counter, mtype, payload_mv = parsed
        payload = bytes(payload_mv)

        # Stats (peer->local bytes count for DATA only)
        if mtype == ChannelMux.MType.DATA and self._on_local_tx:
            try: self._on_local_tx(len(payload))
            except Exception: pass

        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2:
            return self._on_remote_services_payload(payload, peer_id=peer_id)

        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK:
            assembled = self._consume_control_chunk(
                chan_id=chan_id,
                proto=proto,
                mtype=mtype,
                payload=payload,
                peer_id=peer_id,
            )
            if assembled is None:
                return True
            return self._on_remote_services_payload(assembled, peer_id=peer_id)

        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V1:
            self.log.warning("[MUX/CTRL] unsupported REMOTE_SERVICES_SET_V1 payload (%d bytes)", len(payload))
            return False

        if proto == ChannelMux.Proto.UDP:
            self._rx_udp(chan_id, mtype, payload, peer_id=peer_id)
            return True

        if proto == ChannelMux.Proto.TCP:
            self._rx_tcp(chan_id, mtype, payload, peer_id=peer_id)
            return True

        if proto == ChannelMux.Proto.TUN:
            self._rx_tun(chan_id, mtype, payload, peer_id=peer_id)
            return True

        return False

    # ---------- UDP RX path ----------
    def _rx_udp(self, chan_id: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            self._rx_udp_open(chan_id, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.OPEN_CHUNK:
            self._rx_open_chunk(chan_id, ChannelMux.Proto.UDP, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.DATA:
            self._rx_udp_data(chan_id, data)
        elif mtype == ChannelMux.MType.DATA_FRAG:
            self._rx_udp_fragment(chan_id, data)
        elif mtype == ChannelMux.MType.CLOSE:
            self._rx_udp_close(chan_id)
        else:
            self.log.warning(f"[APP] Unknwown mtype to dispatch UDP:{mtype}")

    def _rx_udp_fragment(self, chan: int, payload: bytes) -> None:
        if len(payload) < ChannelMux.UDP_FRAG_HDR.size:
            self.log.warning("[UDP] chan=%s fragment too short (%d bytes)", chan, len(payload))
            return
        datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(payload[:ChannelMux.UDP_FRAG_HDR.size])
        chunk = bytes(payload[ChannelMux.UDP_FRAG_HDR.size:])
        if total_len <= 0:
            self.log.warning("[UDP] chan=%s fragment invalid total_len=%s", chan, total_len)
            return
        if total_len > self._udp_service_datagram_cap:
            self.log.warning(
                "[UDP] chan=%s drop fragment datagram_id=%s total_len=%s cap=%s (%s)",
                chan,
                datagram_id,
                total_len,
                self._udp_service_datagram_cap,
                self._udp_service_datagram_diag,
            )
            self._udp_frag_rx.pop((chan, int(datagram_id)), None)
            return
        if offset > total_len or (offset + len(chunk)) > total_len:
            self.log.warning(
                "[UDP] chan=%s fragment out of bounds datagram_id=%s total=%s offset=%s chunk=%s",
                chan,
                datagram_id,
                total_len,
                offset,
                len(chunk),
            )
            return
        if not chunk:
            self.log.warning("[UDP] chan=%s empty fragment datagram_id=%s", chan, datagram_id)
            return
        if len(self._udp_frag_rx) >= self.UDP_FRAG_MAX_INFLIGHT:
            self._prune_udp_fragment_reassembly()
            if len(self._udp_frag_rx) >= self.UDP_FRAG_MAX_INFLIGHT:
                self.log.warning("[UDP] drop fragment chan=%s datagram_id=%s: reassembly table full", chan, datagram_id)
                return
        key = (chan, int(datagram_id))
        now = time.time()
        state = self._udp_frag_rx.get(key)
        if state is None:
            state = {"total": int(total_len), "parts": {}, "received": 0, "updated": now}
            self._udp_frag_rx[key] = state
        elif int(state.get("total", 0)) != int(total_len):
            self.log.warning(
                "[UDP] chan=%s fragment total mismatch datagram_id=%s seen=%s new=%s",
                chan,
                datagram_id,
                state.get("total"),
                total_len,
            )
            self._udp_frag_rx.pop(key, None)
            return
        parts = state.setdefault("parts", {})
        if offset not in parts:
            parts[offset] = chunk
            state["received"] = int(state.get("received", 0)) + len(chunk)
        state["updated"] = now
        if int(state.get("received", 0)) < int(total_len):
            return
        assembled = bytearray(int(total_len))
        cursor = 0
        for frag_offset, frag_chunk in sorted(parts.items()):
            frag_offset_i = int(frag_offset)
            if frag_offset_i != cursor:
                return
            next_cursor = frag_offset_i + len(frag_chunk)
            if next_cursor > int(total_len):
                self._udp_frag_rx.pop(key, None)
                self.log.warning("[UDP] chan=%s fragment overflow during reassembly datagram_id=%s", chan, datagram_id)
                return
            assembled[frag_offset_i:next_cursor] = frag_chunk
            cursor = next_cursor
        if cursor != int(total_len):
            return
        self._udp_frag_rx.pop(key, None)
        self._rx_udp_data(chan, bytes(assembled))


    def _rx_udp_open(self, chan: int, payload: bytes, peer_id: Optional[int] = None) -> None:
        p = self._parse_open_with_meta(payload)
        if not p:
            self.log.debug("[UDP/CLI] chan=%s OPEN parse failed", chan)
            return
        (
            instance_id,
            connection_seq,
            svc_id,
            l_proto,
            l_bind,
            l_port,
            r_proto,
            host,
            r_port,
            svc_name,
            lifecycle_hooks,
            options,
        ) = p
        peer_key = int(peer_id or 0)
        prev_epoch = self._peer_mux_epochs.get(peer_key)
        if not self._peer_epoch_is_new(peer_id, instance_id, connection_seq):
            self.log.debug("[UDP/CLI] chan=%s duplicate/replay OPEN instance_id=%s connection_seq=%s", chan, instance_id, connection_seq)
        else:
            if prev_epoch is not None:
                self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
        self._udp_client_svc_id[chan] = int(svc_id)
        if int(l_proto) != int(ChannelMux.Proto.UDP):
            self.log.warning("[UDP/CLI] chan=%s OPEN declares non-UDP l_proto=%s (ignored)", chan, l_proto)
            return
        if int(r_proto) != int(ChannelMux.Proto.UDP):
            self.log.warning("[UDP/CLI] chan=%s OPEN requests non-UDP r_proto=%s (ignored)", chan, r_proto)
            return
        open_key = (peer_key, int(chan), int(svc_id), int(l_proto), str(l_bind), int(l_port), int(r_proto), str(host), int(r_port))
        existing_chan = self._udp_chan_by_open_key.get(open_key)
        if existing_chan is not None and existing_chan != chan:
            active = existing_chan in self._udp_client_transports
            if active:
                self.log.info(
                    "[UDP/CLI] duplicate OPEN ignored chan=%s existing_chan=%s key=%s:%s -> %s:%s",
                    chan, existing_chan, l_bind, l_port, host, r_port
                )
                return
            self._forget_udp_open_key(existing_chan)
        self._forget_udp_open_key(chan)
        self._udp_open_key_by_chan[chan] = open_key
        self._udp_chan_by_open_key[open_key] = chan
        if chan in self._udp_client_transports:
            return
        peer_spec = ChannelMux.ServiceSpec(
            svc_id=int(svc_id),
            l_proto="udp",
            l_bind=str(l_bind),
            l_port=int(l_port),
            r_proto="udp",
            r_host=str(host),
            r_port=int(r_port),
            name=svc_name,
            lifecycle_hooks=lifecycle_hooks,
            options=options,
        )
        async def _mk():
            try:
                await self._run_service_hook(peer_spec, None, "client", "before_connect", channel_id=chan, peer_id=peer_id)
                family = _listener_family_for_host(host)
                if family == socket.AF_INET6:
                    local_addr = ("::", 0)
                elif family == socket.AF_INET:
                    local_addr = ("0.0.0.0", 0)
                else:
                    local_addr = None
                tr, _ = await self.loop.create_datagram_endpoint(
                    lambda: self._UDPClientProtocol(self, chan),
                    local_addr=local_addr,
                    remote_addr=(host, int(r_port)),
                    family=family
                )
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s connect failed to %s:%s: %r", chan, host, r_port, e)
                self._forget_udp_open_key(chan)
                self._udp_client_svc_id.pop(chan, None)
                return

            try:
                self._udp_client_transports[chan] = tr  # type: ignore
                self._udp_client_last_ts[chan] = time.time()
                self._schedule_service_hook(peer_spec, None, "client", "on_connected", channel_id=chan, peer_id=peer_id)

                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")  # available on connected UDP sockets
                # Normalize to (ip, port) tuples (IPv6 tuples may have more fields)
                def _get_ip_port(x):
                    return (x[0], int(x[1])) if isinstance(x, tuple) and len(x) >= 2 else None
                l_ep = _get_ip_port(sockname)
                r_ep = _get_ip_port(peername) or (host, int(r_port))

                if l_ep and r_ep:
                    self.log.info("[UDP/CLI] chan=%s connected %s:%s -> %s:%s",
                                chan, l_ep[0], l_ep[1], r_ep[0], r_ep[1])
                else:
                    self.log.info("[UDP/CLI] chan=%s connected -> %s:%s", chan, host, r_port)
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s connect logging failed to %s:%s: %r", chan, host, r_port, e)

            # After creating the connected datagram endpoint and logging:
            try:
                self.log.info("[UDP/CLI] before-flush: chan=%s pending_len=%d",
                            chan, len(self._udp_client_pending.get(chan, [])))    
                pend = self._udp_client_pending.pop(chan, [])
                if pend:
                    try:
                        for idx, pkt in enumerate(pend, 1):
                            tr.sendto(pkt)
                        self.log.info("[UDP/CLI] chan=%s flushed %d early UDP datagram(s)", chan, len(pend))
                    except Exception as e:
                        self.log.info("[UDP/CLI] chan=%s early-buffer flush failed: %r", chan, e)
                else:
                        self.log.info("[UDP/CLI] chan=%s no flushing of early UDP datagram(s) was required ... skipped", chan)
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s flushing failed to %s:%s: %r", chan, host, r_port, e)


        self.loop.create_task(_mk())

    # --- ChannelMux._rx_udp_data (drop-in replacement) ---
    def _rx_udp_data(self, chan: int, data: bytes) -> None:
        """
        UDP RX demux:
        1) If this chan is mapped to a local UDP 'client' (server role), sendto(addr) and RETURN.
        2) Else, if there is a connected client-side UDP transport, sendto(peer) and RETURN.
        3) Else, queue in the early buffer for this chan (preserve datagram boundaries).
        """
        ctr = self._ctr(ChannelMux.Proto.UDP, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(data)        
        if len(data) > self._udp_service_datagram_cap:
            self.log.warning(
                "[UDP] chan=%s drop overlay UDP datagram len=%s cap=%s (%s)",
                chan,
                len(data),
                self._udp_service_datagram_cap,
                self._udp_service_datagram_diag,
            )
            return
        # --- 1) Server-side mapping: remote -> original local sender
        svc = self._udp_by_chan.get(chan)
        if svc is not None:
            svc_key, addr = svc
            srv_tr = self._svc_udp_servers.get(svc_key)
            if srv_tr:
                try:
                    ctr.msgs_out += 1
                    ctr.bytes_out += len(data)
                    srv_tr.sendto(data, addr)
                    # Touch activity
                    key = (svc_key, addr)
                    if key in self._udp_by_client:
                        self._udp_by_client[key] = (chan, time.time())
                except Exception as e:
                    self.log.debug("[UDP/SRV] chan=%s sendto error: %r", chan, e)
                # Best-effort wire log
                try:
                    l_sock = srv_tr.get_extra_info("sockname")
                    src = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None
                    dst = (addr[0], int(addr[1]))
                    self._log_conn("->", "UDP/SRV", chan, data, src=src, dst=dst)
                except Exception as e:
                    self.log.debug(f"[NET] logging failed : %r",e)
                    pass
            return  # <-- prevent falling into client branch

        # --- 2) Client-side: overlay -> connected remote endpoint
        tr = self._udp_client_transports.get(chan)
        if tr is None:
            # 3) Not connected yet: early buffer (cap + datagram boundaries)
            q = self._udp_client_pending.setdefault(chan, [])
            if len(q) < self._udp_client_pending_cap:
                q.append(bytes(data))
                self.log.info(
                    "[UDP/CLI] chan=%s DATA not routed yet (no client transport); early-buffered %dB (pending=%d)",
                    chan,
                    len(data),
                    len(q),
                )
            else:
                self._warning_with_channel_dump(
                    "[UDP/CLI] chan=%s DATA routing failed (no client transport, early-buffer full cap=%d) -> drop %dB",
                    chan,
                    self._udp_client_pending_cap,
                    len(data),
                )
            return

        # We have a transport: send and log
        try:
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
            tr.sendto(data)
            self._udp_client_last_ts[chan] = time.time()
        except Exception as e:
            self.log.debug("[UDP/CLI] chan=%s send error: %r", chan, e)
            return

        try:
            l_sock = tr.get_extra_info("sockname")
            p_sock = tr.get_extra_info("peername")
            src = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None
            dst = (p_sock[0], int(p_sock[1])) if isinstance(p_sock, tuple) and len(p_sock) >= 2 else None
            # NOTE: pass "UDP*" (no trailing colon) to avoid "UDP*::1" tag
            self._log_conn("->", "UDP/CLI", chan, data, src=src, dst=dst)
        except Exception as e:
            self.log.debug(f"[NET] logging failed : %r",e)
            pass           

    def _rx_udp_close(self, chan: int) -> None:
        # Client role cleanup
        tr = self._udp_client_transports.pop(chan, None)
        self._udp_client_last_ts.pop(chan, None)
        self._finalize_channel_stats(chan, ChannelMux.Proto.UDP)
        self._chan_owner_peer_id.pop(chan, None)
        self._drop_udp_fragment_reassembly(chan)
        if tr:
            try: tr.close()
            except Exception: pass
        # Server role cleanup
        self._udp_client_svc_id.pop(chan, None)
        self._udp_client_pending.pop(chan, None)
        self._forget_udp_open_key(chan)
        svc_addr = self._udp_by_chan.pop(chan, None)
        if svc_addr:
            svc_key, addr = svc_addr
            self._udp_by_client.pop((svc_key, addr), None)        
            spec = self._effective_services_by_id().get(svc_key)
            if spec is not None:
                self._schedule_service_hook(spec, svc_key, "listener", "on_channel_closed", channel_id=chan)
        elif tr is not None:
            spec = ChannelMux.ServiceSpec(
                svc_id=int(self._udp_client_svc_id.get(chan) or 0),
                l_proto="udp",
                l_bind="",
                l_port=0,
                r_proto="udp",
                r_host="",
                r_port=0,
            )
            self._schedule_service_hook(spec, None, "client", "after_closed", channel_id=chan)
        self.log.info("[UDP] chan=%s CLOSE => local teardown", chan)

    class _UDPClientProtocol(asyncio.DatagramProtocol):
        def __init__(self, parent: "ChannelMux", chan: int):
            self.parent = parent
            self.chan = chan
            self.transport: Optional[asyncio.DatagramTransport] = None

        def connection_made(self, transport):
            self.transport = transport  # keep for sockname/peername

        def datagram_received(self, data: bytes, addr):
            if len(data) > self.parent._udp_service_datagram_cap:
                self.parent.log.warning(
                    "[UDP/CLI] drop oversize local UDP datagram len=%s cap=%s (%s)",
                    len(data),
                    self.parent._udp_service_datagram_cap,
                    self.parent._udp_service_datagram_diag,
                )
                return
            ctr = self.parent._ctr(ChannelMux.Proto.UDP, self.chan)
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
            # remote -> overlay
            try:
                # Resolve endpoints for logging
                l_sock = self.transport.get_extra_info("sockname") if self.transport else None
                p_sock = self.transport.get_extra_info("peername") if self.transport else None
                src = (addr[0], int(addr[1])) if isinstance(addr, tuple) and len(addr) >= 2 else (
                    (p_sock[0], int(p_sock[1])) if isinstance(p_sock, tuple) and len(p_sock) >= 2 else None)
                dst = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None

                self.parent._log_conn("<-", "UDP/CLI:", self.chan, data, src=src, dst=dst)
            except Exception as e:
                self.log.debug(f"[NET] logging failed : %r",e)
                pass
            self.parent._send_mux(self.chan, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, data)
            self.parent._udp_client_last_ts[self.chan] = time.time()

        def error_received(self, exc):
            self.parent.log.debug("[UDP/CLI] chan=%s error: %r", self.chan, exc)

        def connection_lost(self, exc):
            self.parent.log.info("[UDP/CLI] chan=%s connection_lost: %r", self.chan, exc)
            self.parent._udp_client_transports.pop(self.chan, None)
            self.parent._udp_client_last_ts.pop(self.chan, None)
            self.parent._forget_udp_open_key(self.chan)

    # ---------- TCP server ----------
    async def _start_tcp_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            if not self._overlay_connected or not self._accepting_enabled:
                try:
                    writer.close()
                    await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                except Exception:
                    pass
                return

            chan = self._alloc_tcp_id()
            peer = writer.get_extra_info("peername")
            self._tcp_by_chan[chan] = (spec.svc_id, writer)
            self._tcp_by_writer[writer] = (spec.svc_id, chan)
            self._tcp_role_by_chan[chan] = "server"      
            self._chan_owner_peer_id[chan] = int(svc_key[1]) if str(svc_key[0]) == "peer" else 0
            self.log.info(
                "[TCP/SRV] accept peer=%s -> chan=%s svc=%s map_size=%s",
                peer,
                chan,
                spec.svc_id,
                len(self._tcp_by_chan),
            )
            self._schedule_service_hook(spec, svc_key, "listener", "on_channel_connected", channel_id=chan)

            # Install backpressure worker
            self._ensure_backpressure_task(chan, writer)

            # Send OPEN v4 (peer dials r_proto/r_host/r_port with full tuple metadata)
            try:
                self._send_open_for_service(chan, ChannelMux.Proto.TCP, spec)
            except Exception:
                pass

            # Pump outbound (local->overlay)
            async def _pump():
                try:
                    while True:
                        data = await reader.read(self._SAFE_TCP_READ)  # <= 65535-8
                        if not data:
                            break

                        # --- NEW: connection-level log (local TCP -> overlay) ---
                        try:
                            l_ep, r_ep = self._tcp_endpoints(writer)
                            # src = remote TCP peer; dst = our local listening endpoint
                            src = r_ep
                            dst = l_ep
                            self._log_conn("<-", "TCP", chan, data, src=src, dst=dst)
                        except Exception as e:
                            self.log.debug(f"[NET] logging failed : %r",e)
                            pass

                        # ---------------------------------------------------------
                        ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                        ctr.msgs_in += 1
                        ctr.bytes_in += len(data)
                        self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.DATA, data)
                        self.log.debug("[TCP/SRV] chan=%s local->overlay %dB", chan, len(data))
                except Exception as e:
                    self.log.info("[TCP/SRV] chan=%s pump error: %r", chan, e)
                finally:
                    self.log.info("[TCP/SRV] chan=%s EOF -> CLOSE (srv teardown begin)", chan)
                    self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.CLOSE, b"")
                    try:
                        writer.close()
                        await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                    except Exception:
                        pass
                    self._tcp_by_writer.pop(writer, None)
                    self._tcp_by_chan.pop(chan, None)
                    self._finalize_channel_stats(chan, ChannelMux.Proto.TCP)
                    self._chan_owner_peer_id.pop(chan, None)
                    self._forget_tcp_open_key(chan)
                    self._schedule_service_hook(spec, svc_key, "listener", "on_channel_closed", channel_id=chan)
                    self.log.info("[TCP/SRV] chan=%s CLOSE teardown complete map_size=%s", chan, len(self._tcp_by_chan))

            self.loop.create_task(_pump())
        try:
            family = _listener_family_for_host(spec.l_bind)
            srv = await asyncio.start_server(_handle, host=spec.l_bind, port=spec.l_port, family=family)
        except TypeError:
            srv = await asyncio.start_server(_handle, host=spec.l_bind, port=spec.l_port)

        self._svc_tcp_servers[svc_key] = srv
        sockets = ", ".join(str(s.getsockname()) for s in (srv.sockets or []))
        self.log.info("[TCP/SRV] service=%s:%s listening on %s", svc_key[0], spec.svc_id, sockets)
        self._schedule_service_hook(spec, svc_key, "listener", "on_created")


    # ---------- TCP RX path ----------
    def _rx_tcp_open(self, chan: int, data: bytes, peer_id: Optional[int] = None) -> None:
        p = self._parse_open_with_meta(data)
        if not p:
            self.log.debug("[TCP/CLI] chan=%s OPEN parse failed", chan)
            return
        (
            instance_id,
            connection_seq,
            svc_id,
            l_proto,
            l_bind,
            l_port,
            r_proto,
            host,
            r_port,
            svc_name,
            lifecycle_hooks,
            options,
        ) = p
        peer_key = int(peer_id or 0)
        self._chan_owner_peer_id[chan] = peer_key
        prev_epoch = self._peer_mux_epochs.get(peer_key)
        epoch_is_new = self._peer_epoch_is_new(peer_id, instance_id, connection_seq)
        self.log.info(
            "[TCP/CLI] OPEN recv chan=%s peer=%s iid=%s seq=%s svc=%s l=%s:%s r=%s:%s epoch_is_new=%s prev_epoch=%s",
            chan,
            peer_key,
            instance_id,
            connection_seq,
            svc_id,
            l_bind,
            l_port,
            host,
            r_port,
            epoch_is_new,
            prev_epoch,
        )
        if epoch_is_new:
            if prev_epoch is not None:
                self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
        else:
            self.log.debug(
                "[TCP/CLI] duplicate/replay OPEN epoch observed but not treated as channel duplicate chan=%s iid=%s seq=%s",
                chan,
                instance_id,
                connection_seq,
            )
        if int(l_proto) != int(ChannelMux.Proto.TCP):
            self.log.warning("[TCP/CLI] chan=%s OPEN declares non-TCP l_proto=%s", chan, l_proto)
            return
        if int(r_proto) != int(ChannelMux.Proto.TCP):
            self.log.warning("[TCP/CLI] chan=%s OPEN requests non-TCP r_proto=%s", chan, r_proto)
            return
        open_key = (peer_key, int(svc_id), int(l_proto), str(l_bind), int(l_port), int(r_proto), str(host), int(r_port))
        self._forget_tcp_open_key(chan)
        self._tcp_open_key_by_chan[chan] = open_key
        self._tcp_chan_by_open_key[open_key] = chan
        self.log.info(
            "[TCP/CLI] OPEN channel identity bind chan=%s key=%s:%s->%s:%s key_map_size=%s",
            chan,
            l_bind,
            l_port,
            host,
            r_port,
            len(self._tcp_chan_by_open_key),
        )
        if chan in self._tcp_by_chan:
            self.log.info("[TCP/CLI] chan=%s OPEN ignored because chan already connected", chan)
            return
        peer_spec = ChannelMux.ServiceSpec(
            svc_id=int(svc_id),
            l_proto="tcp",
            l_bind=str(l_bind),
            l_port=int(l_port),
            r_proto="tcp",
            r_host=str(host),
            r_port=int(r_port),
            name=svc_name,
            lifecycle_hooks=lifecycle_hooks,
            options=options,
        )

        async def _dial():
            try:
                await self._run_service_hook(peer_spec, None, "client", "before_connect", channel_id=chan, peer_id=peer_id)
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                self.log.info("[TCP/CLI] chan=%s connecting -> %s:%s", chan, host, r_port)
                transport, _ = await self.loop.create_connection(lambda: protocol, host=host, port=int(r_port))
                writer = asyncio.StreamWriter(transport, protocol, reader, self.loop)
                self._tcp_by_chan[chan] = (svc_id, writer)
                self._tcp_by_writer[writer] = (svc_id, chan)
                self._tcp_role_by_chan[chan] = "client"
                self._schedule_service_hook(peer_spec, None, "client", "on_connected", channel_id=chan, peer_id=peer_id)
                pending = self._tcp_pending_data.pop(chan, [])
                for buf in pending:
                    try:
                        writer.write(buf)
                        ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                        ctr.msgs_out += 1
                        ctr.bytes_out += len(buf)
                        self._maybe_signal_backpressure(chan, writer)
                        self.log.debug("[TCP/CLI] chan=%s flushed pending %dB", chan, len(buf))
                    except Exception as e:
                        self.log.info("[TCP/CLI] chan=%s pending flush error: %r", chan, e)
                        break

                # Backpressure worker
                self._ensure_backpressure_task(chan, writer)

                # Start RX pump: remote->overlay
                async def _rx():
                    try:
                        while True:
                            buf = await reader.read(self._SAFE_TCP_READ)
                            if not buf:
                                break
                            try:
                                l_ep, r_ep = self._tcp_endpoints(writer)
                                src = r_ep
                                dst = l_ep
                                self._log_conn("<-", "TCP", chan, buf, src=src, dst=dst)
                            except Exception as e:
                                self.log.debug(f"[NET] logging failed : %r",e)
                                pass
                            ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                            ctr.msgs_in += 1
                            ctr.bytes_in += len(buf)
                            self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.DATA, buf)
                            self.log.debug("[TCP/CLI] chan=%s remote->overlay %dB", chan, len(buf))
                    except Exception as e:
                        self.log.info("[TCP/CLI] chan=%s rx error: %r", chan, e)
                    finally:
                        self.log.info("[TCP/CLI] chan=%s EOF -> CLOSE", chan)
                        self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.CLOSE, b"")
                        try:
                            writer.close()
                            await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                        except Exception:
                            pass
                        self._tcp_by_writer.pop(writer, None)
                        self._tcp_by_chan.pop(chan, None)
                        self._finalize_channel_stats(chan, ChannelMux.Proto.TCP)
                        self._forget_tcp_open_key(chan)
                        self._schedule_service_hook(peer_spec, None, "client", "after_closed", channel_id=chan, peer_id=peer_id)
                        self.log.info("[TCP/CLI] chan=%s CLOSE teardown complete map_size=%s", chan, len(self._tcp_by_chan))

                self.loop.create_task(_rx())
            except Exception as e:
                self.log.info("[TCP/CLI] chan=%s connect failed: %r", chan, e)
                self._tcp_pending_data.pop(chan, None)
                self._forget_tcp_open_key(chan)

        self.loop.create_task(_dial())

    def _rx_tcp(self, chan: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            self._rx_tcp_open(chan, data, peer_id=peer_id)
            return

        if mtype == ChannelMux.MType.OPEN_CHUNK:
            self._rx_open_chunk(chan, ChannelMux.Proto.TCP, data, peer_id=peer_id)
            return

        # DATA to local TCP writer (overlay -> local)
        if mtype == ChannelMux.MType.DATA:
            open_key = self._tcp_open_key_by_chan.get(chan)
            role = self._tcp_role_by_chan.get(chan)
            pending = len(self._tcp_pending_data.get(chan, []))
            self.log.debug(
                "[TCP] chan=%s DATA arrival check: writer_ready=%s role=%s pending=%s open_bound=%s tcp_map_size=%s",
                chan,
                chan in self._tcp_by_chan,
                role,
                pending,
                open_key is not None,
                len(self._tcp_by_chan),
            )
            tup = self._tcp_by_chan.get(chan)
            if not tup:
                self._tcp_pending_data.setdefault(chan, []).append(data)
                self._warning_with_channel_dump(
                    "[TCP] chan=%s DATA not routed yet (writer not ready); buffered %dB (pending=%d)",
                    chan,
                    len(data),
                    len(self._tcp_pending_data.get(chan, [])),
                )
                return
            svc_id, writer = tup
            try:
                writer.write(data)

                # --- NEW: connection-level log (overlay -> local TCP) ---
                try:
                    l_ep, r_ep = self._tcp_endpoints(writer)
                    # src = our local TCP endpoint, dst = remote peer
                    self._log_conn("->", "TCP", chan, data, src=l_ep, dst=r_ep)
                except Exception as e:
                    self.log.debug(f"[NET] logging failed : %r",e)
                    pass

                # --------------------------------------------------------
                ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                ctr.msgs_out += 1
                ctr.bytes_out += len(data)
                self._maybe_signal_backpressure(chan, writer)
                self.log.debug("[TCP] chan=%s overlay->local %dB", chan, len(data))
            except Exception as e:
                self.log.info("[TCP] chan=%s write error: %r", chan, e)
            return

        # CLOSE
        if mtype == ChannelMux.MType.CLOSE:
            tup = self._tcp_by_chan.pop(chan, None)
            role = self._tcp_role_by_chan.pop(chan, None)
            if tup:
                _, writer = tup
                self._tcp_pending_data.pop(chan, None)
                self._tcp_by_writer.pop(writer, None)
                self._finalize_channel_stats(chan, ChannelMux.Proto.TCP)
                self._chan_owner_peer_id.pop(chan, None)
                try:
                    writer.close()
                except Exception:
                    pass
                if role == "client":
                    spec = ChannelMux.ServiceSpec(svc_id=0, l_proto="tcp", l_bind="", l_port=0, r_proto="tcp", r_host="", r_port=0)
                    self._schedule_service_hook(spec, None, "client", "after_closed", channel_id=chan)
            self._forget_tcp_open_key(chan)
            self.log.info("[TCP] chan=%s CLOSE => local teardown map_size=%s", chan, len(self._tcp_by_chan))

    # ---------- TCP backpressure ----------
    def _ensure_backpressure_task(self, chan: int, writer: asyncio.StreamWriter) -> None:
        if chan in self._tcp_backpressure_tasks:
            return
        evt = self._tcp_backpressure_evt.setdefault(chan, asyncio.Event())
        thr = int(getattr(self, "_tcp_drain_threshold", 1))
        latency_ms = int(getattr(self, "_tcp_bp_latency_ms", 300))
        poll_s = float(getattr(self, "_tcp_bp_poll_interval_s", 0.05))
        latency_ns = max(0, latency_ms) * 1_000_000

        async def _bp():
            try:
                nonzero_since_ns = 0
                while True:
                    # wait for size-based signal or poll
                    try:
                        await asyncio.wait_for(evt.wait(), timeout=poll_s)
                        evt.clear()
                    except asyncio.TimeoutError:
                        pass
                    transport = getattr(writer, "transport", None)
                    if not transport:
                        break
                    try:
                        wbs = transport.get_write_buffer_size()
                    except Exception:
                        wbs = 0
                    now_ns = time.monotonic_ns()
                    if wbs > 0:
                        if nonzero_since_ns == 0:
                            nonzero_since_ns = now_ns
                    else:
                        nonzero_since_ns = 0
                    do_drain = False
                    reason = ""
                    if wbs >= thr:
                        do_drain = True
                        reason = f"wbuf={wbs} thr={thr}"
                    elif latency_ns > 0 and nonzero_since_ns and (now_ns - nonzero_since_ns) >= latency_ns:
                        do_drain = True
                        waited_ms = (now_ns - nonzero_since_ns) / 1e6
                        reason = f"latency_ms={waited_ms:.1f} (>= {latency_ms})"
                    if do_drain:
                        try:
                            t0 = time.perf_counter()
                            await writer.drain()
                            dt = (time.perf_counter() - t0) * 1000.0
                            self.log.debug("[TCP/BP] chan=%s drain in %.2f ms; %s", chan, dt, reason)
                        except Exception as e:
                            self.log.info("[TCP/BP] chan=%s drain failed: %r", chan, e)
                            break
            except asyncio.CancelledError:
                return
            finally:
                self._tcp_backpressure_tasks.pop(chan, None)
                self._tcp_backpressure_evt.pop(chan, None)

        self._tcp_backpressure_tasks[chan] = self.loop.create_task(_bp())

    def _maybe_signal_backpressure(self, chan: int, writer: asyncio.StreamWriter) -> None:
        try:
            transport = writer.transport  # type: ignore[attr-defined]
            if not transport:
                return
            wbs = transport.get_write_buffer_size()
            thr = int(getattr(self, "_tcp_drain_threshold", 1))
            if wbs >= thr:
                evt = self._tcp_backpressure_evt.get(chan)
                if evt:
                    self.log.debug("[TCP/BP] chan=%s signal drain; wbuf=%s thr=%s", chan, wbs, thr)
                    evt.set()
        except Exception:
            pass
    # ---------- TCP endpoint helper ----------
    def _tcp_endpoints(self, writer: asyncio.StreamWriter) -> Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]]:
        """
        Return (local_endpoint, remote_endpoint) as (ip, port) tuples if available.
        Handles IPv6 tuples len>=2; returns None when not accessible.
        """
        try:
            transport = getattr(writer, "transport", None)  # type: ignore[attr-defined]
            if not transport:
                return None, None
            l = transport.get_extra_info("sockname")
            r = transport.get_extra_info("peername")
            def _ip_port(x):
                return (x[0], int(x[1])) if isinstance(x, tuple) and len(x) >= 2 else None
            return _ip_port(l), _ip_port(r)
        except Exception:
            return None, None
    # ---------- helpers ----------
    def _alloc_udp_id(self) -> int:
        start = self._chan_id_start if self._chan_id_stride == 2 else self.UDP_MIN_ID
        stride = self._chan_id_stride if self._chan_id_stride > 0 else 1
        cid = self._next_udp_id
        if cid > self.UDP_MAX_ID or cid < start:
            cid = start
        nxt = cid + stride
        self._next_udp_id = nxt if nxt <= self.UDP_MAX_ID else start
        return cid

    def _alloc_tcp_id(self) -> int:
        start = self._chan_id_start if self._chan_id_stride == 2 else self.TCP_MIN_ID
        stride = self._chan_id_stride if self._chan_id_stride > 0 else 1
        cid = self._next_tcp_id
        if cid > self.TCP_MAX_ID or cid < start:
            cid = start

        # Skip active channel ids during wrap-around to preserve unique in-flight identity.
        scan_start = cid
        while cid in self._tcp_by_chan:
            nxt = cid + stride
            cid = nxt if nxt <= self.TCP_MAX_ID else start
            if cid == scan_start:
                raise RuntimeError("no free TCP channel ids available")

        nxt = cid + stride
        self._next_tcp_id = nxt if nxt <= self.TCP_MAX_ID else start
        self.log.debug(
            "[TCP/SRV] alloc chan=%s next=%s active=%s",
            cid,
            self._next_tcp_id,
            len(self._tcp_by_chan),
        )
        return cid

    def _alloc_tun_id(self) -> int:
        start = self._chan_id_start if self._chan_id_stride == 2 else self.TUN_MIN_ID
        stride = self._chan_id_stride if self._chan_id_stride > 0 else 1
        cid = self._next_tun_id
        if cid > self.TUN_MAX_ID or cid < start:
            cid = start

        scan_start = cid
        while cid in self._tun_by_chan:
            nxt = cid + stride
            cid = nxt if nxt <= self.TUN_MAX_ID else start
            if cid == scan_start:
                raise RuntimeError("no free TUN channel ids available")

        nxt = cid + stride
        self._next_tun_id = nxt if nxt <= self.TUN_MAX_ID else start
        self.log.debug("[TUN/SRV] alloc chan=%s next=%s active=%s", cid, self._next_tun_id, len(self._tun_by_chan))
        return cid

    def _ctr(self, proto: ChannelMux.Proto, chan: int) -> _ChanCtr:
        key = (chan, proto)
        c = self._chan_stats.get((chan, proto))
        if c is None:
            c = _ChanCtr()
            self._chan_stats[(chan, proto)] = c
        return c

    def _finalize_channel_stats(
        self,
        chan: int,
        proto: "ChannelMux.Proto",
        *,
        peer_id: Optional[int] = None,
    ) -> None:
        c = self._chan_stats.pop((chan, proto), None)
        if c is None:
            return
        owner_peer_id = peer_id
        if owner_peer_id is None:
            owner_peer_id = self._chan_owner_peer_id.get(int(chan))
        if owner_peer_id is None:
            return
        total = self._peer_closed_channel_stats.get(int(owner_peer_id))
        if total is None:
            total = _ChanCtr()
            self._peer_closed_channel_stats[int(owner_peer_id)] = total
        total.msgs_in += int(getattr(c, "msgs_in", 0) or 0)
        total.msgs_out += int(getattr(c, "msgs_out", 0) or 0)
        total.bytes_in += int(getattr(c, "bytes_in", 0) or 0)
        total.bytes_out += int(getattr(c, "bytes_out", 0) or 0)

    def snapshot_peer_payload_totals(self) -> dict[int, dict[str, int]]:
        out: dict[int, dict[str, int]] = {}
        for peer_id, total in list(self._peer_closed_channel_stats.items()):
            out[int(peer_id)] = {
                "rx_msgs": int(getattr(total, "msgs_in", 0) or 0),
                "tx_msgs": int(getattr(total, "msgs_out", 0) or 0),
                "rx_bytes": int(getattr(total, "bytes_in", 0) or 0),
                "tx_bytes": int(getattr(total, "bytes_out", 0) or 0),
            }
        return out

    # ---------- Logging helpers ----------

    def _log_app_msg(self, dir: str, data: bytes) -> None:
        # chan_id(2) | proto(1) | counter(2) | mtype(1) | data_len(2)
        parsed = self._unpack_mux(data)
        if not parsed:
            self.log.warning(f"[APP] {dir} not parsed len={len(data)}: {data[:16].hex().upper()}")
            return
        chan_id, proto, counter, mtype, payload_mv = parsed
        data = bytes(payload_mv)
        src="[APP]"

        if len(data) > 65535:
            self.log.error(
                f"{src} Application message longer than 65535 bytes; makes trouble!"
            )

        protostr = ''
        if proto == ChannelMux.Proto.UDP:
            protostr = "UDP"
        if proto == ChannelMux.Proto.TCP:
            protostr = "TCP"
        if proto == ChannelMux.Proto.TUN:
            protostr = "TUN"

        basestr=f"{src} {protostr}:{chan_id} {dir} CNT:{counter}"

        if mtype == ChannelMux.MType.OPEN:
            try:
                pay = self._dbg_parse_open_v4(data) 
            except Exception:
                pay = ''
            self.log.info(f"{basestr} OPEN {pay}")
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2:
            decoded = self._decode_remote_services_set_v2(data)
            if decoded is None:
                self.log.info(f"{basestr} REMOTE_SERVICES_SET_V2 invalid len={len(data)}")
            else:
                iid, seq, services = decoded
                self.log.info(
                    "%s REMOTE_SERVICES_SET_V2 iid=%s seq=%s count=%s",
                    basestr,
                    iid,
                    seq,
                    len(services),
                )
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK:
            self.log.debug(f"{basestr} REMOTE_SERVICES_SET_V2_CHUNK len={len(data)}")
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V1:
            self.log.info(f"{basestr} REMOTE_SERVICES_SET_V1 len={len(data)} (legacy/unsupported)")
        if mtype == ChannelMux.MType.OPEN_CHUNK:
            self.log.debug(f"{basestr} OPEN_CHUNK len={len(data)}")
        if mtype == ChannelMux.MType.DATA:
            self.log.debug(f"{basestr} DATA len={len(data)}:  {data[:5].hex().upper()}")
        if mtype == ChannelMux.MType.DATA_FRAG:
            if len(data) >= ChannelMux.UDP_FRAG_HDR.size:
                datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(data[:ChannelMux.UDP_FRAG_HDR.size])
                self.log.debug(
                    "%s DATA_FRAG datagram_id=%s total=%s offset=%s chunk=%s",
                    basestr,
                    datagram_id,
                    total_len,
                    offset,
                    len(data) - ChannelMux.UDP_FRAG_HDR.size,
                )
            else:
                self.log.debug(f"{basestr} DATA_FRAG short len={len(data)}")
        if mtype == ChannelMux.MType.CLOSE:
            self.log.info(f"{basestr} CLOSE")

    def _dbg_parse_open_v4(self, payload: bytes) -> str:
        try:
            if len(payload) >= 2 and payload[:2] == b"O5":
                parsed = self._parse_open_with_meta(payload)
                if not parsed:
                    return ""
                (
                    instance_id,
                    connection_seq,
                    svc_id,
                    l_proto,
                    l_bind,
                    l_port,
                    r_proto,
                    host,
                    r_port,
                    svc_name,
                    lifecycle_hooks,
                    options,
                ) = parsed
                proto_map = {0: "UDP", 1: "TCP", 2: "TUN"}
                l_proto_s = proto_map.get(int(l_proto), str(int(l_proto)))
                r_proto_s = proto_map.get(int(r_proto), str(int(r_proto)))
                return (
                    f"OPENv5 iid={instance_id} seq={connection_seq} svc={svc_id} "
                    f"name={svc_name or '-'} l={l_proto_s} {l_bind}:{l_port} "
                    f"r={r_proto_s} {host}:{r_port} "
                    f"hooks={'yes' if isinstance(lifecycle_hooks, dict) else 'no'} "
                    f"options={'yes' if isinstance(options, dict) else 'no'}"
                )
            if len(payload) < 22 or payload[:2] != b"O4":
                return ""
            instance_id, connection_seq, svc_id, l_proto, l_len = struct.unpack(">QIHBB", payload[2:18])
            off = 18
            if len(payload) < off + l_len + 3:
                return ""
            l_bind = payload[off:off+l_len].decode("utf-8", "ignore")
            off += l_len
            l_port, r_proto = struct.unpack(">HB", payload[off:off+3])
            off += 3
            (hlen,) = struct.unpack(">B", payload[off:off+1])
            off += 1
            if len(payload) < off + hlen + 2:
                return ""
            host = payload[off:off+hlen].decode("utf-8", "ignore")
            off += hlen
            (r_port,) = struct.unpack(">H", payload[off:off+2])
            proto_s = "TCP" if r_proto == 1 else "UDP"
            l_proto_s = "TCP" if l_proto == 1 else "UDP"
            return (
                f"OPENv4 iid={instance_id} seq={connection_seq} svc={svc_id} "
                f"l={l_proto_s} {l_bind}:{l_port} r={proto_s} {host}:{r_port}"
            )
        except Exception:
            return ""

    # --- in ChannelMux, replace the old helper with this version ---
    def _log_conn(
        self,
        dir: str,            # "<-" or "->"
        mtype: str,          # "UDP" / "UDP*:" etc.
        chan_id: int,
        data: bytes,
        src: Optional[Tuple[str, int]] = None,
        dst: Optional[Tuple[str, int]] = None
    ) -> None:
        if not self.session.is_connected():
            return
        if len(data) > 65535:
            self.log.error("[NET] Too long for UDP frame; will be dropped downstream")
            return

        # Build "a.b.c.d:p -> e.f.g.h:q" if available; preserve old format otherwise
        path = ""
        try:
            if src and dst:
                path = f"  {src[0]}:{src[1]} -> {dst[0]}:{dst[1]}"
        except Exception:
            path = ""

        # Keep the short preview you already had
        self.log.debug(
            f"[NET] {mtype}:{chan_id} {dir}{path}  "
            f"len={len(data)}:  {data[:5].hex().upper()}"
        )

    # --- Dashboard helpers ---

    def _svc_spec_or_none(self, svc_id: int):
        try:
            i = int(svc_id)
            local = self._local_services.get(("local", 0, i))
            if local is not None:
                return local
            for key, spec in self._peer_installed_services.items():
                if key[0] == "peer" and int(key[2]) == i:
                    return spec
            return None
        except Exception:
            return None

    def _chan_stat_dict(self, chan: int, proto: "ChannelMux.Proto") -> dict:
        c = self._chan_stats.get((chan, proto))
        if c is None:
            return {
                "rx_msgs": 0,
                "tx_msgs": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
        return {
            "rx_msgs": int(getattr(c, "msgs_in", 0)),
            "tx_msgs": int(getattr(c, "msgs_out", 0)),
            "rx_bytes": int(getattr(c, "bytes_in", 0)),
            "tx_bytes": int(getattr(c, "bytes_out", 0)),
        }

    def snapshot_udp_connections(self) -> list[dict]:
        rows: list[dict] = []

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": src_ep,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": None,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })

        # Client-side UDP transports: locally created connected UDP socket to remote destination
        for chan, tr in list(self._udp_client_transports.items()):
            try:
                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                peer_ep = (peername[0], int(peername[1])) if isinstance(peername, tuple) and len(peername) >= 2 else None
                svc_id = self._udp_client_svc_id.get(chan)
                spec = self._svc_spec_or_none(svc_id) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

                rows.append({
                    "protocol": "udp",
                    "role": "client",
                    "state": "connected",
                    "chan_id": int(chan),
                    "svc_id": int(svc_id) if svc_id is not None else None,
                    "service_name": str(spec.name) if spec and spec.name else "",
                    "source": local_ep,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else None,
                    "remote_destination": (
                        {"host": peer_ep[0], "port": int(peer_ep[1])} if peer_ep else
                        ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                    ),
                    "stats": stats,
                })
            except Exception:
                continue

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_tcp_connections(self) -> list[dict]:
        rows: list[dict] = []

        for chan, tup in list(self._tcp_by_chan.items()):
            try:
                svc_id, writer = tup
            except Exception:
                continue

            spec = self._svc_spec_or_none(svc_id)
            role = self._tcp_role_by_chan.get(chan, "unknown")
            local_ep, remote_ep = self._tcp_endpoints(writer)
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.TCP)

            if role == "server":
                source = remote_ep
                local = local_ep
                remote_destination = (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                )
            else:
                source = local_ep
                local = local_ep
                remote_destination = (
                    {"host": remote_ep[0], "port": int(remote_ep[1])} if remote_ep else
                    ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                )

            rows.append({
                "protocol": "tcp",
                "role": role,
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": source,
                "local": local,
                "local_port": int(local[1]) if local else (int(spec.l_port) if spec else None),
                "remote_destination": remote_destination,
                "stats": stats,
            })

        rows.sort(key=lambda x: (x["protocol"], x["role"], x["chan_id"]))
        return rows

    def snapshot_connections(self) -> dict:
        udp_rows = self.snapshot_udp_connections()
        tcp_rows = self.snapshot_tcp_connections()
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "counts": {
                "udp": len(udp_rows),
                "tcp": len(tcp_rows),
            },
        }        
    
    def _svc_spec_or_none(self, svc_id: int):
        try:
            i = int(svc_id)
            local = self._local_services.get(("local", 0, i))
            if local is not None:
                return local
            for key, spec in self._peer_installed_services.items():
                if key[0] == "peer" and int(key[2]) == i:
                    return spec
            return None
        except Exception:
            return None

    def _chan_stat_dict(self, chan: int, proto: "ChannelMux.Proto") -> dict:
        c = self._chan_stats.get((chan, proto))
        if c is None:
            return {
                "rx_msgs": 0,
                "tx_msgs": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
        return {
            "rx_msgs": int(getattr(c, "msgs_in", 0)),
            "tx_msgs": int(getattr(c, "msgs_out", 0)),
            "rx_bytes": int(getattr(c, "bytes_in", 0)),
            "tx_bytes": int(getattr(c, "bytes_out", 0)),
        }

    def snapshot_udp_connections(self) -> list[dict]:
        rows: list[dict] = []

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": src_ep,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": None,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })

        # Client-side UDP transports: locally created connected UDP socket to remote destination
        for chan, tr in list(self._udp_client_transports.items()):
            try:
                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                peer_ep = (peername[0], int(peername[1])) if isinstance(peername, tuple) and len(peername) >= 2 else None
                svc_id = self._udp_client_svc_id.get(chan)
                spec = self._svc_spec_or_none(svc_id) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

                rows.append({
                    "protocol": "udp",
                    "role": "client",
                    "state": "connected",
                    "chan_id": int(chan),
                    "svc_id": int(svc_id) if svc_id is not None else None,
                    "service_name": str(spec.name) if spec and spec.name else "",
                    "source": local_ep,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else None,
                    "remote_destination": (
                        {"host": peer_ep[0], "port": int(peer_ep[1])} if peer_ep else
                        ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                    ),
                    "stats": stats,
                })
            except Exception:
                continue

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_tcp_connections(self) -> list[dict]:
        rows: list[dict] = []

        for chan, tup in list(self._tcp_by_chan.items()):
            try:
                svc_id, writer = tup
            except Exception:
                continue

            spec = self._svc_spec_or_none(svc_id)
            role = self._tcp_role_by_chan.get(chan, "unknown")
            local_ep, remote_ep = self._tcp_endpoints(writer)
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.TCP)

            if role == "server":
                source = remote_ep
                local = local_ep
                remote_destination = (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                )
            else:
                source = local_ep
                local = local_ep
                remote_destination = (
                    {"host": remote_ep[0], "port": int(remote_ep[1])} if remote_ep else
                    ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                )

            rows.append({
                "protocol": "tcp",
                "role": role,
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": source,
                "local": local,
                "local_port": int(local[1]) if local else (int(spec.l_port) if spec else None),
                "remote_destination": remote_destination,
                "stats": stats,
            })

        # TCP listeners: bound server sockets waiting for incoming channels.
        for svc_key, srv in list(self._svc_tcp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockets = list((getattr(srv, "sockets", None) or []))
            if not sockets:
                sockets = [None]
            for sock in sockets:
                try:
                    sockname = sock.getsockname() if sock is not None else None
                except Exception:
                    sockname = None
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                rows.append({
                    "protocol": "tcp",
                    "role": "server",
                    "state": "listening",
                    "chan_id": None,
                    "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                    "svc_id": svc_id,
                    "service_name": str(spec.name) if spec and spec.name else "",
                    "source": None,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                    "remote_destination": (
                        {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                    ),
                    "stats": {
                        "rx_msgs": 0,
                        "tx_msgs": 0,
                        "rx_bytes": 0,
                        "tx_bytes": 0,
                    },
                })

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_tun_connections(self) -> list[dict]:
        rows: list[dict] = []
        active_service_keys: set[ChannelMux.ServiceKey] = set()
        dev_channels: dict[int, tuple[ChannelMux.TunDevice, list[int]]] = {}
        for chan, dev in list(self._tun_by_chan.items()):
            key = id(dev)
            if key not in dev_channels:
                dev_channels[key] = (dev, [])
            dev_channels[key][1].append(int(chan))

        for _dev_key, (dev, chans) in dev_channels.items():
            chans = sorted(chans)
            primary_chan = int(getattr(dev, "chan_id", None) or chans[0])
            stats = {"rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0}
            for chan in chans:
                chan_stats = self._chan_stat_dict(chan, ChannelMux.Proto.TUN)
                stats["rx_msgs"] += int(chan_stats.get("rx_msgs", 0) or 0)
                stats["tx_msgs"] += int(chan_stats.get("tx_msgs", 0) or 0)
                stats["rx_bytes"] += int(chan_stats.get("rx_bytes", 0) or 0)
                stats["tx_bytes"] += int(chan_stats.get("tx_bytes", 0) or 0)
            svc_key = getattr(dev, "service_key", None)
            svc_id = int(svc_key[2]) if isinstance(svc_key, tuple) and len(svc_key) >= 3 else None
            spec = self._svc_spec_or_none(svc_id) if svc_id is not None else None
            if isinstance(svc_key, tuple):
                active_service_keys.add(svc_key)
            rows.append({
                "protocol": "tun",
                "role": "server" if svc_key is not None else "client",
                "state": "connected",
                "chan_id": primary_chan,
                "channel_aliases": chans,
                "svc_owner_peer_id": int(svc_key[1]) if isinstance(svc_key, tuple) and len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": None,
                "local": {"ifname": str(getattr(dev, "ifname", "") or ""), "mtu": int(getattr(dev, "mtu", 0) or 0)},
                "local_port": None,
                "remote_destination": (
                    {"ifname": str(spec.r_host), "mtu": int(spec.r_port)} if spec else
                    {"ifname": str(getattr(dev, "ifname", "") or ""), "mtu": int(getattr(dev, "mtu", 0) or 0)}
                ),
                "shared_tun_ownership": self._shared_tun_runtime_snapshot_for_service(svc_key),
                "stats": stats,
            })

        # TUN services are interface-backed rather than socket-backed. Show them
        # as idle listener rows once the device is open, matching UDP/TCP listeners.
        for svc_key, dev in list(self._svc_tun_devices.items()):
            if svc_key in active_service_keys:
                continue
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            local = {
                "ifname": str(getattr(dev, "ifname", "") or ""),
                "mtu": int(getattr(dev, "mtu", 0) or 0),
            }
            rows.append({
                "protocol": "tun",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "service_name": str(spec.name) if spec and spec.name else "",
                "source": None,
                "local": local,
                "local_port": None,
                "remote_destination": (
                    {"ifname": str(spec.r_host), "mtu": int(spec.r_port)} if spec else local
                ),
                "shared_tun_ownership": self._shared_tun_runtime_snapshot_for_service(svc_key),
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })
        rows.sort(key=lambda x: (-1 if x["chan_id"] is None else int(x["chan_id"])))
        return rows

    def snapshot_connections(self) -> dict:
        udp_rows = self.snapshot_udp_connections()
        tcp_rows = self.snapshot_tcp_connections()
        tun_rows = self.snapshot_tun_connections()
        udp_listening = sum(1 for row in udp_rows if str(row.get("state", "connected")).lower() == "listening")
        tcp_listening = sum(1 for row in tcp_rows if str(row.get("state", "connected")).lower() == "listening")
        tun_listening = sum(1 for row in tun_rows if str(row.get("state", "connected")).lower() == "listening")
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "tun": tun_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "tun": len(tun_rows) - tun_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
                "tun_listening": tun_listening,
            },
        }

# ============================================================================
STATE_DISCONNECTED = "DISCONNECTED"
STATE_CONNECTED = "CONNECTED"
STATE_FAILED = "FAILED"
