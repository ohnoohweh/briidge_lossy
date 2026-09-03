from __future__ import annotations

from collections.abc import Mapping

from ._bridge_import import export_bridge_globals

_bridge = export_bridge_globals(globals())

from . import bridge_channelmux_shared_tun as _bridge_channelmux_shared_tun
from . import bridge_channelmux_virtual_peer as _bridge_channelmux_virtual_peer
from .bridge_channelmux_shared_tun import ChannelMuxSharedTunMixin
from .bridge_channelmux_virtual_peer import ChannelMuxVirtualPeerMixin

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

from .bridge_tun_routing import TunRoutingSettings, auto_overlay_peer_excluded_routes
from .bridge_connection_lifecycle import ConnectionLifecycleEvent
from .bridge_proxy_common import open_http_connect_tunnel, resolve_proxy_endpoint
from .bridge_tun_ping import (
    PROBE_KIND_GLOBAL,
    PROBE_KIND_PEER,
    PROBE_MAGIC,
    build_ipv4_echo_request,
    build_ipv6_echo_request,
    parse_echo_request,
    parse_internal_probe_packet,
    parse_echo_reply,
    probe_payload,
)

class _ChanCtr:
    msgs_in: int = 0
    msgs_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    crc_in: int = 0
    crc_out: int = 0


class ProcessSharedTunRegistry:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, int], dict[str, Any]] = {}
        self._by_dev_id: dict[int, tuple[str, int]] = {}
        self._shared_peer_ids: dict[tuple[int, int], int] = {}
        self._shared_peer_routes: dict[int, tuple["ChannelMux", int]] = {}
        self._next_shared_peer_id = 1

    @staticmethod
    def _key(ifname: str, mtu: int) -> tuple[str, int]:
        return (str(ifname or ""), int(mtu))

    def register(self, mux: "ChannelMux", svc_key: Any, dev: Any) -> None:
        key = self._key(getattr(dev, "ifname", ""), int(getattr(dev, "mtu", 0) or 0))
        entry = self._by_key.setdefault(
            key,
            {
                "dev": dev,
                "owner_mux": mux,
                "service_key": svc_key,
                "holders": {},
            },
        )
        entry["dev"] = dev
        entry["owner_mux"] = entry.get("owner_mux") or mux
        entry["service_key"] = entry.get("service_key") or svc_key
        holders = dict(entry.get("holders") or {})
        holders[id(mux)] = mux
        entry["holders"] = holders
        self._by_key[key] = entry
        self._by_dev_id[id(dev)] = key

    def attach_existing(self, mux: "ChannelMux", ifname: str, mtu: int) -> Optional[Any]:
        key = self._key(ifname, mtu)
        entry = self._by_key.get(key)
        if not isinstance(entry, dict):
            return None
        holders = dict(entry.get("holders") or {})
        holders[id(mux)] = mux
        entry["holders"] = holders
        self._by_key[key] = entry
        return entry.get("dev")

    def service_key_for(self, ifname: str, mtu: int) -> Any:
        entry = self._by_key.get(self._key(ifname, mtu))
        if not isinstance(entry, dict):
            return None
        return entry.get("service_key")

    def owner_mux_for_dev(self, dev: Any) -> Optional["ChannelMux"]:
        key = self._by_dev_id.get(id(dev))
        if key is None:
            return None
        entry = self._by_key.get(key)
        if not isinstance(entry, dict):
            return None
        owner = entry.get("owner_mux")
        return owner if owner is not None else None

    def holders_for_dev(self, dev: Any) -> list["ChannelMux"]:
        """Return every mux currently sharing ``dev`` in this process."""
        key = self._by_dev_id.get(id(dev))
        if key is None:
            return []
        entry = self._by_key.get(key)
        if not isinstance(entry, dict):
            return []
        return [holder for holder in dict(entry.get("holders") or {}).values() if holder is not None]

    def shared_peer_id_for(self, mux: "ChannelMux", peer_id: int, *, create: bool = True) -> Optional[int]:
        """Allocate a process-wide identity for a mux-local listener peer."""
        key = (id(mux), int(peer_id))
        existing = self._shared_peer_ids.get(key)
        if existing is not None:
            return existing
        if not create:
            return None
        shared_peer_id = self._next_shared_peer_id
        self._next_shared_peer_id += 1
        self._shared_peer_ids[key] = shared_peer_id
        self._shared_peer_routes[shared_peer_id] = (mux, int(peer_id))
        return shared_peer_id

    def holders(self) -> list["ChannelMux"]:
        holders: dict[int, "ChannelMux"] = {}
        for entry in self._by_key.values():
            for holder in dict(entry.get("holders") or {}).values():
                if holder is not None:
                    holders[id(holder)] = holder
        return list(holders.values())

    def forget_shared_peer(self, mux: "ChannelMux", peer_id: int) -> Optional[int]:
        key = (id(mux), int(peer_id))
        shared_peer_id = self._shared_peer_ids.pop(key, None)
        if shared_peer_id is not None:
            self._shared_peer_routes.pop(shared_peer_id, None)
        return shared_peer_id

    def shared_peer_route_for(self, shared_peer_id: int) -> Optional[tuple["ChannelMux", int]]:
        return self._shared_peer_routes.get(int(shared_peer_id))

    def release(self, mux: "ChannelMux", dev: Any) -> bool:
        key = self._by_dev_id.get(id(dev))
        if key is None:
            return True
        entry = self._by_key.get(key)
        if not isinstance(entry, dict):
            return True
        holders = dict(entry.get("holders") or {})
        holders.pop(id(mux), None)
        entry["holders"] = holders
        self._by_key[key] = entry
        if holders:
            return False
        self._by_key.pop(key, None)
        self._by_dev_id.pop(id(dev), None)
        return True

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


class ChannelMux(ChannelMuxVirtualPeerMixin, ChannelMuxSharedTunMixin):
    """Catalog-based multiplexer with multiple TCP/UDP/TUN services and peer-side dynamic dialers."""
    ProtoName = Literal["tcp", "udp", "tun"]
    ServiceOrigin = Literal["local", "peer"]
    ServiceKey = Tuple[ServiceOrigin, int, int]  # (origin, peer_id, svc_id)
    LOCAL_REPLY_STAGE_KEYS: tuple[str, ...] = (
        "local_reply_skip_overlay_inactive",
        "local_reply_drop_oversize",
        "local_reply_drop_throttled",
        "local_reply_drop_shared_route",
        "local_reply_virtual_probe_delivery",
        "local_reply_drop_no_channel",
        "local_reply_drop_missing_service_spec",
        "local_reply_bound_new_channel",
        "local_reply_before_overlay_send",
    )
    TUN_ICMP_STAGE_KEYS: tuple[str, ...] = (
        "from_local_tun_read",
        "overlay_tx_before_send_app",
        "overlay_rx_after_unpack",
        "from_peer_before_local_write",
        "to_local_tun_written",
        *LOCAL_REPLY_STAGE_KEYS,
    )
    TUN_PROBE_BOUNDARY_KEYS: tuple[str, ...] = (
        "probe_attempt_started",
        "probe_waiter_registered",
        "probe_injected_local_virtual",
        "probe_injected_kernel",
        "probe_injected_channelmux",
        "probe_send_completed",
        "probe_reply_matched",
        "probe_reply_consumed_before_local_write",
        "probe_reply_late_after_timeout",
        "own_probe_reply_unmatched",
        "foreign_probe_reply_unmatched",
        "probe_reply_unmatched",
        "probe_timeout",
        "probe_exception",
        "helper_read_packet",
        "helper_read_probe_packet",
        "helper_write_packet",
        "helper_write_probe_packet",
        "helper_write_error",
    )
    # The outer layer is the protocol-agnostic readiness authority. A live
    # socket with SecureLink/Compression not app-ready must rotate just like a
    # fully disconnected transport.
    CONNECTION_ROTATION_DELAY_S: float = 15.0
    DEFAULT_TRANSPORT_DELAY_THRESHOLD_MS: float = 5_000.0
    DEFAULT_TRANSPORT_DELAY_ROTATION_DELAY_MS: float = 30_000.0

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
        helper_managed: bool = False
        helper_network_applied: bool = False

    def _record_sync_diag(self, name: str, *, phase: str, error: str = "") -> None:
        cb = getattr(self, "_runner_sync_diag_cb", None)
        if not callable(cb):
            return
        with contextlib.suppress(Exception):
            cb(name, kind="callback", phase=phase, error=error)

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
    OVERLAY_BACKPRESSURE_THROTTLE_RATIO = 0.9
    TUN_STREAM_OVERLAY_STALL_NS = 2_500_000_000
    TUN_STREAM_OVERLAY_RX_IDLE_NS_MIN = 500_000_000
    STREAM_OVERLAY_TCP_READ_CAP = 2048
    SHARED_TUN_RECENT_DROP_LIMIT = 16
    TUN_PROBE_TIMEOUT_S = 2.0
    SHARED_TUN_LOCAL_PROBE_PEER_REF = "__local_probe__"
    SHARED_TUN_LOCAL_PROBE_PEER_ID = 0
    SHARED_TUN_LOCAL_PROBE_CHAN_ID = -1

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
        def _json_cli_value(value: Any) -> Any:
            if isinstance(value, (dict, list)):
                return value
            if value is None:
                return None
            return json.loads(str(value))
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
        if not _has('--channel-mux-egress'):
            p.add_argument(
                '--channel-mux-egress',
                dest='channel_mux_egress',
                type=_json_cli_value,
                default={"mode": "system"},
                help=(
                    "ChannelMux target-side egress policy object. "
                    "Use mode system, direct, or manual; system uses WinHTTP on Windows and "
                    "HTTP_PROXY/HTTPS_PROXY/NO_PROXY on Linux/POSIX for TCP target dials."
                ),
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
        if not _has('--channelmux-transport-delay-threshold-ms'):
            p.add_argument(
                '--channelmux-transport-delay-threshold-ms', type=float,
                default=ChannelMux.DEFAULT_TRANSPORT_DELAY_THRESHOLD_MS,
                help='ChannelMux: estimated transport-delay threshold for shedding and sustained-delay rotation (default 5000 ms).',
            )
        if not _has('--channelmux-transport-delay-rotation-delay-ms'):
            p.add_argument(
                '--channelmux-transport-delay-rotation-delay-ms', type=float,
                default=ChannelMux.DEFAULT_TRANSPORT_DELAY_ROTATION_DELAY_MS,
                help='ChannelMux: continuous transport-delay duration before connection rotation (default 30000 ms).',
            )

    @staticmethod
    def from_args(session, loop: asyncio.AbstractEventLoop, args,
                  on_local_rx_bytes: Optional[Callable[[int], None]] = None,
                  on_local_tx_bytes: Optional[Callable[[int], None]] = None) -> "ChannelMux":
        mux = ChannelMux(session, loop, on_local_rx_bytes, on_local_tx_bytes)
        mux.args = args
        with contextlib.suppress(Exception):
            mux._tun_routing_settings = TunRoutingSettings.from_mapping(vars(args))
        mux._tun_helper_settings = getattr(args, "_tun_helper_settings", None)
        mux._tun_helper_client = getattr(args, "_tun_helper_client", None)
        mux._tun_helper_backend = getattr(args, "_tun_helper_backend", None)
        # Parse catalog
        services = ChannelMux._parse_own_servers(getattr(args, 'own_servers', None))
        remote_services = ChannelMux._parse_remote_servers(getattr(args, 'remote_servers', None))
        services = [mux._service_spec_with_tun_mtu_defaults(s) for s in services]
        remote_services = [mux._service_spec_with_tun_mtu_defaults(s) for s in remote_services]
        active_transport = str(getattr(args, "overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
        mux._overlay_transport = active_transport
        bind_attr, peer_attr, peer_port_attr, _listen_port_attr = _overlay_cli_attrs(active_transport)
        raw_overlay_peer = str(getattr(args, peer_attr, None) or "").strip()
        raw_overlay_port = getattr(args, peer_port_attr, None)
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
        try:
            mux._transport_delay_threshold_ms = max(0.0, float(getattr(
                args, 'channelmux_transport_delay_threshold_ms', mux.DEFAULT_TRANSPORT_DELAY_THRESHOLD_MS,
            )))
        except Exception:
            mux._transport_delay_threshold_ms = mux.DEFAULT_TRANSPORT_DELAY_THRESHOLD_MS
        try:
            mux._transport_delay_rotation_delay_s = max(0.0, float(getattr(
                args, 'channelmux_transport_delay_rotation_delay_ms', mux.DEFAULT_TRANSPORT_DELAY_ROTATION_DELAY_MS,
            )) / 1000.0)
        except Exception:
            mux._transport_delay_rotation_delay_s = mux.DEFAULT_TRANSPORT_DELAY_ROTATION_DELAY_MS / 1000.0
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

    @staticmethod

    @staticmethod

    @staticmethod

    @staticmethod

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
            if listen.get("mtu") is None:
                l_port_i = 0
            else:
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
            if target.get("mtu") is None:
                r_port_i = 0
            else:
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
        self._process_shared_tun_registry: Optional[ProcessSharedTunRegistry] = None
        self._tun_helper_settings = None
        self._tun_helper_client = None
        self._tun_helper_backend = None
        self._tun_helper_open_tasks: dict[int, asyncio.Task] = {}
        self._tun_helper_reader_tasks: dict[int, asyncio.Task] = {}
        self._tun_helper_remove_tasks: dict[int, asyncio.Task] = {}
        self._tun_helper_devices: dict[int, ChannelMux.TunDevice] = {}
        self._tun_runtime_health_by_service: dict[ChannelMux.ServiceKey, dict[str, Any]] = {}
        self._tun_runtime_health_tasks: dict[int, asyncio.Task] = {}
        self._tun_probe_tasks: dict[tuple[str, str, str], asyncio.Task] = {}
        self._tun_probe_history: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._tun_probe_waiters: dict[tuple[int, int, int, bytes], asyncio.Future] = {}
        self._tun_probe_timed_out_waiters: dict[tuple[int, int, int, bytes], dict[str, Any]] = {}
        self._tun_probe_last_timeout_diag: dict[str, Any] = {}
        self._tun_probe_sequence: int = 1
        self._tun_probe_identifier: int = random.getrandbits(16)

        # Overlay state gate
        self._overlay_connected: bool = self._session_overlay_inflow_allowed()
        self._accepting_enabled: bool = self._overlay_connected
        self._connection_rotation_task: Optional[asyncio.Task] = None
        self._transport_delay_rotation_task: Optional[asyncio.Task] = None
        self._transport_delay_high_since_mono: Optional[float] = None
        self._on_connection_rotation_result = None
        self._connection_rotation_wait_epoch: Optional[int] = None
        self._transport_delay_threshold_ms: float = self.DEFAULT_TRANSPORT_DELAY_THRESHOLD_MS
        self._transport_delay_rotation_delay_s: float = self.DEFAULT_TRANSPORT_DELAY_ROTATION_DELAY_MS / 1000.0
        self._connection_lifecycle_epoch: int = 0
        # Epoch zero represents an already-ready session before its callback is
        # attached. Any disconnected lifecycle edge clears this bootstrap grant.
        self._tun_admission_epoch: Optional[int] = 0 if self._overlay_connected else None

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
        # Listener creation is reached both by remote-service installation and
        # the self-healing watchdog.  ``asyncio.start_server`` yields, so a
        # membership check before either caller enters it is not sufficient to
        # prevent a second bind of the same endpoint.
        self._tcp_listener_start_locks: dict[ChannelMux.ServiceKey, asyncio.Lock] = {}

        # Backpressure machinery (per TCP writer)
        self._tcp_send_locks: dict[int, asyncio.Lock] = {}
        self._tcp_backpressure_evt: dict[int, asyncio.Event] = {}
        self._tcp_backpressure_tasks: dict[int, asyncio.Task] = {}
        self._tcp_drain_threshold: int = 1
        self._tcp_bp_latency_ms: int = 300
        self._tcp_bp_poll_interval_s: float = 0.05
        self._tcp_ingress_throttle_poll_s: float = 0.05

        # Listener peers may legally reuse channel ids, so counters are scoped
        # to the peer session that receives the frame.
        self._mux_counters: dict[tuple[Optional[int], int, int], int] = {}

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
        self._tcp_first_overlay_to_local_logged: set[int] = set()
        self._tcp_first_remote_to_overlay_logged: set[int] = set()
        self._tcp_pending_drain_logged: set[int] = set()
        self._channel_mux_udp_proxy_warned: bool = False
        self._tun_open_key_by_chan: dict[tuple[int, int], tuple[int, int, int, str, int, int, str, int]] = {}
        self._tun_chan_by_open_key: dict[tuple[int, int, int, str, int, int, str, int], int] = {}
        self._tun_by_chan: dict[int, ChannelMux.TunDevice] = {}
        self._tun_by_peer_chan: dict[tuple[int, int], ChannelMux.TunDevice] = {}
        self._tun_chan_by_service: dict[ChannelMux.ServiceKey, int] = {}
        self._tun_frag_rx: dict[tuple[int, int, int], dict[str, Any]] = {}
        self._shared_tun_ownership_by_service: dict[ChannelMux.ServiceKey, dict[str, Any]] = {}
        self._shared_tun_runtime_by_peer: dict[tuple[ChannelMux.ServiceKey, int], dict[str, Any]] = {}
        self._shared_tun_peer_ref_by_peer: dict[tuple[ChannelMux.ServiceKey, int], str] = {}
        self._shared_tun_peer_id_by_ref: dict[tuple[ChannelMux.ServiceKey, str], int] = {}
        self._shared_tun_drop_state_by_service: dict[ChannelMux.ServiceKey, dict[str, Any]] = {}
        self._tun_reader_activation_deferred: set[ChannelMux.ServiceKey] = set()
        self._tun_inflow_scope_state: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._shared_tun_normalization_warned: set[tuple[str, str, str]] = set()
        self._stream_overlay_idle_warn_until_ns: int = 0
        self._chan_owner_peer_id: dict[int, int] = {}
        self._ctrl_chunk_rx: dict[tuple[int, int, int, int, int], dict[str, Any]] = {}
        self._ctrl_chunk_next_txid: int = 1
        self._tun_flow_local_samples: int = 0
        self._tun_flow_remote_samples: int = 0
        self._tun_flow_drop_samples: int = 0
        self._tun_flow_write_ok_samples: int = 0
        self._tun_mux_tx_samples: int = 0
        self._tun_mux_rx_samples: int = 0
        self._local_reply_stage_counts: dict[str, int] = {
            key: 0 for key in self.LOCAL_REPLY_STAGE_KEYS
        }
        self._tun_icmp_stage_counts: dict[str, int] = {
            key: 0 for key in self.TUN_ICMP_STAGE_KEYS
        }
        self._tun_probe_boundary_counts: dict[str, int] = {
            key: 0 for key in self.TUN_PROBE_BOUNDARY_KEYS
        }

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

    @staticmethod
    def _tun_flow_debug_enabled() -> bool:
        raw = str(os.environ.get("OB_TUN_FLOW_DEBUG", "") or "").strip().lower()
        return raw in {"1", "true", "yes", "on"}

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

    def _log_tun_packet_trace(
        self,
        *,
        stage: str,
        packet: bytes,
        ifname: str = "",
        chan: Optional[int] = None,
        peer_id: Optional[int] = None,
        note: str = "",
        mtype: Optional["ChannelMux.MType"] = None,
    ) -> None:
        if not self._tun_packet_debug_enabled():
            return
        payload = bytes(packet or b"")
        ip_version = (payload[0] >> 4) if payload else -1
        src_ip = ""
        dst_ip = ""
        parse_error = ""
        if mtype in (None, ChannelMux.MType.DATA):
            parsed, parse_error = self._parse_tun_packet_endpoints(payload)
            if isinstance(parsed, dict):
                ip_version = int(parsed.get("ip_version", ip_version) or ip_version)
                src_ip = str(parsed.get("source_ip") or "")
                dst_ip = str(parsed.get("destination_ip") or "")
        crc32 = f"{(zlib.crc32(payload) & 0xFFFFFFFF):08x}" if payload else "00000000"
        preview = payload[:12].hex()
        self.log.debug(
            "[TUN/TRACE] stage=%s if=%s chan=%s peer=%s mtype=%s len=%s ipver=%s src=%s dst=%s crc32=%s preview=%s parse_error=%s note=%s",
            stage,
            ifname,
            "" if chan is None else chan,
            "" if peer_id is None else peer_id,
            "" if mtype is None else int(mtype),
            len(payload),
            ip_version,
            src_ip,
            dst_ip,
            crc32,
            preview,
            parse_error,
            note,
        )

    def _log_tun_icmp_packet(
        self,
        *,
        stage: str,
        packet: bytes,
        ifname: str = "",
        chan: Optional[int] = None,
        peer_id: Optional[int] = None,
        mtype: Optional["ChannelMux.MType"] = None,
        note: str = "",
    ) -> None:
        payload = bytes(packet or b"")
        if stage in self._tun_icmp_stage_counts:
            self._tun_icmp_stage_counts[stage] = int(self._tun_icmp_stage_counts.get(stage, 0) or 0) + 1
        if stage in self._local_reply_stage_counts:
            self._local_reply_stage_counts[stage] = int(self._local_reply_stage_counts.get(stage, 0) or 0) + 1
        parsed = parse_internal_probe_packet(payload)
        packet_type = "internal_probe"
        probe_note = ""
        if isinstance(parsed, dict):
            direction = str(parsed.get("direction") or "").strip()
            packet_type = f"internal_probe_{direction or 'packet'}"
            probe_kind = int(parsed.get("probe_kind") or 0)
            if probe_kind == PROBE_KIND_GLOBAL:
                probe_note = "probe_kind=global"
            elif probe_kind == PROBE_KIND_PEER:
                probe_note = "probe_kind=peer"
            else:
                probe_note = f"probe_kind={probe_kind}"
        else:
            parsed = parse_echo_request(payload)
            packet_type = "echo_request"
            if not isinstance(parsed, dict):
                parsed = parse_echo_reply(payload)
                packet_type = "echo_reply"
        if not isinstance(parsed, dict):
            return
        family = int(parsed.get("family") or 0)
        family_text = "ipv6" if family == socket.AF_INET6 else "ipv4"
        note_bits: list[str] = []
        if note:
            note_bits.append(str(note))
        if probe_note:
            note_bits.append(probe_note)
        crc32 = f"{(zlib.crc32(payload) & 0xFFFFFFFF):08x}" if payload else "00000000"
        self.log.info(
            "[TUN/ICMP] stage=%s type=%s family=%s if=%s chan=%s peer=%s mtype=%s len=%s src=%s dst=%s id=%s seq=%s crc32=%s note=%s",
            stage,
            packet_type,
            family_text,
            ifname,
            "" if chan is None else chan,
            "" if peer_id is None else peer_id,
            "" if mtype is None else int(mtype),
            len(payload),
            str(parsed.get("source_ip") or ""),
            str(parsed.get("destination_ip") or ""),
            int(parsed.get("identifier") or 0),
            int(parsed.get("sequence") or 0),
            crc32,
            "; ".join(note_bits),
        )

    def _log_tun_icmp_overlay_packet(
        self,
        *,
        stage: str,
        packet: bytes,
        chan: int,
        peer_id: Optional[int],
        mtype: "ChannelMux.MType",
        counter: Optional[int] = None,
        note: str = "",
    ) -> None:
        note_bits: list[str] = []
        if note:
            note_bits.append(str(note))
        if counter is not None:
            note_bits.append(f"mux_counter={counter}")
        self._log_tun_icmp_packet(
            stage=stage,
            packet=packet,
            chan=chan,
            peer_id=peer_id,
            mtype=mtype,
            note="; ".join(note_bits),
        )

    def _log_tun_probe_trace(
        self,
        *,
        stage: str,
        packet: bytes,
        ifname: str = "",
        chan: Optional[int] = None,
        peer_id: Optional[int] = None,
        mtype: Optional["ChannelMux.MType"] = None,
        note: str = "",
    ) -> None:
        parsed = parse_internal_probe_packet(bytes(packet or b""))
        if not isinstance(parsed, dict):
            return
        family = int(parsed.get("family") or 0)
        identifier = int(parsed.get("identifier") or 0)
        sequence = int(parsed.get("sequence") or 0)
        nonce = bytes(parsed.get("nonce") or b"")
        probe_kind = int(parsed.get("probe_kind") or 0)
        direction = str(parsed.get("direction") or "").strip() or "unknown"
        owner = self._tun_probe_reply_owner_label(identifier=identifier)
        self.log.info(
            "[TUN/PROBE/TRACE] stage=%s owner=%s dir=%s kind=%s key=%s/%s/%s/%s if=%s chan=%s peer=%s mtype=%s src=%s dst=%s note=%s",
            stage,
            owner,
            direction,
            probe_kind,
            family,
            identifier,
            sequence,
            nonce.hex(),
            ifname,
            "" if chan is None else chan,
            "" if peer_id is None else peer_id,
            "" if mtype is None else int(mtype),
            str(parsed.get("source_ip") or ""),
            str(parsed.get("destination_ip") or ""),
            str(note or ""),
        )

    def _log_tun_icmp_local_decision(
        self,
        *,
        stage: str,
        dev: "ChannelMux.TunDevice",
        packet: bytes,
        chan: Optional[int],
        note: str,
    ) -> None:
        self._log_tun_icmp_packet(
            stage=stage,
            packet=packet,
            ifname=dev.ifname,
            chan=chan,
            peer_id=self._chan_owner_peer_id.get(int(chan)) if chan is not None else None,
            note=note,
        )

    def _record_tun_probe_boundary(self, key: str) -> None:
        if key in self._tun_probe_boundary_counts:
            self._tun_probe_boundary_counts[key] = int(self._tun_probe_boundary_counts.get(key, 0) or 0) + 1

    def _log_overlay_accepting_state(
        self,
        *,
        reason: str,
        connected_arg: Optional[bool] = None,
        epoch: Optional[int] = None,
        was_overlay_connected: Optional[bool] = None,
        new_overlay_connected: Optional[bool] = None,
        was_accepting_enabled: Optional[bool] = None,
        new_accepting_enabled: Optional[bool] = None,
    ) -> None:
        self.log.info(
            "[MUX/STATE] reason=%s connected_arg=%s epoch=%s was_overlay_connected=%s new_overlay_connected=%s was_accepting_enabled=%s new_accepting_enabled=%s session_connected=%s session_app_ready=%s transport=%s",
            reason,
            "" if connected_arg is None else int(bool(connected_arg)),
            "" if epoch is None else int(epoch),
            "" if was_overlay_connected is None else int(bool(was_overlay_connected)),
            "" if new_overlay_connected is None else int(bool(new_overlay_connected)),
            "" if was_accepting_enabled is None else int(bool(was_accepting_enabled)),
            "" if new_accepting_enabled is None else int(bool(new_accepting_enabled)),
            int(bool(self.session.is_connected())),
            int(bool(self._session_app_ready())),
            str(self._overlay_transport or ""),
        )

    @staticmethod
    def _should_log_tun_flow_sample(counter: int) -> bool:
        return counter <= 16 or counter % 100 == 0

    @staticmethod
    def _macos_route_summary(host: str, *, inet6: bool = False) -> str:
        trimmed = str(host or "").strip()
        if not trimmed or not sys.platform.startswith("darwin"):
            return ""
        try:
            args = ["/sbin/route", "-n", "get"]
            if inet6:
                args.append("-inet6")
            args.append(trimmed)
            proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=2.0)
        except Exception:
            return ""
        output = str(proc.stdout or "") + str(proc.stderr or "")
        destination = ""
        mask = ""
        gateway = ""
        interface_name = ""
        for raw_line in output.splitlines():
            line = str(raw_line).strip()
            if line.startswith("destination:"):
                destination = line.split(":", 1)[1].strip()
            elif line.startswith("mask:"):
                mask = line.split(":", 1)[1].strip()
            elif line.startswith("gateway:"):
                gateway = line.split(":", 1)[1].strip()
            elif line.startswith("interface:"):
                interface_name = line.split(":", 1)[1].strip()
        if not destination and not gateway and not interface_name:
            return ""
        return f"host={trimmed} dest={destination} mask={mask} gw={gateway} if={interface_name}"

    def _macos_tun_flow_route_note(self, *, parsed: Optional[dict[str, Any]], direction: str) -> str:
        if not sys.platform.startswith("darwin") or not isinstance(parsed, dict):
            return ""
        src_ip = str(parsed.get("source_ip") or "").strip()
        dst_ip = str(parsed.get("destination_ip") or "").strip()
        ip_version = int(parsed.get("ip_version", 0) or 0)
        inet6 = ip_version == 6
        peer_host = str(self._overlay_peer_host or "").strip()
        peer_summary = ""
        if peer_host and "," not in peer_host and ";" not in peer_host:
            peer_summary = self._macos_route_summary(peer_host, inet6=":" in peer_host)
        src_summary = self._macos_route_summary(src_ip, inet6=inet6) if src_ip else ""
        dst_summary = self._macos_route_summary(dst_ip, inet6=inet6) if dst_ip else ""
        parts = [part for part in [peer_summary, src_summary, dst_summary] if part]
        if not parts:
            return ""
        return f"{direction}_routes=" + " | ".join(parts)

    def _log_tun_flow_sample(
        self,
        *,
        direction: str,
        packet: bytes,
        ifname: str,
        chan: Optional[int],
        peer_id: Optional[int] = None,
        note: str = "",
    ) -> None:
        if not self._tun_flow_debug_enabled():
            return
        if direction == "local_to_peer":
            self._tun_flow_local_samples += 1
            sample = self._tun_flow_local_samples
        elif direction == "peer_to_local":
            self._tun_flow_remote_samples += 1
            sample = self._tun_flow_remote_samples
        elif direction == "peer_to_local_written":
            self._tun_flow_write_ok_samples += 1
            sample = self._tun_flow_write_ok_samples
        else:
            self._tun_flow_drop_samples += 1
            sample = self._tun_flow_drop_samples
        if not self._should_log_tun_flow_sample(sample):
            return
        payload = bytes(packet or b"")
        ip_version = (payload[0] >> 4) if payload else -1
        src_ip = ""
        dst_ip = ""
        parse_error = ""
        parsed, parse_error = self._parse_tun_packet_endpoints(payload)
        if isinstance(parsed, dict):
            ip_version = int(parsed.get("ip_version", ip_version) or ip_version)
            src_ip = str(parsed.get("source_ip") or "")
            dst_ip = str(parsed.get("destination_ip") or "")
        route_note = self._macos_tun_flow_route_note(parsed=parsed, direction=direction)
        note_text = note if not route_note else (f"{note}; {route_note}" if note else route_note)
        self.log.info(
            "[TUN/FLOW] dir=%s sample=%s if=%s chan=%s peer=%s len=%s ipver=%s src=%s dst=%s note=%s parse_error=%s",
            direction,
            sample,
            ifname,
            "" if chan is None else chan,
            "" if peer_id is None else peer_id,
            len(payload),
            ip_version,
            src_ip,
            dst_ip,
            note_text,
            parse_error,
        )

    def _log_tun_mux_handoff_sample(
        self,
        *,
        direction: str,
        chan: int,
        peer_id: Optional[int],
        mtype: "ChannelMux.MType",
        payload: bytes,
        counter: Optional[int] = None,
        note: str = "",
    ) -> None:
        if not self._tun_flow_debug_enabled():
            return
        if direction == "tx_securelink":
            self._tun_mux_tx_samples += 1
            sample = self._tun_mux_tx_samples
        else:
            self._tun_mux_rx_samples += 1
            sample = self._tun_mux_rx_samples
        if not self._should_log_tun_flow_sample(sample):
            return
        parsed, parse_error = self._parse_tun_packet_endpoints(payload)
        ip_version = (payload[0] >> 4) if payload else -1
        src_ip = ""
        dst_ip = ""
        if isinstance(parsed, dict):
            ip_version = int(parsed.get("ip_version", ip_version) or ip_version)
            src_ip = str(parsed.get("source_ip") or "")
            dst_ip = str(parsed.get("destination_ip") or "")
        route_note = self._macos_tun_flow_route_note(parsed=parsed, direction=direction)
        note_bits = []
        if note:
            note_bits.append(note)
        if route_note:
            note_bits.append(route_note)
        if counter is not None:
            note_bits.append(f"mux_counter={counter}")
        note_text = "; ".join(note_bits)
        crc32 = f"{(zlib.crc32(bytes(payload or b'')) & 0xFFFFFFFF):08x}"
        self.log.info(
            "[TUN/E2E] dir=%s sample=%s chan=%s peer=%s mtype=%s len=%s ipver=%s src=%s dst=%s crc32=%s note=%s parse_error=%s",
            direction,
            sample,
            chan,
            "" if peer_id is None else peer_id,
            int(mtype),
            len(payload or b""),
            ip_version,
            src_ip,
            dst_ip,
            crc32,
            note_text,
            parse_error,
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
            extra4, extra6 = auto_overlay_peer_excluded_routes(vars(self.args))
            return config.local_hook_env(
                extra_excluded_routes=extra4,
                extra_excluded_routes6=extra6,
            )
        if origin == "peer":
            return config.remote_hook_env()
        return {}

    def _service_spec_with_tun_mtu_defaults(
        self,
        spec: "ChannelMux.ServiceSpec",
    ) -> "ChannelMux.ServiceSpec":
        tun_config = self._tun_routing_config()
        default_mtu = max(68, int(getattr(tun_config, "mtu", self.TUN_DEFAULT_MTU) or self.TUN_DEFAULT_MTU))
        l_port = int(spec.l_port)
        r_port = int(spec.r_port)
        changed = False
        if str(spec.l_proto) == "tun" and l_port <= 0:
            l_port = default_mtu
            changed = True
        if str(spec.r_proto) == "tun" and r_port <= 0:
            r_port = default_mtu
            changed = True
        if not changed:
            return spec
        return ChannelMux.ServiceSpec(
            svc_id=int(spec.svc_id),
            l_proto=str(spec.l_proto),
            l_bind=str(spec.l_bind),
            l_port=l_port,
            r_proto=str(spec.r_proto),
            r_host=str(spec.r_host),
            r_port=r_port,
            name=spec.name,
            lifecycle_hooks=spec.lifecycle_hooks if isinstance(spec.lifecycle_hooks, dict) else None,
            options=spec.options if isinstance(spec.options, dict) else None,
        )

    def _tun_routing_config(self) -> TunRoutingSettings:
        if self.args is None:
            return self._tun_routing_settings
        with contextlib.suppress(Exception):
            self._tun_routing_settings = TunRoutingSettings.from_mapping(
                vars(self.args),
                base=self._tun_routing_settings,
            )
        return self._tun_routing_settings

    def _clear_tun_runtime_health(self, svc_key: Optional["ChannelMux.ServiceKey"]) -> None:
        if isinstance(svc_key, tuple):
            self._tun_runtime_health_by_service.pop(svc_key, None)

    def _set_tun_runtime_health_warning(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        *,
        code: str,
        severity: str,
        summary: str,
        detail: str,
        **extra: Any,
    ) -> None:
        if not isinstance(svc_key, tuple):
            return
        warning = {
            "code": str(code or "").strip(),
            "severity": str(severity or "warning").strip(),
            "summary": str(summary or "").strip(),
            "detail": str(detail or "").strip(),
            "observed_at_unix_ts": float(time.time()),
        }
        for key, value in extra.items():
            warning[str(key)] = value
        self._tun_runtime_health_by_service[svc_key] = warning

    def _clear_tun_runtime_health_codes(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        *codes: str,
    ) -> None:
        if not isinstance(svc_key, tuple):
            return
        current = dict(self._tun_runtime_health_by_service.get(svc_key) or {})
        if not current:
            return
        if str(current.get("code") or "") not in {str(code or "") for code in codes if str(code or "")}:
            return
        self._tun_runtime_health_by_service.pop(svc_key, None)

    def _cancel_tun_runtime_health_task(self, dev: Optional["ChannelMux.TunDevice"]) -> None:
        if dev is None:
            return
        task = self._tun_runtime_health_tasks.pop(id(dev), None)
        if task is not None:
            task.cancel()

    def _expected_tun_runtime_addresses(
        self,
        spec: Optional["ChannelMux.ServiceSpec"],
    ) -> tuple[str, str]:
        if spec is None or str(getattr(spec, "l_proto", "") or "") != "tun":
            return "", ""
        config = self._tun_routing_config()
        return (
            str(getattr(config, "tunnel_address", "") or "").strip(),
            str(getattr(config, "tunnel_address6", "") or "").strip(),
        )

    @staticmethod
    def _linux_tun_interface_addresses(ifname: str) -> dict[str, list[str] | str]:
        out: dict[str, list[str] | str] = {
            "ipv4": [],
            "ipv6": [],
            "stdout4": "",
            "stdout6": "",
        }
        if sys.platform == "darwin" and str(ifname or "").strip():
            result = subprocess.run(
                ["ifconfig", str(ifname)],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0,
            )
            stdout = str(getattr(result, "stdout", "") or "")
            out["stdout4"] = stdout
            out["stdout6"] = stdout
            ipv4: list[str] = []
            ipv6: list[str] = []
            for line in stdout.splitlines():
                row = str(line or "").strip()
                if row.startswith("inet "):
                    parts = row.split()
                    if len(parts) >= 2:
                        ipv4.append(str(parts[1]))
                elif row.startswith("inet6 "):
                    parts = row.split()
                    if len(parts) >= 2:
                        ipv6.append(str(parts[1]).split("%", 1)[0])
            out["ipv4"] = ipv4
            out["ipv6"] = ipv6
            return out
        if not sys.platform.startswith("linux") or not str(ifname or "").strip():
            return out
        for family_flag, key, field in (
            ("-4", "ipv4", "stdout4"),
            ("-6", "ipv6", "stdout6"),
        ):
            result = subprocess.run(
                ["ip", family_flag, "addr", "show", "dev", str(ifname)],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0,
            )
            stdout = str(getattr(result, "stdout", "") or "")
            out[field] = stdout
            values: list[str] = []
            marker = "inet6 " if key == "ipv6" else "inet "
            for line in stdout.splitlines():
                row = str(line or "").strip()
                if not row.startswith(marker):
                    continue
                token = row[len(marker) :].split(None, 1)[0].strip()
                if token:
                    values.append(token)
            out[key] = values
        return out

    def _schedule_tun_runtime_health_check(
        self,
        dev: Optional["ChannelMux.TunDevice"],
        *,
        reason: str,
        delay_s: float = 0.75,
    ) -> None:
        if dev is None or not self.loop.is_running():
            return
        svc_key = getattr(dev, "service_key", None)
        spec = self._svc_spec_or_none(int(svc_key[2]), svc_key=svc_key) if isinstance(svc_key, tuple) and len(svc_key) >= 3 else None
        expected4, expected6 = self._expected_tun_runtime_addresses(spec)
        if not expected4 and not expected6:
            self._clear_tun_runtime_health(svc_key)
            return
        self._cancel_tun_runtime_health_task(dev)
        task = self.loop.create_task(self._run_tun_runtime_health_check(dev, reason=reason, delay_s=delay_s))
        dev_id = id(dev)
        self._tun_runtime_health_tasks[dev_id] = task

        def _clear_done(done_task: asyncio.Task, *, _dev_id: int = dev_id) -> None:
            current = self._tun_runtime_health_tasks.get(_dev_id)
            if current is done_task:
                self._tun_runtime_health_tasks.pop(_dev_id, None)

        task.add_done_callback(_clear_done)

    async def _run_tun_runtime_health_check(
        self,
        dev: "ChannelMux.TunDevice",
        *,
        reason: str,
        delay_s: float,
    ) -> None:
        if delay_s > 0:
            await asyncio.sleep(delay_s)
        svc_key = getattr(dev, "service_key", None)
        spec = self._svc_spec_or_none(int(svc_key[2]), svc_key=svc_key) if isinstance(svc_key, tuple) and len(svc_key) >= 3 else None
        expected4, expected6 = self._expected_tun_runtime_addresses(spec)
        if not expected4 and not expected6:
            self._clear_tun_runtime_health(svc_key)
            return
        try:
            observed = await asyncio.to_thread(self._linux_tun_interface_addresses, str(getattr(dev, "ifname", "") or ""))
        except Exception as exc:
            self.log.warning(
                "[TUN/ADDR] runtime health check failed if=%s reason=%s err=%r",
                str(getattr(dev, "ifname", "") or ""),
                str(reason or ""),
                exc,
            )
            return
        observed4 = [str(v or "").strip() for v in list(observed.get("ipv4") or []) if str(v or "").strip()]
        observed6 = [str(v or "").strip() for v in list(observed.get("ipv6") or []) if str(v or "").strip()]
        missing4 = bool(expected4) and not any(str(addr).split("/", 1)[0] == expected4 for addr in observed4)
        missing6 = bool(expected6) and not any(str(addr).split("/", 1)[0] == expected6 for addr in observed6)
        if not missing4 and not missing6:
            previous = dict(self._tun_runtime_health_by_service.get(svc_key) or {}) if isinstance(svc_key, tuple) else {}
            self._clear_tun_runtime_health(svc_key)
            if previous:
                self.log.info(
                    "[TUN/ADDR] tunnel address verification recovered if=%s reason=%s ipv4=%s ipv6=%s",
                    str(getattr(dev, "ifname", "") or ""),
                    str(reason or ""),
                    expected4 or "-",
                    expected6 or "-",
                )
            return
        missing_labels: list[str] = []
        if missing4:
            missing_labels.append(f"IPv4 {expected4}")
        if missing6:
            missing_labels.append(f"IPv6 {expected6}")
        warning = {
            "code": "tun_addresses_missing",
            "severity": "critical",
            "summary": (
                f"TUN interface {str(getattr(dev, 'ifname', '') or '')} is up but expected tunnel "
                f"addressing is missing."
            ),
            "detail": f"Missing expected addresses after {reason}: {', '.join(missing_labels)}.",
            "ifname": str(getattr(dev, "ifname", "") or ""),
            "reason": str(reason or ""),
            "expected_ipv4": expected4,
            "expected_ipv6": expected6,
            "observed_ipv4": observed4,
            "observed_ipv6": observed6,
            "observed_at_unix_ts": float(time.time()),
        }
        if isinstance(svc_key, tuple):
            self._tun_runtime_health_by_service[svc_key] = warning
        self.log.critical(
            "[TUN/ADDR] expected tunnel addresses missing if=%s reason=%s missing_ipv4=%s missing_ipv6=%s observed_ipv4=%r observed_ipv6=%r ip4=%r ip6=%r",
            str(getattr(dev, "ifname", "") or ""),
            str(reason or ""),
            expected4 if missing4 else "",
            expected6 if missing6 else "",
            observed4,
            observed6,
            str(observed.get("stdout4", "") or "")[-1200:],
            str(observed.get("stdout6", "") or "")[-1200:],
        )

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
        spec = self._service_spec_with_tun_mtu_defaults(spec)
        if remote_install:
            env_defaults = config.remote_hook_env()
        else:
            extra4, extra6 = auto_overlay_peer_excluded_routes(vars(self.args))
            env_defaults = config.local_hook_env(
                extra_excluded_routes=extra4,
                extra_excluded_routes6=extra6,
            )
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
            hook_diag = ""
            if str(spec.l_proto) == "tun":
                hook_diag = (
                    f" ifname={context.get('ifname')!r}"
                    f" overlay_peer={env.get('OB_OVERLAY_PEER_HOST', '')!r}:{env.get('OB_OVERLAY_PEER_PORT', '')!r}"
                    f" tun_addr={env.get('TUN_ADDR', '')!r}"
                    f" tun_gw={env.get('TUN_GW', '')!r}"
                    f" tun_addr6={env.get('TUN_ADDR6', '')!r}"
                    f" tun_gw6={env.get('TUN_GW6', '')!r}"
                    f" excluded4={env.get('EXCLUDED_ROUTES', '')!r}"
                    f" excluded6={env.get('EXCLUDED_ROUTES6', '')!r}"
                )
            self.log.info(
                "[HOOK] start role=%s event=%s svc=%s argv=%r timeout_ms=%s%s",
                role,
                event,
                spec.svc_id,
                argv,
                timeout_ms,
                hook_diag,
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
            stdout_tail = (stdout_b or b"").decode("utf-8", "replace")[-1200:]
            stderr_tail = (stderr_b or b"").decode("utf-8", "replace")[-1200:]
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
            if str(spec.l_proto) == "tun" and role == "listener" and event == "on_created" and isinstance(svc_key, tuple):
                dev = self._svc_tun_devices.get(svc_key)
                if dev is not None:
                    self._schedule_tun_runtime_health_check(dev, reason="listener_on_created", delay_s=0.25)
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
        getter = getattr(session, "get_stream_record_limit", None)
        if not callable(getter):
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

    def _forget_tun_open_key(self, chan: int, *, peer_id: Optional[int] = None) -> None:
        channel_key = (int(peer_id or 0), int(chan))
        key = self._tun_open_key_by_chan.pop(channel_key, None)
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
            self._rx_tun_close(chan, peer_id=peer_key)
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
            self._open_configured_tun_services_if_ready()
            self._send_remote_services_catalog_if_any()
        self._sweeper_task = self.loop.create_task(self._udp_idle_sweeper())
        self._ensure_task = self.loop.create_task(self._ensure_servers_task())
        self._transport_delay_rotation_task = self.loop.create_task(self._transport_delay_rotation_watchdog())

    async def stop(self, reason: str = "") -> None:
        self.log.info("[MUX] stopping reason=%s", str(reason or "unspecified"))
        for t in (self._ensure_task, self._sweeper_task, self._transport_delay_rotation_task):
            if t:
                try: t.cancel()
                except Exception: pass
        self._ensure_task = self._sweeper_task = self._transport_delay_rotation_task = None
        await self._await_tun_helper_open_tasks()
        await self._stop_all_services()
        await self._close_all_channels()
        await self._await_tun_helper_remove_tasks()
        await self._drop_peer_installed_services(peer_id=None)

    # ---------- overlay state ----------
    def _session_connection_layers_snapshot(self) -> list[dict[str, Any]]:
        getter = getattr(self.session, "get_connection_layers_snapshot", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                layers = list(getter() or [])
                return [dict(layer) for layer in layers if isinstance(layer, dict)]
        return [{
            "layer": "session",
            "transport": str(self._overlay_transport or ""),
            "state": "connected" if bool(self.session.is_connected()) else "disconnected",
            "epoch": 0,
            "connected": bool(self.session.is_connected()),
            "app_ready": bool(self.session.is_connected()),
        }]

    def _session_app_ready(self) -> bool:
        layers = self._session_connection_layers_snapshot()
        if layers:
            return bool(layers[-1].get("app_ready"))
        return bool(self.session.is_connected())

    def _session_overlay_inflow_allowed(self) -> bool:
        # ChannelMux only consumes the binary lifecycle state from its immediate
        # lower wrapper; wrapper-specific security details stay below this layer.
        return bool(self.session.is_connected())

    async def on_overlay_state(self, connected: bool, *, epoch: Optional[int] = None):
        if epoch is not None:
            self._observe_connection_epoch(epoch)
        was_connected = self._overlay_connected
        was_accepting = self._accepting_enabled
        effective_connected = bool(connected)
        self._overlay_connected = effective_connected
        self.log.info("[MUX] overlay -> %s", "CONNECTED" if effective_connected else "DISCONNECTED")
        if not effective_connected:
            self._schedule_connection_rotation()
            self._accepting_enabled = False
            self._log_overlay_accepting_state(
                reason="on_overlay_state_disconnected",
                connected_arg=connected,
                was_overlay_connected=was_connected,
                new_overlay_connected=self._overlay_connected,
                was_accepting_enabled=was_accepting,
                new_accepting_enabled=self._accepting_enabled,
            )
            await self._stop_all_services()
            await self._close_all_channels()
            return
        self._cancel_connection_rotation()
        # Re-enable and (re)start
        if not was_connected:
            self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        self._accepting_enabled = True
        self._log_overlay_accepting_state(
            reason="on_overlay_state_connected",
            connected_arg=connected,
            was_overlay_connected=was_connected,
            new_overlay_connected=self._overlay_connected,
            was_accepting_enabled=was_accepting,
            new_accepting_enabled=self._accepting_enabled,
        )
        await self._start_all_services()
        self._open_configured_tun_services_if_ready()
        self._send_remote_services_catalog_if_any()

    def _cancel_connection_rotation(self) -> None:
        task = self._connection_rotation_task
        self._connection_rotation_task = None
        if task is not None and not task.done():
            task.cancel()

    def _poll_transport_delay_rotation(self, *, now_mono: Optional[float] = None) -> Optional[ConnectionRotationResult]:
        """Rotate once when a connected overlay sustains excessive delay."""
        now = time.monotonic() if now_mono is None else float(now_mono)
        if not self._overlay_connected:
            self._transport_delay_high_since_mono = None
            return None
        snapshot = self._session_overlay_backpressure_snapshot(now_ns=time.monotonic_ns())
        delay_ms = float(snapshot.get("transmit_delay_est_ms", 0.0) or 0.0)
        if delay_ms < self._transport_delay_threshold_ms:
            self._transport_delay_high_since_mono = None
            return None
        if self._transport_delay_high_since_mono is None:
            self._transport_delay_high_since_mono = now
            return None
        if (now - self._transport_delay_high_since_mono) < self._transport_delay_rotation_delay_s:
            return None
        result = self.request_connection_rotation("channelmux_transport_delay")
        accepted = bool(result.get("accepted")) if isinstance(result, dict) else bool(getattr(result, "accepted", False))
        if accepted:
            self.log.warning(
                "[MUX] requested connection rotation after %.1fs transport delay >= %.0fms (current=%.3fms)",
                now - self._transport_delay_high_since_mono,
                self._transport_delay_threshold_ms,
                delay_ms,
            )
        self._transport_delay_high_since_mono = None
        return result

    async def _transport_delay_rotation_watchdog(self) -> None:
        try:
            while True:
                self._poll_transport_delay_rotation()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            return

    def _schedule_connection_rotation(self) -> None:
        if self._connection_rotation_wait_epoch is not None:
            return
        if self._connection_rotation_task is not None and not self._connection_rotation_task.done():
            return

        requested_epoch = self._connection_lifecycle_epoch
        retry_after_rejection = False

        async def _rotate_after_disconnect() -> None:
            nonlocal retry_after_rejection
            try:
                await asyncio.sleep(self.CONNECTION_ROTATION_DELAY_S)
                if self._overlay_connected:
                    return
                if self._connection_rotation_wait_epoch is not None:
                    return
                result = self.request_connection_rotation("channelmux_disconnected")
                self.log.warning("[MUX] requested connection rotation after %.1fs epoch=%s result=%r", self.CONNECTION_ROTATION_DELAY_S, requested_epoch, result)
                accepted = bool(result.get("accepted")) if isinstance(result, dict) else bool(getattr(result, "accepted", False))
                retry_after_rejection = not accepted and not self._overlay_connected
            except asyncio.CancelledError:
                return
            finally:
                if self._connection_rotation_task is asyncio.current_task():
                    self._connection_rotation_task = None
                if retry_after_rejection and self._connection_rotation_wait_epoch is None and not self._overlay_connected:
                    self._schedule_connection_rotation()

        self._connection_rotation_task = self.loop.create_task(_rotate_after_disconnect())

    def request_connection_rotation(self, reason: str = ""):
        """Request one lower-layer rotation for the current lifecycle epoch."""
        if self._connection_rotation_wait_epoch is not None:
            return ConnectionRotationResult(
                accepted=False,
                reason="rotation_waiting_for_new_epoch",
                candidate_cycle=None,
            )
        self._cancel_connection_rotation()
        request = getattr(self.session, "request_connection_rotation", None)
        if not callable(request):
            return ConnectionRotationResult(accepted=False, reason="inner_rotation_unavailable")

        # Reserve the epoch while calling the lower layer so a synchronous
        # lifecycle edge cannot race past us.  A rejected request must not
        # consume that epoch: otherwise a temporarily unavailable transport
        # leaves ChannelMux permanently waiting for an epoch it never started.
        requested_epoch = self._connection_lifecycle_epoch
        self._connection_rotation_wait_epoch = requested_epoch
        try:
            result = request(str(reason or "channelmux_requested"))
        except Exception as exc:
            self.log.warning("[MUX] lower-layer rotation request failed reason=%s error=%r", reason, exc)
            result = ConnectionRotationResult(accepted=False, reason="inner_rotation_error")
        accepted = bool(result.get("accepted")) if isinstance(result, dict) else bool(getattr(result, "accepted", False))
        if not accepted or self._connection_lifecycle_epoch > requested_epoch:
            self._connection_rotation_wait_epoch = None
        if callable(self._on_connection_rotation_result):
            self._on_connection_rotation_result(result)
        return result

    def set_on_connection_rotation_result(self, callback) -> None:
        self._on_connection_rotation_result = callback

    def _observe_connection_epoch(self, epoch: int) -> None:
        observed_epoch = max(0, int(epoch))
        if observed_epoch <= self._connection_lifecycle_epoch:
            return
        self._connection_lifecycle_epoch = observed_epoch
        if self._connection_rotation_wait_epoch is not None and observed_epoch > self._connection_rotation_wait_epoch:
            self._connection_rotation_wait_epoch = None

    async def on_connection_lifecycle(self, event: ConnectionLifecycleEvent) -> None:
        """Apply the outer wrapper lifecycle event to the mux connection gate."""
        self._observe_connection_epoch(event.epoch)
        await self.on_overlay_state(event.connected, epoch=event.epoch)
        if event.connected:
            # Only a full outer-stack recovery clears the transport's failed
            # candidate-cycle budget. Raw transport liveness is insufficient
            # while SecureLink or Compression still reports disconnected.
            reset_cycles = getattr(self.session, "reset_connection_rotation_cycles", None)
            if callable(reset_cycles):
                reset_cycles()
        self._tun_admission_epoch = int(event.epoch) if event.connected and self._accepting_enabled else None
        if self._tun_admission_epoch is None:
            self._pause_tun_admission()
        else:
            for dev in list(self._tun_helper_devices.values()) + list(self._svc_tun_devices.values()):
                self._register_tun_reader(dev)

    def _tun_admission_allowed(self) -> bool:
        return bool(self._overlay_connected and self._accepting_enabled and self._tun_admission_epoch == self._connection_lifecycle_epoch)

    def _pause_tun_admission(self) -> None:
        for dev in list(self._tun_helper_devices.values()) + list(self._svc_tun_devices.values()):
            task = self._tun_helper_reader_tasks.pop(id(dev), None)
            if task is not None:
                task.cancel()
            with contextlib.suppress(Exception):
                self.loop.remove_reader(dev.fd)
            dev.reader_registered = False

    async def on_transport_epoch_change(self, epoch: int) -> None:
        self._observe_connection_epoch(epoch)
        self.log.info("[MUX] transport epoch changed -> %s (hard resync)", epoch)
        was_connected = self._overlay_connected
        was_accepting = self._accepting_enabled
        self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        await self._close_all_channels()
        self._overlay_connected = bool(self._session_overlay_inflow_allowed())
        self._accepting_enabled = self._overlay_connected
        self._log_overlay_accepting_state(
            reason="on_transport_epoch_change",
            epoch=epoch,
            was_overlay_connected=was_connected,
            new_overlay_connected=self._overlay_connected,
            was_accepting_enabled=was_accepting,
            new_accepting_enabled=self._accepting_enabled,
        )
        if self._overlay_connected and self._accepting_enabled:
            await self._start_all_services()
            self._open_configured_tun_services_if_ready()
        self._send_remote_services_catalog_if_any()


    def on_overlay_peer_set(self, host: str, port: int) -> None:
        self._overlay_peer_host = str(host or self._overlay_peer_host or "")
        try:
            self._overlay_peer_port = int(port or self._overlay_peer_port or 0)
        except Exception:
            self._overlay_peer_port = int(self._overlay_peer_port or 0)

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
        self._tun_by_peer_chan.clear()
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

    def _channel_mux_egress_config(self) -> dict[str, Any]:
        raw = getattr(self.args, "channel_mux_egress", None) if self.args is not None else None
        return dict(raw) if isinstance(raw, Mapping) else {}

    def _channel_mux_egress_mode(self) -> str:
        return str(self._channel_mux_egress_config().get("mode") or "system").strip().lower()

    def _channel_mux_egress_proxy_auth(self) -> str:
        egress = self._channel_mux_egress_config()
        default = "negotiate" if self._channel_mux_egress_mode() == "system" and sys.platform == "win32" else "none"
        return str(egress.get("proxy_auth") or egress.get("auth") or default).strip().lower()

    def _channel_mux_egress_connect_timeout(self) -> float:
        value = self._channel_mux_egress_config().get("connect_timeout_seconds", 5.0)
        try:
            return max(0.1, float(value))
        except Exception:
            return 5.0

    def _resolve_channel_mux_egress_proxy(self, host: str, port: int) -> Optional[tuple[str, int]]:
        mode = self._channel_mux_egress_mode()
        if mode in {"", "direct", "off", "none"}:
            return None
        egress = self._channel_mux_egress_config()
        endpoint = resolve_proxy_endpoint(
            mode=mode,
            target_host=str(host),
            target_port=int(port),
            secure=False,
            manual_host=str(egress.get("proxy_host") or egress.get("host") or ""),
            manual_port=int(egress.get("proxy_port") or egress.get("port") or 0),
            feature_enabled=True,
            log=self.log,
            log_prefix="[MUX-EGRESS]",
        )
        if endpoint is None:
            self.log.debug("[MUX-EGRESS] direct TCP target=%s:%d mode=%s", host, int(port), mode)
            return None
        self.log.debug(
            "[MUX-EGRESS] upstream proxy selected TCP target=%s:%d via=%s:%d mode=%s",
            host,
            int(port),
            endpoint[0],
            int(endpoint[1]),
            mode,
        )
        return endpoint

    async def _open_tcp_target_connection(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        upstream_proxy = self._resolve_channel_mux_egress_proxy(host, int(port))
        if upstream_proxy is None:
            return await asyncio.open_connection(host=host, port=int(port))

        sock = await asyncio.to_thread(
            open_http_connect_tunnel,
            target_host=str(host),
            target_port=int(port),
            proxy=upstream_proxy,
            auth_mode=self._channel_mux_egress_proxy_auth(),
            timeout=self._channel_mux_egress_connect_timeout(),
            log=self.log,
            log_prefix="[MUX-EGRESS]",
            user_agent="ObstacleBridge-channelmux/1.0",
        )
        try:
            return await asyncio.open_connection(sock=sock)
        except Exception:
            sock.close()
            raise

    def _note_udp_egress_proxy_limit(self, host: str, port: int) -> None:
        mode = self._channel_mux_egress_mode()
        if mode in {"", "direct", "off", "none"} or self._channel_mux_udp_proxy_warned:
            return
        egress = self._channel_mux_egress_config()
        try:
            endpoint = resolve_proxy_endpoint(
                mode=mode,
                target_host=str(host),
                target_port=int(port),
                secure=False,
                manual_host=str(egress.get("proxy_host") or egress.get("host") or ""),
                manual_port=int(egress.get("proxy_port") or egress.get("port") or 0),
                feature_enabled=True,
                log=self.log,
                log_prefix="[MUX-EGRESS]",
            )
        except Exception as exc:
            self.log.debug("[MUX-EGRESS] UDP proxy-limit note skipped for %s:%d: %r", host, int(port), exc)
            return
        if endpoint is None:
            return
        self._channel_mux_udp_proxy_warned = True
        self.log.info(
            "[MUX-EGRESS] UDP target=%s:%d uses direct UDP; configured egress mode=%s resolves upstream proxy=%s:%d, but HTTP CONNECT-style proxies are not UDP relays",
            host,
            int(port),
            mode,
            endpoint[0],
            int(endpoint[1]),
        )

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
        now_ns = time.monotonic_ns()
        scope_key = ("udp", svc_key, int(chan))
        if not self._local_ingress_send_allowed(len(data), now_ns=now_ns, scope_key=scope_key):
            snapshot = self._session_overlay_backpressure_snapshot(now_ns=now_ns)
            self.log.debug(
                "[UDP/SRV] throttle local datagram chan=%s queued=%s inflight=%s/%s prev_window_bytes=%s packet_bytes=%s",
                chan,
                int(snapshot.get("waiting_count", 0) or 0),
                int(snapshot.get("inflight", 0) or 0),
                int(snapshot.get("max_inflight", 0) or 0),
                int(snapshot.get("prev_window_bytes", 0) or 0),
                len(data),
            )
            return
        self._record_local_udp_forward(len(data), now_ns=now_ns, scope_key=scope_key)
        self._log_udp_diag(
            "server",
            chan,
            "local->overlay",
            data,
            src=src,
            dst=dst,
            remote_target=(spec.r_host, int(spec.r_port)),
            sample_count=ctr.msgs_in,
        )
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



    @staticmethod
    def _direct_tun_inflow_scope_key(
        svc_key: Optional["ChannelMux.ServiceKey"],
        chan_id: Optional[int],
    ) -> tuple[Any, ...]:
        return ("direct", svc_key)

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





    @staticmethod



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
            total_len = (int(payload[2]) << 8) | int(payload[3])
            if total_len < ihl or total_len > len(payload):
                return None, "ipv4_length_invalid"
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
            payload_len = (int(payload[4]) << 8) | int(payload[5])
            total_len = 40 + payload_len
            if total_len < 40 or total_len > len(payload):
                return None, "ipv6_length_invalid"
            return (
                {
                    "ip_version": 6,
                    "source_ip": str(ipaddress.IPv6Address(payload[8:24])),
                    "destination_ip": str(ipaddress.IPv6Address(payload[24:40])),
                },
                None,
            )
        return None, "unsupported_ip_version"



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
        if int(proto) == int(ChannelMux.Proto.TUN):
            self._log_tun_open_diagnostics(
                direction="tx",
                chan=int(chan_id),
                spec=spec,
                peer_id=self._chan_owner_peer_id.get(int(chan_id)),
                note="sending_open_v4",
            )
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

    def _open_configured_tun_services_if_ready(self) -> None:
        """Bind and announce each configured TUN listener for this mux epoch.

        TCP sends its OPEN as soon as a local accepted socket gives it a
        channel.  A TUN listener is its own long-lived local endpoint, so
        waiting for its first packet creates an unnecessary asymmetry: a peer
        can receive DATA for a retained channel without ever seeing the OPEN
        that binds that channel to its shared-TUN owner.  Announce it once the
        authenticated overlay is ready, and let normal channel teardown clear
        the preferred channel before the next epoch.
        """
        if not (
            self._overlay_connected
            and self._accepting_enabled
            and self.session.is_connected()
            and self._session_app_ready()
        ):
            return
        for svc_key, spec in list(self._effective_services_by_id().items()):
            if str(spec.l_proto) != "tun":
                continue
            dev = self._svc_tun_devices.get(svc_key)
            if dev is None or dev.chan_id is not None:
                continue
            chan = self._alloc_tun_id()
            self._chan_owner_peer_id[chan] = int(svc_key[1]) if str(svc_key[0]) == "peer" else 0
            self._bind_tun_channel(chan, dev)
            self._schedule_service_hook(spec, svc_key, "listener", "on_channel_connected", channel_id=chan)
            self._send_open_for_service(chan, ChannelMux.Proto.TUN, spec)
            self.log.info(
                "[TUN/OPEN] proactive local listener bind chan=%s service_key=%s after overlay readiness",
                chan,
                svc_key,
            )

    async def _stop_listener_for_service_id(
        self,
        svc_key: "ChannelMux.ServiceKey",
        proto_name: str,
        *,
        spec: Optional["ChannelMux.ServiceSpec"] = None,
    ) -> None:
        if spec is None:
            spec = self._effective_services_by_id().get(svc_key)
        if proto_name == "udp":
            if spec is not None:
                await self._run_service_hook(spec, svc_key, "listener", "on_stopped")
            tr = self._svc_udp_servers.pop(svc_key, None)
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass
            return
        if proto_name == "tun":
            dev = self._svc_tun_devices.pop(svc_key, None)
            self._clear_tun_runtime_health(svc_key)
            if dev is not None:
                self._unbind_all_tun_channels_for_device(dev)
                close_dev = True
                registry = self._process_shared_tun_registry
                if registry is not None:
                    close_dev = bool(registry.release(self, dev))
                if close_dev:
                    if spec is not None and not self._helper_owns_tun_listener_network_lifecycle(spec, dev=dev):
                        await self._run_service_hook(spec, svc_key, "listener", "on_stopped")
                    elif spec is not None:
                        self.log.info(
                            "[TUN/HELPER] helper owns listener on_stopped host-network lifecycle if=%s service=%s:%s",
                            str(getattr(dev, "ifname", "") or ""),
                            svc_key[0],
                            spec.svc_id,
                        )
                    self._close_tun_device(dev)
                else:
                    self.log.info(
                        "[TUN/SRV] retain shared if=%s mtu=%s svc=%s:%s; skip on_stopped hook until final release",
                        str(getattr(dev, "ifname", "") or ""),
                        int(getattr(dev, "mtu", 0) or 0),
                        svc_key[0],
                        svc_key[2],
                    )
            self._drop_shared_tun_state_for_service(svc_key)
            return
        if spec is not None:
            await self._run_service_hook(spec, svc_key, "listener", "on_stopped")
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
        self._drop_shared_tun_state_for_local_peer(int(peer_id))
        try:
            self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_id))
        except Exception as e:
            self.log.debug("[MUX/CTRL] failed scheduling peer disconnect cleanup for peer_id=%s: %r", peer_id, e)

    # ---------- MUX send ----------
    def _tun_post_mux_transport_delay_exceeded(self) -> bool:
        """Whether TUN data must be dropped before entering SecureLink.

        Local TUN reads are deliberately never paused by overload control.
        Unlike TCP (which stops reading) and local UDP (which drops on read),
        TUN keeps draining its fd and drops completed mux DATA frames at this
        final ChannelMux-to-SecureLink boundary.
        """
        snapshot = self._session_overlay_backpressure_snapshot(now_ns=time.monotonic_ns())
        return float(snapshot.get("transmit_delay_est_ms", 0.0) or 0.0) >= float(
            self._transport_delay_threshold_ms
        )

    def _record_tun_post_mux_drop(
        self,
        chan_id: int,
        payload: bytes,
        *,
        peer_id: Optional[int],
    ) -> None:
        dev = self._tun_by_chan.get(int(chan_id))
        svc_key = getattr(dev, "service_key", None) if dev is not None else None
        self._record_shared_tun_drop(
            svc_key,
            reason="transport_delay_post_mux_tun",
            direction="local_to_peer",
            peer_id=peer_id,
            chan_id=chan_id,
            packet_bytes=len(payload),
        )

    def _send_mux(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType, data: bytes, *, peer_id: Optional[int] = None) -> None:
        try:
            self._record_sync_diag("ChannelMux._send_mux", phase="started")
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
                    self._send_tun_mux_fragments(chan_id, payload, peer_id=peer_id)
                    return
            if data is None:
                data = b""
            effective_peer_id = peer_id if peer_id is not None else self._chan_owner_peer_id.get(int(chan_id))
            if proto == ChannelMux.Proto.TUN and mtype in (ChannelMux.MType.DATA, ChannelMux.MType.DATA_FRAG):
                self._log_tun_packet_trace(
                    stage="overlay_tx_mux_payload",
                    packet=bytes(data),
                    chan=chan_id,
                    peer_id=effective_peer_id,
                    mtype=mtype,
                )
                self._log_tun_mux_handoff_sample(
                    direction="tx_securelink",
                    chan=chan_id,
                    peer_id=effective_peer_id,
                    mtype=mtype,
                    payload=bytes(data),
                    note="before_session_send_app",
                )
                self._log_tun_probe_trace(
                    stage="overlay_tx_before_send_app",
                    packet=bytes(data),
                    chan=chan_id,
                    peer_id=effective_peer_id,
                    mtype=mtype,
                    note="before_session_send_app",
                )
            counter = self._next_ctr(chan_id, proto, mtype, peer_id=peer_id)
            if proto == ChannelMux.Proto.TUN and mtype in (ChannelMux.MType.DATA, ChannelMux.MType.DATA_FRAG):
                self._log_tun_icmp_overlay_packet(
                    stage="overlay_tx_before_send_app",
                    packet=bytes(data),
                    chan=chan_id,
                    peer_id=effective_peer_id,
                    mtype=mtype,
                    counter=counter,
                    note="before_session_send_app",
                )
            self._record_sync_diag("ChannelMux._send_mux:pack_mux", phase="started")
            wire = self._pack_mux(chan_id, proto, counter, mtype, data)
            self._record_sync_diag("ChannelMux._send_mux:pack_mux", phase="finished")
            if len(wire) > self._session_max_app_payload:
                self.log.error(
                    "[MUX] drop oversized app message: %d bytes > %d",
                    len(wire),
                    self._session_max_app_payload,
                )
                return
            if (
                proto == ChannelMux.Proto.TUN
                and mtype in (ChannelMux.MType.DATA, ChannelMux.MType.DATA_FRAG)
                and self._tun_post_mux_transport_delay_exceeded()
            ):
                self._record_tun_post_mux_drop(
                    chan_id,
                    bytes(data),
                    peer_id=effective_peer_id,
                )
                self.log.debug(
                    "[TUN] drop mux data before SecureLink: transmit_delay_est_ms exceeds %.0f",
                    self._transport_delay_threshold_ms,
                )
                return
            if self._on_local_rx:
                try:
                    self._record_sync_diag("ChannelMux._send_mux:on_local_rx", phase="started")
                    self._on_local_rx(len(wire))
                    self._record_sync_diag("ChannelMux._send_mux:on_local_rx", phase="finished")
                except Exception:
                    pass
            try:
                owner_peer_id = effective_peer_id
                self._record_sync_diag("ChannelMux._send_mux:session.send_app", phase="started")
                try:
                    self.session.send_app(wire, peer_id=owner_peer_id)
                except TypeError:
                    self.session.send_app(wire)
                self._record_sync_diag("ChannelMux._send_mux:session.send_app", phase="finished")
            except Exception as e:
                self._record_sync_diag("ChannelMux._send_mux:session.send_app", phase="failed", error=type(e).__name__)
                self.log.debug("[MUX] send_app error: %r", e)
            try:
                self._record_sync_diag("ChannelMux._send_mux:log_app_msg", phase="started")
                self._log_app_msg("->", wire)
                self._record_sync_diag("ChannelMux._send_mux:log_app_msg", phase="finished")
            except Exception as e:
                self._record_sync_diag("ChannelMux._send_mux:log_app_msg", phase="failed", error=type(e).__name__)
                self.log.debug("[MUX] logging error: %r", e)
        except Exception as exc:
            self._record_sync_diag("ChannelMux._send_mux", phase="failed", error=type(exc).__name__)
            raise
        finally:
            self._record_sync_diag("ChannelMux._send_mux", phase="finished")

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

    def _next_ctr(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType, *, peer_id: Optional[int] = None) -> int:
        key = (peer_id, chan_id, int(proto))
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
        if self._tun_helper_active():
            backend = self._tun_helper_backend
            client = self._tun_helper_client
            opened: dict[str, Any]
            if backend is not None:
                opener = getattr(backend, "local_open_tun", None)
                if not callable(opener):
                    raise RuntimeError("helper TUN backend does not support local_open_tun")
                opened = dict(opener({"ifname": ifname, "mtu": mtu}) or {})
            elif client is not None:
                opened = {"ifname": ifname, "mtu": mtu, "backend": "helper-client"}
            else:
                raise RuntimeError("helper TUN mode is active but no helper backend or helper client is available")
            dev = ChannelMux.TunDevice(
                fd=-1,
                ifname=str(opened.get("ifname") or ifname),
                mtu=int(opened.get("mtu") or mtu),
                service_key=svc_key,
                helper_managed=True,
            )
            self._tun_helper_open_device(dev)
            if backend is not None:
                self._tun_helper_apply_network_for_device(dev)
            return dev
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

    def _register_tun_reader(self, dev: "ChannelMux.TunDevice", *, force_owner: bool = False) -> None:
        if not self._tun_admission_allowed():
            return
        if self._tun_helper_manages_device(dev):
            current_owner = getattr(dev, "_reader_mux", None)
            if dev.reader_registered and current_owner is self and not force_owner:
                return
            if current_owner is not None and current_owner is not self:
                old_tasks = getattr(current_owner, "_tun_helper_reader_tasks", None)
                if isinstance(old_tasks, dict):
                    existing_task = old_tasks.pop(id(dev), None)
                    if existing_task is not None:
                        existing_task.cancel()
                current_owner_devices = getattr(current_owner, "_tun_helper_devices", None)
                if isinstance(current_owner_devices, dict):
                    current_owner_devices.pop(id(dev), None)
                self.log.info(
                    "[TUN/HELPER] reader ownership handoff if=%s from_mux=%s to_mux=%s force_owner=%s",
                    str(getattr(dev, "ifname", "") or ""),
                    hex(id(current_owner)),
                    hex(id(self)),
                    int(bool(force_owner)),
                )
            existing_task = self._tun_helper_reader_tasks.pop(id(dev), None)
            if existing_task is not None:
                existing_task.cancel()
            dev.reader_registered = True
            setattr(dev, "_reader_mux", self)
            self._tun_helper_devices[id(dev)] = dev
            self._tun_helper_reader_tasks[id(dev)] = self.loop.create_task(self._tun_helper_read_loop(dev))
            return
        current_owner = getattr(dev, "_reader_mux", None)
        if dev.reader_registered and current_owner is self and not force_owner:
            return
        if dev.reader_registered and current_owner is not None and current_owner is not self:
            with contextlib.suppress(Exception):
                if getattr(dev, "fd", None) is not None:
                    current_owner.loop.remove_reader(dev.fd)
            dev.reader_registered = False
        try:
            _bridge_tun_platform.register_tun_reader(self, dev)
        except (OSError, ValueError) as exc:
            # Unit tests frequently use synthetic integer fds that epoll refuses
            # to watch. Keep those tests routable without masking normal runtime
            # behavior on real TUN descriptors.
            if isinstance(exc, OSError) and getattr(exc, "errno", None) not in (1, 9, 22):
                raise
            self.log.debug(
                "[TUN/BIND] skipping reader registration for non-pollable fd=%r if=%s: %r",
                getattr(dev, "fd", None),
                str(getattr(dev, "ifname", "") or ""),
                exc,
            )
            dev.reader_registered = False
            setattr(dev, "_reader_mux", self)
            return
        setattr(dev, "_reader_mux", self)

    def _schedule_tun_reader_registration(self, dev: "ChannelMux.TunDevice") -> None:
        if dev is None:
            return
        if getattr(dev, "reader_registered", False) and getattr(dev, "_reader_mux", None) is self:
            return
        if self.loop.is_running():
            self.loop.call_soon(self._register_tun_reader, dev)
            return
        self._register_tun_reader(dev)

    def _should_defer_local_tun_reader_activation(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> bool:
        return False

    def _activate_deferred_local_tun_reader(
        self,
        spec: "ChannelMux.ServiceSpec",
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> None:
        if not isinstance(svc_key, tuple):
            return
        if svc_key not in self._tun_reader_activation_deferred:
            return
        dev = self._svc_tun_devices.get(svc_key)
        self._tun_reader_activation_deferred.discard(svc_key)
        if dev is None:
            self.log.warning(
                "[TUN] deferred reader activation skipped: missing device for service=%s:%s",
                svc_key[0],
                svc_key[2],
            )
            return
        self.log.info(
            "[TUN] activating local reader after successful hook if=%s service=%s:%s",
            dev.ifname,
            svc_key[0],
            svc_key[2],
        )
        self._schedule_tun_reader_registration(dev)

    def _close_tun_device(self, dev: "ChannelMux.TunDevice") -> None:
        self._cancel_tun_runtime_health_task(dev)
        if self._tun_helper_manages_device(dev):
            task = self._tun_helper_reader_tasks.pop(id(dev), None)
            if task is not None:
                task.cancel()
            self._tun_helper_devices.pop(id(dev), None)
            self._tun_helper_remove_network_for_device(dev)
            dev.reader_registered = False
            return
        _bridge_tun_platform.close_tun_device(self, dev)

    def _write_tun_packet(self, dev: "ChannelMux.TunDevice", data: bytes) -> None:
        def _log_probe_write(stage: str, note: str = "") -> None:
            self._log_tun_probe_trace(
                stage=stage,
                packet=bytes(data or b""),
                ifname=str(getattr(dev, "ifname", "") or ""),
                chan=getattr(dev, "chan_id", None),
                peer_id=None,
                note=note,
            )

        if self._tun_helper_manages_device(dev):
            backend = self._tun_helper_backend
            if backend is not None:
                writer = getattr(backend, "local_write_packet", None)
                if not callable(writer):
                    raise RuntimeError("helper TUN backend does not support local_write_packet")
                _log_probe_write("local_kernel_inject_before", note="backend=helper-local")
                writer(data)
                _log_probe_write("local_kernel_inject_after", note="backend=helper-local")
                return
            client = self._tun_helper_client
            if client is None:
                raise RuntimeError("helper TUN client is not available for packet write")
            _log_probe_write("local_kernel_inject_before", note="backend=helper-client-async")
            self.loop.create_task(self._tun_helper_write_packet(client, dev, data))
            _log_probe_write("local_kernel_inject_after", note="backend=helper-client-async")
            return
        if _bridge_tun_platform is not None:
            writer = getattr(_bridge_tun_platform, "write_tun_packet", None)
            if callable(writer):
                _log_probe_write("local_kernel_inject_before", note="backend=platform")
                writer(self, dev, data)
                _log_probe_write("local_kernel_inject_after", note="backend=platform")
                return
        adapter = getattr(dev, "wintun_adapter", None)
        if adapter is not None:
            write_names = ["write", "send", "send_packet", "write_packet"]
            for name in write_names:
                if hasattr(adapter, name):
                    _log_probe_write("local_kernel_inject_before", note=f"backend=wintun:{name}")
                    result = getattr(adapter, name)(data)
                    if asyncio.iscoroutine(result):
                        self.loop.create_task(result)
                    _log_probe_write("local_kernel_inject_after", note=f"backend=wintun:{name}")
                    return
            if callable(adapter):
                _log_probe_write("local_kernel_inject_before", note="backend=wintun:callable")
                result = adapter(data)
                if asyncio.iscoroutine(result):
                    self.loop.create_task(result)
                _log_probe_write("local_kernel_inject_after", note="backend=wintun:callable")
                return
            raise RuntimeError("No write method on WinTun adapter")
        _log_probe_write("local_kernel_inject_before", note="backend=os.write")
        os.write(dev.fd, data)
        _log_probe_write("local_kernel_inject_after", note="backend=os.write")

    def _find_service_tun_device(self, ifname: str, mtu: int) -> Optional["ChannelMux.TunDevice"]:
        for dev in self._svc_tun_devices.values():
            if dev.ifname == ifname and int(dev.mtu) == int(mtu):
                return dev
        registry = self._process_shared_tun_registry
        if registry is not None:
            attached = registry.attach_existing(self, str(ifname), int(mtu))
            if attached is not None:
                shared_svc_key = registry.service_key_for(str(ifname), int(mtu))
                if isinstance(shared_svc_key, tuple) and shared_svc_key in self._local_services:
                    self._svc_tun_devices.setdefault(shared_svc_key, attached)
                    spec = self._local_services.get(shared_svc_key)
                    if spec is not None:
                        self._install_shared_tun_ownership_for_service(shared_svc_key, spec)
                return attached
        return None

    def _tun_helper_active(self) -> bool:
        settings = self._tun_helper_settings
        return bool(settings is not None and str(getattr(settings, "mode", "")).strip().lower() == "helper")

    def _tun_helper_manages_device(self, dev: Optional["ChannelMux.TunDevice"]) -> bool:
        return bool(dev is not None and getattr(dev, "helper_managed", False) and self._tun_helper_active())

    def _tun_helper_network_payload(self, dev: "ChannelMux.TunDevice") -> dict[str, Any]:
        service_key = getattr(dev, "service_key", None)
        tun_routing = dict(vars(self._tun_routing_settings))
        extra4, extra6 = auto_overlay_peer_excluded_routes(vars(self.args))
        tun_routing["excluded_routes"] = list(
            dict.fromkeys([*list(tun_routing.get("excluded_routes") or []), *list(extra4)])
        )
        tun_routing["excluded_routes6"] = list(
            dict.fromkeys([*list(tun_routing.get("excluded_routes6") or []), *list(extra6)])
        )
        listener_hook_env: dict[str, str] = {}
        spec = self._effective_services_by_id().get(service_key) if isinstance(service_key, tuple) else None
        if spec is not None:
            for event_name in ("on_created", "on_stopped"):
                command_spec = self._hook_command_spec_for(spec, "listener", event_name)
                env_values = command_spec.get("env") if isinstance(command_spec, dict) else None
                if not isinstance(env_values, dict):
                    continue
                for key, value in env_values.items():
                    text_key = str(key or "").strip()
                    if not text_key:
                        continue
                    listener_hook_env[text_key] = str(value or "")
        return {
            "ifname": str(getattr(dev, "ifname", "") or ""),
            "mtu": int(getattr(dev, "mtu", 0) or 0),
            "service_key": list(service_key) if isinstance(service_key, tuple) else [],
            "service_catalog": "own_servers" if isinstance(service_key, tuple) and str(service_key[0]) == "local" else "remote_servers",
            "listener_hook_env": listener_hook_env,
            "tun_routing": tun_routing,
        }

    def _helper_owns_tun_listener_network_lifecycle(
        self,
        spec: Optional["ChannelMux.ServiceSpec"],
        *,
        dev: Optional["ChannelMux.TunDevice"] = None,
    ) -> bool:
        if spec is None or str(getattr(spec, "l_proto", "") or "") != "tun":
            return False
        settings = self._tun_helper_settings
        if not self._tun_helper_network_apply_enabled():
            return False
        if dev is not None:
            return self._tun_helper_manages_device(dev)
        return False

    def _tun_helper_network_apply_enabled(self) -> bool:
        configured = getattr(self.args, "tun_helper_apply_network", None) if self.args is not None else None
        if configured is not None:
            return bool(configured)
        return bool(getattr(self._tun_helper_settings, "helper_apply_network", False))

    def _tun_helper_open_device(self, dev: "ChannelMux.TunDevice") -> None:
        client = self._tun_helper_client
        if not self._tun_helper_manages_device(dev) or client is None:
            return
        task = self.loop.create_task(self._tun_helper_open_device_async(client, dev))
        dev_id = id(dev)
        self._tun_helper_open_tasks[dev_id] = task
        def _clear_done(_task: asyncio.Task, *, _dev_id: int = dev_id) -> None:
            current = self._tun_helper_open_tasks.get(_dev_id)
            if current is _task:
                self._tun_helper_open_tasks.pop(_dev_id, None)
        task.add_done_callback(_clear_done)

    def _tun_helper_apply_network_for_device(self, dev: "ChannelMux.TunDevice", *, client_override: Any = None) -> None:
        settings = self._tun_helper_settings
        if not self._tun_helper_manages_device(dev):
            return
        if not self._tun_helper_network_apply_enabled():
            return
        backend = self._tun_helper_backend
        if backend is not None:
            apply_network = getattr(backend, "local_apply_network", None)
            if not callable(apply_network):
                self.log.warning("[TUN/HELPER] helper backend does not support local_apply_network for if=%s", dev.ifname)
                return
            apply_network(self._tun_helper_network_payload(dev))
            dev.helper_network_applied = True
            self._schedule_tun_runtime_health_check(dev, reason="helper_apply_network")
            return
        client = client_override if client_override is not None else self._tun_helper_client
        if client is None:
            self.log.warning("[TUN/HELPER] helper client is not available for network apply if=%s", dev.ifname)
            return
        dev.helper_network_applied = True
        self.loop.create_task(self._tun_helper_apply_network_async(client, dev))

    def _tun_helper_remove_network_for_device(self, dev: "ChannelMux.TunDevice") -> None:
        if not self._tun_helper_manages_device(dev):
            return
        if not bool(getattr(dev, "helper_network_applied", False)):
            return
        backend = self._tun_helper_backend
        if backend is not None:
            remove_network = getattr(backend, "local_remove_network", None)
            if not callable(remove_network):
                self.log.warning("[TUN/HELPER] helper backend does not support local_remove_network for if=%s", dev.ifname)
                return
            remove_network(self._tun_helper_network_payload(dev))
            dev.helper_network_applied = False
            return
        client = self._tun_helper_client
        if client is None:
            self.log.warning("[TUN/HELPER] helper client is not available for network remove if=%s", dev.ifname)
            return
        dev.helper_network_applied = False
        task = self.loop.create_task(self._tun_helper_remove_network_async(client, dev))
        dev_id = id(dev)
        self._tun_helper_remove_tasks[dev_id] = task
        def _clear_done(_task: asyncio.Task, *, _dev_id: int = dev_id) -> None:
            current = self._tun_helper_remove_tasks.get(_dev_id)
            if current is _task:
                self._tun_helper_remove_tasks.pop(_dev_id, None)
        task.add_done_callback(_clear_done)

    async def _await_tun_helper_remove_tasks(self) -> None:
        pending = [task for task in self._tun_helper_remove_tasks.values() if not task.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)

    async def _await_tun_helper_open_tasks(self) -> None:
        pending = [task for task in self._tun_helper_open_tasks.values() if not task.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)

    async def _tun_helper_read_loop(self, dev: "ChannelMux.TunDevice") -> None:
        try:
            while True:
                packet = await self._tun_helper_read_packet(dev)
                if not isinstance(packet, (bytes, bytearray)):
                    continue
                self._record_tun_probe_boundary("helper_read_packet")
                if self._parse_internal_tun_probe_packet(bytes(packet)) is not None:
                    self._record_tun_probe_boundary("helper_read_probe_packet")
                    self._log_tun_probe_trace(
                        stage="from_local_tun_helper_read",
                        packet=bytes(packet),
                        ifname=dev.ifname,
                        chan=dev.chan_id,
                        peer_id=self._chan_owner_peer_id.get(int(dev.chan_id)) if dev.chan_id is not None else None,
                        note="helper_read_loop",
                    )
                self._on_local_tun_packet(dev, bytes(packet))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            dev.reader_registered = False
            self.log.warning("[TUN/HELPER] helper-backed reader stopped if=%s err=%r", dev.ifname, exc)

    async def _tun_helper_read_packet(self, dev: "ChannelMux.TunDevice") -> bytes:
        backend = self._tun_helper_backend
        if backend is not None:
            reader = getattr(backend, "read_packet", None)
            if not callable(reader):
                raise RuntimeError(f"helper-backed reader unavailable for if={dev.ifname}")
            return await reader()
        client = self._tun_helper_client
        if client is None:
            raise RuntimeError(f"helper-backed reader unavailable for if={dev.ifname}")
        return await client.read_packet()

    async def _tun_helper_open_device_async(self, client: Any, dev: "ChannelMux.TunDevice") -> None:
        try:
            self.log.info("[TUN/HELPER] helper open start if=%s mtu=%s", dev.ifname, dev.mtu)
            opened = await client.open_tun({"ifname": dev.ifname, "mtu": dev.mtu})
            if isinstance(opened, dict):
                opened_ifname = str(opened.get("ifname") or "")
                if opened_ifname:
                    dev.ifname = opened_ifname
                opened_mtu = opened.get("mtu")
                if opened_mtu is not None:
                    dev.mtu = int(opened_mtu)
            self.log.info("[TUN/HELPER] helper open complete if=%s mtu=%s opened=%r", dev.ifname, dev.mtu, opened)
            if self._tun_helper_network_apply_enabled():
                # Keep OPEN and APPLY_NETWORK ordered so a peer channel cannot
                # start passing packets through an unconfigured TUN.
                dev.helper_network_applied = True
                self.log.info("[TUN/HELPER] helper apply inline after open if=%s", dev.ifname)
                await self._tun_helper_apply_network_async(client, dev)
        except asyncio.CancelledError:
            self.log.warning("[TUN/HELPER] helper open cancelled if=%s mtu=%s", dev.ifname, dev.mtu)
            raise
        except Exception as exc:
            self.log.warning("[TUN/HELPER] helper open failed if=%s mtu=%s err=%r", dev.ifname, dev.mtu, exc)

    async def _tun_helper_apply_network_async(self, client: Any, dev: "ChannelMux.TunDevice") -> None:
        try:
            self.log.info("[TUN/HELPER] helper apply_network start if=%s payload=%r", dev.ifname, self._tun_helper_network_payload(dev))
            await client.apply_network(self._tun_helper_network_payload(dev))
            with contextlib.suppress(Exception):
                await client.snapshot()
            self.log.info("[TUN/HELPER] helper apply_network complete if=%s", dev.ifname)
        except asyncio.CancelledError:
            dev.helper_network_applied = False
            self.log.warning("[TUN/HELPER] helper apply_network cancelled if=%s", dev.ifname)
            raise
        except Exception as exc:
            dev.helper_network_applied = False
            with contextlib.suppress(Exception):
                await client.snapshot()
            self.log.warning("[TUN/HELPER] helper apply_network failed if=%s err=%r", dev.ifname, exc)
        finally:
            self._schedule_tun_runtime_health_check(dev, reason="helper_apply_network")

    async def _tun_helper_remove_network_async(self, client: Any, dev: "ChannelMux.TunDevice") -> None:
        try:
            await client.remove_network(self._tun_helper_network_payload(dev))
        except Exception as exc:
            with contextlib.suppress(Exception):
                await client.snapshot()
            self.log.warning("[TUN/HELPER] helper remove_network failed if=%s err=%r", dev.ifname, exc)

    async def _tun_helper_write_packet(self, client: Any, dev: "ChannelMux.TunDevice", data: bytes) -> None:
        try:
            self._record_tun_probe_boundary("helper_write_packet")
            if self._parse_internal_tun_probe_packet(bytes(data)) is not None:
                self._record_tun_probe_boundary("helper_write_probe_packet")
                self._log_tun_probe_trace(
                    stage="to_local_tun_helper_write_async_start",
                    packet=bytes(data),
                    ifname=dev.ifname,
                    chan=dev.chan_id,
                    peer_id=self._chan_owner_peer_id.get(int(dev.chan_id)) if dev.chan_id is not None else None,
                    note="helper_write_async_start",
                )
            await client.write_packet(data)
            self._log_tun_icmp_packet(
                stage="to_local_tun_helper_written",
                packet=data,
                ifname=dev.ifname,
                chan=dev.chan_id,
                peer_id=self._chan_owner_peer_id.get(int(dev.chan_id)) if dev.chan_id is not None else None,
                note="helper_write_completed",
            )
            if self._parse_internal_tun_probe_packet(bytes(data)) is not None:
                self._log_tun_probe_trace(
                    stage="to_local_tun_helper_write_async_done",
                    packet=bytes(data),
                    ifname=dev.ifname,
                    chan=dev.chan_id,
                    peer_id=self._chan_owner_peer_id.get(int(dev.chan_id)) if dev.chan_id is not None else None,
                    note="helper_write_async_done",
                )
        except Exception as exc:
            self._record_tun_probe_boundary("helper_write_error")
            self.log.warning("[TUN/HELPER] helper write failed if=%s bytes=%s err=%r", dev.ifname, len(data), exc)


    def _service_tun_inventory_summary(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for svc_key, dev in self._svc_tun_devices.items():
            ownership = self._shared_tun_ownership_by_service.get(svc_key)
            rows.append(
                {
                    "svc_key": [str(v) for v in svc_key],
                    "ifname": str(getattr(dev, "ifname", "") or ""),
                    "mtu": int(getattr(dev, "mtu", 0) or 0),
                    "shared_peer_refs": [str(v) for v in list((ownership or {}).get("peer_refs") or [])],
                    "active_bindings": len(
                        [
                            key
                            for key in self._shared_tun_runtime_by_peer
                            if key[0] == svc_key
                        ]
                    ),
                }
            )
        rows.sort(key=lambda item: (item["ifname"], item["mtu"], item["svc_key"]))
        return rows

    def _log_tun_open_diagnostics(
        self,
        *,
        direction: str,
        chan: int,
        spec: "ChannelMux.ServiceSpec",
        peer_id: Optional[int],
        matched_dev: Optional["ChannelMux.TunDevice"] = None,
        note: str = "",
    ) -> None:
        self.log.info(
            "[TUN/OPEN] %s chan=%s peer_id=%s svc=%s name=%r l_if=%s l_mtu=%s r_if=%s r_mtu=%s shared_requested=%s matched_dev=%s note=%s inventory=%s",
            direction,
            chan,
            None if peer_id is None else int(peer_id),
            int(spec.svc_id),
            str(spec.name or ""),
            str(spec.l_bind),
            int(spec.l_port),
            str(spec.r_host),
            int(spec.r_port),
            self._shared_tun_open_requested(spec),
            None if matched_dev is None else {
                "ifname": str(getattr(matched_dev, "ifname", "") or ""),
                "mtu": int(getattr(matched_dev, "mtu", 0) or 0),
                "service_key": list(getattr(matched_dev, "service_key", ()) or ()),
            },
            str(note or ""),
            self._service_tun_inventory_summary(),
        )

    async def _start_tun_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        self._start_tun_server_for_sync(spec, svc_key)

    def _start_tun_server_for_sync(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey") -> "ChannelMux.TunDevice":
        mtu = max(68, int(spec.l_port or self.TUN_DEFAULT_MTU))
        registry = self._process_shared_tun_registry
        if self._is_server_shared_tun_service(spec) and registry is not None:
            shared_dev = registry.attach_existing(self, str(spec.l_bind), mtu)
            if shared_dev is not None:
                self._svc_tun_devices[svc_key] = shared_dev
                self._install_shared_tun_ownership_for_service(svc_key, spec)
                self.log.info(
                    "[TUN/SRV] service=%s:%s attached existing shared if=%s mtu=%s",
                    svc_key[0],
                    spec.svc_id,
                    shared_dev.ifname,
                    shared_dev.mtu,
                )
                return shared_dev
        dev = self._open_tun_device(spec.l_bind, mtu, svc_key=svc_key)
        self._svc_tun_devices[svc_key] = dev
        self._install_shared_tun_ownership_for_service(svc_key, spec)
        if self._is_server_shared_tun_service(spec) and registry is not None:
            registry.register(self, svc_key, dev)
        self.log.info("[TUN/SRV] service=%s:%s opened if=%s mtu=%s", svc_key[0], spec.svc_id, dev.ifname, dev.mtu)
        if self._helper_owns_tun_listener_network_lifecycle(spec, dev=dev):
            self.log.info(
                "[TUN/HELPER] helper owns listener on_created host-network lifecycle if=%s service=%s:%s",
                dev.ifname,
                svc_key[0],
                spec.svc_id,
            )
        else:
            self._schedule_service_hook(spec, svc_key, "listener", "on_created")
            if self._hook_command_spec_for(spec, "listener", "on_created") is None:
                self._schedule_tun_runtime_health_check(dev, reason="listener_started_without_on_created_hook")
        if str(svc_key[0]) == "local":
            self._schedule_tun_reader_registration(dev)
        else:
            self._register_tun_reader(dev)
        return dev

    def _tun_fragment_payload_limit(self) -> int:
        return max(0, self._session_max_app_payload - ChannelMux.MUX_HDR.size - ChannelMux.UDP_FRAG_HDR.size)

    def _send_tun_mux_fragments(self, chan_id: int, payload: bytes, *, peer_id: Optional[int] = None) -> None:
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
            self._send_mux(chan_id, ChannelMux.Proto.TUN, ChannelMux.MType.DATA_FRAG, frag_payload, peer_id=peer_id)

    def _shared_tun_reader_owner_for_device(self, dev: "ChannelMux.TunDevice") -> Optional["ChannelMux"]:
        # Reader ownership is the authoritative routing owner.  A process
        # registry can retain the mux that first created the device while a
        # later listener owns its active read loop.
        reader_owner = getattr(dev, "_reader_mux", None)
        if reader_owner is not None and reader_owner is not self:
            return reader_owner
        registry = self._process_shared_tun_registry
        if registry is None:
            return None
        owner = registry.owner_mux_for_dev(dev)
        if owner is self or owner is None:
            return None
        return owner

    def _mirror_shared_tun_binding_to_reader_owner(
        self,
        dev: "ChannelMux.TunDevice",
        *,
        peer_id: Optional[int],
        chan: int,
    ) -> None:
        if peer_id is None:
            return
        owner = self._shared_tun_reader_owner_for_device(dev)
        if owner is None:
            return
        svc_key = getattr(dev, "service_key", None)
        shared_peer_id = self._shared_tun_peer_id_for_device(dev, int(peer_id))
        owner._record_shared_tun_peer_binding(svc_key, shared_peer_id, int(chan))
        peer_ref = self._shared_tun_peer_ref_by_peer.get((svc_key, shared_peer_id))
        if peer_ref:
            owner._shared_tun_peer_ref_by_peer[(svc_key, shared_peer_id)] = str(peer_ref)
            owner._shared_tun_peer_id_by_ref[(svc_key, str(peer_ref))] = shared_peer_id
        self.log.info(
            "[TUN/SHARED] mirror binding if=%s chan=%s peer_id=%s reader_owner=%s peer_ref=%s",
            str(getattr(dev, "ifname", "") or ""),
            int(chan),
            int(peer_id),
            hex(id(owner)),
            str(peer_ref or ""),
        )

    def _shared_tun_peer_id_for_device(self, dev: "ChannelMux.TunDevice", peer_id: Optional[int]) -> Optional[int]:
        if peer_id is None:
            return None
        registry = self._process_shared_tun_registry
        if registry is None:
            return int(peer_id)
        return registry.shared_peer_id_for(self, int(peer_id))

    def _drop_shared_tun_state_for_local_peer(self, peer_id: int) -> None:
        registry = self._process_shared_tun_registry
        if registry is None:
            self._drop_shared_tun_state_for_peer(int(peer_id))
            return
        shared_peer_id = registry.forget_shared_peer(self, int(peer_id))
        if shared_peer_id is None:
            return
        for holder in registry.holders():
            holder._drop_shared_tun_state_for_peer(int(shared_peer_id))

    def _shared_tun_route_for_peer_id(
        self, dev: "ChannelMux.TunDevice", shared_peer_id: Optional[int]
    ) -> tuple["ChannelMux", Optional[int]]:
        if shared_peer_id is None:
            return self, None
        registry = self._process_shared_tun_registry
        route = registry.shared_peer_route_for(int(shared_peer_id)) if registry is not None else None
        return route if route is not None else (self, int(shared_peer_id))

    def _record_shared_tun_peer_traffic_for_device(
        self,
        dev: "ChannelMux.TunDevice",
        peer_id: Optional[int],
        chan: int,
        packet: bytes,
        *,
        direction: str,
    ) -> None:
        """Keep shared-TUN binding counters identical across its mux holders.

        A virtual-peer mux receives overlay packets, while the mux with the
        single device read loop sends replies. Either mux can supply the
        WebAdmin row, so accounting on only the executing mux loses one half
        of the duplex flow.
        """
        targets: list["ChannelMux"] = [self]
        registry = self._process_shared_tun_registry
        if registry is not None:
            targets.extend(registry.holders_for_dev(dev))
        seen: set[int] = set()
        svc_key = getattr(dev, "service_key", None)
        for target in targets:
            marker = id(target)
            if marker in seen:
                continue
            seen.add(marker)
            target._record_shared_tun_peer_traffic(
                svc_key,
                peer_id,
                chan,
                packet,
                direction=direction,
            )

    def _bind_tun_channel(self, chan: int, dev: "ChannelMux.TunDevice", *, peer_id: Optional[int] = None) -> None:
        # A full-duplex TUN pair can temporarily create symmetric OPENs from both
        # peers. Keep every inbound channel routable; dev.chan_id is only the
        # preferred outbound channel for locally-read packets.
        self._tun_by_chan[chan] = dev
        if peer_id is not None:
            self._tun_by_peer_chan[(int(peer_id), int(chan))] = dev
        self._record_shared_tun_peer_binding(
            getattr(dev, "service_key", None),
            self._shared_tun_peer_id_for_device(
                dev,
                peer_id if peer_id is not None else self._chan_owner_peer_id.get(int(chan)),
            ),
            int(chan),
        )
        reader_owner = self._shared_tun_reader_owner_for_device(dev)
        if reader_owner is None:
            self._register_tun_reader(dev, force_owner=True)
        else:
            self._mirror_shared_tun_binding_to_reader_owner(dev, peer_id=peer_id, chan=chan)
        if dev.chan_id is None:
            dev.chan_id = chan
        if dev.service_key is not None:
            self._tun_chan_by_service.setdefault(dev.service_key, chan)
        self.log.info(
            "[TUN/BIND] chan=%s if=%s mtu=%s peer_id=%s service_key=%s device_chans=%s shared_runtime=%s",
            int(chan),
            str(getattr(dev, "ifname", "") or ""),
            int(getattr(dev, "mtu", 0) or 0),
            self._chan_owner_peer_id.get(int(chan)),
            getattr(dev, "service_key", None),
            self._tun_channels_for_device(dev),
            self._shared_tun_runtime_snapshot_for_service(getattr(dev, "service_key", None)),
        )

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
        for peer_chan, mapped in list(self._tun_by_peer_chan.items()):
            if mapped is not dev:
                continue
            peer_id, chan = peer_chan
            self._drop_shared_tun_peer_binding(
                getattr(dev, "service_key", None),
                int(peer_id),
                int(chan),
            )
            owner = self._shared_tun_reader_owner_for_device(dev)
            if owner is not None:
                owner._drop_shared_tun_peer_binding(
                    getattr(dev, "service_key", None),
                    int(peer_id),
                    int(chan),
                )
            self._tun_by_peer_chan.pop(peer_chan, None)
            self._tun_frag_rx = {
                key: state
                for key, state in self._tun_frag_rx.items()
                if key[:2] != (int(peer_id), int(chan))
            }
            self._forget_tun_open_key(chan, peer_id=peer_id)
        for chan in list(self._tun_by_chan.keys()):
            if self._tun_by_chan.get(chan) is dev:
                self._drop_shared_tun_peer_binding(
                    getattr(dev, "service_key", None),
                    self._chan_owner_peer_id.get(int(chan)),
                    int(chan),
                )
                self._tun_by_chan.pop(chan, None)
                self._tun_frag_rx = {key: state for key, state in self._tun_frag_rx.items() if key[1] != chan}
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

    def _session_overlay_backpressure_snapshot(self, *, now_ns: int) -> dict[str, Any]:
        getter = getattr(self.session, "get_metrics", None)
        if not callable(getter):
            return {
                "waiting_count": 0,
                "inflight": 0,
                "max_inflight": 0,
                "transmit_delay_est_ms": 0.0,
                "rtt_est_ms": 0.0,
                "prev_window_bytes": 0,
                "curr_window_bytes": 0,
                "stalled": False,
            }
        try:
            metrics = getter()
        except Exception:
            return {
                "waiting_count": 0,
                "inflight": 0,
                "max_inflight": 0,
                "transmit_delay_est_ms": 0.0,
                "rtt_est_ms": 0.0,
                "prev_window_bytes": 0,
                "curr_window_bytes": 0,
                "stalled": False,
            }
        waiting_count = 0
        inflight = 0
        max_inflight = 0
        prev_window_bytes = 0
        curr_window_bytes = 0
        last_rtt_ok_ns = getattr(metrics, "last_rtt_ok_ns", None)
        last_rx_ns = getattr(metrics, "last_rx_ns", None)
        transmit_delay_est_ms = getattr(metrics, "transmit_delay_est_ms", None)
        rtt_est_ms = getattr(metrics, "rtt_est_ms", None)
        try:
            waiting_count = max(0, int(getattr(metrics, "waiting_count", 0) or 0))
        except (TypeError, ValueError):
            waiting_count = 0
        try:
            inflight = max(0, int(getattr(metrics, "inflight", 0) or 0))
        except (TypeError, ValueError):
            inflight = 0
        try:
            max_inflight = max(0, int(getattr(metrics, "max_inflight", 0) or 0))
        except (TypeError, ValueError):
            max_inflight = 0
        try:
            prev_window_bytes = max(0, int(getattr(metrics, "egress_prev_window_bytes", 0) or 0))
        except (TypeError, ValueError):
            prev_window_bytes = 0
        try:
            curr_window_bytes = max(0, int(getattr(metrics, "egress_curr_window_bytes", 0) or 0))
        except (TypeError, ValueError):
            curr_window_bytes = 0
        try:
            last_ok = int(last_rtt_ok_ns or 0)
        except (TypeError, ValueError):
            last_ok = 0
        try:
            last_rx = int(last_rx_ns or 0)
        except (TypeError, ValueError):
            last_rx = 0
        progress_ns = max(last_ok, last_rx)
        try:
            tx_delay_ms = max(0.0, float(transmit_delay_est_ms or 0.0))
        except (TypeError, ValueError):
            tx_delay_ms = 0.0
        if progress_ns <= 0:
            try:
                rtt_ms = max(0.0, float(rtt_est_ms or 0.0))
            except (TypeError, ValueError):
                rtt_ms = 0.0
            return {
                "waiting_count": waiting_count,
                "inflight": inflight,
                "max_inflight": max_inflight,
                "transmit_delay_est_ms": tx_delay_ms,
                "rtt_est_ms": rtt_ms,
                "prev_window_bytes": prev_window_bytes,
                "curr_window_bytes": curr_window_bytes,
                "stalled": False,
            }
        idle_budget_ns = int(self.TUN_STREAM_OVERLAY_STALL_NS)
        try:
            rtt_ms = max(0.0, float(rtt_est_ms or 0.0))
        except (TypeError, ValueError):
            rtt_ms = 0.0
        if tx_delay_ms > 0.0:
            adaptive_budget_ns = int(max(
                self.TUN_STREAM_OVERLAY_RX_IDLE_NS_MIN,
                min(
                    self.TUN_STREAM_OVERLAY_STALL_NS,
                    tx_delay_ms * 8.0 * 1_000_000.0,
                ),
            ))
            idle_budget_ns = min(idle_budget_ns, adaptive_budget_ns)
        stalled = (int(now_ns) - progress_ns) >= idle_budget_ns
        return {
            "waiting_count": waiting_count,
            "inflight": inflight,
            "max_inflight": max_inflight,
            "transmit_delay_est_ms": tx_delay_ms,
            "rtt_est_ms": rtt_ms,
            "prev_window_bytes": prev_window_bytes,
            "curr_window_bytes": curr_window_bytes,
            "stalled": stalled,
        }

    def _session_overlay_backpressure_active(self, snapshot: dict[str, Any]) -> bool:
        inflight = max(0, int(snapshot.get("inflight", 0) or 0))
        max_inflight = max(0, int(snapshot.get("max_inflight", 0) or 0))
        return (
            (max_inflight > 0 and inflight >= max_inflight)
            or float(snapshot.get("rtt_est_ms", 0.0) or 0.0) >= self._transport_delay_threshold_ms
        )

    async def _wait_for_local_tcp_ingress(self, chan: int) -> None:
        while self._overlay_connected and self._accepting_enabled:
            snapshot = self._session_overlay_backpressure_snapshot(now_ns=time.monotonic_ns())
            if float(snapshot.get("rtt_est_ms", 0.0) or 0.0) < self._transport_delay_threshold_ms:
                return
            self.log.debug("[TCP/INGRESS] paused chan=%s rtt_est_ms=%.1f", chan, float(snapshot["rtt_est_ms"]))
            await asyncio.sleep(self._tcp_ingress_throttle_poll_s)

    def _tcp_overlay_read_size(self) -> int:
        size = max(1, int(self._SAFE_TCP_READ))
        if str(self._overlay_transport or "").lower() in {"ws", "tcp", "quic"}:
            return min(size, int(self.STREAM_OVERLAY_TCP_READ_CAP))
        return size

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

    @staticmethod
    def _checksum16(payload: bytes) -> int:
        data = bytes(payload or b"")
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for idx in range(0, len(data), 2):
            total += (data[idx] << 8) | data[idx + 1]
            total = (total & 0xFFFF) + (total >> 16)
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    @staticmethod
    def _aggregate_local_ingress_scope_key() -> tuple[str, str]:
        return ("aggregate", "local_ingress")

    def _local_ingress_scope_states(
        self,
        scope_key: tuple[Any, ...],
        *,
        now_ns: int,
    ) -> list[dict[str, Any]]:
        states = [self._advance_tun_inflow_window(self._aggregate_local_ingress_scope_key(), now_ns)]
        normalized_scope_key = tuple(scope_key)
        if normalized_scope_key != self._aggregate_local_ingress_scope_key():
            states.append(self._advance_tun_inflow_window(normalized_scope_key, now_ns))
        return states

    def _local_ingress_scope_keys(self, scope_key: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        keys: list[tuple[Any, ...]] = [self._aggregate_local_ingress_scope_key()]
        normalized_scope_key = tuple(scope_key)
        if normalized_scope_key != self._aggregate_local_ingress_scope_key():
            keys.append(normalized_scope_key)
        return keys

    def _local_ingress_scope_allowance_bytes(
        self,
        *,
        snapshot: dict[str, Any],
        state: dict[str, Any],
        scope_key: tuple[Any, ...],
    ) -> int:
        transport_prev_window_bytes = int(snapshot.get("prev_window_bytes", 0) or 0)
        state_prev_window_bytes = int(state.get("prev_bytes", 0) or 0)
        if tuple(scope_key) == self._aggregate_local_ingress_scope_key():
            base_prev_window_bytes = transport_prev_window_bytes
            if base_prev_window_bytes <= 0:
                base_prev_window_bytes = state_prev_window_bytes
        else:
            base_prev_window_bytes = state_prev_window_bytes
            if base_prev_window_bytes <= 0:
                base_prev_window_bytes = transport_prev_window_bytes
        return int(float(base_prev_window_bytes) * self.OVERLAY_BACKPRESSURE_THROTTLE_RATIO)

    def _local_ingress_throttle_snapshot_for_scope(
        self,
        scope_key: tuple[Any, ...],
        *,
        now_ns: Optional[int] = None,
    ) -> dict[str, Any]:
        if now_ns is None:
            now_ns = time.monotonic_ns()
        snapshot = self._session_overlay_backpressure_snapshot(now_ns=now_ns)
        backpressure_active = self._session_overlay_backpressure_active(snapshot)
        scope_keys = self._local_ingress_scope_keys(scope_key)
        states = self._local_ingress_scope_states(scope_key, now_ns=now_ns)
        details: list[dict[str, Any]] = []
        remaining_candidates: list[int] = []
        for current_scope_key, state in zip(scope_keys, states):
            allowance_bytes = self._local_ingress_scope_allowance_bytes(
                snapshot=snapshot,
                state=state,
                scope_key=current_scope_key,
            )
            used_bytes = int(state.get("curr_bytes", 0) or 0)
            remaining_bytes = max(0, int(allowance_bytes) - used_bytes)
            remaining_candidates.append(remaining_bytes)
            details.append(
                {
                    "scope_id": self._tun_inflow_scope_id(current_scope_key),
                    "budget_bytes": int(allowance_bytes),
                    "used_bytes": used_bytes,
                    "remaining_bytes": remaining_bytes,
                    "prev_window_bytes": int(state.get("prev_bytes", 0) or 0),
                    "throttle_drop_count": int(state.get("throttle_drop_count", 0) or 0),
                }
            )
        aggregate = details[0] if details else {
            "scope_id": self._tun_inflow_scope_id(self._aggregate_local_ingress_scope_key()),
            "budget_bytes": 0,
            "used_bytes": 0,
            "remaining_bytes": 0,
            "prev_window_bytes": 0,
            "throttle_drop_count": 0,
        }
        scoped = details[1] if len(details) > 1 else None
        throttle_disabled = bool(
            self._tun_routing_config().disable_channelmux_inflow_throttle
            or self._tun_routing_config().shared_tun_disable_scoped_throttle
        )
        throttle_engaged = bool(backpressure_active)
        return {
            "applicable": True,
            "scope_id": self._tun_inflow_scope_id(tuple(scope_key)),
            "mode": "aggregate_and_scope" if scoped is not None else "aggregate_only",
            "active": throttle_engaged,
            "stalled": bool(snapshot.get("stalled")) if throttle_engaged else False,
            "backpressure_active": bool(backpressure_active),
            "disabled": throttle_disabled,
            "transport_prev_window_bytes": int(snapshot.get("prev_window_bytes", 0) or 0),
            "waiting_count": int(snapshot.get("waiting_count", 0) or 0),
            "inflight": int(snapshot.get("inflight", 0) or 0),
            "max_inflight": int(snapshot.get("max_inflight", 0) or 0),
            "transmit_delay_est_ms": float(snapshot.get("transmit_delay_est_ms", 0.0) or 0.0),
            "rtt_est_ms": float(snapshot.get("rtt_est_ms", 0.0) or 0.0),
            "budget_bytes": min(remaining_candidates) + aggregate["used_bytes"] if remaining_candidates else 0,
            "used_bytes": max(aggregate["used_bytes"], int(scoped.get("used_bytes", 0) or 0) if scoped else 0),
            "remaining_bytes": min(remaining_candidates) if remaining_candidates else 0,
            "aggregate": aggregate,
            "scope": scoped,
        }


    @classmethod
    def _rewrite_ipv4_source(cls, packet: bytes, new_source: str) -> bytes:
        payload = bytearray(packet)
        if len(payload) < 20:
            return packet
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return packet
        try:
            src_bytes = ipaddress.IPv4Address(str(new_source)).packed
        except Exception:
            return packet
        payload[12:16] = src_bytes
        payload[10:12] = b"\x00\x00"
        payload[10:12] = cls._checksum16(bytes(payload[:ihl])).to_bytes(2, "big")
        proto = int(payload[9])
        total_len = ((payload[2] << 8) | payload[3]) if len(payload) >= 4 else len(payload)
        if total_len <= 0 or total_len > len(payload):
            total_len = len(payload)
        l4 = payload[ihl:total_len]
        if not l4:
            return bytes(payload)
        if proto == 6 and len(l4) >= 20:
            l4[16:18] = b"\x00\x00"
        elif proto == 17 and len(l4) >= 8:
            l4[6:8] = b"\x00\x00"
        elif proto == 1 and len(l4) >= 4:
            l4[2:4] = b"\x00\x00"
        else:
            return bytes(payload)
        pseudo = (
            bytes(payload[12:16])
            + bytes(payload[16:20])
            + b"\x00"
            + bytes([proto])
            + len(l4).to_bytes(2, "big")
        )
        checksum = cls._checksum16(pseudo + bytes(l4))
        if proto == 6 and len(l4) >= 20:
            l4[16:18] = checksum.to_bytes(2, "big")
        elif proto == 17 and len(l4) >= 8:
            l4[6:8] = (checksum or 0xFFFF).to_bytes(2, "big")
        elif proto == 1 and len(l4) >= 4:
            l4[2:4] = checksum.to_bytes(2, "big")
        payload[ihl:total_len] = l4
        return bytes(payload)

    @classmethod
    def _rewrite_ipv6_source(cls, packet: bytes, new_source: str) -> bytes:
        payload = bytearray(packet)
        if len(payload) < 40:
            return packet
        try:
            src_bytes = ipaddress.IPv6Address(str(new_source)).packed
        except Exception:
            return packet
        payload[8:24] = src_bytes
        next_header = int(payload[6])
        l4 = payload[40:]
        if next_header == 6 and len(l4) >= 20:
            l4 = bytearray(l4)
            l4[16:18] = b"\x00\x00"
            pseudo = bytes(payload[8:24]) + bytes(payload[24:40]) + len(l4).to_bytes(4, "big") + b"\x00" * 3 + bytes([next_header])
            l4[16:18] = cls._checksum16(pseudo + bytes(l4)).to_bytes(2, "big")
            payload[40:] = l4
        elif next_header == 17 and len(l4) >= 8:
            l4 = bytearray(l4)
            l4[6:8] = b"\x00\x00"
            pseudo = bytes(payload[8:24]) + bytes(payload[24:40]) + len(l4).to_bytes(4, "big") + b"\x00" * 3 + bytes([next_header])
            checksum = cls._checksum16(pseudo + bytes(l4)) or 0xFFFF
            l4[6:8] = checksum.to_bytes(2, "big")
            payload[40:] = l4
        elif next_header == 58 and len(l4) >= 4:
            l4 = bytearray(l4)
            l4[2:4] = b"\x00\x00"
            pseudo = bytes(payload[8:24]) + bytes(payload[24:40]) + len(l4).to_bytes(4, "big") + b"\x00" * 3 + bytes([next_header])
            l4[2:4] = cls._checksum16(pseudo + bytes(l4)).to_bytes(2, "big")
            payload[40:] = l4
        return bytes(payload)


    def _local_ingress_send_allowed(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> bool:
        snapshot = self._session_overlay_backpressure_snapshot(now_ns=now_ns)
        backpressure_active = self._session_overlay_backpressure_active(snapshot)
        if not backpressure_active:
            return True
        if bool(snapshot.get("stalled")):
            return False
        states = self._local_ingress_scope_states(scope_key, now_ns=now_ns)
        if (
            self._tun_routing_config().disable_channelmux_inflow_throttle
            or self._tun_routing_config().shared_tun_disable_scoped_throttle
        ):
            if backpressure_active and str(self._overlay_transport or "").lower() in {"ws", "tcp", "quic"}:
                return False
            return True
        for allowed_scope_key, state in zip(self._local_ingress_scope_keys(scope_key), states):
            allowance_bytes = self._local_ingress_scope_allowance_bytes(
                snapshot=snapshot,
                state=state,
                scope_key=allowed_scope_key,
            )
            if allowance_bytes <= 0:
                return False
            if (int(state.get("curr_bytes", 0) or 0) + int(packet_len)) > allowance_bytes:
                return False
        return True

    def _local_tun_send_allowed(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> bool:
        return self._local_ingress_send_allowed(packet_len, now_ns=now_ns, scope_key=scope_key)

    def _record_local_tun_forward(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> None:
        for state in self._local_ingress_scope_states(scope_key, now_ns=now_ns):
            state["curr_bytes"] = int(state.get("curr_bytes", 0) or 0) + max(0, int(packet_len))

    def _record_local_udp_forward(self, packet_len: int, *, now_ns: int, scope_key: tuple[Any, ...]) -> None:
        for state in self._local_ingress_scope_states(scope_key, now_ns=now_ns):
            state["curr_bytes"] = int(state.get("curr_bytes", 0) or 0) + max(0, int(packet_len))

    def _tun_probe_cache_key(self, *, probe_kind: str, ifname: str, target: str) -> tuple[str, str, str]:
        return (str(probe_kind or "").strip().lower(), str(ifname or "").strip(), str(target or "").strip())

    def _tun_probe_label(self, probe_kind: str) -> str:
        kind = str(probe_kind or "").strip().lower()
        if kind == "peer":
            return "TUN connectivity verified"
        if kind == "global":
            return "TUN global connectivity verified"
        return "TUN connectivity verification"

    def _tun_probe_kind_code(self, probe_kind: str) -> int:
        return PROBE_KIND_GLOBAL if str(probe_kind or "").strip().lower() == "global" else PROBE_KIND_PEER

    def _tun_probe_result(
        self,
        *,
        probe_kind: str,
        target: str,
        ok: bool,
        state: str,
        summary: str,
        detail: str,
        resolved_target: str = "",
        name_resolution: Optional[dict[str, Any]] = None,
        value_ms: Optional[float] = None,
        last_success_ago_s: Optional[float] = None,
        last_success_rtt_ms: Optional[float] = None,
    ) -> dict[str, Any]:
        result = {
            "label": self._tun_probe_label(probe_kind),
            "ok": bool(ok),
            "state": str(state or ""),
            "summary": str(summary or ""),
            "detail": str(detail or ""),
            "target": str(target or ""),
            "resolved_target": str(resolved_target or ""),
            "name_resolution": dict(name_resolution or {}),
            "method": "internal_icmp_echo",
            "checked_at_unix_ts": float(time.time()),
            "value_ms": None if value_ms is None else float(value_ms),
            "last_success_ago_s": None if last_success_ago_s is None else float(last_success_ago_s),
            "last_success_rtt_ms": None if last_success_rtt_ms is None else float(last_success_rtt_ms),
        }
        if result["value_ms"] is not None:
            result["last_success_rtt_ms"] = result["value_ms"]
        return result

    @staticmethod
    def _tun_probe_name_resolution(*, status: str, resolved_ip: str = "", detail: str = "") -> dict[str, Any]:
        return {
            "status": str(status or "").strip() or "unknown",
            "resolved_ip": str(resolved_ip or "").strip(),
            "detail": str(detail or "").strip(),
        }

    def _tun_probe_runtime_diag_snapshot(
        self,
        *,
        probe_kind: str,
        ifname: str,
        target: str,
        resolved_target: str,
        timeout_s: float,
    ) -> dict[str, Any]:
        now_ns = time.monotonic_ns()
        backpressure = self._session_overlay_backpressure_snapshot(now_ns=now_ns)
        secure_status_getter = getattr(self.session, "get_secure_link_status_snapshot", None)
        secure_status: dict[str, Any] = {}
        if callable(secure_status_getter):
            with contextlib.suppress(Exception):
                secure_status = dict(secure_status_getter() or {})
        return {
            "captured_at_unix_ts": float(time.time()),
            "probe_kind": str(probe_kind or ""),
            "ifname": str(ifname or ""),
            "target": str(target or ""),
            "resolved_target": str(resolved_target or ""),
            "timeout_s": float(timeout_s or 0.0),
            "overlay_transport": str(self._overlay_transport or ""),
            "overlay_connected": bool(self._overlay_connected),
            "accepting_enabled": bool(self._accepting_enabled),
            "session_connected": bool(self.session.is_connected()),
            "session_app_ready": bool(self._session_app_ready()),
            "secure_link_state": str(secure_status.get("state") or ""),
            "secure_link_authenticated": bool(secure_status.get("authenticated")),
            "secure_link_last_event": str(secure_status.get("last_event") or ""),
            "secure_link_failure_reason": str(secure_status.get("failure_reason") or ""),
            "secure_link_failure_detail": str(secure_status.get("failure_detail") or ""),
            "backpressure": {
                "waiting_count": int(backpressure.get("waiting_count", 0) or 0),
                "inflight": int(backpressure.get("inflight", 0) or 0),
                "max_inflight": int(backpressure.get("max_inflight", 0) or 0),
                "transmit_delay_est_ms": float(backpressure.get("transmit_delay_est_ms", 0.0) or 0.0),
                "prev_window_bytes": int(backpressure.get("prev_window_bytes", 0) or 0),
                "curr_window_bytes": int(backpressure.get("curr_window_bytes", 0) or 0),
                "stalled": bool(backpressure.get("stalled")),
                "active": bool(self._session_overlay_backpressure_active(backpressure)),
            },
        }

    def _find_tun_device_by_ifname(self, ifname: str) -> Optional["ChannelMux.TunDevice"]:
        text_ifname = str(ifname or "").strip()
        if not text_ifname:
            return None
        seen: set[int] = set()
        for dev in list(self._tun_by_chan.values()) + list(self._svc_tun_devices.values()):
            if dev is None or id(dev) in seen:
                continue
            seen.add(id(dev))
            if str(getattr(dev, "ifname", "") or "").strip() == text_ifname:
                return dev
        return None

    def _tun_connectivity_tests_allowed(self, dev: "ChannelMux.TunDevice") -> bool:
        """TUN probes share normal admission; TUN has no read-side throttle."""
        return True

    async def _resolve_tun_probe_target(self, target: str, *, family: int) -> str:
        infos = await self.loop.getaddrinfo(
            str(target or "").strip(),
            None,
            family=family,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMPV6 if family == socket.AF_INET6 else socket.IPPROTO_ICMP,
        )
        for entry in infos:
            sockaddr = entry[4] if len(entry) >= 5 else None
            if isinstance(sockaddr, tuple) and sockaddr:
                value = str(sockaddr[0] or "").strip()
                if value:
                    return value
        raise RuntimeError(f"unable to resolve {target!r} for family={family}")

    def _source_address_for_probe_family(self, family: int) -> str:
        if family == socket.AF_INET6:
            return str(self._tun_routing_config().tunnel_address6 or "").strip()
        return str(self._tun_routing_config().tunnel_address or "").strip()
    def _allocate_tun_probe_identity(self) -> tuple[int, int]:
        sequence = int(self._tun_probe_sequence) & 0xFFFF
        if sequence <= 0:
            sequence = 1
        self._tun_probe_sequence = ((sequence + 1) & 0xFFFF) or 1
        return int(self._tun_probe_identifier) & 0xFFFF, sequence

    def _record_tun_probe_success(
        self,
        cache_key: tuple[str, str, str],
        *,
        rtt_ms: float,
    ) -> dict[str, Any]:
        history = {
            "last_success_monotonic": float(time.monotonic()),
            "last_success_rtt_ms": float(rtt_ms),
        }
        self._tun_probe_history[cache_key] = history
        return history

    def _tun_probe_history_snapshot(self, cache_key: tuple[str, str, str]) -> tuple[Optional[float], Optional[float]]:
        history = dict(self._tun_probe_history.get(cache_key) or {})
        last_success_monotonic = history.get("last_success_monotonic")
        last_success_rtt_ms = history.get("last_success_rtt_ms")
        if last_success_monotonic is None:
            return None, None
        return max(0.0, float(time.monotonic()) - float(last_success_monotonic)), (
            None if last_success_rtt_ms is None else float(last_success_rtt_ms)
        )

    def _prune_tun_probe_timed_out_waiters(self) -> None:
        now = float(time.monotonic())
        stale_keys = [
            key
            for key, meta in list(self._tun_probe_timed_out_waiters.items())
            if (now - float(meta.get("timed_out_monotonic", 0.0) or 0.0)) > 30.0
        ]
        for key in stale_keys:
            self._tun_probe_timed_out_waiters.pop(key, None)

    def _tun_probe_reply_owner_label(self, *, identifier: int) -> str:
        return "own" if int(identifier) == int(self._tun_probe_identifier) else "foreign"

    def _observe_tun_probe_reply(self, dev: "ChannelMux.TunDevice", data: bytes) -> bool:
        parsed = parse_echo_reply(data)
        if not isinstance(parsed, dict):
            return False
        payload = bytes(parsed.get("payload") or b"")
        if len(payload) < len(PROBE_MAGIC) + 9 or not payload.startswith(PROBE_MAGIC):
            return False
        nonce = payload[5:13]
        identifier = int(parsed.get("identifier") or 0)
        owner_label = self._tun_probe_reply_owner_label(identifier=identifier)
        waiter_key = (
            int(parsed.get("family") or 0),
            identifier,
            int(parsed.get("sequence") or 0),
            bytes(nonce),
        )
        future = self._tun_probe_waiters.get(waiter_key)
        if future is None:
            self._prune_tun_probe_timed_out_waiters()
            timed_out_meta = dict(self._tun_probe_timed_out_waiters.pop(waiter_key, {}) or {})
            if timed_out_meta:
                self._record_tun_probe_boundary("probe_reply_late_after_timeout")
                self._log_tun_probe_trace(
                    stage="reply_late_after_timeout",
                    packet=data,
                    ifname=str(getattr(dev, "ifname", "") or ""),
                )
                late_count = int(self._tun_probe_boundary_counts.get("probe_reply_late_after_timeout", 0) or 0)
                if self._should_log_tun_flow_sample(late_count):
                    late_ms = max(
                        0.0,
                        (float(time.monotonic()) - float(timed_out_meta.get("timed_out_monotonic", 0.0) or 0.0)) * 1000.0,
                    )
                    self.log.info(
                        "[TUN/PROBE] late_reply_after_timeout owner=%s if=%s family=%s id=%s seq=%s nonce=%s src=%s dst=%s late_ms=%.1f target=%s resolved_target=%s",
                        owner_label,
                        str(getattr(dev, "ifname", "") or ""),
                        int(parsed.get("family") or 0),
                        identifier,
                        int(parsed.get("sequence") or 0),
                        bytes(nonce).hex(),
                        str(parsed.get("source_ip") or ""),
                        str(parsed.get("destination_ip") or ""),
                        late_ms,
                        str(timed_out_meta.get("target") or ""),
                        str(timed_out_meta.get("resolved_target") or ""),
                    )
                return False
            self._record_tun_probe_boundary("probe_reply_unmatched")
            self._record_tun_probe_boundary(f"{owner_label}_probe_reply_unmatched")
            self._log_tun_probe_trace(
                stage="reply_unmatched",
                packet=data,
                ifname=str(getattr(dev, "ifname", "") or ""),
                note=f"waiters={len(self._tun_probe_waiters)}",
            )
            unmatched_count = int(self._tun_probe_boundary_counts.get("probe_reply_unmatched", 0) or 0)
            if self._should_log_tun_flow_sample(unmatched_count):
                waiter_samples: list[str] = []
                for idx, key in enumerate(list(self._tun_probe_waiters.keys())[:4]):
                    family_value, ident_value, seq_value, nonce_value = key
                    waiter_samples.append(
                        f"{idx}:{int(family_value)}/{int(ident_value)}/{int(seq_value)}/{bytes(nonce_value).hex()}"
                    )
                self.log.info(
                    "[TUN/PROBE] unmatched_reply owner=%s if=%s family=%s id=%s seq=%s nonce=%s src=%s dst=%s waiters=%s waiter_samples=%s",
                    owner_label,
                    str(getattr(dev, "ifname", "") or ""),
                    int(parsed.get("family") or 0),
                    identifier,
                    int(parsed.get("sequence") or 0),
                    bytes(nonce).hex(),
                    str(parsed.get("source_ip") or ""),
                    str(parsed.get("destination_ip") or ""),
                    len(self._tun_probe_waiters),
                    ",".join(waiter_samples) if waiter_samples else "-",
                )
            return False
        self._record_tun_probe_boundary("probe_reply_matched")
        self._log_tun_probe_trace(
            stage="reply_matched",
            packet=data,
            ifname=str(getattr(dev, "ifname", "") or ""),
            note="waiter_matched=1",
        )
        self._tun_probe_waiters.pop(waiter_key, None)
        if not future.done():
            future.set_result(
                {
                    "ifname": str(getattr(dev, "ifname", "") or ""),
                    "reply_source_ip": str(parsed.get("source_ip") or ""),
                    "reply_destination_ip": str(parsed.get("destination_ip") or ""),
                    "payload": payload,
                    "received_monotonic_ns": time.monotonic_ns(),
                }
            )
        return True




    async def _probe_tun_connectivity_once(
        self,
        *,
        probe_kind: str,
        ifname: str,
        target: str,
        timeout_s: float,
    ) -> dict[str, Any]:
        cache_key = self._tun_probe_cache_key(probe_kind=probe_kind, ifname=ifname, target=target)
        label = self._tun_probe_label(probe_kind)
        self._record_tun_probe_boundary("probe_attempt_started")
        if not self._tun_admission_allowed():
            return self._tun_probe_result(probe_kind=probe_kind, target=str(target or ""), ok=False, state="skipped", summary=f"{label}: skipped", detail="TUN admission awaits a connected lifecycle epoch.", name_resolution=self._tun_probe_name_resolution(status="skipped"))
        text_target = str(target or "").strip()
        text_ifname = str(ifname or "").strip()
        if not text_target:
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="skipped",
                summary=f"{label}: skipped",
                detail="Verification target is not configured.",
                name_resolution=self._tun_probe_name_resolution(
                    status="skipped",
                    detail="Verification target is not configured.",
                ),
            )
        if not text_ifname:
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="skipped",
                summary=f"{label}: skipped",
                detail="TUN interface name unavailable.",
                name_resolution=self._tun_probe_name_resolution(status="unknown"),
            )
        dev = self._find_tun_device_by_ifname(text_ifname)
        if dev is None:
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="skipped",
                summary=f"{label}: skipped",
                detail=f"TUN interface {text_ifname} is not active on this runtime.",
                name_resolution=self._tun_probe_name_resolution(status="unknown"),
            )
        if not self._tun_connectivity_tests_allowed(dev):
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="skipped",
                summary=f"{label}: skipped",
                detail="TUN verification is suspended while local TUN throttling is active.",
                name_resolution=self._tun_probe_name_resolution(
                    status="skipped",
                    detail="Name resolution is suspended while local TUN throttling is active.",
                ),
            )
        candidate_families: list[int] = []
        configured_v4 = str(self._tun_routing_config().tunnel_address or "").strip()
        configured_v6 = str(self._tun_routing_config().tunnel_address6 or "").strip()
        if configured_v4:
            candidate_families.append(socket.AF_INET)
        if configured_v6:
            candidate_families.append(socket.AF_INET6)
        if not candidate_families:
            candidate_families.append(socket.AF_INET)
        last_error = "target resolution failed"
        resolved_target = ""
        family = candidate_families[0]
        for candidate_family in candidate_families:
            try:
                resolved_target = await self._resolve_tun_probe_target(text_target, family=candidate_family)
                family = candidate_family
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        if not resolved_target:
            last_success_ago_s, last_success_rtt_ms = self._tun_probe_history_snapshot(cache_key)
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="failed",
                summary=f"{label}: failed",
                detail=f"Probe target resolution failed: {last_error}",
                name_resolution=self._tun_probe_name_resolution(
                    status="failed",
                    detail=f"Probe target resolution failed: {last_error}",
                ),
                last_success_ago_s=last_success_ago_s,
                last_success_rtt_ms=last_success_rtt_ms,
            )
        name_resolution = self._tun_probe_name_resolution(
            status="successful",
            resolved_ip=resolved_target,
            detail=f"Resolved {text_target} to {resolved_target}.",
        )
        source_ip = self._source_address_for_probe(probe_kind=probe_kind, family=family)
        if not source_ip:
            last_success_ago_s, last_success_rtt_ms = self._tun_probe_history_snapshot(cache_key)
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="skipped",
                summary=f"{label}: skipped",
                detail=f"No configured tunnel source address is available for {resolved_target}.",
                resolved_target=resolved_target,
                name_resolution=name_resolution,
                last_success_ago_s=last_success_ago_s,
                last_success_rtt_ms=last_success_rtt_ms,
            )
        if self._probe_uses_local_virtual_injection(dev, family=family, source_ip=source_ip):
            if not self._local_virtual_probe_transport_active():
                last_success_ago_s, last_success_rtt_ms = self._tun_probe_history_snapshot(cache_key)
                return self._tun_probe_result(
                    probe_kind=probe_kind,
                    target=text_target,
                    ok=False,
                    state="skipped",
                    summary=f"{label}: skipped",
                    detail=(
                        f"Skipped local virtual probe on inactive transport "
                        f"{str(self._overlay_transport or '').lower() or 'unknown'}."
                    ),
                    resolved_target=resolved_target,
                    name_resolution=name_resolution,
                    last_success_ago_s=last_success_ago_s,
                    last_success_rtt_ms=last_success_rtt_ms,
                )
        sent_monotonic_ns = time.monotonic_ns()
        nonce = secrets.token_bytes(8)
        payload = probe_payload(
            probe_kind=self._tun_probe_kind_code(probe_kind),
            nonce=nonce,
            sent_monotonic_ns=sent_monotonic_ns,
        )
        identifier, sequence = self._allocate_tun_probe_identity()
        if family == socket.AF_INET6:
            packet = build_ipv6_echo_request(
                source_ip=source_ip,
                destination_ip=resolved_target,
                identifier=identifier,
                sequence=sequence,
                payload=payload,
            )
        else:
            packet = build_ipv4_echo_request(
                source_ip=source_ip,
                destination_ip=resolved_target,
                identifier=identifier,
                sequence=sequence,
                payload=payload,
            )
        future = self.loop.create_future()
        waiter_key = (family, identifier, sequence, bytes(nonce))
        self._tun_probe_waiters[waiter_key] = future
        self._record_tun_probe_boundary("probe_waiter_registered")
        self._log_tun_probe_trace(
            stage="probe_waiter_registered",
            packet=packet,
            ifname=text_ifname,
            note=f"target={text_target}; resolved_target={resolved_target}",
        )
        try:
            await self._send_probe_packet_via_local_tun(
                dev,
                family=family,
                source_ip=source_ip,
                destination_ip=resolved_target,
                packet=packet,
            )
            self._record_tun_probe_boundary("probe_send_completed")
            reply = await asyncio.wait_for(future, timeout=max(0.1, float(timeout_s or self.TUN_PROBE_TIMEOUT_S)))
        except asyncio.TimeoutError:
            self._record_tun_probe_boundary("probe_timeout")
            self._prune_tun_probe_timed_out_waiters()
            self._tun_probe_timed_out_waiters[waiter_key] = {
                "timed_out_monotonic": float(time.monotonic()),
                "target": text_target,
                "resolved_target": resolved_target,
            }
            self._tun_probe_last_timeout_diag = self._tun_probe_runtime_diag_snapshot(
                probe_kind=probe_kind,
                ifname=text_ifname,
                target=text_target,
                resolved_target=resolved_target,
                timeout_s=float(timeout_s or self.TUN_PROBE_TIMEOUT_S),
            )
            timeout_diag = dict(self._tun_probe_last_timeout_diag)
            self.log.info(
                "[TUN/PROBE] timeout_runtime transport=%s overlay_connected=%s accepting=%s session_connected=%s app_ready=%s secure_state=%s secure_event=%s secure_failure=%s bp_waiting=%s bp_inflight=%s/%s bp_stalled=%s bp_delay_ms=%.1f target=%s resolved_target=%s",
                str(timeout_diag.get("overlay_transport") or ""),
                int(bool(timeout_diag.get("overlay_connected"))),
                int(bool(timeout_diag.get("accepting_enabled"))),
                int(bool(timeout_diag.get("session_connected"))),
                int(bool(timeout_diag.get("session_app_ready"))),
                str(timeout_diag.get("secure_link_state") or ""),
                str(timeout_diag.get("secure_link_last_event") or ""),
                str(timeout_diag.get("secure_link_failure_reason") or ""),
                int(((timeout_diag.get("backpressure") or {}).get("waiting_count", 0) or 0)),
                int(((timeout_diag.get("backpressure") or {}).get("inflight", 0) or 0)),
                int(((timeout_diag.get("backpressure") or {}).get("max_inflight", 0) or 0)),
                int(bool((timeout_diag.get("backpressure") or {}).get("stalled"))),
                float(((timeout_diag.get("backpressure") or {}).get("transmit_delay_est_ms", 0.0) or 0.0)),
                str(timeout_diag.get("target") or ""),
                str(timeout_diag.get("resolved_target") or ""),
            )
            last_success_ago_s, last_success_rtt_ms = self._tun_probe_history_snapshot(cache_key)
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="failed",
                summary=f"{label}: failed",
                detail=f"No ICMP echo reply received from {resolved_target} within {float(timeout_s or self.TUN_PROBE_TIMEOUT_S):.1f}s.",
                resolved_target=resolved_target,
                name_resolution=name_resolution,
                last_success_ago_s=last_success_ago_s,
                last_success_rtt_ms=last_success_rtt_ms,
            )
        except Exception as exc:
            self._record_tun_probe_boundary("probe_exception")
            last_success_ago_s, last_success_rtt_ms = self._tun_probe_history_snapshot(cache_key)
            return self._tun_probe_result(
                probe_kind=probe_kind,
                target=text_target,
                ok=False,
                state="failed",
                summary=f"{label}: failed",
                detail=f"Internal probe failed: {type(exc).__name__}: {exc}",
                resolved_target=resolved_target,
                name_resolution=name_resolution,
                last_success_ago_s=last_success_ago_s,
                last_success_rtt_ms=last_success_rtt_ms,
            )
        finally:
            self._tun_probe_waiters.pop(waiter_key, None)
        received_monotonic_ns = int(reply.get("received_monotonic_ns") or time.monotonic_ns())
        rtt_ms = max(0.0, (received_monotonic_ns - sent_monotonic_ns) / 1_000_000.0)
        self._record_tun_probe_success(cache_key, rtt_ms=rtt_ms)
        return self._tun_probe_result(
            probe_kind=probe_kind,
            target=text_target,
            ok=True,
            state="verified",
            summary=f"{label}: verified",
            detail=f"ICMP echo reply received from {resolved_target}.",
            resolved_target=resolved_target,
            name_resolution=name_resolution,
            value_ms=rtt_ms,
            last_success_ago_s=0.0,
            last_success_rtt_ms=rtt_ms,
        )

    async def probe_tun_connectivity(
        self,
        *,
        ifname: str,
        target: str,
        timeout_s: float,
        probe_kind: str,
    ) -> dict[str, Any]:
        cache_key = self._tun_probe_cache_key(probe_kind=probe_kind, ifname=ifname, target=target)
        task = self._tun_probe_tasks.get(cache_key)
        if task is None or task.done():
            task = self.loop.create_task(
                self._probe_tun_connectivity_once(
                    probe_kind=probe_kind,
                    ifname=ifname,
                    target=target,
                    timeout_s=timeout_s,
                )
            )
            self._tun_probe_tasks[cache_key] = task
        try:
            return dict(await task)
        finally:
            if task.done() and self._tun_probe_tasks.get(cache_key) is task:
                self._tun_probe_tasks.pop(cache_key, None)

    def _on_local_tun_packet(self, dev: "ChannelMux.TunDevice", packet: bytes) -> None:
        self._record_sync_diag("ChannelMux._on_local_tun_packet", phase="started")
        try:
            packet = self._normalize_local_tun_packet_source(dev, packet)
            current_chan = dev.chan_id
            self._log_tun_packet_debug(stage="from_local_tun", packet=packet, ifname=dev.ifname, chan=dev.chan_id)
            self._log_tun_icmp_packet(
                stage="from_local_tun_read",
                packet=packet,
                ifname=dev.ifname,
                chan=dev.chan_id,
                peer_id=self._chan_owner_peer_id.get(int(dev.chan_id)) if dev.chan_id is not None else None,
                note="local_tun_read",
            )
            self._log_tun_flow_sample(
                direction="local_to_peer",
                packet=packet,
                ifname=dev.ifname,
                chan=dev.chan_id,
                note="local_tun_read",
            )
            if not self._tun_admission_allowed():
                self._log_tun_icmp_local_decision(
                    stage="local_reply_skip_overlay_inactive",
                    dev=dev,
                    packet=packet,
                    chan=current_chan,
                    note=f"overlay_connected={int(bool(self._overlay_connected))}; accepting_enabled={int(bool(self._accepting_enabled))}",
                )
                return
            if len(packet) > int(dev.mtu):
                self._log_tun_icmp_local_decision(
                    stage="local_reply_drop_oversize",
                    dev=dev,
                    packet=packet,
                    chan=current_chan,
                    note=f"packet_len={len(packet)}; mtu={int(dev.mtu)}",
                )
                self.log.warning("[TUN] if=%s drop oversize local packet len=%s mtu=%s", dev.ifname, len(packet), dev.mtu)
                self._record_shared_tun_drop(
                    getattr(dev, "service_key", None),
                    reason="oversize_local_packet",
                    direction="local_to_peer",
                    chan_id=dev.chan_id,
                    packet_bytes=len(packet),
                )
                return
            shared_route = self._shared_tun_plan_local_delivery(getattr(dev, "service_key", None), packet)
            if shared_route is not None:
                if not bool(shared_route.get("routed")):
                    self._log_tun_icmp_local_decision(
                        stage="local_reply_drop_shared_route",
                        dev=dev,
                        packet=packet,
                        chan=current_chan,
                        note=(
                            f"route_class={shared_route.get('route_class')}; dst={shared_route.get('destination_ip')}; "
                            f"reason={shared_route.get('drop_reason') or 'shared_route_drop'}"
                        ),
                    )
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
                selected_peer_ids = [int(v) for v in list(shared_route.get("selected_peer_ids") or [])]
                for index, chan in enumerate(selected_chan_ids):
                    selected_peer_id = selected_peer_ids[index] if index < len(selected_peer_ids) else None
                    if self._is_local_virtual_probe_chan_id(chan):
                        self._log_tun_icmp_local_decision(
                            stage="local_reply_virtual_probe_delivery",
                            dev=dev,
                            packet=packet,
                            chan=chan,
                            note=f"route_class={shared_route.get('route_class') or ''}; virtual_probe=1",
                        )
                        self._handle_local_virtual_probe_delivery(
                            dev,
                            packet,
                            route_class=str(shared_route.get("route_class") or ""),
                        )
                        continue
                    self._log_tun_icmp_local_decision(
                        stage="local_reply_before_overlay_send",
                        dev=dev,
                        packet=packet,
                        chan=chan,
                        note=f"route_class={shared_route.get('route_class') or ''}; selected_chan=1",
                    )
                    ctr = self._ctr(ChannelMux.Proto.TUN, chan)
                    ctr.msgs_in += 1
                    ctr.bytes_in += len(packet)
                    self._record_shared_tun_peer_traffic_for_device(
                        dev,
                        selected_peer_id,
                        chan,
                        packet,
                        direction="tx",
                    )
                    target_mux, target_peer_id = self._shared_tun_route_for_peer_id(dev, selected_peer_id)
                    target_mux._send_mux(chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet, peer_id=target_peer_id)
                return
            chan = dev.chan_id
            if chan is None:
                svc_key = dev.service_key
                if svc_key is None:
                    self._log_tun_icmp_local_decision(
                        stage="local_reply_drop_no_channel",
                        dev=dev,
                        packet=packet,
                        chan=None,
                        note="missing_service_key",
                    )
                    self.log.warning("[TUN] if=%s drop packet: no mux channel bound", dev.ifname)
                    return
                spec = self._effective_services_by_id().get(svc_key)
                if spec is None:
                    self._log_tun_icmp_local_decision(
                        stage="local_reply_drop_missing_service_spec",
                        dev=dev,
                        packet=packet,
                        chan=None,
                        note=f"service_key={svc_key}",
                    )
                    self.log.warning("[TUN] if=%s drop packet: missing service spec", dev.ifname)
                    return
                chan = self._alloc_tun_id()
                self._bind_tun_channel(chan, dev)
                self._chan_owner_peer_id[chan] = int(svc_key[1]) if str(svc_key[0]) == "peer" else 0
                self._schedule_service_hook(spec, svc_key, "listener", "on_channel_connected", channel_id=chan)
                self._send_open_for_service(chan, ChannelMux.Proto.TUN, spec)
                self._log_tun_icmp_local_decision(
                    stage="local_reply_bound_new_channel",
                    dev=dev,
                    packet=packet,
                    chan=chan,
                    note=f"service_key={svc_key}",
                )
            self._log_tun_icmp_local_decision(
                stage="local_reply_before_overlay_send",
                dev=dev,
                packet=packet,
                chan=chan,
                note="direct_chan_send=1",
            )
            ctr = self._ctr(ChannelMux.Proto.TUN, chan)
            ctr.msgs_in += 1
            ctr.bytes_in += len(packet)
            self._send_mux(chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, packet)
        except Exception as exc:
            self._record_sync_diag("ChannelMux._on_local_tun_packet", phase="failed", error=type(exc).__name__)
            raise
        finally:
            self._record_sync_diag("ChannelMux._on_local_tun_packet", phase="finished")

    def _rx_tun(self, chan: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            self._rx_tun_open(chan, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.OPEN_CHUNK:
            self._rx_open_chunk(chan, ChannelMux.Proto.TUN, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.DATA:
            self._rx_tun_data(chan, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.DATA_FRAG:
            self._rx_tun_fragment(chan, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.CLOSE:
            self._rx_tun_close(chan, peer_id=peer_id)
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
        self._chan_owner_peer_id.setdefault(chan, peer_key)
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
        self._forget_tun_open_key(chan, peer_id=peer_key)
        self._tun_open_key_by_chan[(peer_key, int(chan))] = open_key
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
        self._log_tun_open_diagnostics(
            direction="rx",
            chan=int(chan),
            spec=peer_spec,
            peer_id=peer_id,
            note="received_open_v4",
        )
        self._schedule_service_hook(peer_spec, None, "client", "before_connect", channel_id=chan, peer_id=peer_id)
        dev = self._find_service_tun_device(str(host), int(r_port))
        if dev is None:
            shared_tun_requested = self._shared_tun_open_requested(peer_spec)
            if shared_tun_requested:
                self._log_tun_open_diagnostics(
                    direction="rx",
                    chan=int(chan),
                    spec=peer_spec,
                    peer_id=peer_id,
                    note="shared_attach_rejected_no_prestarted_match",
                )
                self.log.info(
                    "[TUN/CLI] chan=%s shared TUN attach rejected: no prestarted server-owned service if=%s mtu=%s",
                    chan,
                    host,
                    r_port,
                )
                self._forget_tun_open_key(chan, peer_id=peer_key)
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
                self._forget_tun_open_key(chan, peer_id=peer_key)
                return
        else:
            self._log_tun_open_diagnostics(
                direction="rx",
                chan=int(chan),
                spec=peer_spec,
                peer_id=peer_id,
                matched_dev=dev,
                note="matched_prestarted_service",
            )
        if dev is None:
            try:
                dev = self._open_tun_device(str(host), max(68, int(r_port or self.TUN_DEFAULT_MTU)))
                self._register_tun_reader(dev)
            except Exception as e:
                self.log.info("[TUN/CLI] chan=%s open failed if=%s mtu=%s: %r", chan, host, r_port, e)
                self._forget_tun_open_key(chan, peer_id=peer_key)
                return
        self._bind_tun_channel(chan, dev, peer_id=peer_key)
        self._schedule_service_hook(peer_spec, None, "client", "on_connected", channel_id=chan, peer_id=peer_id)
        self.log.info("[TUN/CLI] chan=%s bound if=%s mtu=%s svc=%s", chan, dev.ifname, dev.mtu, svc_id)

    def _rx_tun_data(self, chan: int, data: bytes, *, peer_id: Optional[int] = None) -> None:
        self._record_sync_diag("ChannelMux._rx_tun_data", phase="started")
        try:
            dev = self._tun_by_peer_chan.get((int(peer_id), int(chan))) if peer_id is not None else None
            if dev is None:
                dev = self._tun_by_chan.get(chan)
            if dev is None:
                self.log.warning("[TUN] chan=%s DATA not routed yet (no device)", chan)
                return
            owner_peer_id = int(peer_id) if peer_id is not None else self._chan_owner_peer_id.get(int(chan))
            shared_owner_peer_id = self._shared_tun_peer_id_for_device(dev, owner_peer_id)
            allowed, parsed, drop_reason = self._shared_tun_guard_inbound_packet(dev=dev, chan=chan, packet=data, peer_id=shared_owner_peer_id)
            if not allowed:
                self._log_tun_flow_sample(
                    direction="drop_peer_to_local",
                    packet=data,
                    ifname=dev.ifname,
                    chan=chan,
                    peer_id=owner_peer_id,
                    note=str(drop_reason or "inbound_guard_drop"),
                )
                self._record_shared_tun_drop(
                    getattr(dev, "service_key", None),
                    reason=str(drop_reason or "inbound_guard_drop"),
                    direction="peer_to_local",
                    peer_id=owner_peer_id,
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
            self._mirror_shared_tun_binding_to_reader_owner(dev, peer_id=owner_peer_id, chan=chan)
            self._log_tun_packet_debug(stage="to_local_tun", packet=data, ifname=dev.ifname, chan=chan)
            self._log_tun_icmp_packet(
                stage="from_peer_before_local_write",
                packet=data,
                ifname=dev.ifname,
                chan=chan,
                peer_id=owner_peer_id,
                note="before_local_tun_write",
            )
            self._log_tun_flow_sample(
                direction="peer_to_local",
                packet=data,
                ifname=dev.ifname,
                chan=chan,
                peer_id=owner_peer_id,
                note="before_local_tun_write",
            )
            try:
                ctr = self._ctr(ChannelMux.Proto.TUN, chan)
                ctr.msgs_in += 1
                ctr.bytes_in += len(data)
                self._record_shared_tun_peer_traffic_for_device(
                    dev,
                    shared_owner_peer_id,
                    chan,
                    data,
                    direction="rx",
                )
                dispatch_result = self._dispatch_shared_tun_inbound_packet(
                    dev,
                    data,
                    source_peer_id=int(shared_owner_peer_id or 0),
                    source_chan_id=chan,
                    source_note="peer",
                )
                if dispatch_result == "written":
                    self._log_tun_flow_sample(
                        direction="peer_to_local_written",
                        packet=data,
                        ifname=dev.ifname,
                        chan=chan,
                        peer_id=owner_peer_id,
                        note="local_tun_write_completed",
                    )
                    self._log_tun_packet_trace(
                        stage="to_local_tun_written",
                        packet=data,
                        ifname=dev.ifname,
                        chan=chan,
                        peer_id=owner_peer_id,
                    )
                    self._log_tun_icmp_packet(
                        stage="to_local_tun_written",
                        packet=data,
                        ifname=dev.ifname,
                        chan=chan,
                        peer_id=owner_peer_id,
                        note="local_tun_write_completed",
                    )
            except Exception as e:
                self.log.info("[TUN] chan=%s write failed if=%s: %r", chan, dev.ifname, e)
        except Exception as exc:
            self._record_sync_diag("ChannelMux._rx_tun_data", phase="failed", error=type(exc).__name__)
            raise
        finally:
            self._record_sync_diag("ChannelMux._rx_tun_data", phase="finished")

    def _rx_tun_fragment(self, chan: int, payload: bytes, *, peer_id: Optional[int] = None) -> None:
        dev = self._tun_by_peer_chan.get((int(peer_id), int(chan))) if peer_id is not None else None
        if dev is None:
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
            self._tun_frag_rx.pop((int(peer_id or 0), chan, int(datagram_id)), None)
            return
        if offset > total_len or (offset + len(chunk)) > total_len or not chunk:
            self.log.warning("[TUN] chan=%s invalid fragment datagram_id=%s total=%s offset=%s chunk=%s", chan, datagram_id, total_len, offset, len(chunk))
            return
        key = (int(peer_id or 0), chan, int(datagram_id))
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
        self._rx_tun_data(chan, bytes(assembled), peer_id=peer_id)

    def _rx_tun_close(self, chan: int, *, peer_id: Optional[int] = None) -> None:
        if peer_id is not None:
            dev = self._tun_by_peer_chan.pop((int(peer_id), int(chan)), None)
            if dev is not None:
                self._drop_shared_tun_peer_binding(getattr(dev, "service_key", None), int(peer_id), int(chan))
                owner = self._shared_tun_reader_owner_for_device(dev)
                if owner is not None:
                    owner._drop_shared_tun_peer_binding(getattr(dev, "service_key", None), int(peer_id), int(chan))
                # Inbound peer TUN channels are indexed both by (peer, chan)
                # for listener routing and by chan for the device snapshot.
                # Drop the latter too once no other peer owns this channel id;
                # otherwise a closed channel remains visible as a live alias.
                still_bound_for_chan = any(
                    int(peer_chan[1]) == int(chan)
                    for peer_chan in self._tun_by_peer_chan
                )
                if self._tun_by_chan.get(int(chan)) is dev and not still_bound_for_chan:
                    self._unbind_tun_channel(int(chan))
        else:
            dev = self._unbind_tun_channel(chan)
        self._finalize_channel_stats(chan, ChannelMux.Proto.TUN)
        if peer_id is None or self._chan_owner_peer_id.get(chan) == int(peer_id):
            self._chan_owner_peer_id.pop(chan, None)
        if peer_id is None:
            self._tun_frag_rx = {key: state for key, state in self._tun_frag_rx.items() if key[1] != chan}
        else:
            self._tun_frag_rx = {
                key: state
                for key, state in self._tun_frag_rx.items()
                if key[:2] != (int(peer_id), int(chan))
            }
        self._forget_tun_open_key(chan, peer_id=peer_id)
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
        if proto == ChannelMux.Proto.TUN and mtype in (ChannelMux.MType.DATA, ChannelMux.MType.DATA_FRAG):
            self._log_tun_packet_trace(
                stage="overlay_rx_mux_payload",
                packet=payload,
                chan=chan_id,
                peer_id=peer_id,
                mtype=mtype,
                note=f"counter={counter}",
            )
            self._log_tun_mux_handoff_sample(
                direction="rx_securelink",
                chan=chan_id,
                peer_id=peer_id,
                mtype=mtype,
                payload=payload,
                counter=counter,
                note="after_on_app_payload_from_peer",
            )
            self._log_tun_icmp_overlay_packet(
                stage="overlay_rx_after_unpack",
                packet=payload,
                chan=chan_id,
                peer_id=peer_id,
                mtype=mtype,
                counter=counter,
                note="after_on_app_payload_from_peer",
            )
            self._log_tun_probe_trace(
                stage="overlay_rx_after_unpack",
                packet=payload,
                chan=chan_id,
                peer_id=peer_id,
                mtype=mtype,
                note=f"counter={counter}",
            )

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
                self._note_udp_egress_proxy_limit(str(host), int(r_port))
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
                    self._log_udp_diag(
                        "server",
                        chan,
                        "overlay->local",
                        data,
                        dst=(addr[0], int(addr[1])),
                        sample_count=ctr.msgs_out,
                    )
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
            self._log_udp_diag(
                "client",
                chan,
                "overlay->target",
                data,
                src=src,
                dst=dst,
                sample_count=ctr.msgs_out,
            )
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
                self.parent._log_udp_diag(
                    "client",
                    self.chan,
                    "target->overlay",
                    data,
                    src=src,
                    dst=dst,
                    sample_count=ctr.msgs_out,
                )
            except Exception as e:
                self.parent.log.debug(f"[NET] logging failed : %r",e)
                pass
            now_ns = time.monotonic_ns()
            scope_key = ("udp", "client", int(self.chan))
            if not self.parent._local_ingress_send_allowed(len(data), now_ns=now_ns, scope_key=scope_key):
                snapshot = self.parent._session_overlay_backpressure_snapshot(now_ns=now_ns)
                self.parent.log.debug(
                    "[UDP/CLI] throttle local datagram chan=%s queued=%s inflight=%s/%s prev_window_bytes=%s packet_bytes=%s",
                    self.chan,
                    int(snapshot.get("waiting_count", 0) or 0),
                    int(snapshot.get("inflight", 0) or 0),
                    int(snapshot.get("max_inflight", 0) or 0),
                    int(snapshot.get("prev_window_bytes", 0) or 0),
                    len(data),
                )
                return
            self.parent._record_local_udp_forward(len(data), now_ns=now_ns, scope_key=scope_key)
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
        lock = self._tcp_listener_start_locks.setdefault(svc_key, asyncio.Lock())
        async with lock:
            existing = self._svc_tcp_servers.get(svc_key)
            if existing is not None and getattr(existing, "sockets", None) not in (None, []):
                return
            await self._start_tcp_server_for_unlocked(spec, svc_key)

    async def _start_tcp_server_for_unlocked(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
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
                        await self._wait_for_local_tcp_ingress(chan)
                        data = await reader.read(self._tcp_overlay_read_size())
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
                self.log.info("[TCP/CLI] chan=%s connecting -> %s:%s", chan, host, r_port)
                reader, writer = await self._open_tcp_target_connection(str(host), int(r_port))
                self._tcp_by_chan[chan] = (svc_id, writer)
                self._tcp_by_writer[writer] = (svc_id, chan)
                self._tcp_role_by_chan[chan] = "client"
                try:
                    l_ep, r_ep = self._tcp_endpoints(writer)
                    self.log.info("[TCP/CLI] chan=%s connected local=%s remote=%s", chan, l_ep, r_ep)
                except Exception:
                    pass
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
                if pending:
                    try:
                        await writer.drain()
                        if chan not in self._tcp_pending_drain_logged:
                            self._tcp_pending_drain_logged.add(chan)
                            pending_bytes = sum(len(buf) for buf in pending)
                            self.log.info(
                                "[TCP/CLI] chan=%s drained pending writes count=%d bytes=%d",
                                chan,
                                len(pending),
                                pending_bytes,
                            )
                        else:
                            self.log.debug("[TCP/CLI] chan=%s drained pending writes count=%d", chan, len(pending))
                    except Exception as e:
                        self.log.info("[TCP/CLI] chan=%s pending drain error: %r", chan, e)
                        raise

                # Backpressure worker
                self._ensure_backpressure_task(chan, writer)

                # Start RX pump: remote->overlay
                async def _rx():
                    try:
                        while True:
                            await self._wait_for_local_tcp_ingress(chan)
                            buf = await reader.read(self._tcp_overlay_read_size())
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
                            if chan not in self._tcp_first_remote_to_overlay_logged:
                                self._tcp_first_remote_to_overlay_logged.add(chan)
                                self.log.info(
                                    "[TCP/CLI] chan=%s first remote->overlay bytes=%d read_cap=%d buffered_frames=%d",
                                    chan,
                                    len(buf),
                                    self._tcp_overlay_read_size(),
                                    self._session_buffered_frames(),
                                )
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
                        self._tcp_first_remote_to_overlay_logged.discard(chan)
                        self._tcp_pending_drain_logged.discard(chan)
                        self._tcp_first_overlay_to_local_logged.discard(chan)
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
                if chan not in self._tcp_first_overlay_to_local_logged:
                    self._tcp_first_overlay_to_local_logged.add(chan)
                    try:
                        pending_frames = self._session_buffered_frames()
                    except Exception:
                        pending_frames = 0
                    self.log.info(
                        "[TCP] chan=%s first overlay->local bytes=%d pending_frames=%d role=%s",
                        chan,
                        len(data),
                        pending_frames,
                        str(self._tcp_role_by_chan.get(chan) or "unknown"),
                    )
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
                self._tcp_first_overlay_to_local_logged.discard(chan)
                self._tcp_first_remote_to_overlay_logged.discard(chan)
                self._tcp_pending_drain_logged.discard(chan)
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

    def _udp_diag_stats(self, chan_id: int) -> str:
        c = self._chan_stats.get((int(chan_id), ChannelMux.Proto.UDP))
        if c is None:
            return "stats=rx_msgs=0 tx_msgs=0 rx_bytes=0 tx_bytes=0"
        return (
            "stats="
            f"rx_msgs={int(getattr(c, 'msgs_in', 0) or 0)} "
            f"tx_msgs={int(getattr(c, 'msgs_out', 0) or 0)} "
            f"rx_bytes={int(getattr(c, 'bytes_in', 0) or 0)} "
            f"tx_bytes={int(getattr(c, 'bytes_out', 0) or 0)}"
        )

    @staticmethod
    def _udp_diag_should_log(sample_count: int) -> bool:
        count = int(sample_count or 0)
        return count <= 3 or count in (10, 25, 50) or (count > 0 and count % 100 == 0)

    def _log_udp_diag(
        self,
        role: str,
        chan_id: int,
        direction: str,
        data: bytes,
        *,
        src: Optional[tuple[str, int]] = None,
        dst: Optional[tuple[str, int]] = None,
        remote_target: Optional[tuple[str, int]] = None,
        sample_count: int = 0,
    ) -> None:
        if not self._udp_diag_should_log(sample_count):
            return
        path = "-"
        if src and dst:
            path = f"{src[0]}:{src[1]}->{dst[0]}:{dst[1]}"
        elif src:
            path = f"{src[0]}:{src[1]}->?"
        elif dst:
            path = f"?->{dst[0]}:{dst[1]}"
        target = ""
        if remote_target:
            target = f" remote_target={remote_target[0]}:{int(remote_target[1])}"
        self.log.debug(
            "[UDP/DIAG] role=%s chan=%s direction=%s len=%s path=%s%s %s preview=%s",
            role,
            chan_id,
            direction,
            len(data),
            path,
            target,
            self._udp_diag_stats(chan_id),
            data[:8].hex().upper(),
        )

    def _log_app_msg(self, dir: str, data: bytes) -> None:
        checker = getattr(self.log, "isEnabledFor", None)
        debug_enabled = bool(callable(checker) and checker(logging.DEBUG))
        info_enabled = bool(callable(checker) and checker(logging.INFO))
        warning_enabled = bool(callable(checker) and checker(logging.WARNING))
        error_enabled = bool(callable(checker) and checker(logging.ERROR))
        if not (debug_enabled or info_enabled or warning_enabled or error_enabled):
            return

        parsed = self._unpack_mux(data)
        if not parsed:
            if warning_enabled:
                self.log.warning(f"[APP] {dir} not parsed len={len(data)}: {data[:16].hex().upper()}")
            return
        chan_id, proto, counter, mtype, payload_mv = parsed
        payload_len = int(len(payload_mv))

        should_log_info = mtype in (
            ChannelMux.MType.OPEN,
            ChannelMux.MType.REMOTE_SERVICES_SET_V2,
            ChannelMux.MType.REMOTE_SERVICES_SET_V1,
            ChannelMux.MType.CLOSE,
        )
        should_log_debug = mtype in (
            ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
            ChannelMux.MType.OPEN_CHUNK,
            ChannelMux.MType.DATA,
            ChannelMux.MType.DATA_FRAG,
        )
        if (should_log_info and not info_enabled) and (should_log_debug and not debug_enabled) and not error_enabled:
            return

        src = "[APP]"
        if payload_len > 65535 and error_enabled:
            self.log.error("%s Application message longer than 65535 bytes; makes trouble!", src)

        if proto == ChannelMux.Proto.UDP:
            protostr = "UDP"
        elif proto == ChannelMux.Proto.TCP:
            protostr = "TCP"
        elif proto == ChannelMux.Proto.TUN:
            protostr = "TUN"
        else:
            protostr = str(int(proto))
        basestr = f"{src} {protostr}:{chan_id} {dir} CNT:{counter}"

        payload_bytes: Optional[bytes] = None

        def _payload() -> bytes:
            nonlocal payload_bytes
            if payload_bytes is None:
                payload_bytes = bytes(payload_mv)
            return payload_bytes

        if mtype == ChannelMux.MType.OPEN and info_enabled:
            try:
                pay = self._dbg_parse_open_v4(_payload())
            except Exception:
                pay = ""
            self.log.info(f"{basestr} OPEN {pay}")
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2 and info_enabled:
            decoded = self._decode_remote_services_set_v2(_payload())
            if decoded is None:
                self.log.info(f"{basestr} REMOTE_SERVICES_SET_V2 invalid len={payload_len}")
            else:
                iid, seq, services = decoded
                self.log.info(
                    "%s REMOTE_SERVICES_SET_V2 iid=%s seq=%s count=%s",
                    basestr,
                    iid,
                    seq,
                    len(services),
                )
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK and debug_enabled:
            self.log.debug(f"{basestr} REMOTE_SERVICES_SET_V2_CHUNK len={payload_len}")
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V1 and info_enabled:
            self.log.info(f"{basestr} REMOTE_SERVICES_SET_V1 len={payload_len} (legacy/unsupported)")
        if mtype == ChannelMux.MType.OPEN_CHUNK and debug_enabled:
            self.log.debug(f"{basestr} OPEN_CHUNK len={payload_len}")
        if mtype == ChannelMux.MType.DATA and debug_enabled:
            preview = _payload()[:5].hex().upper()
            self.log.debug(f"{basestr} DATA len={payload_len}:  {preview}")
        if mtype == ChannelMux.MType.DATA_FRAG and debug_enabled:
            if payload_len >= ChannelMux.UDP_FRAG_HDR.size:
                payload = _payload()
                datagram_id, total_len, offset = ChannelMux.UDP_FRAG_HDR.unpack(payload[:ChannelMux.UDP_FRAG_HDR.size])
                self.log.debug(
                    "%s DATA_FRAG datagram_id=%s total=%s offset=%s chunk=%s",
                    basestr,
                    datagram_id,
                    total_len,
                    offset,
                    payload_len - ChannelMux.UDP_FRAG_HDR.size,
                )
            else:
                self.log.debug(f"{basestr} DATA_FRAG short len={payload_len}")
        if mtype == ChannelMux.MType.CLOSE and info_enabled:
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

    def _svc_spec_or_none(self, svc_id: int, *, svc_key=None, owner_peer_id=None):
        try:
            i = int(svc_id)
            if svc_key is not None:
                spec = self._local_services.get(svc_key)
                if spec is None:
                    spec = self._peer_installed_services.get(svc_key)
                if spec is not None:
                    return spec
            if owner_peer_id is not None:
                spec = self._peer_installed_services.get(("peer", int(owner_peer_id), i))
                if spec is not None:
                    return spec
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

    def _remote_requested_listener_rows(self, proto: "ChannelMux.ProtoName") -> list[dict]:
        if not (self._overlay_connected and self._accepting_enabled):
            return []
        proto_name = str(proto or "").strip().lower()
        if proto_name not in {"udp", "tcp"}:
            return []
        rows: list[dict] = []
        for spec in list(self._remote_services_requested or []):
            if str(getattr(spec, "l_proto", "") or "").lower() != proto_name:
                continue
            if str(getattr(spec, "r_proto", "") or "").lower() != proto_name:
                continue
            rows.append({
                "protocol": proto_name,
                "role": "client",
                "state": "listening",
                "chan_id": None,
                "svc_id": int(spec.svc_id),
                "service_name": str(spec.name) if spec.name else "",
                "source": None,
                "local": {"host": str(spec.l_bind), "port": int(spec.l_port)},
                "local_port": int(spec.l_port),
                "remote_destination": {"host": str(spec.r_host), "port": int(spec.r_port)},
                "catalog": "remote_servers",
                "listener_location": "remote_peer",
                "throttle": {"applicable": False, "active": False, "reason": "remote_listening"},
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })
        return rows

    def snapshot_udp_connections(self) -> list[dict]:
        rows: list[dict] = []
        now_ns = time.monotonic_ns()

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)
            throttle = self._local_ingress_throttle_snapshot_for_scope(("udp", svc_key, int(chan)), now_ns=now_ns)

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
                "throttle": throttle,
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
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
                "throttle": {"applicable": False, "active": False, "reason": "listening"},
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
                spec = self._svc_spec_or_none(
                    svc_id,
                    owner_peer_id=self._chan_owner_peer_id.get(chan),
                ) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)
                throttle = self._local_ingress_throttle_snapshot_for_scope(("udp", "client", int(chan)), now_ns=now_ns)

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
                    "throttle": throttle,
                    "stats": stats,
                })
            except Exception:
                continue

        rows.extend(self._remote_requested_listener_rows("udp"))

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

            role = self._tcp_role_by_chan.get(chan, "unknown")
            spec = self._svc_spec_or_none(
                svc_id,
                owner_peer_id=self._chan_owner_peer_id.get(chan) if role == "server" else None,
            )
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
                "throttle": {"applicable": False, "active": False, "reason": "tcp_stream_backpressure"},
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
    
    def _svc_spec_or_none(self, svc_id: int, *, svc_key=None, owner_peer_id=None):
        try:
            i = int(svc_id)
            if svc_key is not None:
                spec = self._local_services.get(svc_key)
                if spec is None:
                    spec = self._peer_installed_services.get(svc_key)
                if spec is not None:
                    return spec
            if owner_peer_id is not None:
                spec = self._peer_installed_services.get(("peer", int(owner_peer_id), i))
                if spec is not None:
                    return spec
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
        now_ns = time.monotonic_ns()

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)
            throttle = self._local_ingress_throttle_snapshot_for_scope(("udp", svc_key, int(chan)), now_ns=now_ns)

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
                "throttle": throttle,
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
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
                "throttle": {"applicable": False, "active": False, "reason": "listening"},
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
                spec = self._svc_spec_or_none(
                    svc_id,
                    owner_peer_id=self._chan_owner_peer_id.get(chan),
                ) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)
                throttle = self._local_ingress_throttle_snapshot_for_scope(("udp", "client", int(chan)), now_ns=now_ns)

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
                    "throttle": throttle,
                    "stats": stats,
                })
            except Exception:
                continue

        rows.extend(self._remote_requested_listener_rows("udp"))

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

            role = self._tcp_role_by_chan.get(chan, "unknown")
            spec = self._svc_spec_or_none(
                svc_id,
                owner_peer_id=self._chan_owner_peer_id.get(chan) if role == "server" else None,
            )
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
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
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
                    "throttle": {"applicable": False, "active": False, "reason": "listening"},
                    "stats": {
                        "rx_msgs": 0,
                        "tx_msgs": 0,
                        "rx_bytes": 0,
                        "tx_bytes": 0,
                    },
                })

        rows.extend(self._remote_requested_listener_rows("tcp"))

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
        now_ns = time.monotonic_ns()
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
            # Generic channel counters are tracked from the overlay perspective.
            # For TUN presentation we expose interface-facing semantics instead:
            # packets written into the local TUN device count as RX, and packets
            # read from the local TUN device count as TX.
            stats = {"rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0}
            for chan in chans:
                chan_stats = self._chan_stat_dict(chan, ChannelMux.Proto.TUN)
                stats["rx_msgs"] += int(chan_stats.get("tx_msgs", 0) or 0)
                stats["tx_msgs"] += int(chan_stats.get("rx_msgs", 0) or 0)
                stats["rx_bytes"] += int(chan_stats.get("tx_bytes", 0) or 0)
                stats["tx_bytes"] += int(chan_stats.get("rx_bytes", 0) or 0)
            svc_key = getattr(dev, "service_key", None)
            svc_id = int(svc_key[2]) if isinstance(svc_key, tuple) and len(svc_key) >= 3 else None
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key) if svc_id is not None else None
            if isinstance(svc_key, tuple):
                active_service_keys.add(svc_key)
            shared_snapshot = self._shared_tun_runtime_snapshot_for_service(svc_key)
            throttle = (
                self._local_ingress_throttle_snapshot_for_shared_tun_service(svc_key, now_ns=now_ns)
                if isinstance(shared_snapshot, dict) and isinstance(svc_key, tuple)
                else self._local_ingress_throttle_snapshot_for_scope(
                    self._direct_tun_inflow_scope_key(svc_key, primary_chan),
                    now_ns=now_ns,
                )
            )
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
                "shared_tun_ownership": shared_snapshot,
                "runtime_health": dict(self._tun_runtime_health_by_service.get(svc_key) or {}) if isinstance(svc_key, tuple) else {},
                "throttle": throttle,
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
            spec = self._svc_spec_or_none(svc_id, svc_key=svc_key)
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
                "runtime_health": dict(self._tun_runtime_health_by_service.get(svc_key) or {}),
                "throttle": {"applicable": False, "active": False, "reason": "listening"},
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
            "tun_icmp_stage_counts": {
                key: int(self._tun_icmp_stage_counts.get(key, 0) or 0)
                for key in self.TUN_ICMP_STAGE_KEYS
            },
            "tun_probe_boundary_counts": {
                key: int(self._tun_probe_boundary_counts.get(key, 0) or 0)
                for key in self.TUN_PROBE_BOUNDARY_KEYS
            },
            "tun_local_reply_stage_counts": {
                key: int(self._local_reply_stage_counts.get(key, 0) or 0)
                for key in self.LOCAL_REPLY_STAGE_KEYS
            },
            "tun_probe_last_timeout_diag": dict(self._tun_probe_last_timeout_diag),
        }

# ============================================================================
STATE_DISCONNECTED = "DISCONNECTED"
STATE_CONNECTED = "CONNECTED"
STATE_FAILED = "FAILED"

_bridge_channelmux_shared_tun.ChannelMux = ChannelMux
_bridge_channelmux_virtual_peer.ChannelMux = ChannelMux
