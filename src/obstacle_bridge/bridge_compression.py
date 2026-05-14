from __future__ import annotations

from . import bridge as _bridge

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

class CompressLayerSession(ISession):
    _MUX_HDR = struct.Struct(">HBHBH")
    _MTYPE_COMPRESSED_FLAG = 0x80
    _MAX_MTYPE_VALUE = 0xFF
    _KNOWN_BASE_MTYPES: Set[int] = {
        0x00,  # DATA
        0x01,  # OPEN
        0x02,  # CLOSE
        0x03,  # REMOTE_SERVICES_SET_V1
        0x04,  # REMOTE_SERVICES_SET_V2
        0x05,  # DATA_FRAG
        0x06,  # REMOTE_SERVICES_SET_V2_CHUNK
        0x07,  # OPEN_CHUNK
    }
    _DEFAULT_ALLOWED_MTYPE_NAMES = "data,data_frag"
    _MTYPE_NAME_TO_ID: Dict[str, int] = {
        "data": 0x00,
        "open": 0x01,
        "close": 0x02,
        "remote_services_set_v1": 0x03,
        "remote_services_set_v2": 0x04,
        "data_frag": 0x05,
        "remote_services_set_v2_chunk": 0x06,
        "open_chunk": 0x07,
    }

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has("--compress-layer") and not _has("--no-compress-layer"):
            bool_action = getattr(argparse, "BooleanOptionalAction", None)
            if bool_action is not None:
                p.add_argument(
                    "--compress-layer",
                    action=bool_action,
                    default=True,
                    help="Enable mux-aware compression below ChannelMux and above secure-link/session (default: enabled).",
                )
            else:
                p.add_argument(
                    "--compress-layer",
                    action="store_true",
                    default=True,
                    help="Enable mux-aware compression below ChannelMux and above secure-link/session (default: enabled).",
                )
                p.add_argument(
                    "--no-compress-layer",
                    action="store_false",
                    dest="compress_layer",
                    help="Disable mux-aware compression wrapper.",
                )
        if not _has("--compress-layer-algo"):
            p.add_argument(
                "--compress-layer-algo",
                default="zlib",
                choices=["zlib"],
                help="Compression algorithm for compress-layer (zlib currently).",
            )
        if not _has("--compress-layer-level"):
            p.add_argument(
                "--compress-layer-level",
                type=int,
                default=3,
                help="Compression level for zlib (0..9).",
            )
        if not _has("--compress-layer-min-bytes"):
            p.add_argument(
                "--compress-layer-min-bytes",
                type=int,
                default=64,
                help="Minimum mux payload bytes before attempting compression.",
            )
        if not _has("--compress-layer-types"):
            p.add_argument(
                "--compress-layer-types",
                default=CompressLayerSession._DEFAULT_ALLOWED_MTYPE_NAMES,
                help=(
                    "Comma-separated mux message types eligible for compression "
                    "(data,open,close,remote_services_set_v1,remote_services_set_v2,"
                    "data_frag,remote_services_set_v2_chunk,open_chunk)."
                ),
            )

    def __init__(self, inner: ISession, args: argparse.Namespace, transport_name: str):
        self._inner = inner
        self._transport_name = str(transport_name or "")
        self._log = logging.getLogger("compress_layer")
        self._configured_enabled = bool(getattr(args, "compress_layer", True))
        self._is_peer_client = bool(str(getattr(args, "peer", "") or "").strip())
        self._algo = str(getattr(args, "compress_layer_algo", "zlib") or "zlib").strip().lower()
        self._level = max(0, min(9, int(getattr(args, "compress_layer_level", 3) or 3)))
        self._min_bytes = max(0, int(getattr(args, "compress_layer_min_bytes", 64) or 0))
        self._allowed_mtypes = self._parse_allowed_mtypes(getattr(args, "compress_layer_types", ""))
        self._peer_selected_level = 3
        self._peer_selected_min_bytes = 64
        self._peer_selected_allowed_mtypes = self._parse_allowed_mtypes(self._DEFAULT_ALLOWED_MTYPE_NAMES)
        max_payload = 65535
        getter = getattr(self._inner, "get_max_app_payload_size", None)
        if callable(getter):
            try:
                max_payload = int(getter() or 65535)
            except Exception:
                max_payload = 65535
        self._max_app_payload = max(0, int(max_payload))
        self._max_mux_payload = max(0, self._max_app_payload - self._MUX_HDR.size)
        self._outer_on_app = None
        self._outer_on_state = None
        self._outer_on_peer_rx = None
        self._outer_on_peer_tx = None
        self._outer_on_peer_set = None
        self._outer_on_peer_disconnect = None
        self._outer_on_app_from_peer_bytes = None
        self._outer_on_transport_epoch_change = None
        self._compress_attempts_total = 0
        self._compress_applied_total = 0
        self._compress_skipped_no_gain_total = 0
        self._compress_input_bytes_total = 0
        self._compress_output_bytes_total = 0
        self._decompress_ok_total = 0
        self._decompress_fail_total = 0
        self._peer_compress: Dict[Any, dict] = {}

    def __getattr__(self, name: str):
        return getattr(self._inner, name)

    @classmethod
    def _parse_allowed_mtypes(cls, raw: Any) -> Set[int]:
        value = str(raw or cls._DEFAULT_ALLOWED_MTYPE_NAMES).strip().lower()
        if not value:
            value = cls._DEFAULT_ALLOWED_MTYPE_NAMES
        out: Set[int] = set()
        for token in (item.strip() for item in value.split(",")):
            if not token:
                continue
            if token in cls._MTYPE_NAME_TO_ID:
                out.add(int(cls._MTYPE_NAME_TO_ID[token]))
        if not out:
            out = {
                cls._MTYPE_NAME_TO_ID["data"],
                cls._MTYPE_NAME_TO_ID["data_frag"],
            }
        return out

    @classmethod
    def _parse_mux_frame(cls, payload: bytes) -> Optional[Tuple[int, int, int, int, bytes]]:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            return None
        mv = memoryview(payload)
        if mv.nbytes < cls._MUX_HDR.size:
            return None
        try:
            chan_id, proto, counter, mtype, dlen = cls._MUX_HDR.unpack(mv[:cls._MUX_HDR.size])
        except Exception:
            return None
        if dlen < 0 or mv.nbytes < cls._MUX_HDR.size + int(dlen):
            return None
        body = bytes(mv[cls._MUX_HDR.size:cls._MUX_HDR.size + int(dlen)])
        return int(chan_id), int(proto), int(counter), int(mtype), body

    @classmethod
    def _build_mux_frame(cls, chan_id: int, proto: int, counter: int, mtype: int, body: bytes) -> bytes:
        return cls._MUX_HDR.pack(
            int(chan_id) & 0xFFFF,
            int(proto) & 0xFF,
            int(counter) & 0xFFFF,
            int(mtype) & cls._MAX_MTYPE_VALUE,
            len(body),
        ) + bytes(body or b"")

    @classmethod
    def _safe_decompress(cls, payload: bytes, max_out: int) -> Optional[bytes]:
        if max_out < 0:
            return None
        try:
            decomp = zlib.decompressobj()
            out = decomp.decompress(bytes(payload or b""), max_out + 1)
            if decomp.unconsumed_tail or decomp.unused_data:
                return None
            tail = decomp.flush()
            if tail:
                out += tail
        except Exception:
            return None
        if len(out) > max_out:
            return None
        return bytes(out)

    def _deliver_outer_app(self, payload: bytes, peer_id: Optional[int]) -> None:
        if callable(self._outer_on_app):
            try:
                self._outer_on_app(payload, peer_id=peer_id)
            except TypeError:
                self._outer_on_app(payload)

    @staticmethod
    def _peer_key(peer_id: Optional[int]) -> Any:
        return int(peer_id) if peer_id is not None else "__single__"

    def _new_peer_stats(self) -> dict:
        return {
            "active": False,
            "compress_attempts_total": 0,
            "compress_applied_total": 0,
            "compress_skipped_no_gain_total": 0,
            "compress_input_bytes_total": 0,
            "compress_output_bytes_total": 0,
            "decompress_ok_total": 0,
            "decompress_fail_total": 0,
        }

    def _peer_stats(self, peer_id: Optional[int]) -> dict:
        key = self._peer_key(peer_id)
        stats = self._peer_compress.get(key)
        if not isinstance(stats, dict):
            stats = self._new_peer_stats()
            self._peer_compress[key] = stats
        return stats

    def _mark_peer_active(self, peer_id: Optional[int]) -> None:
        self._peer_stats(peer_id)["active"] = True

    def _peer_send_enabled(self, peer_id: Optional[int]) -> bool:
        if self._is_peer_client:
            return bool(self._configured_enabled)
        if peer_id is None:
            return bool(self._configured_enabled)
        stats = self._peer_stats(peer_id)
        return bool(stats.get("active"))

    def _send_policy(self, peer_id: Optional[int]) -> Tuple[int, int, Set[int]]:
        if not self._is_peer_client and peer_id is not None and self._peer_send_enabled(peer_id):
            return self._peer_selected_level, self._peer_selected_min_bytes, set(self._peer_selected_allowed_mtypes)
        return self._level, self._min_bytes, set(self._allowed_mtypes)

    def _stats_peer_id_for_send(self, peer_id: Optional[int]) -> Optional[int]:
        if self._is_peer_client or peer_id is not None:
            return peer_id
        active_keys = [
            key for key, stats in self._peer_compress.items()
            if isinstance(key, int) and isinstance(stats, dict) and bool(stats.get("active"))
        ]
        if len(active_keys) == 1:
            return int(active_keys[0])
        return peer_id

    def _add_peer_counter(self, peer_id: Optional[int], field: str, value: int = 1) -> None:
        stats = self._peer_stats(peer_id)
        stats[field] = int(stats.get(field) or 0) + int(value)

    def _on_inner_peer_disconnect(self, peer_id: Optional[int] = None, *args, **kwargs) -> None:
        if peer_id is not None:
            self._peer_compress.pop(self._peer_key(peer_id), None)
        if callable(self._outer_on_peer_disconnect):
            try:
                self._outer_on_peer_disconnect(peer_id, *args, **kwargs)
            except TypeError:
                self._outer_on_peer_disconnect(peer_id)

    def _on_inner_payload(self, payload: bytes, peer_id: Optional[int] = None) -> None:
        parsed = self._parse_mux_frame(payload)
        if parsed is None:
            self._deliver_outer_app(payload, peer_id)
            return
        chan_id, proto, counter, mtype, body = parsed
        if mtype < self._MTYPE_COMPRESSED_FLAG:
            self._deliver_outer_app(payload, peer_id)
            return
        base_mtype = int(mtype - self._MTYPE_COMPRESSED_FLAG)
        if base_mtype not in self._KNOWN_BASE_MTYPES:
            self._decompress_fail_total += 1
            self._add_peer_counter(peer_id, "decompress_fail_total")
            self._log.warning(
                "[COMPRESS/RX] unsupported compressed mtype=0x%02X transport=%s peer_id=%r",
                int(mtype),
                self._transport_name,
                peer_id,
            )
            return
        decoded = self._safe_decompress(body, self._max_mux_payload)
        if decoded is None:
            self._decompress_fail_total += 1
            self._add_peer_counter(peer_id, "decompress_fail_total")
            self._log.warning(
                "[COMPRESS/RX] decode failed mtype=0x%02X transport=%s peer_id=%r in_len=%d cap=%d",
                int(mtype),
                self._transport_name,
                peer_id,
                len(body),
                int(self._max_mux_payload),
            )
            return
        self._decompress_ok_total += 1
        self._mark_peer_active(peer_id)
        self._add_peer_counter(peer_id, "decompress_ok_total")
        wire = self._build_mux_frame(chan_id, proto, counter, base_mtype, decoded)
        self._deliver_outer_app(wire, peer_id)

    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        parsed = self._parse_mux_frame(payload)
        if parsed is None:
            sent = self._inner.send_app(payload, peer_id=peer_id)
            return len(payload) if sent else 0
        chan_id, proto, counter, mtype, body = parsed
        stats_peer_id = self._stats_peer_id_for_send(peer_id)
        level, min_bytes, allowed_mtypes = self._send_policy(stats_peer_id)
        if (
            self._algo != "zlib"
            or not self._peer_send_enabled(stats_peer_id)
            or mtype >= self._MTYPE_COMPRESSED_FLAG
            or mtype not in self._KNOWN_BASE_MTYPES
            or mtype not in allowed_mtypes
            or len(body) < min_bytes
        ):
            sent = self._inner.send_app(payload, peer_id=peer_id)
            return len(payload) if sent else 0
        self._compress_attempts_total += 1
        self._compress_input_bytes_total += len(body)
        self._add_peer_counter(stats_peer_id, "compress_attempts_total")
        self._add_peer_counter(stats_peer_id, "compress_input_bytes_total", len(body))
        try:
            compressed = zlib.compress(body, level)
        except Exception:
            compressed = b""
        if not compressed or len(compressed) >= len(body):
            self._compress_skipped_no_gain_total += 1
            self._compress_output_bytes_total += len(body)
            self._add_peer_counter(stats_peer_id, "compress_skipped_no_gain_total")
            self._add_peer_counter(stats_peer_id, "compress_output_bytes_total", len(body))
            sent = self._inner.send_app(payload, peer_id=peer_id)
            return len(payload) if sent else 0
        self._compress_applied_total += 1
        self._compress_output_bytes_total += len(compressed)
        self._add_peer_counter(stats_peer_id, "compress_applied_total")
        self._add_peer_counter(stats_peer_id, "compress_output_bytes_total", len(compressed))
        wire = self._build_mux_frame(
            chan_id,
            proto,
            counter,
            int(mtype + self._MTYPE_COMPRESSED_FLAG),
            compressed,
        )
        sent = self._inner.send_app(wire, peer_id=peer_id)
        return len(payload) if sent else 0

    def set_on_app_payload(self, cb): self._outer_on_app = cb
    def set_on_state_change(self, cb): self._outer_on_state = cb
    def set_on_peer_rx(self, cb): self._outer_on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._outer_on_peer_tx = cb
    def set_on_peer_set(self, cb): self._outer_on_peer_set = cb
    def set_on_peer_disconnect(self, cb): self._outer_on_peer_disconnect = cb
    def set_on_app_from_peer_bytes(self, cb): self._outer_on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._outer_on_transport_epoch_change = cb

    async def start(self) -> None:
        self._inner.set_on_app_payload(self._on_inner_payload)
        self._inner.set_on_state_change(self._outer_on_state)
        self._inner.set_on_peer_rx(self._outer_on_peer_rx)
        self._inner.set_on_peer_tx(self._outer_on_peer_tx)
        self._inner.set_on_peer_set(self._outer_on_peer_set)
        self._inner.set_on_app_from_peer_bytes(self._outer_on_app_from_peer_bytes)
        self._inner.set_on_transport_epoch_change(self._outer_on_transport_epoch_change)
        try:
            self._inner.set_on_peer_disconnect(self._on_inner_peer_disconnect)
        except Exception:
            pass
        await self._inner.start()

    async def stop(self) -> None:
        await self._inner.stop()

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        return await self._inner.wait_connected(timeout)

    def is_connected(self) -> bool:
        return bool(self._inner.is_connected())

    def request_reconnect(self) -> bool:
        trigger = getattr(self._inner, "request_reconnect", None)
        if callable(trigger):
            with contextlib.suppress(Exception):
                return bool(trigger())
        return False

    def get_metrics(self) -> SessionMetrics:
        return self._inner.get_metrics()

    def get_max_app_payload_size(self) -> int:
        return int(getattr(self._inner, "get_max_app_payload_size", lambda: 65535)() or 65535)

    def _compress_snapshot_from_counters(
        self,
        counters: dict,
        *,
        enabled: bool,
        level: Optional[int] = None,
        min_bytes: Optional[int] = None,
    ) -> dict:
        return {
            "enabled": bool(enabled),
            "algorithm": self._algo,
            "transport": self._transport_name,
            "level": int(self._level if level is None else level),
            "min_bytes": int(self._min_bytes if min_bytes is None else min_bytes),
            "compress_attempts_total": int(counters.get("compress_attempts_total") or 0),
            "compress_applied_total": int(counters.get("compress_applied_total") or 0),
            "compress_skipped_no_gain_total": int(counters.get("compress_skipped_no_gain_total") or 0),
            "compress_input_bytes_total": int(counters.get("compress_input_bytes_total") or 0),
            "compress_output_bytes_total": int(counters.get("compress_output_bytes_total") or 0),
            "decompress_ok_total": int(counters.get("decompress_ok_total") or 0),
            "decompress_fail_total": int(counters.get("decompress_fail_total") or 0),
        }

    def get_compress_layer_status_snapshot(self, peer_id: Optional[int] = None) -> dict:
        if peer_id is not None:
            stats = self._peer_compress.get(self._peer_key(peer_id))
            if not isinstance(stats, dict) and self._is_peer_client:
                stats = self._peer_compress.get(self._peer_key(None))
            if not isinstance(stats, dict):
                return self._compress_snapshot_from_counters({}, enabled=bool(self._configured_enabled) if self._is_peer_client else False)
            enabled = bool(self._configured_enabled) if self._is_peer_client else bool(stats.get("active"))
            if not self._is_peer_client and enabled:
                return self._compress_snapshot_from_counters(
                    stats,
                    enabled=enabled,
                    level=self._peer_selected_level,
                    min_bytes=self._peer_selected_min_bytes,
                )
            return self._compress_snapshot_from_counters(stats, enabled=enabled)
        counters = {
            "compress_attempts_total": self._compress_attempts_total,
            "compress_applied_total": self._compress_applied_total,
            "compress_skipped_no_gain_total": self._compress_skipped_no_gain_total,
            "compress_input_bytes_total": self._compress_input_bytes_total,
            "compress_output_bytes_total": self._compress_output_bytes_total,
            "decompress_ok_total": self._decompress_ok_total,
            "decompress_fail_total": self._decompress_fail_total,
        }
        any_peer_active = any(bool(s.get("active")) for s in self._peer_compress.values() if isinstance(s, dict))
        enabled = bool(self._configured_enabled) if self._is_peer_client else bool(any_peer_active)
        return self._compress_snapshot_from_counters(counters, enabled=enabled)

