from __future__ import annotations

from typing import Any, Optional

from ._bridge_import import export_bridge_globals

_bridge = export_bridge_globals(globals())

ChannelMux = None


class ChannelMuxSharedTunMixin:
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
            "local_virtual_peers": [],
            "active_peer_bindings": [],
            "throttle_scopes": [],
            "drop_counters": {"total": 0, "by_reason": {}},
            "recent_drops": [],
        }
        if isinstance(active_peer_bindings, list):
            snapshot["active_peer_bindings"] = [
                {
                    "peer_id": int(entry.get("peer_id", 0) or 0),
                    "peer_ref": str(entry.get("peer_ref") or ""),
                    "preferred_chan_id": (
                        None if entry.get("preferred_chan_id") is None else int(entry.get("preferred_chan_id"))
                    ),
                    "bound_chan_ids": [int(v) for v in list(entry.get("bound_chan_ids") or [])],
                    "ipv4": [str(v) for v in list(entry.get("ipv4") or [])],
                    "ipv6": [str(v) for v in list(entry.get("ipv6") or [])],
                    "address_count": int(entry.get("address_count", 0) or 0),
                    "local_virtual": bool(entry.get("local_virtual")),
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
        peer_details_by_ref = {
            str(entry.get("peer_ref") or ""): {
                "peer_ref": str(entry.get("peer_ref") or ""),
                "ipv4": [str(v) for v in list(entry.get("ipv4") or [])],
                "ipv6": [str(v) for v in list(entry.get("ipv6") or [])],
                "address_count": int(entry.get("address_count", 0) or 0),
            }
            for entry in list(ownership.get("peers") or [])
            if isinstance(entry, dict) and str(entry.get("peer_ref") or "")
        }
        active_peer_bindings = self._shared_tun_active_peer_bindings_for_service(svc_key)
        throttle_scopes = self._shared_tun_throttle_scope_snapshots_for_service(svc_key)
        throttle_by_peer: dict[int, dict[str, Any]] = {}
        for scope in throttle_scopes:
            selected_peer_ids = [int(v) for v in list(scope.get("selected_peer_ids") or [])]
            if len(selected_peer_ids) == 1:
                throttle_by_peer[int(selected_peer_ids[0])] = scope
        for entry in active_peer_bindings:
            if not str(entry.get("peer_ref") or ""):
                peer_id = int(entry.get("peer_id", 0) or 0)
                peer_ref = str(self._shared_tun_peer_ref_by_peer.get((svc_key, peer_id)) or "")
                if not peer_ref:
                    peer_ref = next(
                        (
                            str(mapped_peer_ref)
                            for (mapped_svc_key, mapped_peer_ref), mapped_peer_id in self._shared_tun_peer_id_by_ref.items()
                            if mapped_svc_key == svc_key and int(mapped_peer_id) == peer_id
                        ),
                        "",
                    )
                entry["peer_ref"] = peer_ref
            scope = throttle_by_peer.get(int(entry.get("peer_id", 0) or 0))
            if not isinstance(scope, dict):
                scope = None
            if isinstance(scope, dict):
                entry["throttle_prev_window_bytes"] = int(scope.get("prev_window_bytes", 0) or 0)
                entry["throttle_curr_window_bytes"] = int(scope.get("curr_window_bytes", 0) or 0)
                entry["throttle_drop_count"] = int(scope.get("throttle_drop_count", 0) or 0)
            if bool(entry.get("local_virtual")):
                continue
            peer_details = peer_details_by_ref.get(str(entry.get("peer_ref") or ""))
            if peer_details is None and len(peer_details_by_ref) == 1:
                peer_details = next(iter(peer_details_by_ref.values()))
                entry["peer_ref"] = str(peer_details.get("peer_ref") or "")
            if isinstance(peer_details, dict):
                entry["ipv4"] = list(peer_details.get("ipv4") or [])
                entry["ipv6"] = list(peer_details.get("ipv6") or [])
                entry["address_count"] = int(peer_details.get("address_count", 0) or 0)
            else:
                entry["ipv4"] = []
                entry["ipv6"] = []
                entry["address_count"] = 0
            entry["local_virtual"] = False
        local_virtual_peer = next(
            (entry for entry in active_peer_bindings if bool(entry.get("local_virtual"))),
            None,
        )
        drop_state = self._shared_tun_drop_state_by_service.get(svc_key)
        snapshot = self._shared_tun_runtime_snapshot(ownership, active_peer_bindings, throttle_scopes, drop_state)
        if snapshot is None:
            return None
        if local_virtual_peer is not None:
            snapshot["local_virtual_peers"] = [
                {
                    "peer_id": int(local_virtual_peer.get("peer_id", self.SHARED_TUN_LOCAL_PROBE_PEER_ID) or self.SHARED_TUN_LOCAL_PROBE_PEER_ID),
                    "peer_ref": str(local_virtual_peer.get("peer_ref") or self.SHARED_TUN_LOCAL_PROBE_PEER_REF),
                    "ipv4": [str(v) for v in list(local_virtual_peer.get("ipv4") or [])],
                    "ipv6": [str(v) for v in list(local_virtual_peer.get("ipv6") or [])],
                    "address_count": int(local_virtual_peer.get("address_count", 0) or 0),
                }
            ]
            for addr in list(local_virtual_peer.get("ipv4") or []):
                snapshot["owner_by_ipv4"][str(addr)] = str(local_virtual_peer.get("peer_ref") or self.SHARED_TUN_LOCAL_PROBE_PEER_REF)
            for addr in list(local_virtual_peer.get("ipv6") or []):
                snapshot["owner_by_ipv6"][str(addr)] = str(local_virtual_peer.get("peer_ref") or self.SHARED_TUN_LOCAL_PROBE_PEER_REF)
        return snapshot
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
    def _shared_tun_owner_ref_for_source_ip(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        source_ip: str,
    ) -> str:
        if svc_key is None or not source_ip:
            return ""
        ownership = self._shared_tun_ownership_by_service.get(svc_key)
        if not isinstance(ownership, dict):
            return ""
        owner_by_ipv4 = dict(ownership.get("owner_by_ipv4") or {})
        owner_by_ipv6 = dict(ownership.get("owner_by_ipv6") or {})
        return str(owner_by_ipv4.get(str(source_ip)) or owner_by_ipv6.get(str(source_ip)) or "")
    def _recover_shared_tun_channel_owner(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
        *,
        chan: int,
        source_ip: str,
        owner_ref: str,
    ) -> tuple[Optional[int], str]:
        if svc_key is None or not owner_ref:
            return None, "owner_unavailable"
        owner_candidates: set[int] = set()
        mapped_peer_id = self._shared_tun_peer_id_by_ref.get((svc_key, str(owner_ref)))
        if mapped_peer_id is not None:
            owner_candidates.add(int(mapped_peer_id))
        for (mapped_svc_key, mapped_peer_id), mapped_peer_ref in self._shared_tun_peer_ref_by_peer.items():
            if mapped_svc_key == svc_key and str(mapped_peer_ref) == str(owner_ref):
                owner_candidates.add(int(mapped_peer_id))
        bound_candidates: set[int] = set()
        for (mapped_svc_key, mapped_peer_id), state in self._shared_tun_runtime_by_peer.items():
            if mapped_svc_key != svc_key or not isinstance(state, dict):
                continue
            bound_chan_ids = [int(v) for v in list(state.get("bound_chan_ids") or [])]
            if int(chan) in bound_chan_ids:
                bound_candidates.add(int(mapped_peer_id))
        selected: Optional[int] = None
        detail = "no_candidate"
        intersect = owner_candidates & bound_candidates
        if len(intersect) == 1:
            selected = next(iter(intersect))
            detail = "owner_and_bound_match"
        elif len(owner_candidates) == 1 and not bound_candidates:
            selected = next(iter(owner_candidates))
            detail = "owner_mapping_match"
        elif len(bound_candidates) == 1 and not owner_candidates:
            selected = next(iter(bound_candidates))
            detail = "bound_channel_match"
        elif len(bound_candidates) == 1 and len(owner_candidates) > 1 and next(iter(bound_candidates)) in owner_candidates:
            selected = next(iter(bound_candidates))
            detail = "bound_channel_with_ambiguous_owner_map"
        if selected is None:
            return None, detail
        peer_key = (svc_key, int(selected))
        self._chan_owner_peer_id[int(chan)] = int(selected)
        self._shared_tun_peer_ref_by_peer[peer_key] = str(owner_ref)
        self._shared_tun_peer_id_by_ref[(svc_key, str(owner_ref))] = int(selected)
        self._record_shared_tun_peer_binding(svc_key, int(selected), int(chan))
        return int(selected), detail
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
            internal_probe = ChannelMux._parse_internal_tun_probe_packet(packet)
            if internal_probe and str(internal_probe.get("direction") or "") == "request":
                selected = [
                    entry
                    for entry in active_peer_bindings
                    if entry.get("preferred_chan_id") is not None
                ]
                selected.sort(key=lambda entry: int(entry.get("peer_id", 0) or 0))
                return {
                    "routed": bool(selected),
                    "route_class": "internal_probe",
                    "selected_peer_ids": [int(entry.get("peer_id", 0) or 0) for entry in selected],
                    "selected_chan_ids": [int(entry.get("preferred_chan_id")) for entry in selected],
                    "ip_version": int(parsed.get("ip_version", 0) or 0),
                    "destination_ip": destination_ip,
                    "drop_reason": None if selected else "internal_probe_no_active_peers",
                }
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
        ownership = dict(ownership)
        owner_by_ipv4 = {str(k): str(v) for k, v in dict(ownership.get("owner_by_ipv4") or {}).items()}
        owner_by_ipv6 = {str(k): str(v) for k, v in dict(ownership.get("owner_by_ipv6") or {}).items()}
        peer_id_by_ref = {
            str(peer_ref): int(peer_id)
            for (mapped_svc_key, peer_ref), peer_id in self._shared_tun_peer_id_by_ref.items()
            if mapped_svc_key == svc_key
        }
        local_virtual_peer = self._shared_tun_local_probe_binding_for_service(svc_key)
        if isinstance(local_virtual_peer, dict):
            peer_ref = str(local_virtual_peer.get("peer_ref") or self.SHARED_TUN_LOCAL_PROBE_PEER_REF)
            peer_id_by_ref[str(local_virtual_peer.get("peer_ref") or self.SHARED_TUN_LOCAL_PROBE_PEER_REF)] = int(
                local_virtual_peer.get("peer_id", self.SHARED_TUN_LOCAL_PROBE_PEER_ID) or self.SHARED_TUN_LOCAL_PROBE_PEER_ID
            )
            for addr in list(local_virtual_peer.get("ipv4") or []):
                owner_by_ipv4[str(addr)] = peer_ref
            for addr in list(local_virtual_peer.get("ipv6") or []):
                owner_by_ipv6[str(addr)] = peer_ref
        ownership["owner_by_ipv4"] = owner_by_ipv4
        ownership["owner_by_ipv6"] = owner_by_ipv6
        active_peer_bindings = self._shared_tun_active_peer_bindings_for_service(svc_key)
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
        internal_probe = self._parse_internal_tun_probe_packet(packet)
        if internal_probe and str(internal_probe.get("direction") or "") == "reply":
            waiter_key = (
                int(internal_probe.get("family") or 0),
                int(internal_probe.get("identifier") or 0),
                int(internal_probe.get("sequence") or 0),
                bytes(internal_probe.get("nonce") or b""),
            )
            if waiter_key in self._tun_probe_waiters:
                return True, parsed, None
        source_ip = str(parsed.get("source_ip") or "")
        owner_ref = self._shared_tun_owner_ref_for_source_ip(svc_key, source_ip)
        peer_id = self._chan_owner_peer_id.get(int(chan))
        if peer_id is None and owner_ref:
            recovered_peer_id, recovery_detail = self._recover_shared_tun_channel_owner(
                svc_key,
                chan=int(chan),
                source_ip=source_ip,
                owner_ref=owner_ref,
            )
            if recovered_peer_id is not None:
                peer_id = int(recovered_peer_id)
                self._set_tun_runtime_health_warning(
                    svc_key,
                    code="shared_tun_channel_owner_recovered",
                    severity="warning",
                    summary="Shared-TUN peer identity was missing and had to be recovered from runtime binding state.",
                    detail=(
                        f"Recovered chan {int(chan)} -> peer {int(peer_id)} for source {source_ip} "
                        f"owned by {owner_ref} using {recovery_detail}."
                    ),
                    ifname=str(getattr(dev, "ifname", "") or ""),
                    chan_id=int(chan),
                    peer_id=int(peer_id),
                    source_ip=source_ip,
                    owner_ref=str(owner_ref),
                    recovery_detail=str(recovery_detail),
                )
                self.log.warning(
                    "[TUN/SHARED] recovered missing chan owner if=%s chan=%s peer_id=%s owner_ref=%s source_ip=%s detail=%s",
                    str(getattr(dev, "ifname", "") or ""),
                    int(chan),
                    int(peer_id),
                    str(owner_ref),
                    source_ip,
                    str(recovery_detail),
                )
            else:
                self._set_tun_runtime_health_warning(
                    svc_key,
                    code="shared_tun_channel_owner_missing",
                    severity="critical",
                    summary="Shared-TUN packet source is owned by a configured peer, but the inbound channel lost its peer identity.",
                    detail=(
                        f"Dropping chan {int(chan)} source {source_ip} owned by {owner_ref}: "
                        f"could not recover chan->peer mapping ({recovery_detail})."
                    ),
                    ifname=str(getattr(dev, "ifname", "") or ""),
                    chan_id=int(chan),
                    source_ip=source_ip,
                    owner_ref=str(owner_ref),
                    recovery_detail=str(recovery_detail),
                )
                self.log.critical(
                    "[TUN/SHARED] inbound channel missing peer identity if=%s chan=%s source_ip=%s owner_ref=%s detail=%s",
                    str(getattr(dev, "ifname", "") or ""),
                    int(chan),
                    source_ip,
                    str(owner_ref),
                    str(recovery_detail),
                )
                return False, parsed, "source_peer_identity_missing"
        bound_peer_ref = self._shared_tun_bound_peer_ref_for_packet(svc_key, peer_id, source_ip)
        if bound_peer_ref is None:
            return False, parsed, "source_not_owned_by_peer"
        self._clear_tun_runtime_health_codes(
            svc_key,
            "shared_tun_channel_owner_missing",
        )
        return True, parsed, None
    def _shared_tun_open_requested(self, spec: "ChannelMux.ServiceSpec") -> bool:
        return self._shared_tun_ownership_snapshot_for_spec(spec) is not None
    def _local_ingress_throttle_snapshot_for_shared_tun_service(
        self,
        svc_key: "ChannelMux.ServiceKey",
        *,
        now_ns: Optional[int] = None,
    ) -> dict[str, Any]:
        if now_ns is None:
            now_ns = time.monotonic_ns()
        aggregate_snapshot = self._local_ingress_throttle_snapshot_for_scope(
            self._aggregate_local_ingress_scope_key(),
            now_ns=now_ns,
        )
        shared_scopes = self._shared_tun_throttle_scope_snapshots_for_service(svc_key)
        worst_scope: Optional[dict[str, Any]] = None
        for entry in shared_scopes:
            prev_window_bytes = int(entry.get("prev_window_bytes", 0) or 0)
            allowance_bytes = int(float(prev_window_bytes) * self.OVERLAY_BACKPRESSURE_THROTTLE_RATIO)
            used_bytes = int(entry.get("curr_window_bytes", 0) or 0)
            remaining_bytes = max(0, allowance_bytes - used_bytes)
            scoped = {
                "scope_id": str(entry.get("scope_id") or ""),
                "budget_bytes": allowance_bytes,
                "used_bytes": used_bytes,
                "remaining_bytes": remaining_bytes,
                "prev_window_bytes": prev_window_bytes,
                "throttle_drop_count": int(entry.get("throttle_drop_count", 0) or 0),
            }
            if worst_scope is None or scoped["remaining_bytes"] < worst_scope["remaining_bytes"]:
                worst_scope = scoped
        active = bool(aggregate_snapshot.get("active"))
        remaining_candidates = [int(aggregate_snapshot.get("remaining_bytes", 0) or 0)]
        if worst_scope is not None:
            remaining_candidates.append(int(worst_scope.get("remaining_bytes", 0) or 0))
        return {
            "applicable": True,
            "scope_id": f"shared-service:{svc_key[0]}:{svc_key[1]}:{svc_key[2]}",
            "mode": "aggregate_and_shared_service" if worst_scope is not None else "aggregate_only",
            "active": active,
            "stalled": bool(aggregate_snapshot.get("stalled")),
            "backpressure_active": bool(aggregate_snapshot.get("backpressure_active")),
            "disabled": bool(aggregate_snapshot.get("disabled")),
            "transport_prev_window_bytes": int(aggregate_snapshot.get("transport_prev_window_bytes", 0) or 0),
            "waiting_count": int(aggregate_snapshot.get("waiting_count", 0) or 0),
            "inflight": int(aggregate_snapshot.get("inflight", 0) or 0),
            "max_inflight": int(aggregate_snapshot.get("max_inflight", 0) or 0),
            "transmit_delay_est_ms": float(aggregate_snapshot.get("transmit_delay_est_ms", 0.0) or 0.0),
            "budget_bytes": min(remaining_candidates) + int(aggregate_snapshot.get("aggregate", {}).get("used_bytes", 0) or 0),
            "used_bytes": max(
                int(aggregate_snapshot.get("aggregate", {}).get("used_bytes", 0) or 0),
                int(worst_scope.get("used_bytes", 0) or 0) if worst_scope else 0,
            ),
            "remaining_bytes": min(remaining_candidates),
            "aggregate": dict(aggregate_snapshot.get("aggregate") or {}),
            "scope": worst_scope,
        }
    def _normalize_local_tun_packet_source(
        self,
        dev: "ChannelMux.TunDevice",
        packet: bytes,
    ) -> bytes:
        parsed, parse_error = self._parse_tun_packet_endpoints(packet)
        if parse_error is not None or not isinstance(parsed, dict):
            return packet
        version = int(parsed.get("ip_version", 0) or 0)
        source_ip = str(parsed.get("source_ip") or "")
        svc_key = getattr(dev, "service_key", None)
        if not isinstance(svc_key, tuple) or str(svc_key[0]) != "local":
            return packet
        spec = self._effective_services_by_id().get(svc_key)
        if spec is not None and self._shared_tun_ownership_snapshot_for_spec(spec) is not None:
            return packet
        if version == 4:
            new_source = str(self._tun_routing_config().tunnel_address or "").strip()
            if not new_source or source_ip == new_source:
                return packet
            if self._tun_routing_config().shared_tun_disable_outgoing_normalization:
                warn_key = (str(dev.ifname or ""), source_ip, new_source)
                if warn_key not in self._shared_tun_normalization_warned:
                    self._shared_tun_normalization_warned.add(warn_key)
                    self.log.warning(
                        "[TUN] if=%s outgoing normalization disabled; keeping source=%s instead of configured tunnel source=%s",
                        dev.ifname,
                        source_ip,
                        new_source,
                    )
                return packet
            return self._rewrite_ipv4_source(packet, new_source)
        if version == 6:
            new_source = str(self._tun_routing_config().tunnel_address6 or "").strip()
            if not new_source or source_ip == new_source:
                return packet
            if self._tun_routing_config().shared_tun_disable_outgoing_normalization:
                warn_key = (str(dev.ifname or ""), source_ip, new_source)
                if warn_key not in self._shared_tun_normalization_warned:
                    self._shared_tun_normalization_warned.add(warn_key)
                    self.log.warning(
                        "[TUN] if=%s outgoing normalization disabled; keeping source=%s instead of configured tunnel source=%s",
                        dev.ifname,
                        source_ip,
                        new_source,
                    )
                return packet
            return self._rewrite_ipv6_source(packet, new_source)
        return packet
    def _dispatch_shared_tun_inbound_packet(
        self,
        dev: "ChannelMux.TunDevice",
        data: bytes,
        *,
        source_peer_id: int,
        source_chan_id: Optional[int],
        source_note: str,
    ) -> str:
        def _trace_result(result: str, note: str = "") -> str:
            self._log_tun_probe_trace(
                stage=f"inbound_dispatch_{source_note}_result",
                packet=data,
                ifname=str(getattr(dev, "ifname", "") or ""),
                chan=source_chan_id,
                peer_id=source_peer_id,
                note=f"result={result}" + (f"; {note}" if note else ""),
            )
            return result

        self._log_tun_probe_trace(
            stage=f"inbound_dispatch_{source_note}",
            packet=data,
            ifname=str(getattr(dev, "ifname", "") or ""),
            chan=source_chan_id,
            peer_id=source_peer_id,
            note="before_probe_reply_observe",
        )
        if self._observe_tun_probe_reply(dev, data):
            self._record_tun_probe_boundary("probe_reply_consumed_before_local_write")
            self.log.debug(
                "[TUN] source=%s chan=%s consumed internal probe reply if=%s",
                source_note,
                source_chan_id,
                dev.ifname,
            )
            return _trace_result("consumed")
        parsed, _ = self._parse_tun_packet_endpoints(data)
        if len(data) > int(dev.mtu):
            self.log.warning(
                "[TUN] source=%s chan=%s drop oversize packet len=%s mtu=%s",
                source_note,
                source_chan_id,
                len(data),
                dev.mtu,
            )
            self._record_shared_tun_drop(
                getattr(dev, "service_key", None),
                reason="oversize_inbound_packet",
                direction="peer_to_local" if source_peer_id != self.SHARED_TUN_LOCAL_PROBE_PEER_ID else "virtual_to_local",
                peer_id=source_peer_id,
                chan_id=source_chan_id,
                ip_version=None if parsed is None else parsed.get("ip_version"),
                source_ip=None if parsed is None else parsed.get("source_ip"),
                destination_ip=None if parsed is None else parsed.get("destination_ip"),
                packet_bytes=len(data),
            )
            return _trace_result("dropped", note="reason=oversize")
        shared_relay = self._shared_tun_plan_inbound_peer_relay(
            getattr(dev, "service_key", None),
            source_peer_id,
            data,
        )
        if shared_relay is not None and bool(shared_relay.get("relay_to_peer")):
            selected_chan_ids = [int(v) for v in list(shared_relay.get("selected_chan_ids") or [])]
            for selected_chan in selected_chan_ids:
                if self._is_local_virtual_probe_chan_id(selected_chan):
                    self._handle_local_virtual_probe_delivery(
                        dev,
                        data,
                        route_class=str(shared_relay.get("route_class") or ""),
                    )
                    continue
                target_ctr = self._ctr(ChannelMux.Proto.TUN, selected_chan)
                target_ctr.msgs_in += 1
                target_ctr.bytes_in += len(data)
                self._send_mux(selected_chan, ChannelMux.Proto.TUN, ChannelMux.MType.DATA, data)
            self.log.debug(
                "[TUN] source=%s chan=%s relay shared peer packet if=%s dst=%s relay_peers=%s relay_chans=%s",
                source_note,
                source_chan_id,
                dev.ifname,
                shared_relay.get("destination_ip"),
                shared_relay.get("selected_peer_ids"),
                shared_relay.get("selected_chan_ids"),
            )
            return _trace_result(
                "relayed",
                note=(
                    f"route_class={shared_relay.get('route_class') or ''}; "
                    f"selected_chans={','.join(str(v) for v in selected_chan_ids)}"
                ),
            )
        self._write_tun_packet(dev, data)
        if source_chan_id is not None and not self._is_local_virtual_probe_chan_id(source_chan_id):
            ctr = self._ctr(ChannelMux.Proto.TUN, source_chan_id)
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
        return _trace_result("written")
