from __future__ import annotations

from . import bridge as _bridge
from .bridge_transport_common import _has_configured_overlay_peer

globals().update({
    key: value
    for key, value in _bridge.__dict__.items()
    if key not in {"__builtins__", "__name__", "__package__", "__file__", "__cached__", "__doc__", "__spec__", "__loader__"}
})

@dataclass
class _SecureLinkIdentity:
    cert_body: dict
    cert_body_bytes: bytes
    cert_sig: bytes
    private_key: Any
    public_key: Any
    public_key_der: bytes
    trust_anchor_public_key: Any
    trust_anchor_der: bytes
    trust_anchor_id: str
    issuer_id: str
    serial: str
    subject_id: str
    subject_name: str
    deployment_id: str
    roles: List[str]


def _secure_link_canonical_cert_body_bytes(body: dict) -> bytes:
    if not isinstance(body, dict):
        raise ValueError("certificate body must be a JSON object")
    if "signature" in body:
        raise ValueError("certificate body must not include inline signature field")
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _secure_link_parse_timestamp(value: str) -> float:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("timestamp is required")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _secure_link_load_signature_bytes(path: pathlib.Path) -> bytes:
    raw = path.read_bytes()
    stripped = bytes(raw).strip()
    if not stripped:
        raise ValueError(f"empty signature file: {path}")
    with contextlib.suppress(Exception):
        return base64.b64decode(stripped, validate=True)
    return bytes(raw)


def _secure_link_load_revoked_serials(path: Optional[pathlib.Path]) -> Set[str]:
    if path is None:
        return set()
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return set()
    with contextlib.suppress(Exception):
        payload = json.loads(stripped)
        if isinstance(payload, list):
            return {str(item).strip() for item in payload if str(item).strip()}
    return {line.strip() for line in text.splitlines() if line.strip()}


def _secure_link_public_key_der_b64_to_obj(encoded: str) -> Tuple[Any, bytes]:
    if serialization is None:
        raise RuntimeError("secure-link cryptography helpers are unavailable")
    try:
        der = base64.b64decode(str(encoded or "").encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"invalid public_key encoding: {exc}") from exc
    try:
        pub = serialization.load_der_public_key(der)
    except Exception as exc:
        raise ValueError(f"invalid public_key DER: {exc}") from exc
    return pub, der


def _secure_link_load_identity_from_paths(
    *,
    root_pub_path: pathlib.Path,
    cert_body_path: pathlib.Path,
    cert_sig_path: pathlib.Path,
    private_key_path: pathlib.Path,
) -> _SecureLinkIdentity:
    if serialization is None or ed25519 is None:
        raise RuntimeError("secure-link certificate mode requires 'cryptography'")

    try:
        trust_anchor_public_key = serialization.load_pem_public_key(root_pub_path.read_bytes())
    except Exception as exc:
        raise ValueError(f"failed to load secure_link_root_pub from {root_pub_path}: {exc}") from exc
    if not isinstance(trust_anchor_public_key, ed25519.Ed25519PublicKey):
        raise ValueError("secure_link_root_pub must contain an Ed25519 public key")
    trust_anchor_der = trust_anchor_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_anchor_id = hashlib.sha256(trust_anchor_der).hexdigest()[:16]

    try:
        cert_body = json.loads(cert_body_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to parse secure_link_cert_body from {cert_body_path}: {exc}") from exc
    cert_body_bytes = _secure_link_canonical_cert_body_bytes(cert_body)
    cert_sig = _secure_link_load_signature_bytes(cert_sig_path)

    required = (
        "version", "serial", "issuer_id", "subject_id", "subject_name", "deployment_id",
        "public_key_algorithm", "public_key", "roles", "issued_at", "not_before",
        "not_after", "constraints", "signature_algorithm",
    )
    missing = [key for key in required if key not in cert_body]
    if missing:
        raise ValueError(f"certificate body missing required field(s): {', '.join(missing)}")
    if int(cert_body.get("version") or 0) != 1:
        raise ValueError("certificate body version must be 1")
    if str(cert_body.get("public_key_algorithm") or "") != "Ed25519":
        raise ValueError("certificate public_key_algorithm must be Ed25519")
    if str(cert_body.get("signature_algorithm") or "") != "Ed25519":
        raise ValueError("certificate signature_algorithm must be Ed25519")
    roles = cert_body.get("roles") or []
    if not isinstance(roles, list) or not roles:
        raise ValueError("certificate roles must be a non-empty list")

    public_key, public_key_der = _secure_link_public_key_der_b64_to_obj(str(cert_body.get("public_key") or ""))
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("certificate public_key must decode to an Ed25519 public key")
    try:
        trust_anchor_public_key.verify(cert_sig, cert_body_bytes)
    except Exception as exc:
        raise ValueError(f"certificate signature verification failed: {exc}") from exc

    try:
        private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    except Exception as exc:
        raise ValueError(f"failed to load secure_link_private_key from {private_key_path}: {exc}") from exc
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("secure_link_private_key must contain an Ed25519 private key")
    local_public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if local_public_der != public_key_der:
        raise ValueError("secure_link_private_key does not match certified public_key")

    return _SecureLinkIdentity(
        cert_body=dict(cert_body),
        cert_body_bytes=cert_body_bytes,
        cert_sig=cert_sig,
        private_key=private_key,
        public_key=public_key,
        public_key_der=public_key_der,
        trust_anchor_public_key=trust_anchor_public_key,
        trust_anchor_der=trust_anchor_der,
        trust_anchor_id=trust_anchor_id,
        issuer_id=str(cert_body.get("issuer_id") or ""),
        serial=str(cert_body.get("serial") or ""),
        subject_id=str(cert_body.get("subject_id") or ""),
        subject_name=str(cert_body.get("subject_name") or ""),
        deployment_id=str(cert_body.get("deployment_id") or ""),
        roles=[str(role) for role in roles],
    )


def _secure_link_validate_local_identity_operational(
    identity: _SecureLinkIdentity,
    *,
    revoked_serials: Set[str],
    now_ts: Optional[float] = None,
) -> None:
    current_ts = float(time.time() if now_ts is None else now_ts)
    try:
        not_before = _secure_link_parse_timestamp(str(identity.cert_body.get("not_before") or ""))
        not_after = _secure_link_parse_timestamp(str(identity.cert_body.get("not_after") or ""))
    except Exception as exc:
        raise ValueError(f"local certificate validity fields are invalid: {exc}") from exc
    if current_ts < not_before:
        raise ValueError("local certificate is not valid yet")
    if current_ts > not_after:
        raise ValueError("local certificate has expired")
    if str(identity.serial or "") in set(revoked_serials or set()):
        raise ValueError("local certificate serial is revoked")


@dataclass
class _SecureLinkPeerState:
    session_id: int
    client_nonce: bytes
    server_nonce: bytes = b""
    c2s_key: Optional[bytes] = None
    s2c_key: Optional[bytes] = None
    authenticated: bool = False
    client_handshake_proof_sent: bool = False
    tx_counter: int = 1
    rx_counter: int = 0
    pending_session_id: int = 0
    pending_client_nonce: bytes = b""
    pending_server_nonce: bytes = b""
    pending_c2s_key: Optional[bytes] = None
    pending_s2c_key: Optional[bytes] = None
    auth_fail_code: int = 0
    auth_fail_reason: str = ""
    auth_fail_detail: str = ""
    auth_fail_unix_ts: Optional[float] = None
    consecutive_failures: int = 0
    handshake_attempts_total: int = 0
    last_event: str = ""
    last_event_unix_ts: Optional[float] = None
    last_authenticated_unix_ts: Optional[float] = None
    connected_since_unix_ts: Optional[float] = None
    last_rekey_trigger: str = ""
    rekey_due_unix_ts: Optional[float] = None
    last_failure_session_id: Optional[int] = None
    authenticated_sessions_total: int = 0
    rekeys_completed_total: int = 0
    local_ephemeral_private: Any = None
    pending_local_ephemeral_private: Any = None
    peer_subject_id: str = ""
    peer_subject_name: str = ""
    peer_roles: List[str] = field(default_factory=list)
    peer_deployment_id: str = ""
    peer_serial: str = ""
    issuer_id: str = ""
    trust_anchor_id: str = ""
    peer_public_key: Any = None
    peer_public_key_der: bytes = b""
    trust_validation_state: str = ""
    trust_failure_reason: str = ""
    trust_failure_detail: str = ""
    active_material_generation: int = 0
    last_material_reload_unix_ts: Optional[float] = None
    last_material_reload_scope: str = ""
    last_material_reload_result: str = ""
    last_material_reload_detail: str = ""
    trust_enforced_unix_ts: Optional[float] = None
    disconnect_reason: str = ""
    disconnect_detail: str = ""


class SecureLinkPskSession(ISession):
    _SL_VERSION = 1
    _SL_TYPE_CLIENT_HELLO = 1
    _SL_TYPE_SERVER_HELLO = 2
    _SL_TYPE_AUTH_FAIL = 3
    _SL_TYPE_DATA = 4
    _SL_TYPE_REKEY_HELLO = 5
    _SL_TYPE_REKEY_REPLY = 6
    _SL_TYPE_REKEY_COMMIT = 7
    _SL_TYPE_REKEY_DONE = 8
    _SL_CAP_PSK_V1 = 1
    _SL_CAP_CERT_V1 = 2
    _SL_AUTH_FAIL_BAD_PSK = 1
    _SL_AUTH_FAIL_UNSUPPORTED = 2
    _SL_AUTH_FAIL_REPLAY = 3
    _SL_AUTH_FAIL_DECODE = 4
    _SL_AUTH_FAIL_LIFECYCLE = 5
    _SL_AUTH_FAIL_UNKNOWN_ROOT = 6
    _SL_AUTH_FAIL_BAD_SIGNATURE = 7
    _SL_AUTH_FAIL_BAD_IDENTITY_PROOF = 8
    _SL_AUTH_FAIL_WRONG_ROLE = 9
    _SL_AUTH_FAIL_EXPIRED = 10
    _SL_AUTH_FAIL_NOT_YET_VALID = 11
    _SL_AUTH_FAIL_DEPLOYMENT_MISMATCH = 12
    _SL_AUTH_FAIL_REVOKED_SERIAL = 13
    _SL_AUTH_FAIL_MALFORMED_CERTIFICATE = 14
    _SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM = 15
    _SL_HDR = struct.Struct(">BBBBQQ")
    _SL_FIRST_DATA_COUNTER = 1
    _SL_MAX_DATA_COUNTER = (1 << 64) - 1

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--secure-link'):
            p.add_argument(
                '--secure-link',
                action='store_true',
                default=False,
                help='Enable the secure-link prototype. Phase 1 currently supports PSK mode over myudp, tcp, ws, and quic.'
            )
        if not _has('--secure-link-mode'):
            p.add_argument(
                '--secure-link-mode',
                choices=('off', 'psk', 'cert'),
                default='off',
                help='Secure-link mode. Supported values are off, psk, and cert.'
            )
        if not _has('--secure-link-psk'):
            p.add_argument(
                '--secure-link-psk',
                default='',
                help='Pre-shared secret for secure-link PSK mode. Both peers must use the same non-empty value.'
            )
        if not _has('--secure-link-require'):
            p.add_argument(
                '--secure-link-require',
                action='store_true',
                default=False,
                help='Fail closed if secure-link cannot be negotiated or authenticated.'
            )
        if not _has('--secure-link-rekey-after-frames'):
            p.add_argument(
                '--secure-link-rekey-after-frames',
                type=int,
                default=0,
                help='Automatically initiate PSK rekey after this many protected data frames are sent. 0 disables rekeying.'
            )
        if not _has('--secure-link-rekey-after-seconds'):
            p.add_argument(
                '--secure-link-rekey-after-seconds',
                type=float,
                default=0.0,
                help='Automatically initiate PSK rekey after this many authenticated seconds. 0 disables time-based rekeying.'
            )
        if not _has('--secure-link-retry-backoff-initial-ms'):
            p.add_argument(
                '--secure-link-retry-backoff-initial-ms',
                type=int,
                default=1000,
                help='Initial client-side secure-link retry backoff after authentication failure, in milliseconds.'
            )
        if not _has('--secure-link-retry-backoff-max-ms'):
            p.add_argument(
                '--secure-link-retry-backoff-max-ms',
                type=int,
                default=5000,
                help='Maximum client-side secure-link retry backoff after repeated authentication failures, in milliseconds.'
            )
        if not _has('--secure-link-recover-after-failure'):
            try:
                p.add_argument(
                    '--secure-link-recover-after-failure',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='Reconnect the lower client transport after an already-authenticated secure-link session fails closed.'
                )
            except Exception:
                p.add_argument(
                    '--secure-link-recover-after-failure',
                    action='store_true',
                    default=True,
                    help='Reconnect the lower client transport after an already-authenticated secure-link session fails closed.'
                )
        if not _has('--secure-link-recover-delay-seconds'):
            p.add_argument(
                '--secure-link-recover-delay-seconds',
                type=float,
                default=30.0,
                help='Delay before reconnecting a lower client transport after authenticated secure-link failure recovery.'
            )
        if not _has('--secure-link-root-pub'):
            p.add_argument(
                '--secure-link-root-pub',
                default='',
                help='Path to the deployment admin root public key PEM for secure_link_mode=cert.'
            )
        if not _has('--secure-link-cert-body'):
            p.add_argument(
                '--secure-link-cert-body',
                default='',
                help='Path to the local secure-link certificate body JSON for secure_link_mode=cert.'
            )
        if not _has('--secure-link-cert-sig'):
            p.add_argument(
                '--secure-link-cert-sig',
                default='',
                help='Path to the detached secure-link certificate signature file for secure_link_mode=cert.'
            )
        if not _has('--secure-link-private-key'):
            p.add_argument(
                '--secure-link-private-key',
                default='',
                help='Path to the local secure-link identity private key PEM for secure_link_mode=cert.'
            )
        if not _has('--secure-link-revoked-serials'):
            p.add_argument(
                '--secure-link-revoked-serials',
                default='',
                help='Optional path to a JSON array or line-based list of revoked certificate serials.'
            )
        if not _has('--secure-link-cert-reload-on-restart'):
            try:
                p.add_argument(
                    '--secure-link-cert-reload-on-restart',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='Reload certificate material on process restart. In cert mode, operators can also trigger live reload through the admin API or WebAdmin.'
                )
            except Exception:
                p.add_argument(
                    '--secure-link-cert-reload-on-restart',
                    action='store_true',
                    default=True,
                    help='Reload certificate material on process restart. In cert mode, operators can also trigger live reload through the admin API or WebAdmin.'
                )

    def __init__(self, inner: ISession, args: argparse.Namespace, transport_name: str):
        self._inner = inner
        self._real = getattr(inner, "_real", inner)
        self._args = args
        self._transport_name = str(transport_name)
        self._log = logging.getLogger("secure_link")
        if self._log.level == logging.NOTSET:
            self._log.setLevel(logging.WARNING)
        self._outer_on_app: Optional[Callable[..., None]] = None
        self._outer_on_state: Optional[Callable[[bool], None]] = None
        self._outer_on_peer_rx: Optional[Callable[[int], None]] = None
        self._outer_on_peer_tx: Optional[Callable[[int], None]] = None
        self._outer_on_peer_set: Optional[Callable[[str, int], None]] = None
        self._outer_on_peer_disconnect: Optional[Callable[[int], None]] = None
        self._outer_on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._outer_on_transport_epoch_change: Optional[Callable[[int], None]] = None
        self._client_mode = _has_configured_overlay_peer(args, self._transport_name)
        self._mode = str(getattr(args, "secure_link_mode", "off") or "off").strip().lower()
        self._psk = str(getattr(args, "secure_link_psk", "") or "").encode("utf-8")
        self._rekey_after_frames = max(0, int(getattr(args, "secure_link_rekey_after_frames", 0) or 0))
        self._rekey_after_seconds = max(0.0, float(getattr(args, "secure_link_rekey_after_seconds", 0.0) or 0.0))
        self._retry_backoff_initial_s = max(0.0, float(int(getattr(args, "secure_link_retry_backoff_initial_ms", 1000) or 0)) / 1000.0)
        self._retry_backoff_max_s = max(
            self._retry_backoff_initial_s,
            float(int(getattr(args, "secure_link_retry_backoff_max_ms", 5000) or 0)) / 1000.0,
        )
        self._recover_after_failure = bool(getattr(args, "secure_link_recover_after_failure", True))
        self._recover_delay_s = max(0.0, float(getattr(args, "secure_link_recover_delay_seconds", 30.0) or 0.0))
        self._peer_states: Dict[int, _SecureLinkPeerState] = {}
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1
        self._connected_evt = asyncio.Event()
        self._started = False
        self._last_connected = False
        self._last_auth_fail_code: int = 0
        self._last_auth_fail_reason: str = ""
        self._last_auth_fail_detail: str = ""
        self._last_auth_fail_unix_ts: Optional[float] = None
        self._last_auth_fail_session_id: Optional[int] = None
        self._last_disconnect_reason: str = ""
        self._last_disconnect_detail: str = ""
        self._last_secure_link_event: str = ""
        self._last_secure_link_event_unix_ts: Optional[float] = None
        self._last_authenticated_unix_ts: Optional[float] = None
        self._last_authenticated_session_id: Optional[int] = None
        self._handshake_attempts_total: int = 0
        self._authenticated_sessions_total: int = 0
        self._rekeys_completed_total: int = 0
        self._client_retry_task: Optional[asyncio.Task] = None
        self._client_recovery_task: Optional[asyncio.Task] = None
        self._client_rekey_task: Optional[asyncio.Task] = None
        self._client_retry_consecutive_failures: int = 0
        self._client_retry_not_before_mono: float = 0.0
        self._client_retry_not_before_unix_ts: Optional[float] = None
        self._client_recovery_not_before_mono: float = 0.0
        self._client_recovery_not_before_unix_ts: Optional[float] = None
        self._client_rekey_due_mono: float = 0.0
        self._client_rekey_due_unix_ts: Optional[float] = None
        self._client_rekey_hold_after_commit: bool = False
        self._client_rekey_app_queue = deque()
        self._client_rekey_app_queue_bytes: int = 0
        self._last_rekey_trigger: str = ""
        self._local_identity: Optional[_SecureLinkIdentity] = None
        self._revoked_serials: Set[str] = set()
        self._cert_root_pub_path: Optional[pathlib.Path] = None
        self._cert_body_path: Optional[pathlib.Path] = None
        self._cert_sig_path: Optional[pathlib.Path] = None
        self._cert_private_key_path: Optional[pathlib.Path] = None
        self._revoked_serials_path: Optional[pathlib.Path] = None
        self._active_material_generation: int = 0
        self._last_material_reload_unix_ts: Optional[float] = None
        self._last_material_reload_scope: str = ""
        self._last_material_reload_result: str = ""
        self._last_material_reload_detail: str = ""
        self._trust_enforced_unix_ts: Optional[float] = None
        self._secure_link_peers_dropped_total: int = 0
        if self._mode == "cert":
            root_pub = pathlib.Path(str(getattr(args, "secure_link_root_pub", "") or ""))
            cert_body = pathlib.Path(str(getattr(args, "secure_link_cert_body", "") or ""))
            cert_sig = pathlib.Path(str(getattr(args, "secure_link_cert_sig", "") or ""))
            private_key = pathlib.Path(str(getattr(args, "secure_link_private_key", "") or ""))
            required_paths = {
                "secure_link_root_pub": root_pub,
                "secure_link_cert_body": cert_body,
                "secure_link_cert_sig": cert_sig,
                "secure_link_private_key": private_key,
            }
            missing = [name for name, path in required_paths.items() if not str(path)]
            if missing:
                raise ValueError(f"secure_link_mode=cert requires {', '.join(missing)}")
            revoked_path_raw = str(getattr(args, "secure_link_revoked_serials", "") or "").strip()
            revoked_path = pathlib.Path(revoked_path_raw) if revoked_path_raw else None
            revoked_serials = _secure_link_load_revoked_serials(revoked_path) if revoked_path is not None else set()
            local_identity = _secure_link_load_identity_from_paths(
                root_pub_path=root_pub,
                cert_body_path=cert_body,
                cert_sig_path=cert_sig,
                private_key_path=private_key,
            )
            _secure_link_validate_local_identity_operational(local_identity, revoked_serials=revoked_serials)
            self._local_identity = local_identity
            self._revoked_serials = revoked_serials
            self._cert_root_pub_path = root_pub
            self._cert_body_path = cert_body
            self._cert_sig_path = cert_sig
            self._cert_private_key_path = private_key
            self._revoked_serials_path = revoked_path
            self._active_material_generation = 1

    @staticmethod
    def _require_crypto() -> None:
        if (
            ChaCha20Poly1305 is None
            or HKDF is None
            or hashes is None
            or serialization is None
            or ed25519 is None
            or x25519 is None
        ):
            raise RuntimeError(
                "secure-link requires optional dependency 'cryptography'. "
                "Install the project in an environment where cryptography is available."
            )

    @classmethod
    def _hdr_bytes(cls, sl_type: int, session_id: int, counter: int, flags: int = 0) -> bytes:
        return cls._SL_HDR.pack(cls._SL_VERSION, int(sl_type), int(flags), 0, int(session_id) & 0xFFFFFFFFFFFFFFFF, int(counter) & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def _build_frame(cls, sl_type: int, session_id: int, counter: int, payload: bytes, flags: int = 0) -> bytes:
        return cls._hdr_bytes(sl_type, session_id, counter, flags) + bytes(payload or b"")

    @classmethod
    def _parse_frame(cls, payload: bytes) -> Optional[Tuple[int, int, int, bytes]]:
        if not isinstance(payload, (bytes, bytearray, memoryview)) or len(payload) < cls._SL_HDR.size:
            return None
        version, sl_type, _flags, _reserved, session_id, counter = cls._SL_HDR.unpack(bytes(payload[:cls._SL_HDR.size]))
        if int(version) != cls._SL_VERSION:
            return None
        return int(sl_type), int(session_id), int(counter), bytes(payload[cls._SL_HDR.size:])

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + int(counter).to_bytes(8, "big")

    def _derive_keys(self, session_id: int, client_nonce: bytes, server_nonce: bytes) -> Tuple[bytes, bytes]:
        transcript = (
            b"obstaclebridge-securelink-psk-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_nonce
            + server_nonce
        )
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=hashlib.sha256(self._psk).digest(),
            info=transcript,
        )
        material = hkdf.derive(self._psk + client_nonce + server_nonce)
        return material[:32], material[32:]

    @staticmethod
    def _json_payload(obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _parse_json_payload(payload: bytes) -> Optional[dict]:
        try:
            parsed = json.loads(bytes(payload or b"").decode("utf-8"))
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _cert_capability(self) -> int:
        return self._SL_CAP_CERT_V1

    def _is_cert_mode(self) -> bool:
        return self._mode == "cert"

    def _expected_remote_role(self) -> str:
        return "server" if self._client_mode else "client"

    def _load_remote_cert(self, cert_body_bytes: bytes, cert_sig: bytes) -> Tuple[Optional[_SecureLinkIdentity], int]:
        if self._local_identity is None:
            return None, self._SL_AUTH_FAIL_DECODE
        try:
            cert_body = json.loads(cert_body_bytes.decode("utf-8"))
        except Exception:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        try:
            canonical_bytes = _secure_link_canonical_cert_body_bytes(cert_body)
        except Exception:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        required = (
            "version", "serial", "issuer_id", "subject_id", "subject_name", "deployment_id",
            "public_key_algorithm", "public_key", "roles", "issued_at", "not_before",
            "not_after", "constraints", "signature_algorithm",
        )
        if any(key not in cert_body for key in required):
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        if int(cert_body.get("version") or 0) != 1:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        if str(cert_body.get("public_key_algorithm") or "") != "Ed25519":
            return None, self._SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM
        if str(cert_body.get("signature_algorithm") or "") != "Ed25519":
            return None, self._SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM
        try:
            public_key, public_key_der = _secure_link_public_key_der_b64_to_obj(str(cert_body.get("public_key") or ""))
        except Exception:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return None, self._SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM
        if str(cert_body.get("issuer_id") or "") != str(self._local_identity.issuer_id or ""):
            return None, self._SL_AUTH_FAIL_UNKNOWN_ROOT
        try:
            self._local_identity.trust_anchor_public_key.verify(cert_sig, canonical_bytes)
        except Exception:
            return None, self._SL_AUTH_FAIL_BAD_SIGNATURE
        roles = cert_body.get("roles") or []
        if not isinstance(roles, list) or not roles:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        expected_role = self._expected_remote_role()
        normalized_roles = {str(role).strip() for role in roles if str(role).strip()}
        if expected_role not in normalized_roles and "client,server" not in normalized_roles:
            return None, self._SL_AUTH_FAIL_WRONG_ROLE
        try:
            now_ts = time.time()
            not_before = _secure_link_parse_timestamp(str(cert_body.get("not_before") or ""))
            not_after = _secure_link_parse_timestamp(str(cert_body.get("not_after") or ""))
        except Exception:
            return None, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE
        if now_ts < not_before:
            return None, self._SL_AUTH_FAIL_NOT_YET_VALID
        if now_ts > not_after:
            return None, self._SL_AUTH_FAIL_EXPIRED
        if str(cert_body.get("deployment_id") or "") != str(self._local_identity.deployment_id or ""):
            return None, self._SL_AUTH_FAIL_DEPLOYMENT_MISMATCH
        if str(cert_body.get("serial") or "") in self._revoked_serials:
            return None, self._SL_AUTH_FAIL_REVOKED_SERIAL
        return _SecureLinkIdentity(
            cert_body=dict(cert_body),
            cert_body_bytes=canonical_bytes,
            cert_sig=bytes(cert_sig or b""),
            private_key=None,
            public_key=public_key,
            public_key_der=public_key_der,
            trust_anchor_public_key=self._local_identity.trust_anchor_public_key,
            trust_anchor_der=self._local_identity.trust_anchor_der,
            trust_anchor_id=self._local_identity.trust_anchor_id,
            issuer_id=str(cert_body.get("issuer_id") or ""),
            serial=str(cert_body.get("serial") or ""),
            subject_id=str(cert_body.get("subject_id") or ""),
            subject_name=str(cert_body.get("subject_name") or ""),
            deployment_id=str(cert_body.get("deployment_id") or ""),
            roles=[str(role) for role in roles],
        ), 0

    @staticmethod
    def _cert_client_proof_input(session_id: int, cert_body_bytes: bytes, cert_sig: bytes, eph_pub: bytes) -> bytes:
        return (
            b"obstaclebridge-securelink-cert-client-hello-v1|"
            + int(session_id).to_bytes(8, "big")
            + cert_body_bytes
            + cert_sig
            + eph_pub
        )

    @staticmethod
    def _cert_server_proof_input(
        session_id: int,
        client_cert_body_bytes: bytes,
        client_cert_sig: bytes,
        client_eph_pub: bytes,
        server_cert_body_bytes: bytes,
        server_cert_sig: bytes,
        server_eph_pub: bytes,
    ) -> bytes:
        return (
            b"obstaclebridge-securelink-cert-server-hello-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_cert_body_bytes
            + client_cert_sig
            + client_eph_pub
            + server_cert_body_bytes
            + server_cert_sig
            + server_eph_pub
        )

    @staticmethod
    def _cert_rekey_commit_input(session_id: int, client_eph_pub: bytes, server_eph_pub: bytes) -> bytes:
        return (
            b"obstaclebridge-securelink-cert-rekey-commit-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_eph_pub
            + server_eph_pub
        )

    @staticmethod
    def _cert_rekey_hello_input(session_id: int, client_eph_pub: bytes) -> bytes:
        return (
            b"obstaclebridge-securelink-cert-rekey-hello-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_eph_pub
        )

    @staticmethod
    def _cert_rekey_reply_input(session_id: int, client_eph_pub: bytes, server_eph_pub: bytes) -> bytes:
        return (
            b"obstaclebridge-securelink-cert-rekey-reply-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_eph_pub
            + server_eph_pub
        )

    def _derive_cert_keys(self, session_id: int, shared_secret: bytes, transcript_hash: bytes) -> Tuple[bytes, bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=hashlib.sha256(
                b"obstaclebridge-securelink-cert-v1|"
                + int(session_id).to_bytes(8, "big")
            ).digest(),
            info=b"obstaclebridge-securelink-cert-traffic|" + bytes(transcript_hash or b""),
        )
        material = hkdf.derive(bytes(shared_secret or b""))
        return material[:32], material[32:]

    @staticmethod
    def _peer_identity_fields(identity: Optional[_SecureLinkIdentity]) -> dict:
        if identity is None:
            return {
                "peer_subject_id": "",
                "peer_subject_name": "",
                "peer_roles": [],
                "peer_deployment_id": "",
                "peer_serial": "",
                "issuer_id": "",
                "trust_anchor_id": "",
            }
        return {
            "peer_subject_id": str(identity.subject_id or ""),
            "peer_subject_name": str(identity.subject_name or ""),
            "peer_roles": list(identity.roles or []),
            "peer_deployment_id": str(identity.deployment_id or ""),
            "peer_serial": str(identity.serial or ""),
            "issuer_id": str(identity.issuer_id or ""),
            "trust_anchor_id": str(identity.trust_anchor_id or ""),
        }

    def _apply_peer_identity(self, state: _SecureLinkPeerState, identity: Optional[_SecureLinkIdentity]) -> None:
        fields = self._peer_identity_fields(identity)
        state.peer_subject_id = fields["peer_subject_id"]
        state.peer_subject_name = fields["peer_subject_name"]
        state.peer_roles = list(fields["peer_roles"])
        state.peer_deployment_id = fields["peer_deployment_id"]
        state.peer_serial = fields["peer_serial"]
        state.issuer_id = fields["issuer_id"]
        state.trust_anchor_id = fields["trust_anchor_id"]
        state.peer_public_key = identity.public_key if identity is not None else None
        state.peer_public_key_der = bytes(identity.public_key_der) if identity is not None else b""

    def _build_cert_hello_payload(self, *, session_id: int, eph_public: bytes) -> bytes:
        if self._local_identity is None:
            raise RuntimeError("secure-link cert identity not loaded")
        proof = self._local_identity.private_key.sign(
            self._cert_client_proof_input(
                session_id,
                self._local_identity.cert_body_bytes,
                self._local_identity.cert_sig,
                eph_public,
            )
        )
        return self._json_payload({
            "cap": "cert-v1",
            "cert_body_b64": base64.b64encode(self._local_identity.cert_body_bytes).decode("ascii"),
            "cert_sig_b64": base64.b64encode(self._local_identity.cert_sig).decode("ascii"),
            "ephemeral_pub_b64": base64.b64encode(eph_public).decode("ascii"),
            "proof_b64": base64.b64encode(proof).decode("ascii"),
        })

    def _build_cert_server_payload(
        self,
        *,
        session_id: int,
        client_identity: _SecureLinkIdentity,
        client_eph_public: bytes,
        server_eph_public: bytes,
    ) -> bytes:
        if self._local_identity is None:
            raise RuntimeError("secure-link cert identity not loaded")
        proof = self._local_identity.private_key.sign(
            self._cert_server_proof_input(
                session_id,
                client_identity.cert_body_bytes,
                client_identity.cert_sig,
                client_eph_public,
                self._local_identity.cert_body_bytes,
                self._local_identity.cert_sig,
                server_eph_public,
            )
        )
        return self._json_payload({
            "cap": "cert-v1",
            "cert_body_b64": base64.b64encode(self._local_identity.cert_body_bytes).decode("ascii"),
            "cert_sig_b64": base64.b64encode(self._local_identity.cert_sig).decode("ascii"),
            "ephemeral_pub_b64": base64.b64encode(server_eph_public).decode("ascii"),
            "proof_b64": base64.b64encode(proof).decode("ascii"),
        })

    @staticmethod
    def _parse_cert_handshake_payload(payload: bytes) -> Optional[dict]:
        parsed = SecureLinkPskSession._parse_json_payload(payload)
        if not isinstance(parsed, dict) or str(parsed.get("cap") or "") != "cert-v1":
            return None
        try:
            cert_body = base64.b64decode(str(parsed.get("cert_body_b64") or "").encode("ascii"), validate=True)
            cert_sig = base64.b64decode(str(parsed.get("cert_sig_b64") or "").encode("ascii"), validate=True)
            eph_pub = base64.b64decode(str(parsed.get("ephemeral_pub_b64") or "").encode("ascii"), validate=True)
            proof = base64.b64decode(str(parsed.get("proof_b64") or "").encode("ascii"), validate=True)
        except Exception:
            return None
        return {
            "cert_body": cert_body,
            "cert_sig": cert_sig,
            "ephemeral_pub": eph_pub,
            "proof": proof,
        }

    def _server_proof(self, session_id: int, client_nonce: bytes, server_nonce: bytes) -> bytes:
        return hmac.new(
            self._psk,
            b"obstaclebridge-securelink-server-proof-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_nonce
            + server_nonce,
            hashlib.sha256,
        ).digest()

    def _client_rekey_commit_proof(self, session_id: int, client_nonce: bytes, server_nonce: bytes) -> bytes:
        return hmac.new(
            self._psk,
            b"obstaclebridge-securelink-client-rekey-commit-v1|"
            + int(session_id).to_bytes(8, "big")
            + client_nonce
            + server_nonce,
            hashlib.sha256,
        ).digest()

    @classmethod
    def _new_session_id(cls, *avoid: int) -> int:
        blocked = {int(v) for v in avoid if int(v or 0) > 0}
        session_id = 0
        while int(session_id or 0) <= 0 or int(session_id) in blocked:
            session_id = secrets.randbits(64)
        return int(session_id)

    def _peer_key(self, peer_id: Optional[int]) -> int:
        if self._client_mode:
            return 0
        return int(peer_id) if peer_id is not None else 1

    def _compute_connected(self) -> bool:
        return any(state.authenticated for state in self._peer_states.values())

    @classmethod
    def _auth_fail_reason(cls, code: int) -> Optional[str]:
        return {
            cls._SL_AUTH_FAIL_BAD_PSK: "bad_psk",
            cls._SL_AUTH_FAIL_UNSUPPORTED: "unsupported",
            cls._SL_AUTH_FAIL_REPLAY: "replay",
            cls._SL_AUTH_FAIL_DECODE: "decode",
            cls._SL_AUTH_FAIL_LIFECYCLE: "lifecycle",
            cls._SL_AUTH_FAIL_UNKNOWN_ROOT: "unknown_root",
            cls._SL_AUTH_FAIL_BAD_SIGNATURE: "bad_signature",
            cls._SL_AUTH_FAIL_BAD_IDENTITY_PROOF: "bad_identity_proof",
            cls._SL_AUTH_FAIL_WRONG_ROLE: "wrong_role",
            cls._SL_AUTH_FAIL_EXPIRED: "expired",
            cls._SL_AUTH_FAIL_NOT_YET_VALID: "not_yet_valid",
            cls._SL_AUTH_FAIL_DEPLOYMENT_MISMATCH: "deployment_mismatch",
            cls._SL_AUTH_FAIL_REVOKED_SERIAL: "revoked_serial",
            cls._SL_AUTH_FAIL_MALFORMED_CERTIFICATE: "malformed_certificate",
            cls._SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM: "unsupported_algorithm",
        }.get(int(code or 0))

    @classmethod
    def _auth_fail_detail(cls, code: int) -> Optional[str]:
        return {
            cls._SL_AUTH_FAIL_BAD_PSK: "pre-shared secret mismatch or protected-frame authentication failure",
            cls._SL_AUTH_FAIL_UNSUPPORTED: "peer requested an unsupported secure-link capability",
            cls._SL_AUTH_FAIL_REPLAY: "replayed or out-of-order protected frame rejected",
            cls._SL_AUTH_FAIL_DECODE: "invalid or unexpected secure-link frame",
            cls._SL_AUTH_FAIL_LIFECYCLE: "secure-link session or counter lifecycle invariant violated",
            cls._SL_AUTH_FAIL_UNKNOWN_ROOT: "peer certificate issuer does not match the configured trust anchor",
            cls._SL_AUTH_FAIL_BAD_SIGNATURE: "peer certificate signature verification failed against the configured trust anchor",
            cls._SL_AUTH_FAIL_BAD_IDENTITY_PROOF: "peer failed to prove possession of the certified identity private key",
            cls._SL_AUTH_FAIL_WRONG_ROLE: "peer certificate roles do not permit this secure-link direction",
            cls._SL_AUTH_FAIL_EXPIRED: "peer certificate validity interval has expired",
            cls._SL_AUTH_FAIL_NOT_YET_VALID: "peer certificate is not valid yet",
            cls._SL_AUTH_FAIL_DEPLOYMENT_MISMATCH: "peer certificate deployment_id does not match the local deployment",
            cls._SL_AUTH_FAIL_REVOKED_SERIAL: "peer certificate serial is listed as revoked",
            cls._SL_AUTH_FAIL_MALFORMED_CERTIFICATE: "peer certificate payload is malformed or incomplete",
            cls._SL_AUTH_FAIL_UNSUPPORTED_ALGORITHM: "peer certificate uses an unsupported algorithm",
        }.get(int(code or 0))

    def _mark_auth_fail(self, peer_id: Optional[int], session_id: int, code: int) -> None:
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if state is None:
            state = _SecureLinkPeerState(
                session_id=int(session_id or 0),
                client_nonce=b"",
            )
            self._peer_states[key] = state
        elif int(session_id or 0) > 0:
            state.session_id = int(session_id)
        was_authenticated = bool(state.authenticated or int(state.authenticated_sessions_total or 0) > 0)
        state.authenticated = False
        state.client_handshake_proof_sent = False
        state.client_nonce = b""
        state.server_nonce = b""
        state.c2s_key = None
        state.s2c_key = None
        state.tx_counter = 1
        state.rx_counter = 0
        state.local_ephemeral_private = None
        self._clear_pending_rekey(state)
        self._clear_client_rekey_app_queue()
        if not self._client_mode and peer_id is not None:
            self._server_unregister_peer_channels(int(peer_id))
        state.auth_fail_code = int(code or 0)
        state.auth_fail_reason = str(self._auth_fail_reason(code) or "")
        state.auth_fail_detail = str(self._auth_fail_detail(code) or "")
        state.auth_fail_unix_ts = time.time()
        state.last_failure_session_id = int(state.session_id or 0) or None
        state.last_event = "auth_failed"
        state.last_event_unix_ts = state.auth_fail_unix_ts
        state.rekey_due_unix_ts = None
        state.active_material_generation = int(self._active_material_generation or 0)
        state.trust_validation_state = "failed" if self._is_cert_mode() else state.trust_validation_state
        state.trust_failure_reason = state.auth_fail_reason if self._is_cert_mode() else state.trust_failure_reason
        state.trust_failure_detail = state.auth_fail_detail if self._is_cert_mode() else state.trust_failure_detail
        if self._client_mode:
            state.consecutive_failures = max(1, int(self._client_retry_consecutive_failures or 0))
            self._cancel_client_rekey_task(clear_schedule=True)
        self._last_auth_fail_code = state.auth_fail_code
        self._last_auth_fail_reason = state.auth_fail_reason
        self._last_auth_fail_detail = state.auth_fail_detail
        self._last_auth_fail_unix_ts = state.auth_fail_unix_ts
        self._last_auth_fail_session_id = int(state.session_id or 0) or None
        self._record_secure_link_event("auth_failed", state.auth_fail_unix_ts)
        self._log.warning(
            "[SECURE-LINK] auth failure transport=%s side=%s peer_id=%s session_id=%s reason=%s detail=%s failures=%s retry_backoff_sec=%.3f",
            self._transport_name,
            "client" if self._client_mode else "server",
            "local" if self._client_mode else str(peer_id),
            int(state.session_id or 0),
            state.auth_fail_reason or "unknown",
            state.auth_fail_detail or "unknown secure-link authentication failure",
            int(state.consecutive_failures or 0),
            max(0.0, self._client_retry_not_before_mono - time.monotonic()) if self._client_mode else 0.0,
        )
        if self._client_mode and self._started and was_authenticated:
            self._cancel_client_retry_task(clear_schedule=True)
            self._schedule_client_recovery()
        elif self._client_mode and self._started and bool(getattr(self._inner, "is_connected", lambda: False)()):
            self._schedule_client_retry()
        self._refresh_connected_state()

    def _refresh_connected_state(self) -> None:
        connected = self._compute_connected()
        if connected:
            self._connected_evt.set()
        else:
            self._connected_evt.clear()
        if connected == self._last_connected:
            return
        self._last_connected = connected
        if callable(self._outer_on_state):
            try:
                self._outer_on_state(connected)
            except Exception:
                pass

    def _clear_all_states(self) -> None:
        self._cancel_client_rekey_task(clear_schedule=True)
        self._cancel_client_recovery_task(clear_schedule=True)
        self._clear_client_rekey_app_queue()
        self._peer_states.clear()
        self._server_chan_to_peer.clear()
        self._server_peer_chan_to_mux.clear()
        self._server_next_mux_chan = 1
        self._refresh_connected_state()

    def _clear_client_rekey_app_queue(self) -> None:
        self._client_rekey_hold_after_commit = False
        self._client_rekey_app_queue.clear()
        self._client_rekey_app_queue_bytes = 0

    def _queue_client_rekey_app_payload(self, payload: bytes, peer_id: Optional[int]) -> bool:
        queued_payload = bytes(payload or b"")
        if not queued_payload:
            return False
        max_frames = 256
        max_bytes = 1024 * 1024
        if len(self._client_rekey_app_queue) >= max_frames:
            return False
        if (self._client_rekey_app_queue_bytes + len(queued_payload)) > max_bytes:
            return False
        self._client_rekey_app_queue.append((queued_payload, peer_id))
        self._client_rekey_app_queue_bytes += len(queued_payload)
        return True

    def _flush_client_rekey_app_queue(self) -> None:
        if not self._client_rekey_app_queue:
            return
        queued = list(self._client_rekey_app_queue)
        self._client_rekey_app_queue.clear()
        self._client_rekey_app_queue_bytes = 0
        for idx, (payload, peer_id) in enumerate(queued):
            if self._send_app_immediate(payload, peer_id=peer_id) > 0:
                continue
            remaining = queued[idx:]
            self._client_rekey_app_queue.extend(remaining)
            self._client_rekey_app_queue_bytes = sum(len(item[0]) for item in remaining)
            return

    def _record_secure_link_event(self, event: str, when: Optional[float] = None) -> None:
        ts = float(when if when is not None else time.time())
        self._last_secure_link_event = str(event or "")
        self._last_secure_link_event_unix_ts = ts

    def _record_authenticated_session(
        self,
        state: _SecureLinkPeerState,
        *,
        session_id: int,
        peer_id: Optional[int],
        event: str,
        rekey_completed: bool,
    ) -> None:
        now = time.time()
        state.authenticated = True
        state.consecutive_failures = 0
        state.auth_fail_code = 0
        state.auth_fail_reason = ""
        state.auth_fail_detail = ""
        state.auth_fail_unix_ts = None
        state.last_event = str(event)
        state.last_event_unix_ts = now
        state.last_authenticated_unix_ts = now
        if state.connected_since_unix_ts is None:
            state.connected_since_unix_ts = now
        state.rekey_due_unix_ts = None
        if self._is_cert_mode():
            state.trust_validation_state = "trusted"
            state.trust_failure_reason = ""
            state.trust_failure_detail = ""
            state.disconnect_reason = ""
            state.disconnect_detail = ""
            state.trust_enforced_unix_ts = None
            state.active_material_generation = int(self._active_material_generation or 0)
            if self._last_material_reload_unix_ts is not None:
                state.last_material_reload_unix_ts = self._last_material_reload_unix_ts
                state.last_material_reload_scope = str(self._last_material_reload_scope or "")
                state.last_material_reload_result = str(self._last_material_reload_result or "")
                state.last_material_reload_detail = str(self._last_material_reload_detail or "")
        state.authenticated_sessions_total = int(state.authenticated_sessions_total or 0) + 1
        if rekey_completed:
            state.rekeys_completed_total = int(state.rekeys_completed_total or 0) + 1
            self._rekeys_completed_total += 1
            self._last_rekey_trigger = str(state.last_rekey_trigger or "")
        self._authenticated_sessions_total += 1
        self._last_authenticated_unix_ts = now
        self._last_authenticated_session_id = int(session_id or 0) or None
        self._last_auth_fail_code = 0
        self._last_auth_fail_reason = ""
        self._last_auth_fail_detail = ""
        self._last_auth_fail_unix_ts = None
        self._last_auth_fail_session_id = None
        self._record_secure_link_event(event, now)
        if self._client_mode:
            self._schedule_client_rekey_timer(state)
        self._reset_client_retry_backoff()
        self._log.info(
            "[SECURE-LINK] %s transport=%s side=%s peer_id=%s session_id=%s authenticated_sessions_total=%s rekeys_completed_total=%s",
            str(event).replace("_", " "),
            self._transport_name,
            "client" if self._client_mode else "server",
            "local" if self._client_mode else str(peer_id),
            int(session_id or 0),
            int(self._authenticated_sessions_total or 0),
            int(self._rekeys_completed_total or 0),
        )

    def _cancel_client_retry_task(self, *, clear_schedule: bool) -> None:
        task = self._client_retry_task
        self._client_retry_task = None
        current = None
        try:
            current = asyncio.current_task()
        except Exception:
            current = None
        if task is not None and task is not current and not task.done():
            task.cancel()
        if clear_schedule:
            self._client_retry_not_before_mono = 0.0
            self._client_retry_not_before_unix_ts = None

    def _cancel_client_rekey_task(self, *, clear_schedule: bool) -> None:
        task = self._client_rekey_task
        self._client_rekey_task = None
        current = None
        try:
            current = asyncio.current_task()
        except Exception:
            current = None
        if task is not None and task is not current and not task.done():
            task.cancel()
        if clear_schedule:
            self._client_rekey_due_mono = 0.0
            self._client_rekey_due_unix_ts = None
            state = self._peer_states.get(0) if self._client_mode else None
            if state is not None:
                state.rekey_due_unix_ts = None

    def _reset_client_retry_backoff(self) -> None:
        self._cancel_client_retry_task(clear_schedule=True)
        self._cancel_client_recovery_task(clear_schedule=True)
        self._client_retry_consecutive_failures = 0

    def _cancel_client_recovery_task(self, *, clear_schedule: bool) -> None:
        task = self._client_recovery_task
        self._client_recovery_task = None
        current = None
        try:
            current = asyncio.current_task()
        except Exception:
            current = None
        if task is not None and task is not current and not task.done():
            task.cancel()
        if clear_schedule:
            self._client_recovery_not_before_mono = 0.0
            self._client_recovery_not_before_unix_ts = None

    async def _delayed_client_recovery(self, target_mono: float, expected_session_id: int) -> None:
        try:
            while True:
                remaining = float(target_mono) - time.monotonic()
                if remaining <= 0.0:
                    break
                await asyncio.sleep(min(remaining, 0.25))
            if not self._started or not self._client_mode:
                return
            state = self._peer_states.get(0)
            if state is None or state.authenticated:
                return
            if int(state.session_id or 0) != int(expected_session_id or 0):
                return
            self._client_recovery_not_before_mono = 0.0
            self._client_recovery_not_before_unix_ts = None
            state.last_event = "recovery_reconnect_started"
            state.last_event_unix_ts = time.time()
            self._record_secure_link_event("recovery_reconnect_started", state.last_event_unix_ts)
            if not self.request_reconnect():
                self._log.warning(
                    "[SECURE-LINK] recovery reconnect unavailable transport=%s side=client session_id=%s",
                    self._transport_name,
                    int(expected_session_id or 0),
                )
        except asyncio.CancelledError:
            return
        finally:
            current = None
            try:
                current = asyncio.current_task()
            except Exception:
                current = None
            if self._client_recovery_task is current:
                self._client_recovery_task = None

    def _schedule_client_recovery(self) -> None:
        if (
            not self._client_mode
            or not self._started
            or not self._recover_after_failure
            or self._recover_delay_s <= 0.0
        ):
            return
        state = self._peer_states.get(0)
        if state is None:
            return
        target_mono = time.monotonic() + self._recover_delay_s
        self._client_recovery_not_before_mono = target_mono
        self._client_recovery_not_before_unix_ts = time.time() + self._recover_delay_s
        self._cancel_client_recovery_task(clear_schedule=False)
        state.last_event = "recovery_reconnect_scheduled"
        state.last_event_unix_ts = time.time()
        self._record_secure_link_event("recovery_reconnect_scheduled", state.last_event_unix_ts)
        self._log.warning(
            "[SECURE-LINK] scheduled recovery reconnect transport=%s side=client session_id=%s delay_sec=%.3f",
            self._transport_name,
            int(state.session_id or 0),
            self._recover_delay_s,
        )
        try:
            self._client_recovery_task = asyncio.create_task(
                self._delayed_client_recovery(target_mono, int(state.session_id or 0))
            )
        except Exception:
            self._client_recovery_task = None
            self._client_recovery_not_before_mono = 0.0
            self._client_recovery_not_before_unix_ts = None

    async def _delayed_client_retry(self, target_mono: float) -> None:
        try:
            while True:
                remaining = float(target_mono) - time.monotonic()
                if remaining <= 0.0:
                    break
                await asyncio.sleep(min(remaining, 0.25))
            if not self._started or not self._client_mode:
                return
            if not bool(getattr(self._inner, "is_connected", lambda: False)()):
                return
            state = self._peer_states.get(0)
            if state is not None and state.authenticated:
                return
            self._client_retry_not_before_mono = 0.0
            self._client_retry_not_before_unix_ts = None
            self._begin_client_handshake()
        except asyncio.CancelledError:
            return
        finally:
            current = None
            try:
                current = asyncio.current_task()
            except Exception:
                current = None
            if self._client_retry_task is current:
                self._client_retry_task = None

    def _schedule_client_retry(self) -> None:
        if not self._client_mode or not self._started or self._retry_backoff_max_s <= 0.0:
            return
        self._client_retry_consecutive_failures += 1
        exponent = max(0, self._client_retry_consecutive_failures - 1)
        delay_s = min(self._retry_backoff_max_s, self._retry_backoff_initial_s * (2 ** exponent))
        target_mono = time.monotonic() + delay_s
        self._client_retry_not_before_mono = target_mono
        self._client_retry_not_before_unix_ts = time.time() + delay_s
        self._cancel_client_retry_task(clear_schedule=False)
        state = self._peer_states.get(0) if self._client_mode else None
        if state is not None:
            state.last_event = "retry_scheduled"
            state.last_event_unix_ts = time.time()
        self._record_secure_link_event("retry_scheduled")
        try:
            self._client_retry_task = asyncio.create_task(self._delayed_client_retry(target_mono))
        except Exception:
            self._client_retry_task = None

    async def _delayed_client_rekey(self, target_mono: float, expected_session_id: int) -> None:
        try:
            while True:
                remaining = float(target_mono) - time.monotonic()
                if remaining <= 0.0:
                    break
                await asyncio.sleep(min(remaining, 0.25))
            if not self._started or not self._client_mode:
                return
            if not bool(getattr(self._inner, "is_connected", lambda: False)()):
                return
            state = self._peer_states.get(0)
            if state is None or not state.authenticated:
                return
            if int(state.session_id or 0) != int(expected_session_id or 0):
                return
            if int(state.pending_session_id or 0) > 0:
                return
            self._start_client_rekey(state, trigger="time_threshold")
        except asyncio.CancelledError:
            return
        finally:
            current = None
            try:
                current = asyncio.current_task()
            except Exception:
                current = None
            if self._client_rekey_task is current:
                self._client_rekey_task = None

    def _schedule_client_rekey_timer(self, state: Optional[_SecureLinkPeerState]) -> None:
        self._cancel_client_rekey_task(clear_schedule=True)
        if (
            not self._client_mode
            or self._rekey_after_seconds <= 0.0
            or state is None
            or not state.authenticated
            or int(state.pending_session_id or 0) > 0
        ):
            return
        target_mono = time.monotonic() + self._rekey_after_seconds
        due_unix_ts = time.time() + self._rekey_after_seconds
        self._client_rekey_due_mono = target_mono
        self._client_rekey_due_unix_ts = due_unix_ts
        state.rekey_due_unix_ts = due_unix_ts
        try:
            self._client_rekey_task = asyncio.create_task(
                self._delayed_client_rekey(target_mono, int(state.session_id or 0))
            )
        except Exception:
            self._client_rekey_task = None
            self._client_rekey_due_mono = 0.0
            self._client_rekey_due_unix_ts = None
            state.rekey_due_unix_ts = None

    def _maybe_begin_client_handshake(self) -> None:
        if not self._client_mode or not self._started:
            return
        if self._peer_states and any(state.authenticated for state in self._peer_states.values()):
            return
        if self._client_retry_not_before_mono > time.monotonic():
            if self._client_retry_task is None or self._client_retry_task.done():
                try:
                    self._client_retry_task = asyncio.create_task(
                        self._delayed_client_retry(self._client_retry_not_before_mono)
                    )
                except Exception:
                    self._client_retry_task = None
            return
        self._client_retry_not_before_mono = 0.0
        self._client_retry_not_before_unix_ts = None
        self._begin_client_handshake()

    @staticmethod
    def _clear_pending_rekey(state: _SecureLinkPeerState) -> None:
        state.pending_session_id = 0
        state.pending_client_nonce = b""
        state.pending_server_nonce = b""
        state.pending_c2s_key = None
        state.pending_s2c_key = None
        state.pending_local_ephemeral_private = None

    def _promote_pending_rekey(self, state: _SecureLinkPeerState) -> bool:
        if int(state.pending_session_id or 0) <= 0:
            return False
        state.session_id = int(state.pending_session_id)
        state.client_nonce = bytes(state.pending_client_nonce or b"")
        state.server_nonce = bytes(state.pending_server_nonce or b"")
        state.c2s_key = bytes(state.pending_c2s_key or b"") or None
        state.s2c_key = bytes(state.pending_s2c_key or b"") or None
        if state.pending_local_ephemeral_private is not None:
            state.local_ephemeral_private = state.pending_local_ephemeral_private
        state.authenticated = True
        state.client_handshake_proof_sent = False
        state.tx_counter = 1
        state.rx_counter = 0
        state.auth_fail_code = 0
        state.auth_fail_reason = ""
        state.auth_fail_detail = ""
        state.auth_fail_unix_ts = None
        self._clear_pending_rekey(state)
        return True

    def _start_client_rekey(self, state: _SecureLinkPeerState, *, trigger: str) -> None:
        if not self._client_mode or not state.authenticated or int(state.pending_session_id or 0) > 0:
            return
        self._cancel_client_rekey_task(clear_schedule=True)
        pending_session_id = self._new_session_id(state.session_id, state.pending_session_id)
        state.last_rekey_trigger = str(trigger or "")
        state.rekey_due_unix_ts = None
        self._last_rekey_trigger = state.last_rekey_trigger
        state.last_event = "rekey_started"
        state.last_event_unix_ts = time.time()
        self._record_secure_link_event("rekey_started", state.last_event_unix_ts)
        state.pending_session_id = pending_session_id
        state.pending_server_nonce = b""
        state.pending_c2s_key = None
        state.pending_s2c_key = None
        if self._is_cert_mode():
            eph_private = x25519.X25519PrivateKey.generate()
            eph_public = eph_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            state.pending_local_ephemeral_private = eph_private
            state.pending_client_nonce = eph_public
            proof = self._local_identity.private_key.sign(self._cert_rekey_hello_input(pending_session_id, eph_public))
            payload = self._json_payload({
                "cap": "cert-v1",
                "ephemeral_pub_b64": base64.b64encode(eph_public).decode("ascii"),
                "proof_b64": base64.b64encode(proof).decode("ascii"),
            })
        else:
            pending_client_nonce = secrets.token_bytes(32)
            state.pending_client_nonce = pending_client_nonce
            payload = pending_client_nonce + bytes([self._SL_CAP_PSK_V1, 0])
        self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_HELLO, pending_session_id, 0, payload))

    def _maybe_trigger_rekey(self, state: Optional[_SecureLinkPeerState]) -> None:
        if not self._client_mode or self._rekey_after_frames <= 0 or state is None or not state.authenticated:
            return
        if int(state.pending_session_id or 0) > 0:
            return
        sent_frames = max(0, int(state.tx_counter or 1) - 1 - int(bool(state.client_handshake_proof_sent)))
        if sent_frames < self._rekey_after_frames:
            return
        self._start_client_rekey(state, trigger="frame_threshold")

    def _apply_material_reload_metadata_to_state(
        self,
        state: _SecureLinkPeerState,
        *,
        scope: str,
        result: str,
        detail: str,
        when: float,
    ) -> None:
        state.active_material_generation = int(self._active_material_generation or 0)
        state.last_material_reload_unix_ts = when
        state.last_material_reload_scope = str(scope or "")
        state.last_material_reload_result = str(result or "")
        state.last_material_reload_detail = str(detail or "")

    def _load_local_identity_bundle(
        self,
        *,
        revoked_serials: Optional[Set[str]] = None,
    ) -> _SecureLinkIdentity:
        if self._cert_root_pub_path is None or self._cert_body_path is None or self._cert_sig_path is None or self._cert_private_key_path is None:
            raise ValueError("secure-link cert mode paths are not configured")
        identity = _secure_link_load_identity_from_paths(
            root_pub_path=self._cert_root_pub_path,
            cert_body_path=self._cert_body_path,
            cert_sig_path=self._cert_sig_path,
            private_key_path=self._cert_private_key_path,
        )
        _secure_link_validate_local_identity_operational(identity, revoked_serials=set(revoked_serials or self._revoked_serials))
        return identity

    def _load_revoked_serials_bundle(self) -> Set[str]:
        if self._revoked_serials_path is None:
            return set()
        return _secure_link_load_revoked_serials(self._revoked_serials_path)

    def _policy_disconnect_peer(
        self,
        peer_key: int,
        *,
        reason: str,
        detail: str,
        auth_fail_code: int,
        trust_reason: Optional[str] = None,
        trust_detail: Optional[str] = None,
    ) -> None:
        state = self._peer_states.get(int(peer_key))
        if state is None:
            return
        session_id = int(state.session_id or 0)
        self._mark_auth_fail(None if self._client_mode else peer_key, session_id, auth_fail_code)
        state = self._peer_states.get(int(peer_key))
        if state is None:
            return
        now = time.time()
        state.disconnect_reason = str(reason or "")
        state.disconnect_detail = str(detail or "")
        self._last_disconnect_reason = state.disconnect_reason
        self._last_disconnect_detail = state.disconnect_detail
        state.trust_enforced_unix_ts = now
        state.connected_since_unix_ts = None
        state.last_event = "trust_enforced_disconnect"
        state.last_event_unix_ts = now
        state.authenticated = False
        state.active_material_generation = int(self._active_material_generation or 0)
        if self._is_cert_mode():
            state.trust_validation_state = "failed"
            if trust_reason is not None:
                state.trust_failure_reason = str(trust_reason or "")
            if trust_detail is not None:
                state.trust_failure_detail = str(trust_detail or "")
        self._trust_enforced_unix_ts = now
        self._secure_link_peers_dropped_total += 1
        self._record_secure_link_event("trust_enforced_disconnect", now)
        if (
            self._client_mode
            and self._started
            and str(reason or "") != "revocation_applied"
            and bool(getattr(self._inner, "is_connected", lambda: False)())
        ):
            self._maybe_begin_client_handshake()

    def request_secure_link_reload(self, scope: str = "all", target_peer_id: Optional[str] = None) -> dict:
        normalized_scope = str(scope or "").strip().lower()
        if normalized_scope not in {"revocation", "local_identity", "all"}:
            return {"ok": False, "reason": "invalid_scope", "scope": normalized_scope}
        if not self._is_cert_mode():
            return {"ok": False, "reason": "secure_link_cert_mode_required", "scope": normalized_scope}

        previous_identity = self._local_identity
        previous_revoked = set(self._revoked_serials or set())
        try:
            reloaded_revoked = previous_revoked
            if normalized_scope in {"revocation", "all"}:
                reloaded_revoked = self._load_revoked_serials_bundle()
            reloaded_identity = previous_identity
            if normalized_scope in {"local_identity", "all"}:
                reloaded_identity = self._load_local_identity_bundle(revoked_serials=reloaded_revoked)
            if reloaded_identity is None:
                raise ValueError("secure-link local identity is unavailable")
        except Exception as exc:
            now = time.time()
            detail = str(exc)
            self._last_material_reload_unix_ts = now
            self._last_material_reload_scope = normalized_scope
            self._last_material_reload_result = "failed"
            self._last_material_reload_detail = detail
            for state in self._peer_states.values():
                self._apply_material_reload_metadata_to_state(
                    state,
                    scope=normalized_scope,
                    result="failed",
                    detail=detail,
                    when=now,
                )
            return {"ok": False, "reason": "reload_failed", "scope": normalized_scope, "detail": detail, "dropped": 0}

        self._local_identity = reloaded_identity
        self._revoked_serials = set(reloaded_revoked or set())
        self._active_material_generation = max(1, int(self._active_material_generation or 0) + 1)
        now = time.time()
        changed_detail = []
        if normalized_scope in {"revocation", "all"}:
            changed_detail.append(f"revoked_serials={len(self._revoked_serials)}")
        if normalized_scope in {"local_identity", "all"} and self._local_identity is not None:
            changed_detail.append(f"local_subject_id={self._local_identity.subject_id}")
        detail = ", ".join(changed_detail) if changed_detail else "material reloaded"
        self._last_material_reload_unix_ts = now
        self._last_material_reload_scope = normalized_scope
        self._last_material_reload_result = "applied"
        self._last_material_reload_detail = detail
        dropped = 0
        for key, state in list(self._peer_states.items()):
            self._apply_material_reload_metadata_to_state(
                state,
                scope=normalized_scope,
                result="applied",
                detail=detail,
                when=now,
            )
            if not state.authenticated:
                continue
            if str(state.peer_serial or "") in self._revoked_serials:
                self._policy_disconnect_peer(
                    key,
                    reason="revocation_applied",
                    detail="peer certificate serial is revoked by the reloaded denylist",
                    auth_fail_code=self._SL_AUTH_FAIL_REVOKED_SERIAL,
                    trust_reason="revoked_serial",
                    trust_detail="peer certificate serial is listed as revoked by the active denylist",
                )
                dropped += 1
                continue
            if normalized_scope in {"local_identity", "all"}:
                self._policy_disconnect_peer(
                    key,
                    reason="local_identity_reloaded",
                    detail="local secure-link identity material changed and the peer must re-authenticate",
                    auth_fail_code=self._SL_AUTH_FAIL_LIFECYCLE,
                    trust_reason=state.trust_failure_reason or "",
                    trust_detail=state.trust_failure_detail or "",
                )
                dropped += 1
        return {
            "ok": True,
            "reason": "reload_applied",
            "scope": normalized_scope,
            "dropped": dropped,
            "active_material_generation": int(self._active_material_generation or 0),
            "detail": detail,
        }

    def request_secure_link_rekey(self) -> Tuple[bool, str]:
        if not self._client_mode:
            return (False, "server_side_initiation_not_supported")
        state = self._peer_states.get(0)
        if state is None or not state.authenticated:
            return (False, "not_authenticated")
        if max(0, int(state.tx_counter or 1) - 1) <= 0:
            return (False, "protected_data_not_established")
        if int(state.pending_session_id or 0) > 0:
            return (False, "rekey_already_in_progress")
        self._start_client_rekey(state, trigger="operator")
        return (True, "rekey_started")

    def set_on_app_payload(self, cb): self._outer_on_app = cb
    def set_on_state_change(self, cb): self._outer_on_state = cb
    def set_on_peer_rx(self, cb): self._outer_on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._outer_on_peer_tx = cb
    def set_on_peer_set(self, cb): self._outer_on_peer_set = cb
    def set_on_peer_disconnect(self, cb): self._outer_on_peer_disconnect = cb
    def set_on_app_from_peer_bytes(self, cb): self._outer_on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._outer_on_transport_epoch_change = cb

    def reset_sender(self) -> None:
        resetter = getattr(self._inner, "reset_sender", None)
        if callable(resetter):
            resetter()

    def reset_transport_epoch(self) -> None:
        self._cancel_client_retry_task(clear_schedule=False)
        self._cancel_client_rekey_task(clear_schedule=False)
        self._clear_all_states()
        resetter = getattr(self._inner, "reset_transport_epoch", None)
        if not callable(resetter):
            resetter = getattr(self._inner, "reset_sender", None)
        if callable(resetter):
            resetter()

    def get_connection_failure_snapshot(self) -> dict:
        getter = getattr(self._inner, "get_connection_failure_snapshot", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                return dict(getter() or {})
        return {
            "failed": False,
            "reason": None,
            "detail": None,
            "unix_ts": None,
            "last_event": "",
            "last_event_unix_ts": None,
            "transport": self._transport_name,
        }

    async def start(self) -> None:
        self._require_crypto()
        setter = getattr(self._inner, "set_app_payload_passthrough", None)
        if callable(setter):
            setter(True)
        self._inner.set_on_app_payload(self._on_inner_payload)
        self._inner.set_on_state_change(self._on_inner_state_change)
        self._inner.set_on_peer_rx(self._outer_on_peer_rx)
        self._inner.set_on_peer_tx(self._outer_on_peer_tx)
        self._inner.set_on_peer_set(self._outer_on_peer_set)
        self._inner.set_on_app_from_peer_bytes(self._outer_on_app_from_peer_bytes)
        self._inner.set_on_transport_epoch_change(self._on_inner_transport_epoch_change)
        try:
            self._inner.set_on_peer_disconnect(self._on_inner_peer_disconnect)
        except Exception:
            pass
        self._started = True
        await self._inner.start()

    async def stop(self) -> None:
        self._cancel_client_retry_task(clear_schedule=True)
        self._cancel_client_rekey_task(clear_schedule=True)
        self._clear_all_states()
        await self._inner.stop()

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if self.is_connected():
            return True
        try:
            await asyncio.wait_for(self._connected_evt.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def is_connected(self) -> bool:
        return self._compute_connected()

    def request_reconnect(self) -> bool:
        trigger = getattr(self._inner, "request_reconnect", None)
        if callable(trigger):
            with contextlib.suppress(Exception):
                return bool(trigger())
        return False

    def get_metrics(self) -> SessionMetrics:
        return self._inner.get_metrics()

    def get_max_app_payload_size(self) -> int:
        getter = getattr(self._inner, "get_max_app_payload_size", None)
        inner_limit = int(getter() or 65535) if callable(getter) else 65535
        # Protected DATA frames add the secure-link header and AEAD tag before they
        # reach the wrapped transport session.
        return max(0, inner_limit - self._SL_HDR.size - 16)

    @staticmethod
    def _snapshot_peer_host(row: dict) -> str:
        peer_label = str(row.get("peer") or "").strip()
        if not peer_label:
            return ""
        if peer_label.startswith("["):
            closing = peer_label.find("]")
            return peer_label[1:closing] if closing > 1 else peer_label
        if ":" not in peer_label:
            return peer_label
        return peer_label.rsplit(":", 1)[0]

    def _filter_superseded_myudp_listener_rows(self, rows: list[dict]) -> list[dict]:
        if self._client_mode or str(self._transport_name or "").strip().lower() != "myudp":
            return rows
        candidates_by_host: dict[str, list[tuple[int, int, float, int, int, str]]] = {}
        for idx, row in enumerate(rows):
            if bool(row.get("listening")) or str(row.get("state") or "").strip().lower() == "listening":
                continue
            secure_link = row.get("secure_link") or {}
            if not bool(secure_link.get("authenticated")):
                continue
            session_id = int(secure_link.get("session_id") or 0)
            if session_id <= 0:
                continue
            host = self._snapshot_peer_host(row)
            if not host:
                continue
            authenticated_ts = float(secure_link.get("last_authenticated_unix_ts") or 0.0)
            mux_count = len(list(row.get("mux_chans") or []))
            rekeys_completed = int(secure_link.get("rekeys_completed_total") or 0)
            last_rekey_trigger = str(secure_link.get("last_rekey_trigger") or "")
            candidates_by_host.setdefault(host, []).append(
                (idx, session_id, authenticated_ts, mux_count, rekeys_completed, last_rekey_trigger)
            )
        suppress: set[int] = set()
        for items in candidates_by_host.values():
            if len(items) < 2:
                continue
            newest_idx, newest_session_id, newest_ts, _newest_mux_count, _newest_rekeys_completed, _newest_trigger = max(
                items,
                key=lambda item: (item[2], item[1]),
            )
            for idx, session_id, authenticated_ts, mux_count, rekeys_completed, last_rekey_trigger in items:
                if idx == newest_idx or session_id == newest_session_id:
                    continue
                if mux_count > 0:
                    continue
                if rekeys_completed <= 0 and not last_rekey_trigger:
                    continue
                if newest_ts > 0.0 and authenticated_ts > newest_ts:
                    continue
                suppress.add(idx)
        if not suppress:
            return rows
        return [row for idx, row in enumerate(rows) if idx not in suppress]

    def get_overlay_peers_snapshot(self) -> list[dict]:
        getter = getattr(self._inner, "get_overlay_peers_snapshot", None)
        rows = list(getter() or []) if callable(getter) else []
        out: list[dict] = []
        inner_is_connected = bool(getattr(self._inner, "is_connected", lambda: False)())
        secure_mux_by_peer: dict[int, set[int]] = {}
        if not self._client_mode:
            for mux_chan, mapped in list(self._server_chan_to_peer.items()):
                with contextlib.suppress(Exception):
                    peer_id, _peer_chan = mapped
                    secure_mux_by_peer.setdefault(int(peer_id), set()).add(int(mux_chan))
        for row in rows:
            r = dict(row)
            listening = bool(r.get("listening")) or str(r.get("state") or "").strip().lower() == "listening"
            peer_id = int(r.get("peer_id", 0) or 0)
            key = self._peer_key(None if self._client_mode else peer_id)
            state = self._peer_states.get(key)
            authenticated = False
            failure_code = None
            failure_reason = None
            failure_detail = None
            failure_unix_ts = None
            session_id = None
            if listening:
                secure_state = "listening"
            elif state is None:
                secure_state = "handshaking" if inner_is_connected else "waiting_transport"
            elif state.authenticated:
                secure_state = "authenticated"
                authenticated = True
                session_id = int(state.session_id or 0) or None
            elif state.auth_fail_code:
                secure_state = "failed"
                failure_code = int(state.auth_fail_code or 0) or None
                failure_reason = state.auth_fail_reason or self._auth_fail_reason(state.auth_fail_code)
                failure_detail = state.auth_fail_detail or self._auth_fail_detail(state.auth_fail_code)
                failure_unix_ts = state.auth_fail_unix_ts
                session_id = int(state.session_id or 0) or None
            else:
                secure_state = "handshaking" if inner_is_connected else "waiting_transport"
                session_id = int(state.session_id or 0) or None
            r["secure_link"] = {
                "enabled": True,
                "mode": self._mode,
                "state": secure_state,
                "authenticated": authenticated,
                "session_id": session_id,
                "rekey_in_progress": bool(state is not None and int(state.pending_session_id or 0) > 0),
                "last_rekey_trigger": str(state.last_rekey_trigger or "") if state is not None else "",
                "rekey_due_unix_ts": state.rekey_due_unix_ts if state is not None else None,
                "failure_code": failure_code,
                "failure_reason": failure_reason,
                "failure_detail": failure_detail,
                "failure_unix_ts": failure_unix_ts,
                "failure_session_id": state.last_failure_session_id if state is not None else None,
                "consecutive_failures": int(state.consecutive_failures or 0) if state is not None else 0,
                "retry_backoff_sec": max(0.0, self._client_retry_not_before_mono - time.monotonic()) if self._client_mode and self._client_retry_not_before_mono > 0.0 else 0.0,
                "next_retry_unix_ts": self._client_retry_not_before_unix_ts if self._client_mode else None,
                "recovery_enabled": bool(self._recover_after_failure) if self._client_mode else False,
                "recovery_delay_sec": self._recover_delay_s if self._client_mode else 0.0,
                "recovery_reconnect_sec": max(0.0, self._client_recovery_not_before_mono - time.monotonic()) if self._client_mode and self._client_recovery_not_before_mono > 0.0 else 0.0,
                "next_recovery_reconnect_unix_ts": self._client_recovery_not_before_unix_ts if self._client_mode else None,
                "handshake_attempts_total": int(state.handshake_attempts_total or 0) if state is not None else 0,
                "last_event": str(state.last_event or "") if state is not None else "",
                "last_event_unix_ts": state.last_event_unix_ts if state is not None else None,
                "last_authenticated_unix_ts": state.last_authenticated_unix_ts if state is not None else None,
                "connected_since_unix_ts": state.connected_since_unix_ts if state is not None else None,
                "authenticated_sessions_total": int(state.authenticated_sessions_total or 0) if state is not None else 0,
                "rekeys_completed_total": int(state.rekeys_completed_total or 0) if state is not None else 0,
                "transport": self._transport_name,
                "peer_subject_id": str(state.peer_subject_id or "") if state is not None else "",
                "peer_subject_name": str(state.peer_subject_name or "") if state is not None else "",
                "peer_roles": list(state.peer_roles or []) if state is not None else [],
                "peer_deployment_id": str(state.peer_deployment_id or "") if state is not None else "",
                "peer_serial": str(state.peer_serial or "") if state is not None else "",
                "issuer_id": str(state.issuer_id or "") if state is not None else "",
                "trust_anchor_id": str(state.trust_anchor_id or "") if state is not None else (self._local_identity.trust_anchor_id if self._local_identity is not None else ""),
                "trust_validation_state": str(state.trust_validation_state or "") if state is not None else "",
                "trust_failure_reason": str(state.trust_failure_reason or "") if state is not None else "",
                "trust_failure_detail": str(state.trust_failure_detail or "") if state is not None else "",
                "active_material_generation": int(state.active_material_generation or 0) if state is not None else int(self._active_material_generation or 0),
                "last_material_reload_unix_ts": state.last_material_reload_unix_ts if state is not None else self._last_material_reload_unix_ts,
                "last_material_reload_scope": str(state.last_material_reload_scope or "") if state is not None else str(self._last_material_reload_scope or ""),
                "last_material_reload_result": str(state.last_material_reload_result or "") if state is not None else str(self._last_material_reload_result or ""),
                "last_material_reload_detail": str(state.last_material_reload_detail or "") if state is not None else str(self._last_material_reload_detail or ""),
                "trust_enforced_unix_ts": state.trust_enforced_unix_ts if state is not None else self._trust_enforced_unix_ts,
                "disconnect_reason": str(state.disconnect_reason or "") if state is not None else "",
                "disconnect_detail": str(state.disconnect_detail or "") if state is not None else "",
            }
            out.append(r)
        out = self._filter_superseded_myudp_listener_rows(out)
        if not self._client_mode and secure_mux_by_peer:
            for row in out:
                if bool(row.get("listening")) or str(row.get("state") or "").strip().lower() == "listening":
                    continue
                mux_chans = set()
                for chan in list(row.get("mux_chans") or []):
                    with contextlib.suppress(Exception):
                        mux_chans.add(int(chan))
                mux_chans.update(secure_mux_by_peer.get(int(row.get("peer_id", 0) or 0), set()))
                row["mux_chans"] = sorted(mux_chans)
        return out

    def get_secure_link_status_snapshot(self) -> dict:
        any_failed = False
        failure_code = None
        failure_reason = None
        failure_detail = None
        failure_unix_ts = None
        any_handshaking = False
        authenticated_peers = 0
        primary_state: Optional[_SecureLinkPeerState] = None
        for state in self._peer_states.values():
            if primary_state is None:
                primary_state = state
            if state.authenticated:
                authenticated_peers += 1
            elif state.auth_fail_code:
                any_failed = True
                failure_code = failure_code or int(state.auth_fail_code or 0) or None
                failure_reason = failure_reason or state.auth_fail_reason or self._auth_fail_reason(state.auth_fail_code)
                failure_detail = failure_detail or state.auth_fail_detail or self._auth_fail_detail(state.auth_fail_code)
                failure_unix_ts = failure_unix_ts or state.auth_fail_unix_ts
            else:
                any_handshaking = True
        if authenticated_peers > 0:
            overall_state = "authenticated"
        elif any_failed:
            overall_state = "failed"
        elif self._last_auth_fail_code:
            overall_state = "failed"
            failure_code = failure_code or int(self._last_auth_fail_code or 0) or None
            failure_reason = self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code)
            failure_detail = self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code)
            failure_unix_ts = self._last_auth_fail_unix_ts
        elif any_handshaking:
            overall_state = "handshaking"
        elif bool(getattr(self._inner, "is_connected", lambda: False)()):
            overall_state = "waiting_hello"
        else:
            overall_state = "waiting_transport"
        return {
            "enabled": True,
            "mode": self._mode,
            "transport": self._transport_name,
            "state": overall_state,
            "authenticated": authenticated_peers > 0,
            "authenticated_peers": authenticated_peers,
            "rekey_in_progress": any(int(state.pending_session_id or 0) > 0 for state in self._peer_states.values()),
            "last_rekey_trigger": self._last_rekey_trigger,
            "rekey_due_unix_ts": self._client_rekey_due_unix_ts if self._client_mode else None,
            "failure_code": failure_code,
            "failure_reason": failure_reason,
            "failure_detail": failure_detail,
            "failure_unix_ts": failure_unix_ts,
            "failure_session_id": self._last_auth_fail_session_id,
            "consecutive_failures": int(self._client_retry_consecutive_failures or 0) if self._client_mode else 0,
            "retry_backoff_sec": max(0.0, self._client_retry_not_before_mono - time.monotonic()) if self._client_mode and self._client_retry_not_before_mono > 0.0 else 0.0,
            "next_retry_unix_ts": self._client_retry_not_before_unix_ts if self._client_mode else None,
            "recovery_enabled": bool(self._recover_after_failure) if self._client_mode else False,
            "recovery_delay_sec": self._recover_delay_s if self._client_mode else 0.0,
            "recovery_reconnect_sec": max(0.0, self._client_recovery_not_before_mono - time.monotonic()) if self._client_mode and self._client_recovery_not_before_mono > 0.0 else 0.0,
            "next_recovery_reconnect_unix_ts": self._client_recovery_not_before_unix_ts if self._client_mode else None,
            "handshake_attempts_total": int(self._handshake_attempts_total or 0),
            "last_event": self._last_secure_link_event,
            "last_event_unix_ts": self._last_secure_link_event_unix_ts,
            "last_authenticated_unix_ts": self._last_authenticated_unix_ts,
            "connected_since_unix_ts": primary_state.connected_since_unix_ts if primary_state is not None else None,
            "last_authenticated_session_id": self._last_authenticated_session_id,
            "authenticated_sessions_total": int(self._authenticated_sessions_total or 0),
            "rekeys_completed_total": int(self._rekeys_completed_total or 0),
            "peer_subject_id": str(primary_state.peer_subject_id or "") if primary_state is not None else "",
            "peer_subject_name": str(primary_state.peer_subject_name or "") if primary_state is not None else "",
            "peer_roles": list(primary_state.peer_roles or []) if primary_state is not None else [],
            "peer_deployment_id": str(primary_state.peer_deployment_id or "") if primary_state is not None else "",
            "peer_serial": str(primary_state.peer_serial or "") if primary_state is not None else "",
            "issuer_id": str(primary_state.issuer_id or "") if primary_state is not None else "",
            "trust_anchor_id": str(primary_state.trust_anchor_id or "") if primary_state is not None else (self._local_identity.trust_anchor_id if self._local_identity is not None else ""),
            "trust_validation_state": str(primary_state.trust_validation_state or "") if primary_state is not None else "",
            "trust_failure_reason": str(primary_state.trust_failure_reason or "") if primary_state is not None else "",
            "trust_failure_detail": str(primary_state.trust_failure_detail or "") if primary_state is not None else "",
            "active_material_generation": int(self._active_material_generation or 0),
            "last_material_reload_unix_ts": self._last_material_reload_unix_ts,
            "last_material_reload_scope": self._last_material_reload_scope,
            "last_material_reload_result": self._last_material_reload_result,
            "last_material_reload_detail": self._last_material_reload_detail,
            "trust_enforced_unix_ts": self._trust_enforced_unix_ts,
            "disconnect_reason": (str(primary_state.disconnect_reason or "") if primary_state is not None else "") or self._last_disconnect_reason,
            "disconnect_detail": (str(primary_state.disconnect_detail or "") if primary_state is not None else "") or self._last_disconnect_detail,
            "peers_dropped_total": int(self._secure_link_peers_dropped_total or 0),
        }

    def get_secure_link_operational_summary(self) -> dict:
        return {
            "enabled": bool(self._mode != "off"),
            "mode": self._mode,
            "transport": self._transport_name,
            "secure_link_material_generation": int(self._active_material_generation or 0),
            "secure_link_last_reload_unix_ts": self._last_material_reload_unix_ts,
            "secure_link_last_reload_scope": str(self._last_material_reload_scope or ""),
            "secure_link_last_reload_result": str(self._last_material_reload_result or ""),
            "secure_link_last_reload_detail": str(self._last_material_reload_detail or ""),
            "secure_link_peers_dropped_total": int(self._secure_link_peers_dropped_total or 0),
        }

    def _send_auth_fail(self, peer_id: Optional[int], session_id: int, code: int) -> None:
        self._mark_auth_fail(peer_id, session_id, code)
        try:
            self._inner.send_app(self._build_frame(self._SL_TYPE_AUTH_FAIL, session_id, 0, bytes([int(code) & 0xFF])), peer_id=peer_id)
        except Exception:
            pass

    def _begin_client_handshake(self) -> None:
        self._cancel_client_retry_task(clear_schedule=True)
        self._handshake_attempts_total += 1
        state = _SecureLinkPeerState(
            session_id=self._new_session_id(),
            client_nonce=secrets.token_bytes(32),
            consecutive_failures=int(self._client_retry_consecutive_failures or 0),
            handshake_attempts_total=int(self._handshake_attempts_total or 0),
        )
        state.last_event = "handshake_started"
        state.last_event_unix_ts = time.time()
        self._peer_states[0] = state
        self._record_secure_link_event("handshake_started", state.last_event_unix_ts)
        if self._is_cert_mode():
            eph_private = x25519.X25519PrivateKey.generate()
            eph_public = eph_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            state.local_ephemeral_private = eph_private
            state.client_nonce = eph_public
            payload = self._build_cert_hello_payload(session_id=state.session_id, eph_public=eph_public)
        else:
            payload = state.client_nonce + bytes([self._SL_CAP_PSK_V1, 0])
        self._inner.send_app(self._build_frame(self._SL_TYPE_CLIENT_HELLO, state.session_id, 0, payload))

    def _on_inner_state_change(self, connected: bool) -> None:
        if not connected:
            self._cancel_client_retry_task(clear_schedule=False)
            self._cancel_client_rekey_task(clear_schedule=False)
            self._clear_all_states()
            return
        if self._client_mode and self._started and not self._peer_states:
            self._maybe_begin_client_handshake()

    def _on_inner_transport_epoch_change(self, epoch: int) -> None:
        self._cancel_client_retry_task(clear_schedule=False)
        self._cancel_client_rekey_task(clear_schedule=False)
        self._clear_all_states()
        if self._client_mode and self._started and bool(getattr(self._inner, "is_connected", lambda: False)()):
            self._maybe_begin_client_handshake()
        if callable(self._outer_on_transport_epoch_change):
            try:
                self._outer_on_transport_epoch_change(epoch)
            except Exception:
                pass

    def _on_inner_peer_disconnect(self, peer_id: int) -> None:
        self._peer_states.pop(self._peer_key(peer_id), None)
        self._server_unregister_peer_channels(peer_id)
        self._refresh_connected_state()
        if callable(self._outer_on_peer_disconnect):
            try:
                self._outer_on_peer_disconnect(peer_id)
            except Exception:
                pass

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    @staticmethod
    def _rewrite_mux_chan_id(payload: bytes, new_chan: int) -> bytes:
        hdr = struct.Struct(">HBHBH")
        if len(payload) < hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        return hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[hdr.size:hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        hdr = struct.Struct(">HBHBH")
        if len(payload) < hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        key = (int(peer_id), int(peer_chan))
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = int(peer_chan)
            mapped = self._server_chan_to_peer.get(mux_chan)
            if mapped is not None and mapped != key:
                mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if int(key[0]) != int(peer_id):
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _resolve_server_send_target(self, payload: bytes, peer_id: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        hdr = struct.Struct(">HBHBH")
        if len(payload) < hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return None
        if len(payload) < hdr.size + dlen:
            return None
        target_peer_id = int(peer_id) if peer_id is not None else None
        mapped = self._server_chan_to_peer.get(int(mux_chan))
        if target_peer_id is None and mapped is not None:
            target_peer_id = int(mapped[0])
        if target_peer_id is None:
            if len(self._peer_states) == 1:
                target_peer_id = next(iter(self._peer_states.keys()))
            else:
                return None
        state = self._peer_states.get(int(target_peer_id))
        if state is None or not state.authenticated:
            return None
        peer_chan = int(mux_chan)
        if mapped is not None:
            if int(mapped[0]) != target_peer_id:
                return None
            peer_chan = int(mapped[1])
        else:
            key = (target_peer_id, int(mux_chan))
            self._server_peer_chan_to_mux[key] = int(mux_chan)
            self._server_chan_to_peer[int(mux_chan)] = key
        routed = self._rewrite_mux_chan_id(payload, peer_chan) if peer_chan != int(mux_chan) else payload
        return target_peer_id, routed

    def _handle_client_hello(self, peer_id: Optional[int], session_id: int, body: bytes) -> None:
        try:
            self._log.debug("[SECURE-LINK] _handle_client_hello peer_id=%r session_id=%s body_len=%d", peer_id, int(session_id or 0), len(body or b""))
        except Exception:
            pass
        if self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if self._is_cert_mode():
            parsed = self._parse_cert_handshake_payload(body)
            if parsed is None:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            remote_identity, fail_code = self._load_remote_cert(parsed["cert_body"], parsed["cert_sig"])
            if remote_identity is None:
                self._send_auth_fail(peer_id, session_id, fail_code)
                return
            try:
                remote_identity.public_key.verify(
                    parsed["proof"],
                    self._cert_client_proof_input(session_id, remote_identity.cert_body_bytes, remote_identity.cert_sig, parsed["ephemeral_pub"]),
                )
            except Exception:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_IDENTITY_PROOF)
                return
            try:
                remote_eph_public = x25519.X25519PublicKey.from_public_bytes(parsed["ephemeral_pub"])
            except Exception:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            server_eph_private = x25519.X25519PrivateKey.generate()
            server_eph_public = server_eph_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            payload = self._build_cert_server_payload(
                session_id=session_id,
                client_identity=remote_identity,
                client_eph_public=parsed["ephemeral_pub"],
                server_eph_public=server_eph_public,
            )
            transcript_hash = hashlib.sha256(body + payload).digest()
            c2s_key, s2c_key = self._derive_cert_keys(
                session_id,
                server_eph_private.exchange(remote_eph_public),
                transcript_hash,
            )
            key = self._peer_key(peer_id)
            self._handshake_attempts_total += 1
            state = _SecureLinkPeerState(
                session_id=session_id,
                client_nonce=parsed["ephemeral_pub"],
                server_nonce=server_eph_public,
                c2s_key=c2s_key,
                s2c_key=s2c_key,
                handshake_attempts_total=int(self._handshake_attempts_total or 0),
            )
            state.local_ephemeral_private = server_eph_private
            self._apply_peer_identity(state, remote_identity)
            state.last_event = "handshake_started"
            state.last_event_unix_ts = time.time()
            self._peer_states[key] = state
            self._record_secure_link_event("server_hello_sent", state.last_event_unix_ts)
            self._inner.send_app(self._build_frame(self._SL_TYPE_SERVER_HELLO, session_id, 0, payload), peer_id=peer_id)
            return
        if len(body) < 34:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        client_nonce = body[:32]
        capability = int(body[32])
        if capability != self._SL_CAP_PSK_V1:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)
            return
        server_nonce = secrets.token_bytes(32)
        c2s_key, s2c_key = self._derive_keys(session_id, client_nonce, server_nonce)
        key = self._peer_key(peer_id)
        self._handshake_attempts_total += 1
        self._peer_states[key] = _SecureLinkPeerState(
            session_id=session_id,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
            handshake_attempts_total=int(self._handshake_attempts_total or 0),
        )
        self._peer_states[key].last_event = "handshake_started"
        self._peer_states[key].last_event_unix_ts = time.time()
        self._record_secure_link_event("server_hello_sent", self._peer_states[key].last_event_unix_ts)
        proof = self._server_proof(session_id, client_nonce, server_nonce)
        payload = server_nonce + bytes([self._SL_CAP_PSK_V1]) + proof
        self._inner.send_app(self._build_frame(self._SL_TYPE_SERVER_HELLO, session_id, 0, payload), peer_id=peer_id)

    def _handle_server_hello(self, session_id: int, body: bytes) -> None:
        try:
            self._log.debug("[SECURE-LINK] _handle_server_hello session_id=%s body_len=%d", int(session_id or 0), len(body or b""))
        except Exception:
            pass
        if not self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        state = self._peer_states.get(0)
        if state is None or int(state.session_id) != int(session_id):
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if self._is_cert_mode():
            parsed = self._parse_cert_handshake_payload(body)
            if parsed is None:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            remote_identity, fail_code = self._load_remote_cert(parsed["cert_body"], parsed["cert_sig"])
            if remote_identity is None:
                self._send_auth_fail(None, session_id, fail_code)
                return
            try:
                remote_identity.public_key.verify(
                    parsed["proof"],
                    self._cert_server_proof_input(
                        session_id,
                        self._local_identity.cert_body_bytes if self._local_identity is not None else b"",
                        self._local_identity.cert_sig if self._local_identity is not None else b"",
                        state.client_nonce,
                        remote_identity.cert_body_bytes,
                        remote_identity.cert_sig,
                        parsed["ephemeral_pub"],
                    ),
                )
            except Exception:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_BAD_IDENTITY_PROOF)
                return
            if state.local_ephemeral_private is None:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
                return
            try:
                remote_eph_public = x25519.X25519PublicKey.from_public_bytes(parsed["ephemeral_pub"])
            except Exception:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            transcript_hash = hashlib.sha256(
                self._build_cert_hello_payload(session_id=session_id, eph_public=state.client_nonce) + body
            ).digest()
            c2s_key, s2c_key = self._derive_cert_keys(
                session_id,
                state.local_ephemeral_private.exchange(remote_eph_public),
                transcript_hash,
            )
            state.server_nonce = parsed["ephemeral_pub"]
            state.c2s_key = c2s_key
            state.s2c_key = s2c_key
            self._apply_peer_identity(state, remote_identity)
            self._record_authenticated_session(
                state,
                session_id=session_id,
                peer_id=None,
                event="authenticated",
                rekey_completed=False,
            )
            self._refresh_connected_state()
            return
        if len(body) < 65:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        server_nonce = body[:32]
        capability = int(body[32])
        proof = body[33:65]
        if capability != self._SL_CAP_PSK_V1:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)
            return
        expected = self._server_proof(session_id, state.client_nonce, server_nonce)
        if not hmac.compare_digest(proof, expected):
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_BAD_PSK)
            return
        c2s_key, s2c_key = self._derive_keys(session_id, state.client_nonce, server_nonce)
        state.server_nonce = server_nonce
        state.c2s_key = c2s_key
        state.s2c_key = s2c_key
        self._record_authenticated_session(
            state,
            session_id=session_id,
            peer_id=None,
            event="authenticated",
            rekey_completed=False,
        )
        self._refresh_connected_state()
        self._send_client_handshake_proof(state)

    def _handle_rekey_hello(self, peer_id: Optional[int], session_id: int, body: bytes) -> None:
        if self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if (
            state is None
            or int(state.session_id or 0) <= 0
            or not state.c2s_key
            or not state.s2c_key
        ):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if int(state.pending_session_id or 0) > 0 and int(state.pending_session_id or 0) != int(session_id):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
            return
        if self._is_cert_mode():
            parsed = self._parse_json_payload(body)
            if not isinstance(parsed, dict) or str(parsed.get("cap") or "") != "cert-v1":
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            try:
                client_eph_public = base64.b64decode(str(parsed.get("ephemeral_pub_b64") or "").encode("ascii"), validate=True)
                proof = base64.b64decode(str(parsed.get("proof_b64") or "").encode("ascii"), validate=True)
                remote_eph_public = x25519.X25519PublicKey.from_public_bytes(client_eph_public)
            except Exception:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            remote_identity = state.peer_public_key
            if not isinstance(remote_identity, ed25519.Ed25519PublicKey):
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
                return
            try:
                remote_identity.verify(proof, self._cert_rekey_hello_input(session_id, client_eph_public))
            except Exception:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_IDENTITY_PROOF)
                return
            server_eph_private = x25519.X25519PrivateKey.generate()
            server_eph_public = server_eph_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            transcript_hash = hashlib.sha256(
                b"rekey-cert|" + int(session_id).to_bytes(8, "big") + client_eph_public + server_eph_public
            ).digest()
            c2s_key, s2c_key = self._derive_cert_keys(
                session_id,
                server_eph_private.exchange(remote_eph_public),
                transcript_hash,
            )
            state.pending_session_id = int(session_id)
            state.pending_client_nonce = client_eph_public
            state.pending_server_nonce = server_eph_public
            state.pending_c2s_key = c2s_key
            state.pending_s2c_key = s2c_key
            state.pending_local_ephemeral_private = server_eph_private
            state.last_rekey_trigger = "remote"
            server_proof = self._local_identity.private_key.sign(
                self._cert_rekey_reply_input(session_id, client_eph_public, server_eph_public)
            )
            payload = self._json_payload({
                "cap": "cert-v1",
                "ephemeral_pub_b64": base64.b64encode(server_eph_public).decode("ascii"),
                "proof_b64": base64.b64encode(server_proof).decode("ascii"),
            })
            self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_REPLY, session_id, 0, payload), peer_id=peer_id)
            return
        if len(body) < 34:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        client_nonce = body[:32]
        capability = int(body[32])
        if capability != self._SL_CAP_PSK_V1:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)
            return
        server_nonce = secrets.token_bytes(32)
        c2s_key, s2c_key = self._derive_keys(session_id, client_nonce, server_nonce)
        state.pending_session_id = int(session_id)
        state.pending_client_nonce = client_nonce
        state.pending_server_nonce = server_nonce
        state.pending_c2s_key = c2s_key
        state.pending_s2c_key = s2c_key
        state.last_rekey_trigger = "remote"
        proof = self._server_proof(session_id, client_nonce, server_nonce)
        payload = server_nonce + bytes([self._SL_CAP_PSK_V1]) + proof
        self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_REPLY, session_id, 0, payload), peer_id=peer_id)

    def _handle_rekey_reply(self, session_id: int, body: bytes) -> None:
        if not self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        state = self._peer_states.get(0)
        if state is None or int(state.pending_session_id or 0) != int(session_id):
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if self._is_cert_mode():
            parsed = self._parse_json_payload(body)
            if not isinstance(parsed, dict) or str(parsed.get("cap") or "") != "cert-v1":
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            try:
                server_eph_public = base64.b64decode(str(parsed.get("ephemeral_pub_b64") or "").encode("ascii"), validate=True)
                proof = base64.b64decode(str(parsed.get("proof_b64") or "").encode("ascii"), validate=True)
                remote_eph_public = x25519.X25519PublicKey.from_public_bytes(server_eph_public)
            except Exception:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_MALFORMED_CERTIFICATE)
                return
            if state.pending_local_ephemeral_private is None or self._local_identity is None:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
                return
            # Proof is validated against the already-authenticated peer identity stored on state.
            remote_identity = state.peer_public_key
            if not isinstance(remote_identity, ed25519.Ed25519PublicKey):
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
                return
            try:
                remote_identity.verify(
                    proof,
                    self._cert_rekey_reply_input(session_id, state.pending_client_nonce, server_eph_public),
                )
            except Exception:
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_BAD_IDENTITY_PROOF)
                return
            transcript_hash = hashlib.sha256(
                b"rekey-cert|" + int(session_id).to_bytes(8, "big") + state.pending_client_nonce + server_eph_public
            ).digest()
            c2s_key, s2c_key = self._derive_cert_keys(
                session_id,
                state.pending_local_ephemeral_private.exchange(remote_eph_public),
                transcript_hash,
            )
            state.pending_server_nonce = server_eph_public
            state.pending_c2s_key = c2s_key
            state.pending_s2c_key = s2c_key
            commit = self._local_identity.private_key.sign(
                self._cert_rekey_commit_input(session_id, state.pending_client_nonce, server_eph_public)
            )
            self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_COMMIT, session_id, 0, commit))
            return
        if len(body) < 65:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        server_nonce = body[:32]
        capability = int(body[32])
        proof = body[33:65]
        if capability != self._SL_CAP_PSK_V1:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)
            return
        expected = self._server_proof(session_id, state.pending_client_nonce, server_nonce)
        if not hmac.compare_digest(proof, expected):
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_BAD_PSK)
            return
        c2s_key, s2c_key = self._derive_keys(session_id, state.pending_client_nonce, server_nonce)
        state.pending_server_nonce = server_nonce
        state.pending_c2s_key = c2s_key
        state.pending_s2c_key = s2c_key
        commit = self._client_rekey_commit_proof(session_id, state.pending_client_nonce, server_nonce)
        self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_COMMIT, session_id, 0, commit))
        self._client_rekey_hold_after_commit = True

    def _handle_rekey_commit(self, peer_id: Optional[int], session_id: int, body: bytes) -> None:
        if self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if state is None or int(state.pending_session_id or 0) != int(session_id):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if self._is_cert_mode():
            remote_identity = state.peer_public_key
            if not isinstance(remote_identity, ed25519.Ed25519PublicKey):
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
                return
            try:
                remote_identity.verify(bytes(body or b""), self._cert_rekey_commit_input(session_id, state.pending_client_nonce, state.pending_server_nonce))
            except Exception:
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_IDENTITY_PROOF)
                return
            self._promote_pending_rekey(state)
            self._record_authenticated_session(
                state,
                session_id=session_id,
                peer_id=peer_id,
                event="rekey_completed",
                rekey_completed=True,
            )
            self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_DONE, session_id, 0, b""), peer_id=peer_id)
            self._refresh_connected_state()
            return
        expected = self._client_rekey_commit_proof(session_id, state.pending_client_nonce, state.pending_server_nonce)
        if not hmac.compare_digest(bytes(body or b""), expected):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_PSK)
            return
        self._promote_pending_rekey(state)
        self._record_authenticated_session(
            state,
            session_id=session_id,
            peer_id=peer_id,
            event="rekey_completed",
            rekey_completed=True,
        )
        self._inner.send_app(self._build_frame(self._SL_TYPE_REKEY_DONE, session_id, 0, b""), peer_id=peer_id)
        self._refresh_connected_state()

    def _handle_rekey_done(self, session_id: int) -> None:
        if not self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        state = self._peer_states.get(0)
        if state is None or int(state.pending_session_id or 0) != int(session_id):
            self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        self._promote_pending_rekey(state)
        self._record_authenticated_session(
            state,
            session_id=session_id,
            peer_id=None,
            event="rekey_completed",
            rekey_completed=True,
        )
        self._refresh_connected_state()
        self._client_rekey_hold_after_commit = False
        self._flush_client_rekey_app_queue()

    def _deliver_outer_app(self, payload: bytes, peer_id: Optional[int]) -> None:
        if callable(self._outer_on_app):
            try:
                self._outer_on_app(payload, peer_id=peer_id)
            except TypeError:
                self._outer_on_app(payload)

    def _handle_data(self, peer_id: Optional[int], session_id: int, counter: int, body: bytes, aad: bytes) -> None:
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if state is None or int(state.session_id) != int(session_id):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        if int(session_id or 0) <= 0 or int(counter or 0) < self._SL_FIRST_DATA_COUNTER or int(counter) > self._SL_MAX_DATA_COUNTER:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
            return
        if counter <= int(state.rx_counter):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_REPLAY)
            return
        inbound_key = state.s2c_key if self._client_mode else state.c2s_key
        if not inbound_key:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_DECODE)
            return
        try:
            plaintext = ChaCha20Poly1305(inbound_key).decrypt(self._nonce(counter), body, aad)
        except Exception:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_PSK)
            return
        state.rx_counter = counter
        if not state.authenticated:
            self._record_authenticated_session(
                state,
                session_id=session_id,
                peer_id=peer_id,
                event="authenticated",
                rekey_completed=False,
            )
            self._refresh_connected_state()
        if not plaintext:
            return
        if not self._client_mode and peer_id is not None:
            plaintext = self._server_rewrite_inbound_app(int(peer_id), plaintext)
        self._deliver_outer_app(plaintext, None if self._client_mode else peer_id)

    def _on_inner_payload(self, payload: bytes, peer_id: Optional[int] = None) -> None:
        try:
            self._log.debug("[SECURE-LINK/RX] raw payload len=%d peer_id=%r", len(payload or b""), peer_id)
        except Exception:
            pass
        parsed = self._parse_frame(payload)
        if parsed is None:
            self._send_auth_fail(peer_id, 0, self._SL_AUTH_FAIL_DECODE)
            return
        sl_type, session_id, counter, body = parsed
        try:
            self._log.debug(
                "[SECURE-LINK/RX] parsed type=%s session_id=%s counter=%s peer_id=%r body_len=%d",
                str(sl_type), int(session_id or 0), int(counter or 0), peer_id, len(body or b""),
            )
        except Exception:
            pass
        aad = self._hdr_bytes(sl_type, session_id, counter)
        state = self._peer_states.get(self._peer_key(peer_id))
        if (
            state is not None
            and int(session_id or 0) > 0
            and int(state.session_id or 0) == int(session_id)
            and int(state.auth_fail_code or 0) > 0
        ):
            return
        if sl_type == self._SL_TYPE_CLIENT_HELLO:
            self._handle_client_hello(peer_id, session_id, body)
            return
        if sl_type == self._SL_TYPE_SERVER_HELLO:
            self._handle_server_hello(session_id, body)
            return
        if sl_type == self._SL_TYPE_AUTH_FAIL:
            code = int(body[0]) if body else self._SL_AUTH_FAIL_DECODE
            self._mark_auth_fail(peer_id, session_id, code)
            return
        if sl_type == self._SL_TYPE_REKEY_HELLO:
            self._handle_rekey_hello(peer_id, session_id, body)
            return
        if sl_type == self._SL_TYPE_REKEY_REPLY:
            self._handle_rekey_reply(session_id, body)
            return
        if sl_type == self._SL_TYPE_REKEY_COMMIT:
            self._handle_rekey_commit(peer_id, session_id, body)
            return
        if sl_type == self._SL_TYPE_REKEY_DONE:
            self._handle_rekey_done(session_id)
            return
        if sl_type == self._SL_TYPE_DATA:
            self._handle_data(peer_id, session_id, counter, body, aad)
            return
        self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)

    def _send_app_immediate(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        routed_payload = payload
        if not self._client_mode:
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                return 0
            peer_id, routed_payload = target
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if not routed_payload or state is None or not state.authenticated:
            return 0
        outbound_key = state.c2s_key if self._client_mode else state.s2c_key
        if not outbound_key:
            return 0
        counter = int(state.tx_counter)
        if counter < self._SL_FIRST_DATA_COUNTER or counter > self._SL_MAX_DATA_COUNTER:
            self._send_auth_fail(peer_id, int(state.session_id or 0), self._SL_AUTH_FAIL_LIFECYCLE)
            return 0
        aad = self._hdr_bytes(self._SL_TYPE_DATA, state.session_id, counter)
        ciphertext = ChaCha20Poly1305(outbound_key).encrypt(self._nonce(counter), routed_payload, aad)
        state.tx_counter += 1
        wire = aad + ciphertext
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._maybe_trigger_rekey(state)
        return len(payload) if sent else 0

    def _send_client_handshake_proof(self, state: Optional[_SecureLinkPeerState]) -> None:
        if not self._client_mode or state is None or not state.authenticated or state.client_handshake_proof_sent:
            return
        outbound_key = state.c2s_key
        if not outbound_key:
            return
        counter = int(state.tx_counter or 0)
        if counter < self._SL_FIRST_DATA_COUNTER or counter > self._SL_MAX_DATA_COUNTER:
            self._send_auth_fail(None, int(state.session_id or 0), self._SL_AUTH_FAIL_LIFECYCLE)
            return
        aad = self._hdr_bytes(self._SL_TYPE_DATA, state.session_id, counter)
        ciphertext = ChaCha20Poly1305(outbound_key).encrypt(self._nonce(counter), b"", aad)
        wire = aad + ciphertext
        sent = self._inner.send_app(wire)
        if sent:
            state.tx_counter += 1
            state.client_handshake_proof_sent = True

    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if self._client_mode and self._client_rekey_hold_after_commit:
            return len(payload) if self._queue_client_rekey_app_payload(payload, peer_id) else 0
        return self._send_app_immediate(payload, peer_id=peer_id)
