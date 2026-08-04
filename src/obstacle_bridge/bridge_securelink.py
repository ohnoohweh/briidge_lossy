from __future__ import annotations

from ._bridge_import import export_bridge_globals
from .bridge_transport_common import _has_configured_overlay_peer

_bridge = export_bridge_globals(globals())

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
    peer_confirmed_authenticated: bool = False
    client_handshake_proof_sent: bool = False
    handshake_started_unix_ts: Optional[float] = None
    pending_started_unix_ts: Optional[float] = None
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
    auth_fail_context: str = ""
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
    frames_passed_total: int = 0
    frames_dropped_total: int = 0
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
    last_inbound_sl_type: int = 0
    last_inbound_session_id: int = 0
    last_inbound_counter: int = 0
    last_outbound_sl_type: int = 0
    last_outbound_session_id: int = 0
    last_outbound_counter: int = 0
    server_hello_received: bool = False
    server_hello_validated: bool = False
    sticky_auth_fail_code: int = 0
    sticky_auth_fail_reason: str = ""
    client_telemetry_source: str = ""
    client_telemetry_impl_rev: str = ""
    client_telemetry_received_unix_ts: Optional[float] = None
    client_telemetry_current_attempt_session_id: Optional[int] = None
    client_telemetry_local_authenticated: bool = False
    client_telemetry_peer_confirmed_authenticated: bool = False
    client_telemetry_server_hello_received: bool = False
    client_telemetry_server_hello_validated: bool = False
    client_telemetry_handshake_proof_session_id: Optional[int] = None
    client_telemetry_handshake_proof_counter: Optional[int] = None
    client_telemetry_handshake_proof_sent: bool = False
    client_telemetry_handshake_telemetry_build_succeeded: bool = False
    client_telemetry_handshake_telemetry_payload_bytes: Optional[int] = None
    client_telemetry_handshake_telemetry_payload_sha256_prefix: str = ""
    client_telemetry_handshake_telemetry_build_error: str = ""
    client_telemetry_handshake_proof_emit_session_id: Optional[int] = None
    client_telemetry_handshake_proof_emit_counter: Optional[int] = None
    client_telemetry_handshake_proof_emit_payload_bytes: Optional[int] = None
    client_telemetry_handshake_proof_emit_payload_sha256_prefix: str = ""
    client_telemetry_tx_counter: Optional[int] = None
    client_telemetry_observed_session_id: Optional[int] = None
    client_telemetry_observed_counter: Optional[int] = None
    client_telemetry_last_inbound_sl_type: int = 0
    client_telemetry_last_inbound_session_id: int = 0
    client_telemetry_last_inbound_counter: int = 0
    client_telemetry_last_outbound_sl_type: int = 0
    client_telemetry_last_outbound_session_id: int = 0
    client_telemetry_last_outbound_counter: int = 0
    client_telemetry_parse_status: str = ""
    client_telemetry_parse_detail: str = ""
    client_telemetry_payload_len: Optional[int] = None
    client_telemetry_payload_sha256_prefix: str = ""
    client_telemetry_payload_preview: str = ""


class SecureLinkPskSession(ISession):
    _SL_IPHONE_FOCUS_LOG_REV = "bridge_securelink.py:iphone-focus-r2"

    _SL_VERSION = 1
    _SL_TYPE_CLIENT_HELLO = 1
    _SL_TYPE_SERVER_HELLO = 2
    _SL_TYPE_AUTH_FAIL = 3
    _SL_TYPE_DATA = 4
    _SL_TYPE_REKEY_HELLO = 5
    _SL_TYPE_REKEY_REPLY = 6
    _SL_TYPE_REKEY_COMMIT = 7
    _SL_TYPE_REKEY_DONE = 8
    _SL_TYPE_CLIENT_PLAINTEXT_TELEMETRY = 9
    _SL_CAP_PSK_V1 = 1
    _SL_CAP_CERT_V1 = 2
    _SL_AUTH_FAIL_BAD_PSK = 1
    _SL_AUTH_FAIL_UNSUPPORTED = 2
    _SL_AUTH_FAIL_REPLAY = 3
    _SL_AUTH_FAIL_DECODE = 4
    _SL_AUTH_FAIL_LIFECYCLE = 5
    _SL_AUTH_FAIL_UNKNOWN_ROOT = 6
    _SL_AUTH_FAIL_BAD_SIGNATURE = 7
    _SL_CLIENT_TELEMETRY_KIND = "secure_link_client_telemetry_v1"
    _SL_CLIENT_PLAINTEXT_TELEMETRY_KIND = "secure_link_client_plaintext_telemetry_v1"
    _SL_CLIENT_TELEMETRY_MAX_BYTES = 2048
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
    _HANDSHAKE_TIMEOUT_S = 60.0
    _HANDSHAKE_WATCHDOG_INTERVAL_S = 0.25

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
        self._last_auth_fail_context: str = ""
        self._last_auth_fail_unix_ts: Optional[float] = None
        self._last_auth_fail_session_id: Optional[int] = None
        self._last_terminal_failure_code: int = 0
        self._last_terminal_failure_reason: str = ""
        self._last_terminal_failure_detail: str = ""
        self._last_terminal_failure_context: str = ""
        self._last_terminal_failure_unix_ts: Optional[float] = None
        self._last_terminal_failure_session_id: Optional[int] = None
        self._last_transport_epoch_change_unix_ts: Optional[float] = None
        self._last_disconnect_reason: str = ""
        self._last_disconnect_detail: str = ""
        self._last_secure_link_event: str = ""
        self._last_secure_link_event_unix_ts: Optional[float] = None
        self._last_authenticated_unix_ts: Optional[float] = None
        self._last_authenticated_session_id: Optional[int] = None
        self._last_inbound_sl_type: int = 0
        self._last_inbound_session_id: int = 0
        self._last_inbound_counter: int = 0
        self._last_outbound_sl_type: int = 0
        self._last_outbound_session_id: int = 0
        self._last_outbound_counter: int = 0
        self._server_hello_received: bool = False
        self._server_hello_validated: bool = False
        self._last_client_telemetry_source: str = ""
        self._last_client_telemetry_impl_rev: str = ""
        self._last_client_telemetry_received_unix_ts: Optional[float] = None
        self._last_client_telemetry_current_attempt_session_id: Optional[int] = None
        self._last_client_telemetry_local_authenticated: bool = False
        self._last_client_telemetry_peer_confirmed_authenticated: bool = False
        self._last_client_telemetry_server_hello_received: bool = False
        self._last_client_telemetry_server_hello_validated: bool = False
        self._last_client_telemetry_handshake_proof_session_id: Optional[int] = None
        self._last_client_telemetry_handshake_proof_counter: Optional[int] = None
        self._last_client_telemetry_handshake_proof_sent: bool = False
        self._last_client_telemetry_handshake_telemetry_build_succeeded: bool = False
        self._last_client_telemetry_handshake_telemetry_payload_bytes: Optional[int] = None
        self._last_client_telemetry_handshake_telemetry_payload_sha256_prefix: str = ""
        self._last_client_telemetry_handshake_telemetry_build_error: str = ""
        self._last_client_telemetry_handshake_proof_emit_session_id: Optional[int] = None
        self._last_client_telemetry_handshake_proof_emit_counter: Optional[int] = None
        self._last_client_telemetry_handshake_proof_emit_payload_bytes: Optional[int] = None
        self._last_client_telemetry_handshake_proof_emit_payload_sha256_prefix: str = ""
        self._last_client_telemetry_tx_counter: Optional[int] = None
        self._last_client_telemetry_observed_session_id: Optional[int] = None
        self._last_client_telemetry_observed_counter: Optional[int] = None
        self._last_client_telemetry_last_inbound_sl_type: int = 0
        self._last_client_telemetry_last_inbound_session_id: int = 0
        self._last_client_telemetry_last_inbound_counter: int = 0
        self._last_client_telemetry_last_outbound_sl_type: int = 0
        self._last_client_telemetry_last_outbound_session_id: int = 0
        self._last_client_telemetry_last_outbound_counter: int = 0
        self._last_client_telemetry_parse_status: str = ""
        self._last_client_telemetry_parse_detail: str = ""
        self._last_client_telemetry_payload_len: Optional[int] = None
        self._last_client_telemetry_payload_sha256_prefix: str = ""
        self._last_client_telemetry_payload_preview: str = ""
        self._last_client_telemetry_log_fingerprint_by_peer: dict[int, tuple] = {}
        self._sticky_auth_fail_code: int = 0
        self._sticky_auth_fail_reason: str = ""
        self._handshake_attempts_total: int = 0
        self._authenticated_sessions_total: int = 0
        self._rekeys_completed_total: int = 0
        self._preserve_connected_during_epoch_restart = False
        self._client_retry_task: Optional[asyncio.Task] = None
        self._client_recovery_task: Optional[asyncio.Task] = None
        self._client_rekey_task: Optional[asyncio.Task] = None
        self._handshake_watchdog_task: Optional[asyncio.Task] = None
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

    def _build_client_telemetry_payload(
        self,
        state: _SecureLinkPeerState,
        *,
        proof_session_id: int,
        proof_counter: int,
    ) -> bytes:
        payload = {
            "kind": self._SL_CLIENT_TELEMETRY_KIND,
            "impl": "python",
            "current_attempt_session_id": int(state.session_id or 0) or None,
            "local_authenticated": bool(state.authenticated),
            "peer_confirmed_authenticated": bool(state.peer_confirmed_authenticated),
            "server_hello_received": bool(state.server_hello_received),
            "server_hello_validated": bool(state.server_hello_validated),
            "client_handshake_proof_session_id": int(proof_session_id or 0) or None,
            "client_handshake_proof_counter": int(proof_counter or 0) or None,
            "last_inbound_sl_type": int(state.last_inbound_sl_type or 0) or None,
            "last_inbound_session_id": int(state.last_inbound_session_id or 0) or None,
            "last_inbound_counter": int(state.last_inbound_counter or 0) or None,
            "last_outbound_sl_type": self._SL_TYPE_DATA,
            "last_outbound_session_id": int(proof_session_id or 0) or None,
            "last_outbound_counter": int(proof_counter or 0) or None,
        }
        return self._json_payload(payload)

    @staticmethod
    def _telemetry_payload_preview(payload: bytes, *, limit: int = 64) -> str:
        try:
            text = bytes(payload or b"").decode("utf-8", errors="backslashreplace")
        except Exception:
            return ""
        text = text.replace("\r", "\\r").replace("\n", "\\n")
        return text[:limit]

    def _remember_client_telemetry_state(self, state: Optional[_SecureLinkPeerState]) -> None:
        if state is None:
            return
        self._last_client_telemetry_source = str(state.client_telemetry_source or "")
        self._last_client_telemetry_impl_rev = str(state.client_telemetry_impl_rev or "")
        self._last_client_telemetry_received_unix_ts = state.client_telemetry_received_unix_ts
        self._last_client_telemetry_current_attempt_session_id = state.client_telemetry_current_attempt_session_id
        self._last_client_telemetry_local_authenticated = bool(state.client_telemetry_local_authenticated)
        self._last_client_telemetry_peer_confirmed_authenticated = bool(state.client_telemetry_peer_confirmed_authenticated)
        self._last_client_telemetry_server_hello_received = bool(state.client_telemetry_server_hello_received)
        self._last_client_telemetry_server_hello_validated = bool(state.client_telemetry_server_hello_validated)
        self._last_client_telemetry_handshake_proof_session_id = state.client_telemetry_handshake_proof_session_id
        self._last_client_telemetry_handshake_proof_counter = state.client_telemetry_handshake_proof_counter
        self._last_client_telemetry_handshake_proof_sent = bool(state.client_telemetry_handshake_proof_sent)
        self._last_client_telemetry_handshake_telemetry_build_succeeded = bool(
            state.client_telemetry_handshake_telemetry_build_succeeded
        )
        self._last_client_telemetry_handshake_telemetry_payload_bytes = state.client_telemetry_handshake_telemetry_payload_bytes
        self._last_client_telemetry_handshake_telemetry_payload_sha256_prefix = str(
            state.client_telemetry_handshake_telemetry_payload_sha256_prefix or ""
        )
        self._last_client_telemetry_handshake_telemetry_build_error = str(
            state.client_telemetry_handshake_telemetry_build_error or ""
        )
        self._last_client_telemetry_handshake_proof_emit_session_id = (
            state.client_telemetry_handshake_proof_emit_session_id
        )
        self._last_client_telemetry_handshake_proof_emit_counter = (
            state.client_telemetry_handshake_proof_emit_counter
        )
        self._last_client_telemetry_handshake_proof_emit_payload_bytes = (
            state.client_telemetry_handshake_proof_emit_payload_bytes
        )
        self._last_client_telemetry_handshake_proof_emit_payload_sha256_prefix = str(
            state.client_telemetry_handshake_proof_emit_payload_sha256_prefix or ""
        )
        self._last_client_telemetry_tx_counter = state.client_telemetry_tx_counter
        self._last_client_telemetry_observed_session_id = state.client_telemetry_observed_session_id
        self._last_client_telemetry_observed_counter = state.client_telemetry_observed_counter
        self._last_client_telemetry_last_inbound_sl_type = int(state.client_telemetry_last_inbound_sl_type or 0)
        self._last_client_telemetry_last_inbound_session_id = int(state.client_telemetry_last_inbound_session_id or 0)
        self._last_client_telemetry_last_inbound_counter = int(state.client_telemetry_last_inbound_counter or 0)
        self._last_client_telemetry_last_outbound_sl_type = int(state.client_telemetry_last_outbound_sl_type or 0)
        self._last_client_telemetry_last_outbound_session_id = int(state.client_telemetry_last_outbound_session_id or 0)
        self._last_client_telemetry_last_outbound_counter = int(state.client_telemetry_last_outbound_counter or 0)
        self._last_client_telemetry_parse_status = str(state.client_telemetry_parse_status or "")
        self._last_client_telemetry_parse_detail = str(state.client_telemetry_parse_detail or "")
        self._last_client_telemetry_payload_len = state.client_telemetry_payload_len
        self._last_client_telemetry_payload_sha256_prefix = str(state.client_telemetry_payload_sha256_prefix or "")
        self._last_client_telemetry_payload_preview = str(state.client_telemetry_payload_preview or "")

    @staticmethod
    def _server_state_log_summary(
        state: Optional[_SecureLinkPeerState],
        *,
        peer_id: Optional[int],
    ) -> dict:
        if state is None:
            return {
                "peer_id": None if peer_id is None else int(peer_id),
                "session_id": 0,
                "pending_session_id": 0,
                "authenticated": False,
                "peer_confirmed_authenticated": False,
                "auth_fail_code": 0,
                "auth_fail_context": "",
                "last_event": "",
                "last_inbound_sl_type": 0,
                "last_inbound_session_id": 0,
                "last_inbound_counter": 0,
                "last_outbound_sl_type": 0,
                "last_outbound_session_id": 0,
                "last_outbound_counter": 0,
            }
        return {
            "peer_id": None if peer_id is None else int(peer_id),
            "session_id": int(state.session_id or 0),
            "pending_session_id": int(state.pending_session_id or 0),
            "authenticated": bool(state.authenticated),
            "peer_confirmed_authenticated": bool(state.peer_confirmed_authenticated),
            "auth_fail_code": int(state.auth_fail_code or 0),
            "auth_fail_context": str(state.auth_fail_context or ""),
            "last_event": str(state.last_event or ""),
            "last_inbound_sl_type": int(state.last_inbound_sl_type or 0),
            "last_inbound_session_id": int(state.last_inbound_session_id or 0),
            "last_inbound_counter": int(state.last_inbound_counter or 0),
            "last_outbound_sl_type": int(state.last_outbound_sl_type or 0),
            "last_outbound_session_id": int(state.last_outbound_session_id or 0),
            "last_outbound_counter": int(state.last_outbound_counter or 0),
        }

    @staticmethod
    def _client_telemetry_log_summary(state: Optional[_SecureLinkPeerState]) -> dict:
        if state is None:
            return {
                "source": "",
                "impl_rev": "",
                "parse_status": "",
                "parse_detail": "",
                "current_attempt_session_id": 0,
                "local_authenticated": False,
                "peer_confirmed_authenticated": False,
                "server_hello_received": False,
                "server_hello_validated": False,
                "handshake_proof_session_id": 0,
                "handshake_proof_counter": 0,
                "handshake_proof_sent": False,
                "handshake_telemetry_build_succeeded": False,
                "handshake_telemetry_payload_bytes": None,
                "handshake_telemetry_payload_sha256_prefix": "",
                "handshake_telemetry_build_error": "",
                "handshake_proof_emit_session_id": 0,
                "handshake_proof_emit_counter": 0,
                "handshake_proof_emit_payload_bytes": None,
                "handshake_proof_emit_payload_sha256_prefix": "",
                "tx_counter": 0,
                "observed_session_id": 0,
                "observed_counter": 0,
                "last_inbound_sl_type": 0,
                "last_inbound_session_id": 0,
                "last_inbound_counter": 0,
                "last_outbound_sl_type": 0,
                "last_outbound_session_id": 0,
                "last_outbound_counter": 0,
                "payload_len": None,
                "payload_sha256_prefix": "",
            }
        return {
            "source": str(state.client_telemetry_source or ""),
            "impl_rev": str(state.client_telemetry_impl_rev or ""),
            "parse_status": str(state.client_telemetry_parse_status or ""),
            "parse_detail": str(state.client_telemetry_parse_detail or ""),
            "current_attempt_session_id": int(state.client_telemetry_current_attempt_session_id or 0),
            "local_authenticated": bool(state.client_telemetry_local_authenticated),
            "peer_confirmed_authenticated": bool(state.client_telemetry_peer_confirmed_authenticated),
            "server_hello_received": bool(state.client_telemetry_server_hello_received),
            "server_hello_validated": bool(state.client_telemetry_server_hello_validated),
            "handshake_proof_session_id": int(state.client_telemetry_handshake_proof_session_id or 0),
            "handshake_proof_counter": int(state.client_telemetry_handshake_proof_counter or 0),
            "handshake_proof_sent": bool(state.client_telemetry_handshake_proof_sent),
            "handshake_telemetry_build_succeeded": bool(state.client_telemetry_handshake_telemetry_build_succeeded),
            "handshake_telemetry_payload_bytes": state.client_telemetry_handshake_telemetry_payload_bytes,
            "handshake_telemetry_payload_sha256_prefix": str(
                state.client_telemetry_handshake_telemetry_payload_sha256_prefix or ""
            ),
            "handshake_telemetry_build_error": str(state.client_telemetry_handshake_telemetry_build_error or ""),
            "handshake_proof_emit_session_id": int(state.client_telemetry_handshake_proof_emit_session_id or 0),
            "handshake_proof_emit_counter": int(state.client_telemetry_handshake_proof_emit_counter or 0),
            "handshake_proof_emit_payload_bytes": state.client_telemetry_handshake_proof_emit_payload_bytes,
            "handshake_proof_emit_payload_sha256_prefix": str(
                state.client_telemetry_handshake_proof_emit_payload_sha256_prefix or ""
            ),
            "tx_counter": int(state.client_telemetry_tx_counter or 0),
            "observed_session_id": int(state.client_telemetry_observed_session_id or 0),
            "observed_counter": int(state.client_telemetry_observed_counter or 0),
            "last_inbound_sl_type": int(state.client_telemetry_last_inbound_sl_type or 0),
            "last_inbound_session_id": int(state.client_telemetry_last_inbound_session_id or 0),
            "last_inbound_counter": int(state.client_telemetry_last_inbound_counter or 0),
            "last_outbound_sl_type": int(state.client_telemetry_last_outbound_sl_type or 0),
            "last_outbound_session_id": int(state.client_telemetry_last_outbound_session_id or 0),
            "last_outbound_counter": int(state.client_telemetry_last_outbound_counter or 0),
            "payload_len": state.client_telemetry_payload_len,
            "payload_sha256_prefix": str(state.client_telemetry_payload_sha256_prefix or ""),
        }

    def _log_server_handshake_trace(
        self,
        event: str,
        *,
        peer_id: Optional[int],
        session_id: int,
        counter: int = 0,
        sl_type: Optional[int] = None,
        state: Optional[_SecureLinkPeerState] = None,
        note: str = "",
        body_len: Optional[int] = None,
    ) -> None:
        if self._client_mode:
            return
        try:
            self._log.info(
                "[SECURE-LINK] trace event=%s peer_id=%s session_id=%s counter=%s sl_type=%s note=%s server=%s client=%s body_len=%s",
                str(event or ""),
                None if peer_id is None else int(self._peer_key(peer_id)),
                int(session_id or 0),
                int(counter or 0),
                None if sl_type is None else int(sl_type),
                str(note or ""),
                self._server_state_log_summary(state, peer_id=peer_id),
                self._client_telemetry_log_summary(state),
                None if body_len is None else int(body_len),
            )
        except Exception:
            pass

    def _log_iphone_focus_marker(
        self,
        event: str,
        *,
        peer_id: Optional[int],
        session_id: int,
        counter: int = 0,
        state: Optional[_SecureLinkPeerState] = None,
        note: str = "",
    ) -> None:
        if self._client_mode or peer_id is None:
            return
        try:
            self._log.info(
                "[SECURE-LINK][IPHONE-FOCUS] rev=%s event=%s peer_id=%s session_id=%s counter=%s note=%s state_session_id=%s state_pending_session_id=%s authenticated=%s peer_confirmed=%s auth_fail_code=%s auth_fail_context=%s last_in_type=%s last_in_session=%s last_in_counter=%s last_out_type=%s last_out_session=%s last_out_counter=%s telemetry_source=%s telemetry_attempt_session_id=%s",
                self._SL_IPHONE_FOCUS_LOG_REV,
                str(event or ""),
                int(self._peer_key(peer_id)),
                int(session_id or 0),
                int(counter or 0),
                str(note or ""),
                0 if state is None else int(state.session_id or 0),
                0 if state is None else int(state.pending_session_id or 0),
                False if state is None else bool(state.authenticated),
                False if state is None else bool(state.peer_confirmed_authenticated),
                0 if state is None else int(state.auth_fail_code or 0),
                "" if state is None else str(state.auth_fail_context or ""),
                0 if state is None else int(state.last_inbound_sl_type or 0),
                0 if state is None else int(state.last_inbound_session_id or 0),
                0 if state is None else int(state.last_inbound_counter or 0),
                0 if state is None else int(state.last_outbound_sl_type or 0),
                0 if state is None else int(state.last_outbound_session_id or 0),
                0 if state is None else int(state.last_outbound_counter or 0),
                "" if state is None else str(state.client_telemetry_source or ""),
                0 if state is None else int(state.client_telemetry_current_attempt_session_id or 0),
            )
        except Exception:
            pass

    def _maybe_log_client_telemetry_update(
        self,
        state: Optional[_SecureLinkPeerState],
        *,
        peer_id: Optional[int],
        reason: str,
    ) -> None:
        if state is None or self._client_mode:
            return
        peer_key = self._peer_key(peer_id)
        summary = self._client_telemetry_log_summary(state)
        fingerprint = tuple(sorted(summary.items()))
        previous = self._last_client_telemetry_log_fingerprint_by_peer.get(int(peer_key))
        if previous == fingerprint:
            return
        self._last_client_telemetry_log_fingerprint_by_peer[int(peer_key)] = fingerprint
        self._log.info(
            "[SECURE-LINK] client telemetry update peer_id=%s reason=%s client=%s server=%s",
            int(peer_key),
            str(reason or ""),
            summary,
            self._server_state_log_summary(state, peer_id=peer_id),
        )

    def _capture_client_telemetry(
        self,
        state: _SecureLinkPeerState,
        payload: bytes,
        *,
        peer_id: Optional[int],
        observed_session_id: int,
        observed_counter: int,
        expected_kind: Optional[str] = None,
        parse_status: str = "captured",
    ) -> bool:
        payload_bytes = bytes(payload or b"")
        state.client_telemetry_payload_len = len(payload_bytes)
        state.client_telemetry_payload_sha256_prefix = (
            hashlib.sha256(payload_bytes).hexdigest()[:16] if payload_bytes else ""
        )
        state.client_telemetry_payload_preview = self._telemetry_payload_preview(payload_bytes)
        if not payload_bytes:
            state.client_telemetry_parse_status = "empty_payload"
            state.client_telemetry_parse_detail = "proof plaintext was empty"
            self._remember_client_telemetry_state(state)
            self._maybe_log_client_telemetry_update(state, peer_id=peer_id, reason="empty_payload")
            return False
        if len(payload_bytes) > self._SL_CLIENT_TELEMETRY_MAX_BYTES:
            state.client_telemetry_parse_status = "too_large"
            state.client_telemetry_parse_detail = (
                f"payload exceeds {self._SL_CLIENT_TELEMETRY_MAX_BYTES} bytes"
            )
            self._remember_client_telemetry_state(state)
            self._maybe_log_client_telemetry_update(state, peer_id=peer_id, reason="too_large")
            return False
        parsed = self._parse_json_payload(payload_bytes)
        if not isinstance(parsed, dict):
            state.client_telemetry_parse_status = "not_json"
            state.client_telemetry_parse_detail = "proof plaintext was not a JSON object"
            self._remember_client_telemetry_state(state)
            self._maybe_log_client_telemetry_update(state, peer_id=peer_id, reason="not_json")
            return False
        if str(parsed.get("kind") or "") != str(expected_kind or self._SL_CLIENT_TELEMETRY_KIND):
            state.client_telemetry_parse_status = "wrong_kind"
            state.client_telemetry_parse_detail = str(parsed.get("kind") or "")
            self._remember_client_telemetry_state(state)
            self._maybe_log_client_telemetry_update(state, peer_id=peer_id, reason="wrong_kind")
            return False
        state.client_telemetry_parse_status = str(parse_status or "captured")
        state.client_telemetry_parse_detail = ""
        state.client_telemetry_source = str(parsed.get("impl") or "")
        state.client_telemetry_impl_rev = str(parsed.get("impl_rev") or "")
        state.client_telemetry_received_unix_ts = time.time()
        state.client_telemetry_current_attempt_session_id = int(parsed.get("current_attempt_session_id") or 0) or None
        state.client_telemetry_local_authenticated = bool(parsed.get("local_authenticated"))
        state.client_telemetry_peer_confirmed_authenticated = bool(parsed.get("peer_confirmed_authenticated"))
        state.client_telemetry_server_hello_received = bool(parsed.get("server_hello_received"))
        state.client_telemetry_server_hello_validated = bool(parsed.get("server_hello_validated"))
        state.client_telemetry_handshake_proof_session_id = int(parsed.get("client_handshake_proof_session_id") or 0) or None
        state.client_telemetry_handshake_proof_counter = int(parsed.get("client_handshake_proof_counter") or 0) or None
        state.client_telemetry_handshake_proof_sent = bool(parsed.get("client_handshake_proof_sent"))
        state.client_telemetry_handshake_telemetry_build_succeeded = bool(
            parsed.get("client_handshake_telemetry_build_succeeded")
        )
        state.client_telemetry_handshake_telemetry_payload_bytes = (
            int(parsed.get("client_handshake_telemetry_payload_bytes") or 0) or None
        )
        state.client_telemetry_handshake_telemetry_payload_sha256_prefix = str(
            parsed.get("client_handshake_telemetry_payload_sha256_prefix") or ""
        )
        state.client_telemetry_handshake_telemetry_build_error = str(
            parsed.get("client_handshake_telemetry_build_error") or ""
        )
        state.client_telemetry_handshake_proof_emit_session_id = (
            int(parsed.get("client_handshake_proof_emit_session_id") or 0) or None
        )
        state.client_telemetry_handshake_proof_emit_counter = (
            int(parsed.get("client_handshake_proof_emit_counter") or 0) or None
        )
        state.client_telemetry_handshake_proof_emit_payload_bytes = (
            int(parsed.get("client_handshake_proof_emit_payload_bytes") or 0) or None
        )
        state.client_telemetry_handshake_proof_emit_payload_sha256_prefix = str(
            parsed.get("client_handshake_proof_emit_payload_sha256_prefix") or ""
        )
        state.client_telemetry_tx_counter = int(parsed.get("tx_counter") or 0) or None
        state.client_telemetry_observed_session_id = int(observed_session_id or 0) or None
        state.client_telemetry_observed_counter = int(observed_counter or 0) or None
        state.client_telemetry_last_inbound_sl_type = int(parsed.get("last_inbound_sl_type") or 0)
        state.client_telemetry_last_inbound_session_id = int(parsed.get("last_inbound_session_id") or 0)
        state.client_telemetry_last_inbound_counter = int(parsed.get("last_inbound_counter") or 0)
        state.client_telemetry_last_outbound_sl_type = int(parsed.get("last_outbound_sl_type") or 0)
        state.client_telemetry_last_outbound_session_id = int(parsed.get("last_outbound_session_id") or 0)
        state.client_telemetry_last_outbound_counter = int(parsed.get("last_outbound_counter") or 0)
        if state.client_telemetry_handshake_proof_session_id is None:
            state.client_telemetry_handshake_proof_session_id = int(observed_session_id or 0) or None
        if state.client_telemetry_handshake_proof_counter is None:
            state.client_telemetry_handshake_proof_counter = int(observed_counter or 0) or None
        self._remember_client_telemetry_state(state)
        self._maybe_log_client_telemetry_update(
            state,
            peer_id=peer_id,
            reason=str(parse_status or "captured"),
        )
        return True

    def _capture_client_plaintext_telemetry(
        self,
        peer_id: Optional[int],
        session_id: int,
        payload: bytes,
    ) -> bool:
        key = self._peer_key(peer_id)
        previous_state = self._peer_states.get(key)
        state = previous_state
        if state is None or int(state.session_id or 0) != int(session_id or 0):
            state = self._maybe_reassociate_server_peer_for_session(peer_id, session_id)
            if state is not None:
                key = self._peer_key(peer_id)
        if state is None:
            state = _SecureLinkPeerState(
                session_id=int(session_id or 0),
                client_nonce=b"",
            )
            if previous_state is not None:
                state.auth_fail_code = int(previous_state.auth_fail_code or 0)
                state.auth_fail_reason = str(previous_state.auth_fail_reason or "")
                state.auth_fail_detail = str(previous_state.auth_fail_detail or "")
                state.auth_fail_context = str(previous_state.auth_fail_context or "")
                state.auth_fail_unix_ts = previous_state.auth_fail_unix_ts
                state.sticky_auth_fail_code = int(previous_state.sticky_auth_fail_code or 0)
                state.sticky_auth_fail_reason = str(previous_state.sticky_auth_fail_reason or "")
                state.last_failure_session_id = previous_state.last_failure_session_id
                state.last_event = str(previous_state.last_event or "")
                state.last_event_unix_ts = previous_state.last_event_unix_ts
                state.last_inbound_sl_type = int(previous_state.last_inbound_sl_type or 0)
                state.last_inbound_session_id = int(previous_state.last_inbound_session_id or 0)
                state.last_inbound_counter = int(previous_state.last_inbound_counter or 0)
                state.last_outbound_sl_type = int(previous_state.last_outbound_sl_type or 0)
                state.last_outbound_session_id = int(previous_state.last_outbound_session_id or 0)
                state.last_outbound_counter = int(previous_state.last_outbound_counter or 0)
            self._peer_states[key] = state
        return self._capture_client_telemetry(
            state,
            payload,
            peer_id=peer_id,
            observed_session_id=int(session_id or 0),
            observed_counter=0,
            expected_kind=self._SL_CLIENT_PLAINTEXT_TELEMETRY_KIND,
            parse_status="captured_plaintext",
        )

    def _client_telemetry_snapshot(self, state: Optional[_SecureLinkPeerState]) -> dict:
        source = state
        if source is None:
            class _Fallback:
                pass
            fallback = _Fallback()
            fallback.client_telemetry_source = self._last_client_telemetry_source
            fallback.client_telemetry_impl_rev = self._last_client_telemetry_impl_rev
            fallback.client_telemetry_received_unix_ts = self._last_client_telemetry_received_unix_ts
            fallback.client_telemetry_current_attempt_session_id = self._last_client_telemetry_current_attempt_session_id
            fallback.client_telemetry_local_authenticated = self._last_client_telemetry_local_authenticated
            fallback.client_telemetry_peer_confirmed_authenticated = self._last_client_telemetry_peer_confirmed_authenticated
            fallback.client_telemetry_server_hello_received = self._last_client_telemetry_server_hello_received
            fallback.client_telemetry_server_hello_validated = self._last_client_telemetry_server_hello_validated
            fallback.client_telemetry_handshake_proof_session_id = self._last_client_telemetry_handshake_proof_session_id
            fallback.client_telemetry_handshake_proof_counter = self._last_client_telemetry_handshake_proof_counter
            fallback.client_telemetry_handshake_proof_sent = self._last_client_telemetry_handshake_proof_sent
            fallback.client_telemetry_handshake_telemetry_build_succeeded = (
                self._last_client_telemetry_handshake_telemetry_build_succeeded
            )
            fallback.client_telemetry_handshake_telemetry_payload_bytes = (
                self._last_client_telemetry_handshake_telemetry_payload_bytes
            )
            fallback.client_telemetry_handshake_telemetry_payload_sha256_prefix = (
                self._last_client_telemetry_handshake_telemetry_payload_sha256_prefix
            )
            fallback.client_telemetry_handshake_telemetry_build_error = (
                self._last_client_telemetry_handshake_telemetry_build_error
            )
            fallback.client_telemetry_handshake_proof_emit_session_id = (
                self._last_client_telemetry_handshake_proof_emit_session_id
            )
            fallback.client_telemetry_handshake_proof_emit_counter = (
                self._last_client_telemetry_handshake_proof_emit_counter
            )
            fallback.client_telemetry_handshake_proof_emit_payload_bytes = (
                self._last_client_telemetry_handshake_proof_emit_payload_bytes
            )
            fallback.client_telemetry_handshake_proof_emit_payload_sha256_prefix = (
                self._last_client_telemetry_handshake_proof_emit_payload_sha256_prefix
            )
            fallback.client_telemetry_tx_counter = self._last_client_telemetry_tx_counter
            fallback.client_telemetry_observed_session_id = self._last_client_telemetry_observed_session_id
            fallback.client_telemetry_observed_counter = self._last_client_telemetry_observed_counter
            fallback.client_telemetry_last_inbound_sl_type = self._last_client_telemetry_last_inbound_sl_type
            fallback.client_telemetry_last_inbound_session_id = self._last_client_telemetry_last_inbound_session_id
            fallback.client_telemetry_last_inbound_counter = self._last_client_telemetry_last_inbound_counter
            fallback.client_telemetry_last_outbound_sl_type = self._last_client_telemetry_last_outbound_sl_type
            fallback.client_telemetry_last_outbound_session_id = self._last_client_telemetry_last_outbound_session_id
            fallback.client_telemetry_last_outbound_counter = self._last_client_telemetry_last_outbound_counter
            fallback.client_telemetry_parse_status = self._last_client_telemetry_parse_status
            fallback.client_telemetry_parse_detail = self._last_client_telemetry_parse_detail
            fallback.client_telemetry_payload_len = self._last_client_telemetry_payload_len
            fallback.client_telemetry_payload_sha256_prefix = self._last_client_telemetry_payload_sha256_prefix
            fallback.client_telemetry_payload_preview = self._last_client_telemetry_payload_preview
            source = fallback
        if source is None:
            return {
                "client_telemetry_source": "",
                "client_telemetry_impl_rev": "",
                "client_telemetry_received_unix_ts": None,
                "client_telemetry_current_attempt_session_id": None,
                "client_telemetry_local_authenticated": False,
                "client_telemetry_peer_confirmed_authenticated": False,
                "client_telemetry_server_hello_received": False,
                "client_telemetry_server_hello_validated": False,
                "client_telemetry_handshake_proof_session_id": None,
                "client_telemetry_handshake_proof_counter": None,
                "client_telemetry_handshake_proof_sent": False,
                "client_telemetry_handshake_telemetry_build_succeeded": False,
                "client_telemetry_handshake_telemetry_payload_bytes": None,
                "client_telemetry_handshake_telemetry_payload_sha256_prefix": "",
                "client_telemetry_handshake_telemetry_build_error": "",
                "client_telemetry_handshake_proof_emit_session_id": None,
                "client_telemetry_handshake_proof_emit_counter": None,
                "client_telemetry_handshake_proof_emit_payload_bytes": None,
                "client_telemetry_handshake_proof_emit_payload_sha256_prefix": "",
                "client_telemetry_tx_counter": None,
                "client_telemetry_last_inbound_sl_type": None,
                "client_telemetry_last_inbound_session_id": None,
                "client_telemetry_last_inbound_counter": None,
                "client_telemetry_last_outbound_sl_type": None,
                "client_telemetry_last_outbound_session_id": None,
                "client_telemetry_last_outbound_counter": None,
                "client_telemetry_parse_status": "",
                "client_telemetry_parse_detail": "",
                "client_telemetry_payload_len": None,
                "client_telemetry_payload_sha256_prefix": "",
                "client_telemetry_payload_preview": "",
                "client_telemetry_attempt_matches_server_session": None,
                "client_telemetry_proof_matches_observed_frame": None,
            }
        observed_session_id = int(source.client_telemetry_observed_session_id or 0) or None
        observed_counter = int(source.client_telemetry_observed_counter or 0) or None
        proof_session_id = int(source.client_telemetry_handshake_proof_session_id or 0) or None
        proof_counter = int(source.client_telemetry_handshake_proof_counter or 0) or None
        current_attempt_session_id = int(source.client_telemetry_current_attempt_session_id or 0) or None
        return {
            "client_telemetry_source": str(source.client_telemetry_source or ""),
            "client_telemetry_impl_rev": str(source.client_telemetry_impl_rev or ""),
            "client_telemetry_received_unix_ts": source.client_telemetry_received_unix_ts,
            "client_telemetry_current_attempt_session_id": current_attempt_session_id,
            "client_telemetry_local_authenticated": bool(source.client_telemetry_local_authenticated),
            "client_telemetry_peer_confirmed_authenticated": bool(source.client_telemetry_peer_confirmed_authenticated),
            "client_telemetry_server_hello_received": bool(source.client_telemetry_server_hello_received),
            "client_telemetry_server_hello_validated": bool(source.client_telemetry_server_hello_validated),
            "client_telemetry_handshake_proof_session_id": proof_session_id,
            "client_telemetry_handshake_proof_counter": proof_counter,
            "client_telemetry_handshake_proof_sent": bool(source.client_telemetry_handshake_proof_sent),
            "client_telemetry_handshake_telemetry_build_succeeded": bool(
                source.client_telemetry_handshake_telemetry_build_succeeded
            ),
            "client_telemetry_handshake_telemetry_payload_bytes": (
                source.client_telemetry_handshake_telemetry_payload_bytes
            ),
            "client_telemetry_handshake_telemetry_payload_sha256_prefix": str(
                source.client_telemetry_handshake_telemetry_payload_sha256_prefix or ""
            ),
            "client_telemetry_handshake_telemetry_build_error": str(
                source.client_telemetry_handshake_telemetry_build_error or ""
            ),
            "client_telemetry_handshake_proof_emit_session_id": (
                int(source.client_telemetry_handshake_proof_emit_session_id or 0) or None
            ),
            "client_telemetry_handshake_proof_emit_counter": (
                int(source.client_telemetry_handshake_proof_emit_counter or 0) or None
            ),
            "client_telemetry_handshake_proof_emit_payload_bytes": (
                source.client_telemetry_handshake_proof_emit_payload_bytes
            ),
            "client_telemetry_handshake_proof_emit_payload_sha256_prefix": str(
                source.client_telemetry_handshake_proof_emit_payload_sha256_prefix or ""
            ),
            "client_telemetry_tx_counter": int(source.client_telemetry_tx_counter or 0) or None,
            "client_telemetry_last_inbound_sl_type": int(source.client_telemetry_last_inbound_sl_type or 0) or None,
            "client_telemetry_last_inbound_session_id": int(source.client_telemetry_last_inbound_session_id or 0) or None,
            "client_telemetry_last_inbound_counter": int(source.client_telemetry_last_inbound_counter or 0) or None,
            "client_telemetry_last_outbound_sl_type": int(source.client_telemetry_last_outbound_sl_type or 0) or None,
            "client_telemetry_last_outbound_session_id": int(source.client_telemetry_last_outbound_session_id or 0) or None,
            "client_telemetry_last_outbound_counter": int(source.client_telemetry_last_outbound_counter or 0) or None,
            "client_telemetry_parse_status": str(source.client_telemetry_parse_status or ""),
            "client_telemetry_parse_detail": str(source.client_telemetry_parse_detail or ""),
            "client_telemetry_payload_len": source.client_telemetry_payload_len,
            "client_telemetry_payload_sha256_prefix": str(source.client_telemetry_payload_sha256_prefix or ""),
            "client_telemetry_payload_preview": str(source.client_telemetry_payload_preview or ""),
            "client_telemetry_attempt_matches_server_session": (
                current_attempt_session_id == observed_session_id
                if current_attempt_session_id is not None and observed_session_id is not None
                else None
            ),
            "client_telemetry_proof_matches_observed_frame": (
                proof_session_id == observed_session_id and proof_counter == observed_counter
                if proof_session_id is not None and observed_session_id is not None and proof_counter is not None and observed_counter is not None
                else None
            ),
        }

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

    @staticmethod
    def _state_debug_summary(state: Optional[_SecureLinkPeerState]) -> dict:
        if state is None:
            return {
                "session_id": 0,
                "pending_session_id": 0,
                "authenticated": False,
                "peer_confirmed_authenticated": False,
                "has_c2s_key": False,
                "has_s2c_key": False,
                "telemetry_source": "",
                "telemetry_attempt_session_id": 0,
            }
        return {
            "session_id": int(state.session_id or 0),
            "pending_session_id": int(state.pending_session_id or 0),
            "authenticated": bool(state.authenticated),
            "peer_confirmed_authenticated": bool(state.peer_confirmed_authenticated),
            "has_c2s_key": bool(state.c2s_key),
            "has_s2c_key": bool(state.s2c_key),
            "telemetry_source": str(state.client_telemetry_source or ""),
            "telemetry_attempt_session_id": int(state.client_telemetry_current_attempt_session_id or 0),
        }

    @classmethod
    def _server_peer_placeholder_reject_reason(
        cls,
        current: Optional[_SecureLinkPeerState],
        *,
        session_id: int,
    ) -> str:
        if current is None:
            return "replaceable"
        if int(current.session_id or 0) == int(session_id):
            return "same_session"
        if current.authenticated:
            return "authenticated_state"
        if current.peer_confirmed_authenticated:
            return "peer_confirmed_state"
        if int(current.authenticated_sessions_total or 0) > 0:
            return "historically_authenticated_state"
        if current.c2s_key or current.s2c_key:
            return "replaceable_transient_handshake_state"
        if int(current.pending_session_id or 0) > 0:
            return "replaceable_pending_handshake_state"
        return "replaceable"

    @staticmethod
    def _can_replace_server_peer_placeholder(
        current: Optional[_SecureLinkPeerState],
        *,
        session_id: int,
    ) -> bool:
        if current is None:
            return True
        if int(current.session_id or 0) == int(session_id):
            return False
        if current.authenticated or current.peer_confirmed_authenticated:
            return False
        if int(current.authenticated_sessions_total or 0) > 0:
            return False
        return True

    @staticmethod
    def _merge_client_telemetry_state(
        dst: _SecureLinkPeerState,
        src: Optional[_SecureLinkPeerState],
    ) -> None:
        if src is None:
            return
        dst.client_telemetry_source = str(src.client_telemetry_source or dst.client_telemetry_source or "")
        dst.client_telemetry_impl_rev = str(src.client_telemetry_impl_rev or dst.client_telemetry_impl_rev or "")
        dst.client_telemetry_received_unix_ts = (
            src.client_telemetry_received_unix_ts
            if src.client_telemetry_received_unix_ts is not None
            else dst.client_telemetry_received_unix_ts
        )
        dst.client_telemetry_current_attempt_session_id = (
            int(src.client_telemetry_current_attempt_session_id or 0)
            or int(dst.client_telemetry_current_attempt_session_id or 0)
        )
        dst.client_telemetry_local_authenticated = bool(
            src.client_telemetry_local_authenticated or dst.client_telemetry_local_authenticated
        )
        dst.client_telemetry_peer_confirmed_authenticated = bool(
            src.client_telemetry_peer_confirmed_authenticated or dst.client_telemetry_peer_confirmed_authenticated
        )
        dst.client_telemetry_server_hello_received = bool(
            src.client_telemetry_server_hello_received or dst.client_telemetry_server_hello_received
        )
        dst.client_telemetry_server_hello_validated = bool(
            src.client_telemetry_server_hello_validated or dst.client_telemetry_server_hello_validated
        )
        dst.client_telemetry_handshake_proof_session_id = (
            int(src.client_telemetry_handshake_proof_session_id or 0)
            or int(dst.client_telemetry_handshake_proof_session_id or 0)
        )
        dst.client_telemetry_handshake_proof_counter = (
            int(src.client_telemetry_handshake_proof_counter or 0)
            or int(dst.client_telemetry_handshake_proof_counter or 0)
        )
        dst.client_telemetry_handshake_proof_sent = bool(
            src.client_telemetry_handshake_proof_sent or dst.client_telemetry_handshake_proof_sent
        )
        dst.client_telemetry_handshake_telemetry_build_succeeded = bool(
            src.client_telemetry_handshake_telemetry_build_succeeded
            or dst.client_telemetry_handshake_telemetry_build_succeeded
        )
        dst.client_telemetry_handshake_telemetry_payload_bytes = (
            src.client_telemetry_handshake_telemetry_payload_bytes
            if src.client_telemetry_handshake_telemetry_payload_bytes is not None
            else dst.client_telemetry_handshake_telemetry_payload_bytes
        )
        dst.client_telemetry_handshake_telemetry_payload_sha256_prefix = str(
            src.client_telemetry_handshake_telemetry_payload_sha256_prefix
            or dst.client_telemetry_handshake_telemetry_payload_sha256_prefix
            or ""
        )
        dst.client_telemetry_handshake_telemetry_build_error = str(
            src.client_telemetry_handshake_telemetry_build_error
            or dst.client_telemetry_handshake_telemetry_build_error
            or ""
        )
        dst.client_telemetry_handshake_proof_emit_session_id = (
            int(src.client_telemetry_handshake_proof_emit_session_id or 0)
            or int(dst.client_telemetry_handshake_proof_emit_session_id or 0)
        )
        dst.client_telemetry_handshake_proof_emit_counter = (
            int(src.client_telemetry_handshake_proof_emit_counter or 0)
            or int(dst.client_telemetry_handshake_proof_emit_counter or 0)
        )
        dst.client_telemetry_handshake_proof_emit_payload_bytes = (
            src.client_telemetry_handshake_proof_emit_payload_bytes
            if src.client_telemetry_handshake_proof_emit_payload_bytes is not None
            else dst.client_telemetry_handshake_proof_emit_payload_bytes
        )
        dst.client_telemetry_handshake_proof_emit_payload_sha256_prefix = str(
            src.client_telemetry_handshake_proof_emit_payload_sha256_prefix
            or dst.client_telemetry_handshake_proof_emit_payload_sha256_prefix
            or ""
        )
        dst.client_telemetry_tx_counter = (
            int(src.client_telemetry_tx_counter or 0)
            or int(dst.client_telemetry_tx_counter or 0)
        )
        dst.client_telemetry_observed_session_id = (
            int(src.client_telemetry_observed_session_id or 0)
            or int(dst.client_telemetry_observed_session_id or 0)
        )
        dst.client_telemetry_observed_counter = (
            int(src.client_telemetry_observed_counter or 0)
            or int(dst.client_telemetry_observed_counter or 0)
        )
        dst.client_telemetry_last_inbound_sl_type = (
            int(src.client_telemetry_last_inbound_sl_type or 0)
            or int(dst.client_telemetry_last_inbound_sl_type or 0)
        )
        dst.client_telemetry_last_inbound_session_id = (
            int(src.client_telemetry_last_inbound_session_id or 0)
            or int(dst.client_telemetry_last_inbound_session_id or 0)
        )
        dst.client_telemetry_last_inbound_counter = (
            int(src.client_telemetry_last_inbound_counter or 0)
            or int(dst.client_telemetry_last_inbound_counter or 0)
        )
        dst.client_telemetry_last_outbound_sl_type = (
            int(src.client_telemetry_last_outbound_sl_type or 0)
            or int(dst.client_telemetry_last_outbound_sl_type or 0)
        )
        dst.client_telemetry_last_outbound_session_id = (
            int(src.client_telemetry_last_outbound_session_id or 0)
            or int(dst.client_telemetry_last_outbound_session_id or 0)
        )
        dst.client_telemetry_last_outbound_counter = (
            int(src.client_telemetry_last_outbound_counter or 0)
            or int(dst.client_telemetry_last_outbound_counter or 0)
        )
        dst.client_telemetry_parse_status = str(src.client_telemetry_parse_status or dst.client_telemetry_parse_status or "")
        dst.client_telemetry_parse_detail = str(src.client_telemetry_parse_detail or dst.client_telemetry_parse_detail or "")
        dst.client_telemetry_payload_len = (
            src.client_telemetry_payload_len
            if src.client_telemetry_payload_len is not None
            else dst.client_telemetry_payload_len
        )
        dst.client_telemetry_payload_sha256_prefix = str(
            src.client_telemetry_payload_sha256_prefix or dst.client_telemetry_payload_sha256_prefix or ""
        )
        dst.client_telemetry_payload_preview = str(
            src.client_telemetry_payload_preview or dst.client_telemetry_payload_preview or ""
        )

    def _maybe_reassociate_server_peer_for_session(self, peer_id: Optional[int], session_id: int) -> Optional[_SecureLinkPeerState]:
        if self._client_mode or peer_id is None or int(session_id or 0) <= 0:
            return None
        new_key = self._peer_key(peer_id)
        current = self._peer_states.get(new_key)
        try:
            self._log.info(
                "[SECURE-LINK] reassociate lookup peer_id=%s session_id=%s current=%s known_peers=%s",
                int(new_key),
                int(session_id),
                self._state_debug_summary(current),
                sorted(int(k) for k in self._peer_states.keys()),
            )
        except Exception:
            pass
        if current is not None and (
            int(current.session_id or 0) == int(session_id)
            or int(current.pending_session_id or 0) == int(session_id)
        ):
            try:
                self._log.info(
                    "[SECURE-LINK] reassociate short-circuit peer_id=%s session_id=%s reason=already_bound current=%s",
                    int(new_key),
                    int(session_id),
                    self._state_debug_summary(current),
                )
            except Exception:
                pass
            return current
        for old_key, state in list(self._peer_states.items()):
            if int(old_key) == int(new_key):
                continue
            if (
                int(state.session_id or 0) != int(session_id)
                and int(state.pending_session_id or 0) != int(session_id)
            ):
                continue
            reject_reason = self._server_peer_placeholder_reject_reason(current, session_id=int(session_id))
            if not self._can_replace_server_peer_placeholder(current, session_id=int(session_id)):
                try:
                    self._log.warning(
                        "[SECURE-LINK] reassociate refused new_peer_id=%s old_peer_id=%s session_id=%s reason=%s current=%s matched=%s",
                        int(new_key),
                        int(old_key),
                        int(session_id),
                        str(reject_reason),
                        self._state_debug_summary(current),
                        self._state_debug_summary(state),
                    )
                except Exception:
                    pass
                return current
            self._merge_client_telemetry_state(state, current)
            self._peer_states[new_key] = state
            self._peer_states.pop(old_key, None)
            moved_channel_pairs: list[tuple[tuple[int, int], int]] = []
            for pair_key, mux_chan in list(self._server_peer_chan_to_mux.items()):
                try:
                    mapped_peer_id, peer_chan = pair_key
                except Exception:
                    continue
                if int(mapped_peer_id) != int(old_key):
                    continue
                moved_channel_pairs.append(((int(new_key), int(peer_chan)), int(mux_chan)))
                self._server_peer_chan_to_mux.pop(pair_key, None)
            for new_pair_key, mux_chan in moved_channel_pairs:
                self._server_peer_chan_to_mux[new_pair_key] = mux_chan
                self._server_chan_to_peer[int(mux_chan)] = new_pair_key
            try:
                self._log.info(
                    "[SECURE-LINK] reassociated server peer old_peer_id=%s new_peer_id=%s session_id=%s old=%s merged_current=%s",
                    int(old_key),
                    int(new_key),
                    int(session_id),
                    self._state_debug_summary(state),
                    self._state_debug_summary(current),
                )
            except Exception:
                pass
            return state
        try:
            self._log.warning(
                "[SECURE-LINK] reassociate miss peer_id=%s session_id=%s current=%s candidates=%s",
                int(new_key),
                int(session_id),
                self._state_debug_summary(current),
                [
                    {
                        "peer_id": int(old_key),
                        **self._state_debug_summary(state),
                    }
                    for old_key, state in sorted(self._peer_states.items(), key=lambda item: int(item[0]))
                    if int(old_key) != int(new_key)
                ],
            )
        except Exception:
            pass
        return None

    @staticmethod
    def _inherit_peer_counters(dst: _SecureLinkPeerState, src: Optional[_SecureLinkPeerState]) -> None:
        if src is None:
            return
        dst.frames_passed_total = int(src.frames_passed_total or 0)
        dst.frames_dropped_total = int(src.frames_dropped_total or 0)
        dst.sticky_auth_fail_code = int(src.sticky_auth_fail_code or 0)
        dst.sticky_auth_fail_reason = str(src.sticky_auth_fail_reason or "")
        dst.auth_fail_context = str(src.auth_fail_context or "")
        dst.last_outbound_sl_type = int(src.last_outbound_sl_type or 0)
        dst.last_outbound_session_id = int(src.last_outbound_session_id or 0)
        dst.last_outbound_counter = int(src.last_outbound_counter or 0)

    def _reset_runtime_debug_transient(self) -> None:
        self._last_inbound_sl_type = 0
        self._last_inbound_session_id = 0
        self._last_inbound_counter = 0
        self._last_outbound_sl_type = 0
        self._last_outbound_session_id = 0
        self._last_outbound_counter = 0
        self._server_hello_received = False
        self._server_hello_validated = False

    def _record_inbound_debug(
        self,
        *,
        peer_id: Optional[int],
        sl_type: int,
        session_id: int,
        counter: int,
    ) -> None:
        self._last_inbound_sl_type = int(sl_type or 0)
        self._last_inbound_session_id = int(session_id or 0)
        self._last_inbound_counter = int(counter or 0)
        state = self._peer_states.get(self._peer_key(peer_id))
        if state is None:
            return
        state.last_inbound_sl_type = int(sl_type or 0)
        state.last_inbound_session_id = int(session_id or 0)
        state.last_inbound_counter = int(counter or 0)

    def _record_outbound_debug(
        self,
        *,
        peer_id: Optional[int],
        sl_type: int,
        session_id: int,
        counter: int,
    ) -> None:
        self._last_outbound_sl_type = int(sl_type or 0)
        self._last_outbound_session_id = int(session_id or 0)
        self._last_outbound_counter = int(counter or 0)
        state = self._peer_states.get(self._peer_key(peer_id))
        if state is None:
            return
        state.last_outbound_sl_type = int(sl_type or 0)
        state.last_outbound_session_id = int(session_id or 0)
        state.last_outbound_counter = int(counter or 0)

    @staticmethod
    def _handshake_age_seconds(state: Optional[_SecureLinkPeerState], *, display_authenticated: bool) -> Optional[float]:
        if state is None:
            return None
        if display_authenticated or int(state.auth_fail_code or 0) > 0 or int(state.session_id or 0) <= 0:
            return None
        started = state.handshake_started_unix_ts
        if started is None:
            return None
        return max(0.0, time.time() - float(started))

    def _compute_connected(self) -> bool:
        if any(state.authenticated for state in self._peer_states.values()):
            return True
        return bool(self._preserve_connected_during_epoch_restart)

    def _compute_app_ready(self) -> bool:
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

    def _mark_auth_fail(self, peer_id: Optional[int], session_id: int, code: int, *, context: str = "") -> None:
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if (
            self._client_mode
            and int(session_id or 0) <= 0
            and self._client_recovery_not_before_mono > 0.0
            and (
                (state is not None and int(state.auth_fail_code or 0) > 0)
                or int(self._last_auth_fail_code or 0) > 0
            )
        ):
            return
        if state is None:
            state = _SecureLinkPeerState(
                session_id=int(session_id or 0),
                client_nonce=b"",
            )
            self._peer_states[key] = state
        elif int(session_id or 0) > 0:
            state.session_id = int(session_id)
        was_authenticated = bool(
            state.peer_confirmed_authenticated
            or int(state.authenticated_sessions_total or 0) > 0
            or (self._client_mode and int(self._authenticated_sessions_total or 0) > 0)
        )
        state.authenticated = False
        state.peer_confirmed_authenticated = False
        state.client_handshake_proof_sent = False
        state.handshake_started_unix_ts = None
        state.client_nonce = b""
        state.server_nonce = b""
        state.c2s_key = None
        state.s2c_key = None
        state.tx_counter = 1
        state.rx_counter = 0
        state.local_ephemeral_private = None
        self._clear_pending_rekey(state)
        self._clear_client_rekey_app_queue()
        state.auth_fail_code = int(code or 0)
        state.auth_fail_reason = str(self._auth_fail_reason(code) or "")
        state.auth_fail_detail = str(self._auth_fail_detail(code) or "")
        state.auth_fail_context = str(context or "")
        state.auth_fail_unix_ts = time.time()
        state.server_hello_received = False
        state.server_hello_validated = False
        state.sticky_auth_fail_code = int(code or 0)
        state.sticky_auth_fail_reason = state.auth_fail_reason
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
        self._last_auth_fail_context = state.auth_fail_context
        self._last_auth_fail_unix_ts = state.auth_fail_unix_ts
        self._last_auth_fail_session_id = int(state.session_id or 0) or None
        self._sticky_auth_fail_code = int(code or 0)
        self._sticky_auth_fail_reason = state.auth_fail_reason
        if not self._client_mode and peer_id is not None:
            self._server_unregister_peer_channels(int(peer_id))
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
        inner_connected = bool(getattr(self._inner, "is_connected", lambda: False)())
        recent_transport_epoch_change = bool(
            self._client_mode
            and self._last_transport_epoch_change_unix_ts is not None
            and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
        )
        if self._client_mode and self._started and int(code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL:
            self._cancel_client_retry_task(clear_schedule=True)
            self._cancel_client_recovery_task(clear_schedule=True)
        elif (
            self._client_mode
            and self._started
            and int(code or 0) == self._SL_AUTH_FAIL_DECODE
            and recent_transport_epoch_change
            and inner_connected
        ):
            self._cancel_client_recovery_task(clear_schedule=True)
            if self._client_retry_not_before_mono <= time.monotonic():
                self._client_retry_consecutive_failures = 0
                self._schedule_client_retry()
        elif self._client_mode and self._started and was_authenticated:
            self._cancel_client_retry_task(clear_schedule=True)
            if inner_connected:
                self._schedule_client_recovery()
            else:
                self._cancel_client_recovery_task(clear_schedule=True)
        elif self._client_mode and self._started and inner_connected:
            self._schedule_client_retry()
        self._refresh_connected_state()

    def _refresh_connected_state(self) -> None:
        connected = self._compute_app_ready()
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
        self._reset_runtime_debug_transient()
        self._refresh_connected_state()

    def _has_pending_client_recovery(self) -> bool:
        if not self._client_mode:
            return False
        if self._client_recovery_not_before_mono <= 0.0 and self._client_recovery_not_before_unix_ts is None:
            return False
        state = self._peer_states.get(0)
        return bool(state is not None and int(state.auth_fail_code or 0) > 0)

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

    def _record_local_client_auth_progress(self, state: _SecureLinkPeerState, *, session_id: int) -> None:
        now = time.time()
        state.authenticated = True
        state.peer_confirmed_authenticated = False
        state.auth_fail_code = 0
        state.auth_fail_reason = ""
        state.auth_fail_detail = ""
        state.auth_fail_unix_ts = None
        state.last_event = "handshake_local_authenticated"
        state.last_event_unix_ts = now
        if state.handshake_started_unix_ts is None:
            state.handshake_started_unix_ts = now
        self._last_auth_fail_code = 0
        self._last_auth_fail_reason = ""
        self._last_auth_fail_detail = ""
        self._last_auth_fail_unix_ts = None
        self._last_auth_fail_session_id = None
        self._record_secure_link_event("handshake_local_authenticated", now)

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
        self._preserve_connected_during_epoch_restart = False
        state.authenticated = True
        state.peer_confirmed_authenticated = True
        state.consecutive_failures = 0
        state.auth_fail_code = 0
        state.auth_fail_reason = ""
        state.auth_fail_detail = ""
        state.auth_fail_unix_ts = None
        state.handshake_started_unix_ts = None
        state.pending_started_unix_ts = None
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
        self._last_auth_fail_context = ""
        self._last_terminal_failure_code = 0
        self._last_terminal_failure_reason = ""
        self._last_terminal_failure_detail = ""
        self._last_terminal_failure_context = ""
        self._last_terminal_failure_unix_ts = None
        self._last_terminal_failure_session_id = None
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

    def _mark_peer_confirmed_authenticated(
        self,
        state: _SecureLinkPeerState,
        *,
        session_id: int,
        peer_id: Optional[int],
        event: str,
    ) -> None:
        if state.peer_confirmed_authenticated:
            return
        self._record_authenticated_session(
            state,
            session_id=session_id,
            peer_id=peer_id,
            event=event,
            rekey_completed=False,
        )
        self._refresh_connected_state()

    def _mark_handshake_timeout(
        self,
        peer_id: Optional[int],
        *,
        session_id: int,
        phase: str,
    ) -> None:
        self._mark_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE)
        state = self._peer_states.get(self._peer_key(peer_id))
        if state is None:
            return
        now = time.time()
        state.auth_fail_reason = "lifecycle"
        state.auth_fail_detail = (
            "secure-link peer confirmation timed out"
            if phase == "handshake"
            else "secure-link re-authentication timed out"
        )
        state.last_event = f"{phase}_timeout"
        state.last_event_unix_ts = now
        state.handshake_started_unix_ts = None
        state.pending_started_unix_ts = None
        self._last_auth_fail_reason = state.auth_fail_reason
        self._last_auth_fail_detail = state.auth_fail_detail
        self._last_auth_fail_unix_ts = state.auth_fail_unix_ts or now
        self._record_secure_link_event(state.last_event, now)

    def _expire_stale_handshakes(self) -> None:
        timeout_s = max(0.0, float(self._HANDSHAKE_TIMEOUT_S))
        if timeout_s <= 0.0:
            return
        now = time.time()
        for key, state in list(self._peer_states.items()):
            if int(state.auth_fail_code or 0) > 0:
                continue
            if (
                not state.peer_confirmed_authenticated
                and int(state.session_id or 0) > 0
                and state.handshake_started_unix_ts is not None
                and (now - float(state.handshake_started_unix_ts)) >= timeout_s
            ):
                self._mark_handshake_timeout(
                    None if self._client_mode else int(key),
                    session_id=int(state.session_id or 0),
                    phase="handshake",
                )
                continue
            if (
                int(state.pending_session_id or 0) > 0
                and state.pending_started_unix_ts is not None
                and (now - float(state.pending_started_unix_ts)) >= timeout_s
            ):
                self._mark_handshake_timeout(
                    None if self._client_mode else int(key),
                    session_id=int(state.pending_session_id or 0),
                    phase="rekey",
                )

    async def _handshake_watchdog(self) -> None:
        try:
            while self._started:
                self._expire_stale_handshakes()
                await asyncio.sleep(self._HANDSHAKE_WATCHDOG_INTERVAL_S)
        except asyncio.CancelledError:
            return

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
            state.last_event = "recovery_reconnect_started"
            state.last_event_unix_ts = time.time()
            self._record_secure_link_event("recovery_reconnect_started", state.last_event_unix_ts)
            self._client_recovery_not_before_mono = 0.0
            self._client_recovery_not_before_unix_ts = None
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
        if self._client_recovery_not_before_mono > time.monotonic():
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
        if any(int(state.auth_fail_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL for state in self._peer_states.values()):
            return
        if int(self._last_terminal_failure_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL:
            return
        if self._peer_states and any(state.authenticated for state in self._peer_states.values()):
            return
        if self._peer_states and any(
            int(state.session_id or 0) > 0
            and not int(state.auth_fail_code or 0)
            and not str(state.disconnect_reason or "")
            and not str(state.disconnect_detail or "")
            for state in self._peer_states.values()
        ):
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

    def _maybe_begin_client_recovery_handshake_after_reconnect(self) -> bool:
        if not self._client_mode or not self._started:
            return False
        if not bool(getattr(self._inner, "is_connected", lambda: False)()):
            return False
        if any(int(state.auth_fail_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL for state in self._peer_states.values()):
            return False
        if int(self._last_terminal_failure_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL:
            return False
        should_recover = bool(
            self._client_recovery_not_before_mono > 0.0
            or self._client_recovery_not_before_unix_ts is not None
            or any(
                str(state.last_event or "").strip().lower() == "recovery_reconnect_started"
                for state in self._peer_states.values()
            )
        )
        if not should_recover:
            return False
        self._cancel_client_retry_task(clear_schedule=True)
        self._cancel_client_recovery_task(clear_schedule=True)
        self._begin_client_handshake()
        return True

    @staticmethod
    def _clear_pending_rekey(state: _SecureLinkPeerState) -> None:
        state.pending_session_id = 0
        state.pending_client_nonce = b""
        state.pending_server_nonce = b""
        state.pending_c2s_key = None
        state.pending_s2c_key = None
        state.pending_local_ephemeral_private = None
        state.pending_started_unix_ts = None

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
        state.peer_confirmed_authenticated = True
        state.client_handshake_proof_sent = False
        state.tx_counter = 1
        state.rx_counter = 0
        state.auth_fail_code = 0
        state.auth_fail_reason = ""
        state.auth_fail_detail = ""
        state.auth_fail_unix_ts = None
        state.handshake_started_unix_ts = None
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
        state.pending_started_unix_ts = state.last_event_unix_ts
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
        if int(auth_fail_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL:
            self._last_terminal_failure_code = int(auth_fail_code or 0)
            self._last_terminal_failure_reason = state.auth_fail_reason or self._auth_fail_reason(auth_fail_code)
            self._last_terminal_failure_detail = state.auth_fail_detail or self._auth_fail_detail(auth_fail_code)
            self._last_terminal_failure_context = str(state.auth_fail_context or "")
            self._last_terminal_failure_unix_ts = state.auth_fail_unix_ts or now
            self._last_terminal_failure_session_id = int(state.last_failure_session_id or session_id or 0) or None
        self._trust_enforced_unix_ts = now
        self._secure_link_peers_dropped_total += 1
        self._record_secure_link_event("trust_enforced_disconnect", now)
        if (
            self._client_mode
            and self._started
            and str(reason or "") != "revocation_applied"
            and str(reason or "") != "local_identity_reloaded"
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
        self._last_terminal_failure_code = 0
        self._last_terminal_failure_reason = ""
        self._last_terminal_failure_detail = ""
        self._last_terminal_failure_context = ""
        self._last_terminal_failure_unix_ts = None
        self._last_terminal_failure_session_id = None
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
        dropped_total_before = int(self._secure_link_peers_dropped_total or 0)
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
                if self._client_mode:
                    self._cancel_client_retry_task(clear_schedule=True)
                    self._cancel_client_recovery_task(clear_schedule=True)
                    state.last_event = "recovery_reconnect_started"
                    state.last_event_unix_ts = time.time()
                    self._record_secure_link_event("recovery_reconnect_started", state.last_event_unix_ts)
                    if not self.request_reconnect() and bool(getattr(self._inner, "is_connected", lambda: False)()):
                        self._maybe_begin_client_recovery_handshake_after_reconnect()
        expected_dropped_total = dropped_total_before + int(dropped or 0)
        if int(self._secure_link_peers_dropped_total or 0) < expected_dropped_total:
            self._secure_link_peers_dropped_total = expected_dropped_total
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
        recent_inner_epoch_change = bool(
            self._last_transport_epoch_change_unix_ts is not None
            and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
        )
        if recent_inner_epoch_change:
            return
        self._cancel_client_retry_task(clear_schedule=False)
        self._cancel_client_rekey_task(clear_schedule=False)
        preserve_client_recovery = self._has_pending_client_recovery()
        if not preserve_client_recovery:
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
        self._handshake_watchdog_task = asyncio.create_task(self._handshake_watchdog())
        await self._inner.start()

    async def stop(self) -> None:
        if self._handshake_watchdog_task is not None:
            self._handshake_watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._handshake_watchdog_task
            self._handshake_watchdog_task = None
        self._cancel_client_retry_task(clear_schedule=True)
        self._cancel_client_rekey_task(clear_schedule=True)
        self._started = False
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
        return self._compute_app_ready()

    def get_connection_layers_snapshot(self) -> list[dict[str, object]]:
        layers = []
        getter = getattr(self._inner, "get_connection_layers_snapshot", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                layers = list(getter() or [])
        status = self.get_secure_link_status_snapshot()
        layers.append(
            {
                "layer": "secure_link",
                "transport": self._transport_name,
                "state": str(status.get("state") or ""),
                "epoch": int(self._last_authenticated_session_id or 0),
                "connected": bool(self._compute_connected()),
                "app_ready": bool(self._compute_app_ready()),
                "preserve_connected_during_epoch_restart": bool(self._preserve_connected_during_epoch_restart),
            }
        )
        return layers

    def get_transport_connected_since_unix_ts(self, peer_id: Optional[int] = None) -> Optional[float]:
        getter = getattr(self._inner, "get_transport_connected_since_unix_ts", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                value = getter(peer_id=peer_id)
                return float(value) if value is not None else None
        return None

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
        self._expire_stale_handshakes()
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
            terminal_revoked = (
                self._client_mode
                and int(self._last_terminal_failure_code or 0) == self._SL_AUTH_FAIL_REVOKED_SERIAL
            )
            authenticated = False
            failure_code = None
            failure_reason = None
            failure_detail = None
            failure_unix_ts = None
            session_id = None
            if listening:
                secure_state = "listening"
            elif (
                self._client_mode
                and not state.authenticated
                and not int(state.auth_fail_code or 0)
                and int(self._last_auth_fail_code or 0) > 0
                and int(state.handshake_attempts_total or 0) <= 0
                and int(state.session_id or 0) <= 0
            ):
                secure_state = "failed"
                failure_code = int(self._last_auth_fail_code or 0) or None
                failure_reason = self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code)
                failure_detail = self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code)
                failure_unix_ts = self._last_auth_fail_unix_ts
                session_id = int(self._last_auth_fail_session_id or 0) or None
            elif state is None and terminal_revoked:
                secure_state = "failed"
                failure_code = int(self._last_terminal_failure_code or 0) or None
                failure_reason = self._last_terminal_failure_reason or self._auth_fail_reason(self._last_terminal_failure_code)
                failure_detail = self._last_terminal_failure_detail or self._auth_fail_detail(self._last_terminal_failure_code)
                failure_unix_ts = self._last_terminal_failure_unix_ts
                session_id = int(self._last_terminal_failure_session_id or 0) or None
            elif state is None and self._last_auth_fail_code:
                secure_state = "failed"
                failure_code = int(self._last_auth_fail_code or 0) or None
                failure_reason = self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code)
                failure_detail = self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code)
                failure_unix_ts = self._last_auth_fail_unix_ts
                session_id = int(self._last_auth_fail_session_id or 0) or None
            elif state is None:
                secure_state = "handshaking" if inner_is_connected else "waiting_transport"
            elif state.peer_confirmed_authenticated:
                secure_state = "authenticated"
                authenticated = True
                session_id = int(state.session_id or 0) or None
            elif terminal_revoked:
                secure_state = "failed"
                failure_code = int(self._last_terminal_failure_code or 0) or None
                failure_reason = self._last_terminal_failure_reason or self._auth_fail_reason(self._last_terminal_failure_code)
                failure_detail = self._last_terminal_failure_detail or self._auth_fail_detail(self._last_terminal_failure_code)
                failure_unix_ts = self._last_terminal_failure_unix_ts
                session_id = int(self._last_terminal_failure_session_id or 0) or None
            elif state.auth_fail_code:
                secure_state = "failed"
                failure_code = int(state.auth_fail_code or 0) or None
                failure_reason = state.auth_fail_reason or self._auth_fail_reason(state.auth_fail_code)
                failure_detail = state.auth_fail_detail or self._auth_fail_detail(state.auth_fail_code)
                failure_unix_ts = state.auth_fail_unix_ts
                session_id = int(state.session_id or 0) or None
            elif self._last_auth_fail_code:
                secure_state = "failed"
                failure_code = int(self._last_auth_fail_code or 0) or None
                failure_reason = self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code)
                failure_detail = self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code)
                failure_unix_ts = self._last_auth_fail_unix_ts
                session_id = int(self._last_auth_fail_session_id or 0) or None
            else:
                secure_state = "handshaking" if inner_is_connected else "waiting_transport"
                session_id = int(state.session_id or 0) or None
            local_authenticated = bool(state is not None and state.authenticated)
            peer_confirmed_authenticated = bool(state is not None and state.peer_confirmed_authenticated)
            auth_fail_code = int(state.auth_fail_code or 0) if state is not None else 0
            handshake_age_sec = self._handshake_age_seconds(state, display_authenticated=authenticated)
            last_inbound_sl_type = int(state.last_inbound_sl_type or 0) if state is not None else int(self._last_inbound_sl_type or 0)
            last_inbound_session_id = int(state.last_inbound_session_id or 0) if state is not None else int(self._last_inbound_session_id or 0)
            last_inbound_counter = int(state.last_inbound_counter or 0) if state is not None else int(self._last_inbound_counter or 0)
            last_outbound_sl_type = int(state.last_outbound_sl_type or 0) if state is not None else int(self._last_outbound_sl_type or 0)
            last_outbound_session_id = int(state.last_outbound_session_id or 0) if state is not None else int(self._last_outbound_session_id or 0)
            last_outbound_counter = int(state.last_outbound_counter or 0) if state is not None else int(self._last_outbound_counter or 0)
            server_hello_received = bool(state.server_hello_received) if state is not None else bool(self._server_hello_received)
            server_hello_validated = bool(state.server_hello_validated) if state is not None else bool(self._server_hello_validated)
            sticky_auth_fail_code = int(state.sticky_auth_fail_code or 0) if state is not None else int(self._sticky_auth_fail_code or 0)
            sticky_auth_fail_reason = str(state.sticky_auth_fail_reason or "") if state is not None else str(self._sticky_auth_fail_reason or "")
            r["secure_link"] = {
                "enabled": True,
                "mode": self._mode,
                "state": secure_state,
                "authenticated": authenticated,
                "local_authenticated": local_authenticated,
                "peer_confirmed_authenticated": peer_confirmed_authenticated,
                "session_id": session_id,
                "auth_fail_code": auth_fail_code,
                "auth_fail_context": str(state.auth_fail_context or "") if state is not None else "",
                "rekey_in_progress": bool(state is not None and int(state.pending_session_id or 0) > 0),
                "last_rekey_trigger": str(state.last_rekey_trigger or "") if state is not None else "",
                "rekey_due_unix_ts": state.rekey_due_unix_ts if state is not None else None,
                "failure_code": failure_code,
                "failure_reason": failure_reason,
                "failure_detail": failure_detail,
                "failure_unix_ts": failure_unix_ts,
                "failure_session_id": state.last_failure_session_id if state is not None else None,
                "last_inbound_sl_type": last_inbound_sl_type or None,
                "last_inbound_session_id": last_inbound_session_id or None,
                "last_inbound_counter": last_inbound_counter or None,
                "last_outbound_sl_type": last_outbound_sl_type or None,
                "last_outbound_session_id": last_outbound_session_id or None,
                "last_outbound_counter": last_outbound_counter or None,
                "server_hello_received": server_hello_received,
                "server_hello_validated": server_hello_validated,
                "sticky_auth_fail_code": sticky_auth_fail_code,
                "sticky_auth_fail_reason": sticky_auth_fail_reason,
                "sticky_auth_fail_context": str(state.auth_fail_context or "") if state is not None else str(self._last_auth_fail_context or ""),
                "consecutive_failures": int(state.consecutive_failures or 0) if state is not None else 0,
                "retry_backoff_sec": max(0.0, self._client_retry_not_before_mono - time.monotonic()) if self._client_mode and self._client_retry_not_before_mono > 0.0 else 0.0,
                "next_retry_unix_ts": self._client_retry_not_before_unix_ts if self._client_mode else None,
                "recovery_enabled": bool(self._recover_after_failure) if self._client_mode else False,
                "recovery_delay_sec": self._recover_delay_s if self._client_mode else 0.0,
                "recovery_reconnect_sec": max(0.0, self._client_recovery_not_before_mono - time.monotonic()) if self._client_mode and self._client_recovery_not_before_mono > 0.0 else 0.0,
                "next_recovery_reconnect_unix_ts": self._client_recovery_not_before_unix_ts if self._client_mode else None,
                "handshake_age_sec": handshake_age_sec,
                "handshake_attempts_total": int(state.handshake_attempts_total or 0) if state is not None else 0,
                "last_event": str(state.last_event or "") if state is not None else "",
                "last_event_unix_ts": state.last_event_unix_ts if state is not None else None,
                "last_authenticated_unix_ts": state.last_authenticated_unix_ts if state is not None else None,
                "connected_since_unix_ts": state.connected_since_unix_ts if state is not None else None,
                "authenticated_sessions_total": int(state.authenticated_sessions_total or 0) if state is not None else 0,
                "rekeys_completed_total": int(state.rekeys_completed_total or 0) if state is not None else 0,
                "frames_passed_total": int(state.frames_passed_total or 0) if state is not None else 0,
                "frames_dropped_total": int(state.frames_dropped_total or 0) if state is not None else 0,
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
                "last_material_reload_unix_ts": (
                    state.last_material_reload_unix_ts
                    if state is not None and state.last_material_reload_unix_ts is not None
                    else self._last_material_reload_unix_ts
                ),
                "last_material_reload_scope": (
                    str(state.last_material_reload_scope or self._last_material_reload_scope or "")
                    if state is not None
                    else str(self._last_material_reload_scope or "")
                ),
                "last_material_reload_result": (
                    str(state.last_material_reload_result or self._last_material_reload_result or "")
                    if state is not None
                    else str(self._last_material_reload_result or "")
                ),
                "last_material_reload_detail": (
                    str(state.last_material_reload_detail or self._last_material_reload_detail or "")
                    if state is not None
                    else str(self._last_material_reload_detail or "")
                ),
                "trust_enforced_unix_ts": state.trust_enforced_unix_ts if state is not None else self._trust_enforced_unix_ts,
                "disconnect_reason": (
                    str(state.disconnect_reason or "")
                    if state is not None and str(state.disconnect_reason or "")
                    else (
                        str(self._last_disconnect_reason or "")
                        or ("revocation_applied" if failure_reason == "revoked_serial" else "")
                    )
                ),
                "disconnect_detail": (
                    str(state.disconnect_detail or "")
                    if state is not None and str(state.disconnect_detail or "")
                    else (
                        str(self._last_disconnect_detail or "")
                        or (
                            "peer certificate serial is revoked by the reloaded denylist"
                            if failure_reason == "revoked_serial"
                            else ""
                        )
                    )
                ),
            }
            r["secure_link"].update(self._client_telemetry_snapshot(state))
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
        if (
            self._last_auth_fail_code
            and not any(
                str((row.get("secure_link") or {}).get("state") or "").strip().lower() == "failed"
                for row in out
            )
        ):
            out.append(
                {
                    "id": "secure-link:last-failure",
                    "transport": self._transport_name,
                    "state": "disconnected",
                    "connected": False,
                    "listen": None,
                    "peer": None,
                    "rtt_est_ms": None,
                    "transmit_delay_sample_ms": None,
                    "transmit_delay_est_ms": None,
                    "last_incoming_age_seconds": None,
                    "inflight": None,
                    "decode_errors": 0,
                    "open_connections": {"udp": 0, "tcp": 0, "tun": 0},
                    "traffic": {"rx_bytes": 0, "tx_bytes": 0, "rx_bytes_per_sec": 0.0, "tx_bytes_per_sec": 0.0},
                    "myudp": {"buffered_frames": 0, "first_pass": 0, "repeated_once": 0, "repeated_multiple": 0, "confirmed_total": 0},
                    "secure_link": {
                        "enabled": True,
                        "mode": self._mode,
                        "state": "failed",
                        "authenticated": False,
                        "local_authenticated": False,
                        "peer_confirmed_authenticated": False,
                        "session_id": int(self._last_auth_fail_session_id or 0) or None,
                        "auth_fail_code": int(self._last_auth_fail_code or 0),
                        "auth_fail_context": str(self._last_auth_fail_context or ""),
                        "rekey_in_progress": False,
                        "last_rekey_trigger": self._last_rekey_trigger,
                        "rekey_due_unix_ts": None,
                        "failure_code": int(self._last_auth_fail_code or 0) or None,
                        "failure_reason": self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code),
                        "failure_detail": self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code),
                        "failure_unix_ts": self._last_auth_fail_unix_ts,
                        "failure_session_id": self._last_auth_fail_session_id,
                        "last_inbound_sl_type": int(self._last_inbound_sl_type or 0) or None,
                        "last_inbound_session_id": int(self._last_inbound_session_id or 0) or None,
                        "last_inbound_counter": int(self._last_inbound_counter or 0) or None,
                        "last_outbound_sl_type": int(self._last_outbound_sl_type or 0) or None,
                        "last_outbound_session_id": int(self._last_outbound_session_id or 0) or None,
                        "last_outbound_counter": int(self._last_outbound_counter or 0) or None,
                        "server_hello_received": bool(self._server_hello_received),
                        "server_hello_validated": bool(self._server_hello_validated),
                        "sticky_auth_fail_code": int(self._sticky_auth_fail_code or 0),
                        "sticky_auth_fail_reason": str(self._sticky_auth_fail_reason or ""),
                        "sticky_auth_fail_context": str(self._last_auth_fail_context or ""),
                        "consecutive_failures": 0,
                        "retry_backoff_sec": 0.0,
                        "next_retry_unix_ts": None,
                        "recovery_enabled": False,
                        "recovery_delay_sec": 0.0,
                        "recovery_reconnect_sec": 0.0,
                        "next_recovery_reconnect_unix_ts": None,
                        "handshake_age_sec": None,
                        "handshake_attempts_total": int(self._handshake_attempts_total or 0),
                        "last_event": self._last_secure_link_event,
                        "last_event_unix_ts": self._last_secure_link_event_unix_ts,
                        "last_authenticated_unix_ts": self._last_authenticated_unix_ts,
                        "connected_since_unix_ts": None,
                        "authenticated_sessions_total": int(self._authenticated_sessions_total or 0),
                        "rekeys_completed_total": int(self._rekeys_completed_total or 0),
                        "frames_passed_total": 0,
                        "frames_dropped_total": 0,
                        "transport": self._transport_name,
                        "peer_subject_id": "",
                        "peer_subject_name": "",
                        "peer_roles": [],
                        "peer_deployment_id": "",
                        "peer_serial": "",
                        "issuer_id": "",
                        "trust_anchor_id": self._local_identity.trust_anchor_id if self._local_identity is not None else "",
                        "trust_validation_state": "",
                        "trust_failure_reason": "",
                        "trust_failure_detail": "",
                        "active_material_generation": int(self._active_material_generation or 0),
                        "last_material_reload_unix_ts": self._last_material_reload_unix_ts,
                        "last_material_reload_scope": str(self._last_material_reload_scope or ""),
                        "last_material_reload_result": str(self._last_material_reload_result or ""),
                        "last_material_reload_detail": str(self._last_material_reload_detail or ""),
                        "trust_enforced_unix_ts": self._trust_enforced_unix_ts,
                        "disconnect_reason": self._last_disconnect_reason,
                        "disconnect_detail": self._last_disconnect_detail,
                    },
                    "compress_layer": {
                        "enabled": False,
                        "algorithm": "zlib",
                        "transport": self._transport_name,
                        "level": 3,
                        "min_bytes": 64,
                        "compress_attempts_total": 0,
                        "compress_applied_total": 0,
                        "compress_skipped_no_gain_total": 0,
                        "compress_input_bytes_total": 0,
                        "compress_output_bytes_total": 0,
                        "decompress_ok_total": 0,
                        "decompress_fail_total": 0,
                    },
                }
            )
            out[-1]["secure_link"].update(self._client_telemetry_snapshot(None))
        return out

    def get_secure_link_status_snapshot(self) -> dict:
        self._expire_stale_handshakes()
        any_failed = False
        failure_code = None
        failure_reason = None
        failure_detail = None
        failure_context = None
        failure_unix_ts = None
        any_handshaking = False
        authenticated_peers = 0
        local_authenticated = False
        primary_state: Optional[_SecureLinkPeerState] = None
        for state in self._peer_states.values():
            if primary_state is None:
                primary_state = state
            if state.authenticated:
                local_authenticated = True
            if state.peer_confirmed_authenticated:
                authenticated_peers += 1
            elif state.auth_fail_code:
                any_failed = True
                failure_code = failure_code or int(state.auth_fail_code or 0) or None
                failure_reason = failure_reason or state.auth_fail_reason or self._auth_fail_reason(state.auth_fail_code)
                failure_detail = failure_detail or state.auth_fail_detail or self._auth_fail_detail(state.auth_fail_code)
                failure_context = failure_context or str(state.auth_fail_context or "")
                failure_unix_ts = failure_unix_ts or state.auth_fail_unix_ts
            else:
                any_handshaking = True
        if authenticated_peers > 0:
            overall_state = "authenticated"
        elif any_failed:
            overall_state = "failed"
        elif int(self._last_terminal_failure_code or 0) > 0:
            overall_state = "failed"
            failure_code = failure_code or int(self._last_terminal_failure_code or 0) or None
            failure_reason = self._last_terminal_failure_reason or self._auth_fail_reason(self._last_terminal_failure_code)
            failure_detail = self._last_terminal_failure_detail or self._auth_fail_detail(self._last_terminal_failure_code)
            failure_context = self._last_terminal_failure_context or failure_context
            failure_unix_ts = self._last_terminal_failure_unix_ts
        elif self._last_auth_fail_code:
            overall_state = "failed"
            failure_code = failure_code or int(self._last_auth_fail_code or 0) or None
            failure_reason = self._last_auth_fail_reason or self._auth_fail_reason(self._last_auth_fail_code)
            failure_detail = self._last_auth_fail_detail or self._auth_fail_detail(self._last_auth_fail_code)
            failure_context = self._last_auth_fail_context or failure_context
            failure_unix_ts = self._last_auth_fail_unix_ts
        elif any_handshaking:
            overall_state = "handshaking"
        elif bool(getattr(self._inner, "is_connected", lambda: False)()):
            overall_state = "waiting_hello"
        else:
            overall_state = "waiting_transport"
        handshake_age_sec = self._handshake_age_seconds(primary_state, display_authenticated=authenticated_peers > 0)
        return {
            "enabled": True,
            "mode": self._mode,
            "transport": self._transport_name,
            "state": overall_state,
            "authenticated": authenticated_peers > 0,
            "local_authenticated": local_authenticated,
            "peer_confirmed_authenticated": authenticated_peers > 0,
            "auth_fail_code": int(primary_state.auth_fail_code or 0) if primary_state is not None else int(self._last_auth_fail_code or 0),
            "auth_fail_context": (
                str(primary_state.auth_fail_context or "")
                if primary_state is not None
                else str(self._last_auth_fail_context or "")
            ),
            "authenticated_peers": authenticated_peers,
            "rekey_in_progress": any(int(state.pending_session_id or 0) > 0 for state in self._peer_states.values()),
            "last_rekey_trigger": self._last_rekey_trigger,
            "rekey_due_unix_ts": self._client_rekey_due_unix_ts if self._client_mode else None,
            "failure_code": failure_code,
            "failure_reason": failure_reason,
            "failure_detail": failure_detail,
            "failure_context": failure_context,
            "failure_unix_ts": failure_unix_ts,
            "failure_session_id": (
                self._last_terminal_failure_session_id
                if int(self._last_terminal_failure_code or 0) > 0
                else self._last_auth_fail_session_id
            ),
            "consecutive_failures": int(self._client_retry_consecutive_failures or 0) if self._client_mode else 0,
            "retry_backoff_sec": max(0.0, self._client_retry_not_before_mono - time.monotonic()) if self._client_mode and self._client_retry_not_before_mono > 0.0 else 0.0,
            "next_retry_unix_ts": self._client_retry_not_before_unix_ts if self._client_mode else None,
            "recovery_enabled": bool(self._recover_after_failure) if self._client_mode else False,
            "recovery_delay_sec": self._recover_delay_s if self._client_mode else 0.0,
            "recovery_reconnect_sec": max(0.0, self._client_recovery_not_before_mono - time.monotonic()) if self._client_mode and self._client_recovery_not_before_mono > 0.0 else 0.0,
            "next_recovery_reconnect_unix_ts": self._client_recovery_not_before_unix_ts if self._client_mode else None,
            "handshake_attempts_total": int(self._handshake_attempts_total or 0),
            "handshake_age_sec": handshake_age_sec,
            "last_event": self._last_secure_link_event,
            "last_event_unix_ts": self._last_secure_link_event_unix_ts,
            "last_authenticated_unix_ts": self._last_authenticated_unix_ts,
            "connected_since_unix_ts": primary_state.connected_since_unix_ts if primary_state is not None else None,
            "last_authenticated_session_id": self._last_authenticated_session_id,
            "last_inbound_sl_type": (
                int(primary_state.last_inbound_sl_type or 0) if primary_state is not None else int(self._last_inbound_sl_type or 0)
            ) or None,
            "last_inbound_session_id": (
                int(primary_state.last_inbound_session_id or 0) if primary_state is not None else int(self._last_inbound_session_id or 0)
            ) or None,
            "last_inbound_counter": (
                int(primary_state.last_inbound_counter or 0) if primary_state is not None else int(self._last_inbound_counter or 0)
            ) or None,
            "last_outbound_sl_type": (
                int(primary_state.last_outbound_sl_type or 0) if primary_state is not None else int(self._last_outbound_sl_type or 0)
            ) or None,
            "last_outbound_session_id": (
                int(primary_state.last_outbound_session_id or 0) if primary_state is not None else int(self._last_outbound_session_id or 0)
            ) or None,
            "last_outbound_counter": (
                int(primary_state.last_outbound_counter or 0) if primary_state is not None else int(self._last_outbound_counter or 0)
            ) or None,
            "server_hello_received": (
                bool(primary_state.server_hello_received) if primary_state is not None else bool(self._server_hello_received)
            ),
            "server_hello_validated": (
                bool(primary_state.server_hello_validated) if primary_state is not None else bool(self._server_hello_validated)
            ),
            "sticky_auth_fail_code": (
                int(primary_state.sticky_auth_fail_code or 0) if primary_state is not None else int(self._sticky_auth_fail_code or 0)
            ),
            "sticky_auth_fail_reason": (
                str(primary_state.sticky_auth_fail_reason or "") if primary_state is not None else str(self._sticky_auth_fail_reason or "")
            ),
            "sticky_auth_fail_context": (
                str(primary_state.auth_fail_context or "")
                if primary_state is not None
                else str(self._last_auth_fail_context or "")
            ),
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
            "disconnect_reason": (
                (str(primary_state.disconnect_reason or "") if primary_state is not None else "")
                or self._last_disconnect_reason
                or ("revocation_applied" if failure_reason == "revoked_serial" else "")
            ),
            "disconnect_detail": (
                (str(primary_state.disconnect_detail or "") if primary_state is not None else "")
                or self._last_disconnect_detail
                or ("peer certificate serial is revoked by the reloaded denylist" if failure_reason == "revoked_serial" else "")
            ),
            "peers_dropped_total": int(self._secure_link_peers_dropped_total or 0),
        } | self._client_telemetry_snapshot(primary_state)

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

    def _send_auth_fail(self, peer_id: Optional[int], session_id: int, code: int, *, context: str = "") -> None:
        if (
            self._client_mode
            and int(code or 0) == self._SL_AUTH_FAIL_DECODE
            and self._last_transport_epoch_change_unix_ts is not None
            and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
        ):
            return
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if state is None:
            state = _SecureLinkPeerState(
                session_id=int(session_id or 0),
                client_nonce=b"",
            )
            self._peer_states[key] = state
        state.frames_dropped_total = int(state.frames_dropped_total or 0) + 1
        self._mark_auth_fail(peer_id, session_id, code, context=context)
        try:
            wire = self._build_frame(self._SL_TYPE_AUTH_FAIL, session_id, 0, bytes([int(code) & 0xFF]))
            sent = self._inner.send_app(wire, peer_id=peer_id)
            if sent:
                self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_AUTH_FAIL, session_id=session_id, counter=0)
        except Exception:
            pass

    def _begin_client_handshake(self) -> None:
        self._cancel_client_retry_task(clear_schedule=True)
        self._last_auth_fail_code = 0
        self._last_auth_fail_reason = ""
        self._last_auth_fail_detail = ""
        self._last_auth_fail_unix_ts = None
        self._last_auth_fail_session_id = None
        self._handshake_attempts_total += 1
        self._reset_runtime_debug_transient()
        state = _SecureLinkPeerState(
            session_id=self._new_session_id(),
            client_nonce=secrets.token_bytes(32),
            consecutive_failures=int(self._client_retry_consecutive_failures or 0),
            handshake_attempts_total=int(self._handshake_attempts_total or 0),
        )
        self._inherit_peer_counters(state, self._peer_states.get(0))
        state.last_event = "handshake_started"
        state.last_event_unix_ts = time.time()
        state.handshake_started_unix_ts = state.last_event_unix_ts
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
        wire = self._build_frame(self._SL_TYPE_CLIENT_HELLO, state.session_id, 0, payload)
        sent = self._inner.send_app(wire)
        if sent:
            self._record_outbound_debug(peer_id=None, sl_type=self._SL_TYPE_CLIENT_HELLO, session_id=state.session_id, counter=0)

    def _on_inner_state_change(self, connected: bool) -> None:
        if not connected:
            if bool(getattr(self._inner, "is_connected", lambda: False)()):
                self._refresh_connected_state()
                return
            self._preserve_connected_during_epoch_restart = False
            self._cancel_client_retry_task(clear_schedule=False)
            self._cancel_client_rekey_task(clear_schedule=False)
            if self._client_mode:
                preserving_epoch_restart_handshake = bool(
                    self._last_transport_epoch_change_unix_ts is not None
                    and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
                    and any(
                        not state.peer_confirmed_authenticated
                        and int(state.session_id or 0) > 0
                        and int(state.handshake_attempts_total or 0) > 0
                        and not int(state.auth_fail_code or 0)
                        and not str(state.disconnect_reason or "")
                        and not str(state.disconnect_detail or "")
                        for state in self._peer_states.values()
                    )
                )
                if preserving_epoch_restart_handshake:
                    self._refresh_connected_state()
                    return
                preserving_failure_state = bool(
                    self._client_recovery_not_before_mono > 0.0
                    or self._client_recovery_not_before_unix_ts is not None
                    or any(
                        int(state.auth_fail_code or 0) > 0
                        or str(state.disconnect_reason or "")
                        or str(state.disconnect_detail or "")
                        for state in self._peer_states.values()
                    )
                )
                if preserving_failure_state:
                    self._refresh_connected_state()
                    return
            self._clear_all_states()
            return
        if self._client_mode and self._started:
            if self._maybe_begin_client_recovery_handshake_after_reconnect():
                return
            self._maybe_begin_client_handshake()

    def _on_inner_transport_epoch_change(self, epoch: int) -> None:
        self._cancel_client_retry_task(clear_schedule=False)
        self._cancel_client_rekey_task(clear_schedule=False)
        self._last_transport_epoch_change_unix_ts = time.time()
        client_has_authenticated_history = bool(int(self._authenticated_sessions_total or 0) > 0)
        preserve_connected_epoch_restart = (
            self._client_mode
            and bool(getattr(self._inner, "is_connected", lambda: False)())
            and any(
                state.peer_confirmed_authenticated
                or int(state.authenticated_sessions_total or 0) > 0
                for state in self._peer_states.values()
            )
        )
        preserve_client_handshake = (
            self._client_mode
            and not client_has_authenticated_history
            and any(
                not state.peer_confirmed_authenticated
                and int(state.session_id or 0) > 0
                and int(state.handshake_attempts_total or 0) > 0
                and int(state.authenticated_sessions_total or 0) <= 0
                and not int(state.auth_fail_code or 0)
                for state in self._peer_states.values()
            )
        )
        preserve_client_recovery = self._has_pending_client_recovery()
        self._log.info(
            "[SECURE-LINK] transport epoch change transport=%s side=%s epoch=%s preserve_connected=%s preserve_handshake=%s preserve_recovery=%s authenticated_sessions_total=%s peer_states=%s",
            self._transport_name,
            "client" if self._client_mode else "server",
            int(epoch),
            bool(preserve_connected_epoch_restart),
            bool(preserve_client_handshake),
            bool(preserve_client_recovery),
            int(self._authenticated_sessions_total or 0),
            len(self._peer_states),
        )
        self._preserve_connected_during_epoch_restart = bool(preserve_connected_epoch_restart)
        if not preserve_client_handshake and not preserve_client_recovery:
            self._clear_all_states()
        if (
            self._client_mode
            and self._started
            and bool(getattr(self._inner, "is_connected", lambda: False)())
            and not preserve_client_handshake
            and not preserve_client_recovery
        ):
            self._maybe_begin_client_handshake()
        if callable(self._outer_on_transport_epoch_change):
            try:
                self._outer_on_transport_epoch_change(epoch)
            except Exception:
                pass

    def _on_inner_peer_disconnect(self, peer_id: int) -> None:
        state = self._peer_states.get(self._peer_key(peer_id))
        preserve_server_peer_handoff = bool(
            (not self._client_mode)
            and bool(getattr(self._inner, "is_connected", lambda: False)())
            and state is not None
            and (
                state.peer_confirmed_authenticated
                or int(state.authenticated_sessions_total or 0) > 0
            )
        )
        if state is None or (not state.auth_fail_code and not state.disconnect_reason and not state.disconnect_detail):
            self._peer_states.pop(self._peer_key(peer_id), None)
        else:
            state.authenticated = False
            state.connected_since_unix_ts = None
        if preserve_server_peer_handoff:
            self._preserve_connected_during_epoch_restart = True
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
        self._log_server_handshake_trace(
            "client_hello_received",
            peer_id=peer_id,
            session_id=session_id,
            sl_type=self._SL_TYPE_CLIENT_HELLO,
            state=self._peer_states.get(self._peer_key(peer_id)),
            body_len=len(body or b""),
        )
        self._log_iphone_focus_marker(
            "client_hello_received",
            peer_id=peer_id,
            session_id=session_id,
            state=self._peer_states.get(self._peer_key(peer_id)),
            note="before_server_hello",
        )
        if self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_client_hello.invalid_mode_or_session",
            )
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
            previous_state = self._peer_states.get(key)
            self._handshake_attempts_total += 1
            state = _SecureLinkPeerState(
                session_id=session_id,
                client_nonce=parsed["ephemeral_pub"],
                server_nonce=server_eph_public,
                c2s_key=c2s_key,
                s2c_key=s2c_key,
                handshake_attempts_total=int(self._handshake_attempts_total or 0),
            )
            self._inherit_peer_counters(state, previous_state)
            state.local_ephemeral_private = server_eph_private
            self._apply_peer_identity(state, remote_identity)
            if previous_state is not None and int(previous_state.auth_fail_code or 0) > 0 and not previous_state.authenticated:
                state.auth_fail_code = int(previous_state.auth_fail_code or 0)
                state.auth_fail_reason = str(previous_state.auth_fail_reason or "")
                state.auth_fail_detail = str(previous_state.auth_fail_detail or "")
                state.auth_fail_unix_ts = previous_state.auth_fail_unix_ts
                state.last_failure_session_id = previous_state.last_failure_session_id
                state.last_event = str(previous_state.last_event or "")
                state.last_event_unix_ts = previous_state.last_event_unix_ts
            else:
                state.last_event = "handshake_started"
                state.last_event_unix_ts = time.time()
            self._peer_states[key] = state
            self._record_secure_link_event("server_hello_sent", state.last_event_unix_ts)
            wire = self._build_frame(self._SL_TYPE_SERVER_HELLO, session_id, 0, payload)
            sent = self._inner.send_app(wire, peer_id=peer_id)
            if sent:
                self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_SERVER_HELLO, session_id=session_id, counter=0)
                self._log_server_handshake_trace(
                    "server_hello_sent",
                    peer_id=peer_id,
                    session_id=session_id,
                    sl_type=self._SL_TYPE_SERVER_HELLO,
                    state=previous_state,
                    note="reused_pending_handshake",
                    body_len=len(payload),
                )
                self._log_iphone_focus_marker(
                    "server_hello_sent",
                    peer_id=peer_id,
                    session_id=session_id,
                    state=previous_state,
                    note="reused_pending_handshake",
                )
            return
        if len(body) < 34:
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_client_hello.body_too_short",
            )
            return
        client_nonce = body[:32]
        capability = int(body[32])
        if capability != self._SL_CAP_PSK_V1:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_UNSUPPORTED)
            return
        key = self._peer_key(peer_id)
        previous_state = self._peer_states.get(key)
        if (
            previous_state is not None
            and not previous_state.authenticated
            and int(previous_state.auth_fail_code or 0) == 0
            and int(previous_state.session_id or 0) == int(session_id)
            and bytes(previous_state.client_nonce or b"") == bytes(client_nonce)
            and len(bytes(previous_state.server_nonce or b"")) == 32
            and previous_state.c2s_key
            and previous_state.s2c_key
        ):
            proof = self._server_proof(session_id, client_nonce, bytes(previous_state.server_nonce))
            payload = bytes(previous_state.server_nonce) + bytes([self._SL_CAP_PSK_V1]) + proof
            wire = self._build_frame(self._SL_TYPE_SERVER_HELLO, session_id, 0, payload)
            sent = self._inner.send_app(wire, peer_id=peer_id)
            if sent:
                self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_SERVER_HELLO, session_id=session_id, counter=0)
            return
        server_nonce = secrets.token_bytes(32)
        c2s_key, s2c_key = self._derive_keys(session_id, client_nonce, server_nonce)
        self._handshake_attempts_total += 1
        state = _SecureLinkPeerState(
            session_id=session_id,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
            handshake_attempts_total=int(self._handshake_attempts_total or 0),
        )
        self._inherit_peer_counters(state, previous_state)
        state.handshake_started_unix_ts = time.time()
        if previous_state is not None and int(previous_state.auth_fail_code or 0) > 0 and not previous_state.authenticated:
            state.auth_fail_code = int(previous_state.auth_fail_code or 0)
            state.auth_fail_reason = str(previous_state.auth_fail_reason or "")
            state.auth_fail_detail = str(previous_state.auth_fail_detail or "")
            state.auth_fail_unix_ts = previous_state.auth_fail_unix_ts
            state.last_failure_session_id = previous_state.last_failure_session_id
            state.last_event = str(previous_state.last_event or "")
            state.last_event_unix_ts = previous_state.last_event_unix_ts
        else:
            state.last_event = "handshake_started"
            state.last_event_unix_ts = time.time()
        self._peer_states[key] = state
        self._record_secure_link_event("server_hello_sent", state.last_event_unix_ts)
        proof = self._server_proof(session_id, client_nonce, server_nonce)
        payload = server_nonce + bytes([self._SL_CAP_PSK_V1]) + proof
        wire = self._build_frame(self._SL_TYPE_SERVER_HELLO, session_id, 0, payload)
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_SERVER_HELLO, session_id=session_id, counter=0)
            self._log_server_handshake_trace(
                "server_hello_sent",
                peer_id=peer_id,
                session_id=session_id,
                sl_type=self._SL_TYPE_SERVER_HELLO,
                state=state,
                note="new_handshake_state",
                body_len=len(payload),
            )
            self._log_iphone_focus_marker(
                "server_hello_sent",
                peer_id=peer_id,
                session_id=session_id,
                state=state,
                note="new_handshake_state",
            )

    def _handle_server_hello(self, session_id: int, body: bytes) -> None:
        try:
            self._log.debug("[SECURE-LINK] _handle_server_hello session_id=%s body_len=%d", int(session_id or 0), len(body or b""))
        except Exception:
            pass
        if not self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(
                None,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_server_hello.invalid_mode_or_session",
            )
            return
        state = self._peer_states.get(0)
        if state is None or int(state.session_id) != int(session_id):
            recent_transport_epoch_change = bool(
                self._client_mode
                and self._last_transport_epoch_change_unix_ts is not None
                and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
            )
            if recent_transport_epoch_change:
                return
            self._send_auth_fail(
                None,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_server_hello.session_mismatch",
            )
            return
        self._server_hello_received = True
        state.server_hello_received = True
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
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_server_hello.proof_send")
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
            self._server_hello_validated = True
            state.server_hello_validated = True
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
            self._send_auth_fail(
                None,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_server_hello.body_too_short",
            )
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
        self._server_hello_validated = True
        state.server_hello_validated = True
        self._record_local_client_auth_progress(state, session_id=session_id)
        self._send_client_handshake_proof(state)

    def _handle_rekey_hello(self, peer_id: Optional[int], session_id: int, body: bytes) -> None:
        if self._client_mode or int(session_id or 0) <= 0:
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_rekey_hello.invalid_mode_or_session",
            )
            return
        key = self._peer_key(peer_id)
        state = self._peer_states.get(key)
        if (
            state is None
            or int(state.session_id or 0) <= 0
            or not state.c2s_key
            or not state.s2c_key
        ):
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_rekey_hello.missing_active_state",
            )
            return
        if int(state.pending_session_id or 0) > 0 and int(state.pending_session_id or 0) != int(session_id):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_rekey_hello.pending_session_mismatch")
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
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_rekey_hello.remote_identity_missing")
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
            wire = self._build_frame(self._SL_TYPE_REKEY_REPLY, session_id, 0, payload)
            sent = self._inner.send_app(wire, peer_id=peer_id)
            if sent:
                self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_REKEY_REPLY, session_id=session_id, counter=0)
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
        wire = self._build_frame(self._SL_TYPE_REKEY_REPLY, session_id, 0, payload)
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_REKEY_REPLY, session_id=session_id, counter=0)

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
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_rekey_reply.pending_local_identity_missing")
                return
            # Proof is validated against the already-authenticated peer identity stored on state.
            remote_identity = state.peer_public_key
            if not isinstance(remote_identity, ed25519.Ed25519PublicKey):
                self._send_auth_fail(None, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_rekey_reply.remote_identity_missing")
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
            wire = self._build_frame(self._SL_TYPE_REKEY_COMMIT, session_id, 0, commit)
            sent = self._inner.send_app(wire)
            if sent:
                self._record_outbound_debug(peer_id=None, sl_type=self._SL_TYPE_REKEY_COMMIT, session_id=session_id, counter=0)
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
        wire = self._build_frame(self._SL_TYPE_REKEY_COMMIT, session_id, 0, commit)
        sent = self._inner.send_app(wire)
        if sent:
            self._record_outbound_debug(peer_id=None, sl_type=self._SL_TYPE_REKEY_COMMIT, session_id=session_id, counter=0)
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
                self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_rekey_commit.pending_session_mismatch")
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
            wire = self._build_frame(self._SL_TYPE_REKEY_DONE, session_id, 0, b"")
            sent = self._inner.send_app(wire, peer_id=peer_id)
            if sent:
                self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_REKEY_DONE, session_id=session_id, counter=0)
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
        wire = self._build_frame(self._SL_TYPE_REKEY_DONE, session_id, 0, b"")
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_REKEY_DONE, session_id=session_id, counter=0)
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
        if state is None:
            state = self._maybe_reassociate_server_peer_for_session(peer_id, session_id)
        self._log_server_handshake_trace(
            "data_frame_received",
            peer_id=peer_id,
            session_id=session_id,
            counter=counter,
            sl_type=self._SL_TYPE_DATA,
            state=state,
            note="pre_validation",
            body_len=len(body or b""),
        )
        self._log_iphone_focus_marker(
            "data_frame_received",
            peer_id=peer_id,
            session_id=session_id,
            counter=counter,
            state=state,
            note="pre_validation",
        )
        if state is None or int(state.session_id) != int(session_id):
            try:
                self._log.warning(
                    "[SECURE-LINK] data session mismatch peer_id=%s session_id=%s counter=%s current=%s peers=%s",
                    int(key),
                    int(session_id),
                    int(counter or 0),
                    self._state_debug_summary(state),
                    [
                        {
                            "peer_id": int(existing_key),
                            **self._state_debug_summary(existing_state),
                        }
                        for existing_key, existing_state in sorted(self._peer_states.items(), key=lambda item: int(item[0]))
                    ],
                )
            except Exception:
                pass
            self._log_server_handshake_trace(
                "data_session_mismatch",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                sl_type=self._SL_TYPE_DATA,
                state=state,
                note="reject_before_decrypt",
                body_len=len(body or b""),
            )
            self._log_iphone_focus_marker(
                "data_session_mismatch",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                state=state,
                note="reject_before_decrypt",
            )
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_data.session_mismatch",
            )
            return
        if int(session_id or 0) <= 0 or int(counter or 0) < self._SL_FIRST_DATA_COUNTER or int(counter) > self._SL_MAX_DATA_COUNTER:
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_LIFECYCLE, context="handle_data.counter_range")
            return
        if counter <= int(state.rx_counter):
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_REPLAY)
            return
        inbound_key = state.s2c_key if self._client_mode else state.c2s_key
        if not inbound_key:
            self._log_server_handshake_trace(
                "data_missing_inbound_key",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                sl_type=self._SL_TYPE_DATA,
                state=state,
                note="reject_before_decrypt",
                body_len=len(body or b""),
            )
            self._send_auth_fail(
                peer_id,
                session_id,
                self._SL_AUTH_FAIL_DECODE,
                context="handle_data.missing_inbound_key",
            )
            return
        try:
            plaintext = ChaCha20Poly1305(inbound_key).decrypt(self._nonce(counter), body, aad)
        except Exception:
            self._log_server_handshake_trace(
                "data_decrypt_failed",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                sl_type=self._SL_TYPE_DATA,
                state=state,
                note="bad_psk_or_wrong_key",
                body_len=len(body or b""),
            )
            self._send_auth_fail(peer_id, session_id, self._SL_AUTH_FAIL_BAD_PSK)
            return
        state.rx_counter = counter
        state.frames_passed_total = int(state.frames_passed_total or 0) + 1
        was_peer_confirmed = bool(state.peer_confirmed_authenticated)
        newly_authenticated = False
        if not state.authenticated:
            self._record_authenticated_session(
                state,
                session_id=session_id,
                peer_id=peer_id,
                event="authenticated",
                rekey_completed=False,
            )
            self._refresh_connected_state()
            newly_authenticated = True
        elif not state.peer_confirmed_authenticated:
            self._mark_peer_confirmed_authenticated(
                state,
                session_id=session_id,
                peer_id=peer_id,
                event="authenticated",
            )
        if newly_authenticated and not self._client_mode:
            self._send_server_handshake_ack(state, peer_id=peer_id)
        if not self._client_mode and not was_peer_confirmed and self._capture_client_telemetry(
            state,
            plaintext,
            peer_id=peer_id,
            observed_session_id=session_id,
            observed_counter=counter,
        ):
            self._log_server_handshake_trace(
                "data_client_telemetry_captured",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                sl_type=self._SL_TYPE_DATA,
                state=state,
                note="post_decrypt",
                body_len=len(plaintext),
            )
            return
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
        if not self._client_mode:
            self._log_iphone_focus_marker(
                "inner_payload_parsed",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                state=self._peer_states.get(self._peer_key(peer_id)),
                note=f"sl_type={int(sl_type or 0)} body_len={len(body or b'')}",
            )
        if not self._client_mode and sl_type != self._SL_TYPE_CLIENT_HELLO:
            self._maybe_reassociate_server_peer_for_session(peer_id, session_id)
        self._record_inbound_debug(
            peer_id=peer_id,
            sl_type=sl_type,
            session_id=session_id,
            counter=counter,
        )
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
            sl_type != self._SL_TYPE_CLIENT_PLAINTEXT_TELEMETRY
            and state is not None
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
            if self._client_mode and int(session_id or 0) > 0:
                recent_transport_epoch_change = bool(
                    self._last_transport_epoch_change_unix_ts is not None
                    and (time.time() - float(self._last_transport_epoch_change_unix_ts)) <= 2.0
                )
                if state is None:
                    if recent_transport_epoch_change:
                        return
                else:
                    current_session_id = int(state.session_id or 0)
                    pending_session_id = int(state.pending_session_id or 0)
                    if (
                        current_session_id > 0
                        and int(session_id or 0) != current_session_id
                        and int(session_id or 0) != pending_session_id
                    ):
                        return
            code = int(body[0]) if body else self._SL_AUTH_FAIL_DECODE
            self._mark_auth_fail(peer_id, session_id, code)
            return
        if sl_type == self._SL_TYPE_CLIENT_PLAINTEXT_TELEMETRY:
            self._log_server_handshake_trace(
                "plaintext_telemetry_received",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                sl_type=sl_type,
                state=self._peer_states.get(self._peer_key(peer_id)),
                note="pre_capture",
                body_len=len(body or b""),
            )
            self._log_iphone_focus_marker(
                "plaintext_telemetry_received",
                peer_id=peer_id,
                session_id=session_id,
                counter=counter,
                state=self._peer_states.get(self._peer_key(peer_id)),
                note="pre_capture",
            )
            self._capture_client_plaintext_telemetry(peer_id, session_id, body)
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
            self._send_auth_fail(peer_id, int(state.session_id or 0), self._SL_AUTH_FAIL_LIFECYCLE, context="send_app.counter_range")
            return 0
        aad = self._hdr_bytes(self._SL_TYPE_DATA, state.session_id, counter)
        ciphertext = ChaCha20Poly1305(outbound_key).encrypt(self._nonce(counter), routed_payload, aad)
        state.tx_counter += 1
        wire = aad + ciphertext
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_DATA, session_id=int(state.session_id or 0), counter=counter)
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
            self._send_auth_fail(None, int(state.session_id or 0), self._SL_AUTH_FAIL_LIFECYCLE, context="send_client_handshake_proof.counter_range")
            return
        aad = self._hdr_bytes(self._SL_TYPE_DATA, state.session_id, counter)
        telemetry = self._build_client_telemetry_payload(
            state,
            proof_session_id=int(state.session_id or 0),
            proof_counter=counter,
        )
        ciphertext = ChaCha20Poly1305(outbound_key).encrypt(self._nonce(counter), telemetry, aad)
        wire = aad + ciphertext
        sent = self._inner.send_app(wire)
        if sent:
            self._record_outbound_debug(peer_id=None, sl_type=self._SL_TYPE_DATA, session_id=int(state.session_id or 0), counter=counter)
            state.tx_counter += 1
            state.client_handshake_proof_sent = True

    def _send_server_handshake_ack(self, state: Optional[_SecureLinkPeerState], *, peer_id: Optional[int]) -> None:
        if self._client_mode or state is None or not state.authenticated:
            return
        outbound_key = state.s2c_key
        if not outbound_key:
            return
        counter = int(state.tx_counter or 0)
        if counter < self._SL_FIRST_DATA_COUNTER or counter > self._SL_MAX_DATA_COUNTER:
            self._send_auth_fail(peer_id, int(state.session_id or 0), self._SL_AUTH_FAIL_LIFECYCLE, context="send_server_handshake_ack.counter_range")
            return
        aad = self._hdr_bytes(self._SL_TYPE_DATA, state.session_id, counter)
        ciphertext = ChaCha20Poly1305(outbound_key).encrypt(self._nonce(counter), b"", aad)
        wire = aad + ciphertext
        sent = self._inner.send_app(wire, peer_id=peer_id)
        if sent:
            self._record_outbound_debug(peer_id=peer_id, sl_type=self._SL_TYPE_DATA, session_id=int(state.session_id or 0), counter=counter)
            state.tx_counter += 1

    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if self._client_mode and self._client_rekey_hold_after_commit:
            return len(payload) if self._queue_client_rekey_app_payload(payload, peer_id) else 0
        return self._send_app_immediate(payload, peer_id=peer_id)
