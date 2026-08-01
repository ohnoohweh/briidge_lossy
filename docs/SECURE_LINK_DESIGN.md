# Secure Link Design

## Purpose

This document describes the current SecureLink design and implementation state in ObstacleBridge.

SecureLink is the transport-independent security layer that adds:

- mutual peer authentication
- tunnel confidentiality
- tunnel integrity
- replay protection
- key rotation and revocation hooks

Current branch state:

- ObstacleBridge already ships a transport-independent secure-link layer below `ChannelMux` and above the transport sessions
- PSK mode is delivered across `myudp`, `tcp`, `ws`, and `quic`
- certificate mode with admin-signed identities, revocation, and live reload/apply controls is delivered
- the remaining work is now hardening, parity tightening, observability polish, and any future wire-compatibility/operational improvements rather than initial feature bring-up

The design intentionally keeps authentication and encryption below `ChannelMux` and above the transport sessions so that:

- `ChannelMux` continues to process plaintext authenticated frames only
- `myudp`, `tcp`, `ws`, and `quic` session classes do not need to understand certificate policy
- one security model can span all overlay transports

## Scope

This document is state-based, not a historical rollout log.

It covers:

- identity and trust model
- handshake model
- session-key derivation
- frame protection
- layering
- dependency strategy

It does not yet define:

- a frozen long-term wire-compatibility commitment for every secure-link frame shape
- exact storage format for private keys on disk
- full admin UI flows for certificate issuance
- every remaining parity or observability gap across Python, macOS Swift, and iOS Swift surfaces

## Current State Summary

The following points describe the currently delivered SecureLink baseline:

- one transport-independent secure-link layer spans the supported overlay transports
- the secure-link layer sits below `ChannelMux` and above the transport/session layer
- PSK mode exists as an explicit, opt-in development and compatibility mode
- certificate mode is the deployment-rooted trust model
- peer-scoped admin/API visibility is part of the delivered model, but some presentation/parity details still evolve
- the primary open work is no longer "whether SecureLink exists", but how clearly and safely it behaves under churn, replay, reload, parity, and operator troubleshooting

### Trust model

- one deployment-local admin root keypair acts as the trust anchor
- the root public key is provisioned explicitly on peer clients and peer servers
- the root private key is not intended to live on normal runtime nodes
- each peer client and peer server gets its own leaf identity keypair and its own admin-signed certificate
- mutual authentication is required: client verifies server and server verifies client
- certificate roles are explicit and enforced:
  - `client`
  - `server`
  - `client,server`
- revocation is identified by certificate serial number
- the first operational revocation model is a local denylist by serial number
- no intermediate CA hierarchy is currently part of the design

### Certificate profile

- the project will use a minimal project-local certificate profile rather than X.509 as the first target
- the certificate format must be versioned and canonicalizable for signing
- the certificate expresses identity and authorization metadata only
- traffic encryption keys are always ephemeral and are never stored in certificates

### Layer boundary

- transport/session code remains responsible for sockets, listener/client state, reconnect logic, and transport-specific bootstrap such as websocket proxy traversal
- the secure-link layer owns handshake state, certificate validation, identity proof, session-key derivation, ciphertext/plaintext transition, replay protection, and rekey hooks
- `ChannelMux` remains unaware of certificates, identity policy, and traffic ciphers
- admin APIs may later expose peer identity metadata, but admin rendering is not part of the secure-link layer itself
- WebAdmin visibility of secure-link state is a joint function of the secure-link layer, runner snapshot wiring, and the admin web/observability layer

### Dependency policy

- the Python runtime accepts `cryptography` as the focused mandatory crypto dependency for SecureLink-capable environments
- no second crypto framework should be introduced for the same feature without a deliberate redesign decision
- stdlib helpers may be used for configuration, serialization, hashing support, and HKDF-related glue, but not as a substitute for modern asymmetric crypto and AEAD primitives
- transport-specific TLS libraries are not the primary dependency strategy for secure-link

## Current PSK Runtime Model

Current explicit PSK mode:

- `secure_link_mode = psk`

Behavioral intent:

- both peers are manually provisioned with the same pre-shared secret
- the PSK mode is explicit and opt-in
- PSK mode is useful for development, interoperability checks, troubleshooting, and environments that are not yet operating with certificate material
- PSK mode is not the long-term production trust model

### PSK frame envelope

The delivered PSK secure-link layer wraps bytes exchanged between the transport/session layer and the current overlay framing/mux path.

Conceptual envelope fields:

- `sl_version`
  - secure-link wire version
  - current value: `1`
- `sl_type`
  - one of:
    - `client_hello`
    - `server_hello`
    - `auth_fail`
    - `data`
- `sl_flags`
  - reserved for later negotiation or rekey bits
  - current default: `0`
- `sl_session_id`
  - random session identifier chosen by the initiator
  - used to bind the handshake and later data frames to one secure-link session
- `sl_counter`
  - per-direction monotonic counter
  - `0` for initial handshake messages
  - increments for protected `data` frames
- `sl_payload`
  - handshake payload or ciphertext payload depending on `sl_type`

Boundary rule:

- transport/session code carries this envelope opaquely
- `ChannelMux` does not see the envelope directly

Serialization note:

- a compact binary encoding is preferred for the actual implementation
- the exact byte layout is implementation-defined and versioned in code; this document describes the logical contract rather than freezing a permanent public wire standard

### PSK handshake messages

The delivered PSK handshake remains intentionally small and symmetric.

#### `client_hello`

Sent by the initiating peer.

Payload contents:

- `client_nonce`
  - random 32-byte nonce
- `client_capabilities`
  - initial fixed value identifying `psk-v1`
- `key_schedule_hint`
  - reserved field for later compatibility
  - current fixed value: `0`

Meaning:

- announces the intent to start a PSK secure-link session
- contributes entropy to the derived session keys

#### `server_hello`

Sent by the accepting peer in response to `client_hello`.

Payload contents:

- `server_nonce`
  - random 32-byte nonce
- `selected_capability`
  - `psk-v1`
- `server_proof`
  - HMAC over the handshake transcript so far using the configured PSK

Meaning:

- confirms that the responder knows the PSK
- commits the responder to the handshake transcript

#### Client handshake confirmation

Instead:

- immediately after validating `server_hello`, the client emits one internal zero-length protected `data` frame as proof that it derived the same traffic keys
- the responder authenticates the session when it successfully decrypts that proof frame rather than waiting for the first real application payload
- if the responder cannot authenticate that proof frame, the secure-link session is rejected
- the proof frame is consumed inside the secure-link layer and is not surfaced upward as application payload or `ChannelMux` traffic

This keeps the PSK control surface smaller while still validating both directions.

#### `auth_fail`

Sent optionally when failure can be signaled cleanly.

Payload contents:

- failure code such as:
  - `bad_psk`
  - `unsupported_mode`
  - `replay_detected`
  - `decode_error`

Meaning:

- makes lab/debug failures easier to observe
- is not required on every failure path if the safer action is to close the session immediately

### PSK key derivation

Inputs:

- configured PSK bytes
- `client_nonce`
- `server_nonce`
- transcript bytes for `client_hello` and `server_hello`

Derivation shape:

- derive a handshake secret from `PSK + client_nonce + server_nonce`
- derive directional traffic keys with HKDF-SHA256
- derive separate keys for:
  - client-to-server traffic
  - server-to-client traffic

Replay and nonce rule:

- each protected `data` frame uses the directional `sl_counter` as AEAD nonce/counter input
- counters are monotonic per direction
- duplicate or older counters are rejected

### Protected data frames

After successful PSK handshake:

- `sl_type = data`
- `sl_payload` carries AEAD-protected bytes
- plaintext input to the AEAD is exactly the byte stream or frame sequence that would otherwise continue upward to the existing overlay logic

Layering rule:

- secure-link decrypts before bytes reach the current overlay framing/mux path
- secure-link encrypts after bytes leave the current overlay framing/mux path toward the transport/session layer
- `ChannelMux` remains unchanged

### Config keys

Recommended keys:

- `secure_link`
  - boolean
  - default: `false`
  - enables the secure-link layer
- `secure_link_mode`
  - string
  - one of:
    - `off`
    - `psk`
    - `cert`
- `secure_link_psk`
  - string
  - shared secret input for lab/development PSK mode
- `secure_link_rekey_after_frames`
  - integer
  - default: `0`
  - when `> 0`, the client side automatically initiates PSK rekey after this many protected data frames have been sent under the current secure-link session
- `secure_link_require`
  - boolean
  - default: `false`
  - when `true`, fail closed if secure-link cannot be negotiated

Config interpretation rules:

- if `secure_link = false`, the runtime behaves exactly as today
- if `secure_link = true` and `secure_link_mode = psk`, both sides must have the same `secure_link_psk`
- if `secure_link_rekey_after_frames > 0`, the current PSK runtime slice initiates client-driven rekey using a fresh secure-link session id and fresh nonces while preserving the overlay connection
- `secure_link_require = true` is mainly useful for tests to ensure the path does not silently fall back to plaintext

## Design goals

- keep the transport/session layer mostly unchanged
- keep `ChannelMux` unaware of authentication and encryption
- support mutual authentication between peer client and peer server
- support per-session forward-secret encryption
- allow admin-controlled certificate issuance and revocation
- keep the Python dependency footprint as small and portable as practical

## Proposal rationale

The recommended design is based on the following security requirements:

- a trust anchor must exist and be deployment-local
- both sides must authenticate each other
- identity proof and session encryption must be separate concerns
- the handshake must resist replay and active manipulation
- traffic encryption must include integrity protection, not just confidentiality

This rules out a minimal "signed public key plus symmetric cipher" approach.

Main reasons:

- client authentication is described, but server authentication is not fully symmetric
- signing a public key is not enough without certificate metadata such as role, validity, issuer, and revocation identity
- a signed identity alone does not define a secure session-key agreement
- a secure-link design must bind the handshake transcript strongly enough to stop replay or active manipulation
- "AES256 encryption" is not sufficient as a protocol description without nonce handling, integrity protection, and key derivation

Conclusion:

- keep the trust-chain idea
- do not implement the protocol as an ad hoc custom signature-and-AES scheme

## Recommended architecture

Introduce a new layer:

- transport/session layer
- secure-link layer
- `ChannelMux`

Responsibilities:

- transport/session layer:
  - carry opaque byte streams or datagrams
  - manage transport connectivity and reconnect behavior
- secure-link layer:
  - handshake
  - certificate validation
  - key agreement
  - encryption/decryption
  - replay protection
  - rekeying
- `ChannelMux`:
  - unchanged logical multiplexing over authenticated plaintext frames

This matches the current architecture well because it localizes security responsibilities in one place instead of fragmenting them across every transport implementation.

## Trust model

Recommended model: small private PKI with one admin trust anchor.

Actors:

- server admin / deployment admin
  - owns the root signing keypair
- peer server / listener instance
  - owns its own identity keypair
  - holds an admin-signed certificate
- peer client instance
  - owns its own identity keypair
  - holds an admin-signed certificate

Trust anchor distribution:

- each peer client and peer server is configured with the admin root public key
- only the admin root private key can issue valid peer certificates

This is not a public CA model. It is a deployment-local trust hierarchy.

Current design decision:

- no certificate chain beyond root -> leaf is currently part of the design
- leaf certificates are bound to concrete peer identities, not to anonymous user groups
- the trust anchor is deployment-scoped, so cross-deployment trust is intentionally out of scope
- the initial revocation model is file/config-driven rather than OCSP/CRL infrastructure

## Certificate model

The design does not require X.509 specifically. A minimal custom certificate format is acceptable if it is signed correctly and versioned carefully.

Required certificate fields:

- format version
- subject identifier
- subject display name or label
- issuer identifier
- certificate serial number
- public-key algorithm identifier
- public identity key
- role:
  - `client`
  - `server`
  - `client,server`
- issued-at timestamp
- validity:
  - `not_before`
  - `not_after`
- deployment identifier
- optional constraints or permissions
- signature by admin root private key

Recommended logical field names:

- `version`
- `serial`
- `issuer_id`
- `subject_id`
- `subject_name`
- `deployment_id`
- `public_key_algorithm`
- `public_key`
- `roles`
- `issued_at`
- `not_before`
- `not_after`
- `constraints`
- `signature_algorithm`
- `signature`

Field expectations:

- `serial` must be globally unique within one deployment
- `subject_id` must be stable enough to identify one peer instance across reconnects and certificate renewal
- `deployment_id` prevents accidental trust crossover between separate installations that may otherwise reuse hostnames or labels
- `roles` must be machine-enforced, not only informational
- `constraints` should start simple and may be empty in early operational use
- the signed content must exclude the `signature` field itself and must use one canonical serialization rule

Initial certificate policy decisions:

- certificates are signed only by the admin root private key
- self-signatures are not part of trust evaluation
- certificate renewal is expected to issue a new serial number
- certificate expiry is mandatory; indefinitely valid certificates are not the target model

Important:

- self-signing by the user should not be treated as part of trust establishment
- the meaningful trust statement is the admin signature over the subject public key and metadata

## Mutual authentication

Authentication must be symmetric.

When a connection is established:

- client authenticates server
- server authenticates client
- both validate the presented certificate against the admin root public key
- both verify proof-of-possession of the private identity key

Without server authentication, a man-in-the-middle can still impersonate the listener side.

Current design decision:

- anonymous secure-link mode is not the target default
- one-sided authentication is not the target model
- any future lab/bootstrap mode such as PSK must be explicit and must not silently weaken certificate-based deployments

## Session-key establishment

Do not use long-term identity keys directly as traffic-encryption keys.

Recommended model:

- long-term static identity keys:
  - for certificates and identity proof
- ephemeral ECDH keys:
  - for session key agreement

Session-key flow:

1. both sides exchange ephemeral public keys
2. both sides authenticate the handshake using their certified identity keys
3. both derive shared session secrets from the ECDH result and handshake transcript
4. both derive separate send and receive traffic keys using HKDF

Why:

- provides forward secrecy
- allows frequent rekeying
- limits blast radius if a traffic key leaks

Current cryptographic direction:

- static identity signatures: Ed25519
- ephemeral key agreement: X25519
- key derivation: HKDF-SHA256

These choices are made for simplicity, portability, and mature library support rather than for algorithm variety.

## Tunnel encryption

Use an AEAD cipher, not raw AES.

Recommended options:

- `AES-256-GCM`
- `ChaCha20-Poly1305`

Requirements for the secure-link data phase:

- authenticated encryption
- monotonically increasing sequence number or nonce counter
- replay rejection
- key separation for each direction
- optional rekey after byte or time thresholds

The secure-link layer should encrypt the payload that `ChannelMux` would otherwise send directly to the transport.

Current cipher decision:

- preferred baseline cipher: `ChaCha20-Poly1305`
- acceptable alternative when platform constraints or library integration make it preferable: `AES-256-GCM`

Rationale:

- both are standard AEAD constructions
- `ChaCha20-Poly1305` is a good default across mixed hardware classes without requiring AES acceleration assumptions

## Handshake recommendation

The safest design direction is to model the handshake after a well-known pattern such as Noise.

Recommended conceptual shape:

- admin-signed static identity keys
- ephemeral ECDH for the session
- transcript-bound mutual authentication

Good pattern family:

- Noise-style `XX`
  - flexible when neither side wants to assume prior static-key pinning

Alternative:

- Noise-style `IK`
  - useful if the client is provisioned with the exact server static identity
  - faster, but more opinionated

This document does not lock the project into the Noise protocol library. It recommends adopting the same security properties and handshake structure.

Current handshake decision:

- use a Noise-style authenticated handshake shape as the design model
- do not add a separate Noise framework dependency by default
- keep the delivered protocol aligned with the same security properties even if the implementation is project-local

## Dependency strategy

This project should avoid heavy platform-fragile dependency chains.

Dependency decision:

- SecureLink-capable runtime work uses exactly one focused mandatory crypto dependency on the Python side: `cryptography`
- introducing `cryptography` is preferred over combining several smaller crypto packages or platform-specific wrappers
- dependencies such as a full TLS stack, PKI framework, or separate Noise library are intentionally not part of the initial dependency plan

Therefore:

- do not require a large PKI or TLS framework for the secure-link layer
- do not require transport-specific TLS for all transports
- keep the mandatory crypto dependency surface minimal

### What the Python standard library can do

The standard library can help with:

- configuration
- file I/O
- hashing
- HMAC
- HKDF-style building blocks via `hashlib` / `hmac`
- serialization

But the standard library does not provide a complete modern asymmetric and AEAD toolkit suitable for this design.

### Practical recommendation

Use one focused crypto dependency rather than several large ones.

Best portability-minded options:

1. `cryptography`
- broad platform support
- mature and well maintained
- supports Ed25519, X25519, HKDF, AES-GCM, ChaCha20-Poly1305
- larger than stdlib, but still the most practical single dependency

2. optional staged evolution
- keep one focused dependency for secure-link only
- keep advanced admin issuance tooling optional

Recommended decision:

- if this feature is implemented, accept one mandatory crypto dependency: `cryptography`
- avoid introducing multiple crypto stacks or platform-specific wrappers

Rationale:

- implementing modern asymmetric crypto safely without a proper library is not realistic
- one well-supported dependency is less risky than a home-grown cryptographic protocol

## Alternatives

### Alternative A: transport-specific TLS only

Example:

- TLS for WebSocket
- TLS for TCP
- QUIC built-in security
- nothing equivalent for `myudp`

Pros:

- low conceptual novelty
- more standard per transport

Cons:

- fragmented security model
- leaves `myudp` behind or forces a separate solution
- security behavior differs by transport
- TLS is often actively broken, intercepted, or policy-gated in corporate proxy environments, which makes it a poor universal answer for this project’s target obstacle scenarios

Conclusion:

- not recommended as the primary project direction

### Alternative B: pre-shared keys only

Example:

- each deployment or peer pair gets a configured shared secret
- secure-link uses PSK authentication plus encryption

Pros:

- operationally simple
- easier first implementation
- no certificate issuance yet

Cons:

- weak identity lifecycle
- poor revocation and rotation story at scale
- no clean delegated issuance model

Conclusion:

- useful as a bootstrap mode or lab mode
- not ideal as the long-term model

### Alternative C: admin-signed certificates plus secure-link

Pros:

- one consistent model across transports
- mutual authentication
- good lifecycle model
- forward secrecy possible

Cons:

- needs one real crypto dependency
- more design effort up front

Conclusion:

- recommended long-term direction

## Proposed classes

Suggested new classes:

- `SecureLinkConfig`
  - local certificate paths
  - root public key path
  - revocation configuration
  - cipher preferences
  - rekey thresholds
- `SecureLinkIdentity`
  - parsed certificate
  - private key handle
  - role and validity checks
- `SecureLinkHandshake`
  - handshake state machine
  - transcript hashing
  - certificate exchange and verification
  - ephemeral key exchange
- `SecureLinkCipherState`
  - traffic keys
  - sequence counters
  - encrypt/decrypt operations
  - rekey logic
- `SecureLinkSession`
  - transport-facing wrapper
  - owns handshake and cipher state
  - exposes plaintext frame send/receive API upward

Layering:

- transport sessions read/write ciphertext frames to `SecureLinkSession`
- `SecureLinkSession` exposes plaintext frames to `ChannelMux`

## Delivered Slices And Remaining Gaps

### Architecture And Boundaries

Current state:

- fulfilled
- trust model, certificate profile, layer boundary, and dependency policy are all documented and implemented as active project decisions

Evidence:

- [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md):
  - `Current State Summary`
  - trust model, dependency policy, and certificate-profile sections
- [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md):
  - `2. Secure-link layer`
  - component decomposition and ownership boundary
- [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md):
  - secure-link certificate input profile and external responsibility split
- [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md):
  - active `REQ-AUT-*` secure-link requirement set

### PSK Runtime Slice

Current state:

- fulfilled for the PSK runtime slice
- certificate mode exists separately and does not replace the utility of PSK mode for development and troubleshooting

Evidence:

- runtime:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    `SecureLinkPskSession`
- architecture:
  - [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
    `2. Secure-link layer`
- requirements:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-001` to `REQ-AUT-005`
- unit evidence:
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
  - [test_runner_overlay_transports.py](/home/ohnoohweh/quic_br/tests/unit/test_runner_overlay_transports.py)
  - [test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py)
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py):
    - `test_overlay_e2e_tcp_secure_link_psk_happy_path`
    - `test_overlay_e2e_secure_link_psk_happy_path_other_transports`
    - `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected`
    - listener multi-peer secure-link cases
- traceability:
  - [.github/requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml)
    `REQ-AUT-001` to `REQ-AUT-005`

### PSK Hardening State

This section describes hardening that is already delivered plus the remaining gaps for the PSK runtime slice.

#### Rekeying

- define a rekey trigger policy:
  - byte-count threshold
  - time-based threshold
  - optional operator-forced rekey hook
- define a rekey handshake:
  - who initiates
  - how both sides confirm the new keys
  - when old keys stop being accepted
- define rollback behavior if rekey stalls mid-flight

Acceptance criteria:

- long-lived sessions can rotate traffic keys without disconnecting healthy peers
- once rekey completes, frames under superseded keys are rejected
- failed or abandoned rekey attempts do not silently fall back to ambiguous mixed-key operation

Current status:

- fulfilled for the currently delivered client-driven frame-count-triggered rekey path
- fulfilled for time-based rekey on authenticated client-side sessions after the first protected client-data frame
- fulfilled for operator-forced rekey through the admin API on authenticated client-side sessions after the first protected client-data frame
- fulfilled for the previously exposed client/server cutover race where the server could switch on `REKEY_COMMIT` before the client received `REKEY_DONE`; the current runtime now holds only client outbound application payloads in that commit-to-done window and flushes them immediately under the new session once `REKEY_DONE` arrives, so healthy overlay traffic does not depend on an overlap period where both old and new secure-link sessions are accepted simultaneously

Evidence:

- runtime:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    rekey hello/reply/commit/done handling, `secure_link_rekey_after_frames`, `secure_link_rekey_after_seconds`, and `/api/secure-link/rekey`
- requirements:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-006` and `REQ-AUT-010`
- unit evidence:
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_psk_rekey_rotates_session_id_and_keeps_data_flowing`
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_time_based_rekey_rotates_session_without_extra_data_frames`
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_operator_forced_rekey_rotates_session_and_reports_trigger`
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_operator_forced_rekey`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_myudp_secure_link_psk_rekey_done_delay_keeps_same_udp_channel_healthy`

#### Nonce and counter lifecycle

- define per-direction counter ownership explicitly
- define initial counter values for:
  - fresh session
  - reconnected session
  - rekeyed session
- bind counters to session identity so reconnect does not risk nonce reuse
- define counter-overflow behavior
- define whether any limited out-of-order tolerance is allowed or whether the model stays strictly monotonic

Current runtime decision:

- protected `data` counters are owned per direction and start at `1`
- counter value `0` is reserved and rejected as a lifecycle violation
- reconnect and completed rekey install a fresh secure-link session id and reset directional counters to the initial values
- stale counters and stale session ids are rejected deterministically
- current counter exhaustion behavior is fail-closed rather than wraparound or implicit reuse

Acceptance criteria:

- no reconnect, restart, or rekey path can reuse an AEAD nonce under the same key
- duplicate frames are rejected deterministically
- stale frames from an earlier session are rejected deterministically
- counter exhaustion results in a safe rekey or fail-closed shutdown rather than undefined behavior

Current status:

- partially fulfilled
- the delivered runtime enforces strictly monotonic counters, reserved counter rejection, fresh session ids on reconnect/rekey, and fail-closed counter exhaustion
- explicit reconnect/replay integration coverage beyond the current PSK slice is still pending

Evidence:

- runtime:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    counter validation, session-id rotation, and exhaustion fail-closed behavior
- requirements:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-006`
- unit evidence:
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py):
    - `test_data_counter_zero_is_rejected_as_lifecycle_violation`
    - `test_counter_exhaustion_fails_closed_before_nonce_wrap`
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`
- remaining gap:
  - the planned reconnect/replay hardening tests listed below are not all implemented yet

#### Failure handling

- enumerate fail-closed behavior for:
  - malformed handshake frame
  - unexpected message order
  - decrypt/tag failure
  - replayed frame
  - plaintext frame when secure-link is required
  - internal secure-link exception
- define whether each case should:
  - emit `auth_fail`
  - log a diagnostic only
  - close the peer immediately
  - mark the session as failed and observable in admin/API state
- define reconnect throttling so persistent auth failures do not create noisy loops

Observed field case that now drives the current hardening contract:

- two clients behind the same public NAT can progress differently during PSK handshake churn, for example when one Linux peer was previously healthy, an iPhone peer then connected from the same public IP, and later one side reported the session as authenticated while the other still exposed the same peer slot as handshaking
- the concrete bad state was "local client verified `server_hello` and derived keys" without yet receiving any protected peer-confirmation traffic back, while the responder had not promoted that session to authenticated
- in that state, the failure was not only cosmetic in admin/UI state:
  - the client application could believe the secure-link session was authenticated
  - the server still treated the peer as unauthenticated or handshaking
  - TUN and UDP forwarding could appear broken because the overlay had not actually reached a mutually authenticated protected-data phase
- operationally, a handshaking state lasting longer than the one-minute reauthentication window is unacceptable and must be treated as a failure rather than as a tolerated steady state
- accepted outcomes for PSK mode are intentionally strict:
  - both sides peer-confirm and report authenticated
  - both sides fail closed and retry or reconnect when the PSK or handshake lifecycle is wrong
  - one-sided "authenticated here, handshaking there" must not persist

Current runtime decision:

- malformed secure-link frames are treated as `decode` failures
- unexpected or out-of-order secure-link control messages are treated as `decode` or `lifecycle` failures depending on whether the violated invariant is structural or state-machine related
- once a peer enters secure-link failure, overlay forwarding stops for that peer
- listener/server-side mux routing state for the failed peer is dropped so stale channels cannot continue to route through an unauthenticated peer slot
- the failure remains observable through `/api/status` and `/api/peers` until a later healthy authenticated session replaces it
- client-side sessions that had already authenticated and then fail closed schedule a lower-transport reconnect, defaulting to a 30 second delay, so availability can recover through a fresh transport epoch and a fresh secure-link handshake instead of reusing the failed cryptographic session
- client-side verification of `server_hello` is treated as local handshake progress only, not as final authenticated state
- a secure-link session is reported as authenticated only after peer-confirmed protected traffic proves that both sides derived and accepted the same keys
- if a handshake remains locally progressed but not peer-confirmed for 60 seconds, the runtime converts that state into a lifecycle failure instead of letting it linger indefinitely
- the timeout path is fail-closed and observable through the admin/API surface, and the client-side recovery path can restart the lower transport rather than preserving a half-authenticated session

Acceptance criteria:

- no failure path can leave the overlay falsely reported as connected
- no failure path can silently accept plaintext when secure-link is required
- admin/API state and logs expose a stable machine reason plus human-readable detail
- repeated auth failures remain observable without destabilizing the surrounding runner state machine
- no peer can remain in an unbounded locally-authenticated-but-not-peer-confirmed handshake state
- handshake observability must distinguish "local proof accepted" from "peer-confirmed authenticated" so operators can diagnose lower-level UDP/TUN impact correctly

Current runtime decision:

- repeated client-side PSK authentication failures now retry under bounded exponential backoff rather than immediate tight looping
- the current admin/API surface exposes `consecutive_failures`, `retry_backoff_sec`, and `next_retry_unix_ts` for that throttle window
- authenticated-session failure recovery is distinct from wrong-secret retry: initial PSK mismatch stays on the bounded handshake retry path, while a post-authentication secure-link failure schedules lower-transport reconnect recovery through `secure_link_recover_after_failure` and `secure_link_recover_delay_seconds`
- the current admin/API surface exposes `recovery_enabled`, `recovery_delay_sec`, `recovery_reconnect_sec`, and `next_recovery_reconnect_unix_ts` so operators can see when a failed client-side secure-link session is waiting for reconnect recovery
- the current admin/API surface also exposes stronger operational diagnostics such as `failure_session_id`, `handshake_attempts_total`, `last_event`, `last_event_unix_ts`, `last_authenticated_unix_ts`, `authenticated_sessions_total`, and `rekeys_completed_total`
- the current PSK runtime and iOS parity runtime both implement the peer-confirmation rule and the 60 second unconfirmed-handshake timeout for the secure-link state machine

Current status:

- substantially fulfilled for the delivered PSK slice
- remaining work is mainly broader transport/runtime hardening rather than absence of basic fail-closed behavior

Evidence:

- runtime:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    malformed-frame rejection, auth-failure handling, retry throttling, recovery reconnect scheduling, and admin/API snapshot fields
- requirements:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-007`, `REQ-AUT-008`, and `REQ-AUT-009`
- unit evidence:
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py):
    - malformed/out-of-order fail-closed tests
    - wrong-PSK retry/backoff tests
    - authenticated failure recovery reconnect tests
    - `test_client_local_secure_link_auth_times_out_without_peer_confirmation`
    - operational diagnostics assertions
  - [test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py)
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py):
    - `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected`
    - `test_overlay_e2e_tcp_secure_link_psk_happy_path`
    - `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`
- supporting contract:
  - [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md)
    secure-link coverage tables and criteria notes

#### Delivered Hardening Coverage

- integration test for rekey under live traffic
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`
- unit and integration tests for time-based rekey
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_time_based_rekey_rotates_session_without_extra_data_frames`
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold`
- unit and integration tests for operator-forced rekey
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_operator_forced_rekey_rotates_session_and_reports_trigger`
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_operator_forced_rekey`
- integration test for the delayed-`REKEY_DONE` cutover window on a single live myudp UDP channel
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_myudp_secure_link_psk_rekey_done_delay_keeps_same_udp_channel_healthy`
- unit tests for counter overflow handling
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_counter_exhaustion_fails_closed_before_nonce_wrap`
- unit tests for reserved/invalid counter lifecycle handling
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_data_counter_zero_is_rejected_as_lifecycle_violation`
- unit tests for malformed-frame fail-closed behavior
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_malformed_frame_after_authentication_fails_closed`
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_unexpected_rekey_commit_fails_closed`
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_auth_failure_unregisters_server_mux_routes`
- integration test for persistent wrong-PSK failure throttling and observability
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected`
- unit tests for wrong-PSK retry/backoff behavior
  - evidence:
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_wrong_psk_retries_with_bounded_backoff_and_reports_retry_window`
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    `test_reconnect_respects_remaining_retry_backoff_after_auth_failure`
- unit and integration checks for stronger operational diagnostics
  - evidence:
    [test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py)
    [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py)
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_happy_path`
    `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected`
    `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`
- integration test for reconnect without nonce reuse
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_reconnects_with_fresh_session`
- integration tests for replay rejection after reconnect and after rekey
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_replay_after_reconnect_is_rejected`
    `test_overlay_e2e_tcp_secure_link_psk_replay_after_rekey_is_rejected`
- integration test for malformed-frame fail-closed behavior as a full subprocess case
  - evidence:
    [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_psk_malformed_frame_fails_closed_subprocess`

### Certificate-Based Mutual Authentication

Current state:

- fulfilled for the delivered certificate-mode runtime slice

Evidence:

- runtime/config:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    `secure_link_mode=cert`, file-path material loading, detached-signature/root verification, certificate handshake path, cert-mode rekey reuse of the shared secure-link data plane, and peer-scoped trust diagnostics
- generated test material:
  - [tests/fixtures/secure_link_cert/__init__.py](/home/ohnoohweh/quic_br/tests/fixtures/secure_link_cert/__init__.py)
    runtime generation of the trust anchors, signed cert bodies, detached signatures, private keys, and revoked-serial fixtures used by the certificate-mode unit and integration suites
- unit evidence:
  - [test_secure_link_cert.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_cert.py)
    happy path, trust-anchor mismatch, wrong-role rejection, expired/not-yet-valid/deployment-mismatch rejection, revoked-serial rejection, and cert-mode operator rekey
  - [test_runner_overlay_transports.py](/home/ohnoohweh/quic_br/tests/unit/test_runner_overlay_transports.py)
    cert-mode wrapping and required startup material validation
  - [test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py)
    peer-scoped cert identity/trust payload shaping
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_secure_link_cert_happy_path_transports`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_rejection_matrix`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_operator_forced_rekey`
- requirements/testing references:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-011` to `REQ-AUT-014`
  - [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md)
    `Current certificate-mode secure-link coverage`

### Operational Controls

Current state:

- fulfilled for the delivered operational-control slice

Evidence:

- runtime/config:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    `POST /api/secure-link/reload`, live revocation/local-identity/all apply, aggregate reload summaries, peer-scoped disconnect/trust-enforcement metadata, and atomic cert-bundle validation before activation
- unit evidence:
  - [test_secure_link_cert.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_cert.py)
    revocation reload drop, atomic local-identity reload rejection, and successful local-identity apply with new material generation
  - [test_runner_overlay_transports.py](/home/ohnoohweh/quic_br/tests/unit/test_runner_overlay_transports.py)
    peer-targeted secure-link reload dispatch and unknown-peer rejection
  - [test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py)
    aggregate reload-result shaping on `/api/status` and peer-scoped reload/disconnect fields on `/api/peers`
- integration evidence:
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_revocation_reload_happy_path`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_revocation_reload_noop`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_happy_path`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_rejected`
  - [test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
    `test_overlay_e2e_tcp_secure_link_cert_full_reload_applies_atomically`
- requirements/testing references:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-015` to `REQ-AUT-019`
  - [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md)
    `Current certificate-mode secure-link coverage`

## Minimal operational model

Recommended operational model:

- one admin root keypair per deployment
- one certificate per peer client and per peer server
- short certificate validity periods
- local revocation denylist by serial number
- optional future automation for re-issuance

## Threat model summary

This design aims to protect against:

- passive eavesdropping on overlay traffic
- unauthorized peer connection attempts
- man-in-the-middle attacks by unauthenticated intermediaries
- replay of old encrypted frames

This design does not by itself solve:

- compromise of the admin root private key
- compromise of endpoint hosts
- malicious but already-authorized peers exceeding their allowed permissions unless role/constraint checks are enforced carefully

## Final recommendation

Recommended direction:

- keep the transport-independent secure-link layer below `ChannelMux`
- keep admin-signed peer certificates as the deployment-rooted mutual-authentication model
- keep ephemeral ECDH plus HKDF for per-session key derivation in certificate mode
- keep AEAD-protected traffic with explicit replay and lifecycle controls
- keep PSK mode explicit and opt-in for development, compatibility, and troubleshooting rather than as the primary long-term trust model
- keep the crypto dependency surface focused instead of splitting the security model across transports or introducing multiple overlapping crypto stacks

Remaining practical action plan:

1. add the remaining reconnect/replay hardening coverage that this document still marks as pending, especially integration coverage beyond the current PSK slice for stale-frame rejection and reconnect/replay behavior across more transport/runtime combinations
2. decide whether SecureLink should commit to a more explicit long-term wire-compatibility/frozen frame-shape policy instead of leaving the on-wire contract versioned but implementation-defined
3. decide whether certificate issuance should remain an external/operator workflow or gain fuller first-party admin UI support beyond the current reload/apply and observability controls
