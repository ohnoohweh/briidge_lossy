# Secure Link Design

## Purpose

This document proposes a transport-independent security layer for ObstacleBridge that adds:

- mutual peer authentication
- tunnel confidentiality
- tunnel integrity
- replay protection
- key rotation and revocation hooks

The goal is to solve two current gaps:

1. overlay traffic is not protected end to end at the ObstacleBridge layer
2. the tunnel service itself lacks a strong peer-authentication model

The design intentionally keeps authentication and encryption below `ChannelMux` and above the transport sessions so that:

- `ChannelMux` continues to process plaintext authenticated frames only
- `myudp`, `tcp`, `ws`, and `quic` session classes do not need to understand certificate policy
- one security model can span all overlay transports

## Scope

This is a design proposal, not an implementation plan tied to one release.

It covers:

- identity and trust model
- handshake model
- session-key derivation
- frame protection
- layering
- dependency strategy

It does not yet define:

- exact binary wire formats
- exact storage format for private keys on disk
- admin UI flows for certificate issuance or revocation

## Phase 0 outcome

Phase 0 in this project means architectural commitment without runtime crypto yet.

The expected output of Phase 0 is:

- a stable layer boundary below `ChannelMux` and above the transport sessions
- a clear trust model for future secure-link authentication
- a certificate field set that later implementation can follow
- a dependency policy that avoids a large or platform-fragile crypto stack
- contributor documentation that explains what is already decided and what is still intentionally deferred

Phase 0 intentionally does not include:

- encrypted overlay traffic in the runtime
- certificate parsing or validation in the runtime
- new CLI/config options for secure-link operation
- new product requirements claiming secure-link behavior already exists

Current Phase 0 decisions captured by this document:

- the project should use one transport-independent secure-link layer rather than transport-specific security behavior
- that layer should sit below `ChannelMux` and above the transport/session layer
- the long-term direction is admin-signed identities plus ephemeral session keys
- the project should accept at most one focused crypto dependency if implementation proceeds
- secure-link behavior remains a planned feature until runtime code and black-box tests exist

## Phase 0 decision summary

The following points are considered finalized for Phase 0.

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
- no intermediate CA hierarchy is planned for the first implementation phases

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

- Phase 0 adds no new mandatory runtime dependency
- if secure-link runtime implementation starts, the only planned mandatory crypto dependency is `cryptography`
- no second crypto framework should be introduced for the same feature without a deliberate redesign decision
- stdlib helpers may be used for configuration, serialization, hashing support, and HKDF-related glue, but not as a substitute for modern asymmetric crypto and AEAD primitives
- transport-specific TLS libraries are not the primary dependency strategy for secure-link

## Phase 1 mini-spec

Phase 1 is the smallest runtime slice intended to validate the secure-link layer boundary before certificate-based authentication is introduced.

Goals:

- implement secure-link framing hooks
- support an optional PSK mode for development and testing
- validate layering with `ChannelMux` unchanged

Non-goals for Phase 1:

- certificate parsing
- certificate validation
- revocation
- admin issuance tooling
- final long-term wire compatibility guarantees

### Phase 1 operating mode

Phase 1 adds one explicit lab/development mode:

- `secure_link_mode = psk`

Behavioral intent:

- both peers are manually provisioned with the same pre-shared secret
- the PSK mode is explicit and opt-in
- PSK mode exists to validate layering, handshake flow, and ciphertext/plaintext transitions before the certificate-based mode is built
- PSK mode is not the long-term production trust model

### Phase 1 frame envelope

The Phase 1 secure-link layer wraps bytes exchanged between the transport/session layer and the current overlay framing/mux path.

Conceptual envelope fields:

- `sl_version`
  - secure-link wire version
  - Phase 1 value: `1`
- `sl_type`
  - one of:
    - `client_hello`
    - `server_hello`
    - `auth_fail`
    - `data`
- `sl_flags`
  - reserved for later negotiation or rekey bits
  - Phase 1 default: `0`
- `sl_session_id`
  - random session identifier chosen by the initiator
  - used to bind the handshake and later data frames to one secure-link session
- `sl_counter`
  - per-direction monotonic counter
  - `0` for initial handshake messages
  - increments for protected `data` frames
- `sl_payload`
  - handshake payload or ciphertext payload depending on `sl_type`

Phase 1 boundary rule:

- transport/session code carries this envelope opaquely
- `ChannelMux` does not see the envelope directly

Phase 1 serialization guidance:

- a compact binary encoding is preferred for the actual implementation
- however, the first implementation may use a simple deterministic struct/length-prefix format as long as it is versioned and testable
- the exact byte layout is intentionally deferred until code starts

### Phase 1 PSK handshake messages

The Phase 1 PSK handshake is intentionally small and symmetric enough to validate the new layer without introducing certificate logic.

#### `client_hello`

Sent by the initiating peer.

Payload contents:

- `client_nonce`
  - random 32-byte nonce
- `client_capabilities`
  - initial fixed value identifying `psk-v1`
- `key_schedule_hint`
  - reserved field for later compatibility
  - Phase 1 fixed value: `0`

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

#### client handshake confirmation

The initiator does not need a third explicit handshake frame in Phase 1.

Instead:

- the first protected `data` frame from the client acts as proof that the initiator derived the same traffic keys
- if the responder cannot authenticate that first protected frame, the secure-link session is rejected

This keeps Phase 1 smaller while still validating both directions.

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

### Phase 1 key derivation

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

Phase 1 replay and nonce rule:

- each protected `data` frame uses the directional `sl_counter` as AEAD nonce/counter input
- counters are monotonic per direction
- duplicate or older counters are rejected

### Phase 1 protected data frames

After successful PSK handshake:

- `sl_type = data`
- `sl_payload` carries AEAD-protected bytes
- plaintext input to the AEAD is exactly the byte stream or frame sequence that would otherwise continue upward to the existing overlay logic

Phase 1 layering validation rule:

- secure-link decrypts before bytes reach the current overlay framing/mux path
- secure-link encrypts after bytes leave the current overlay framing/mux path toward the transport/session layer
- `ChannelMux` remains unchanged

### Phase 1 config keys

The first implementation should introduce only a minimal explicit config surface.

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
  - Phase 1 supported values:
    - `off`
    - `psk`
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
- if `secure_link = true` and `secure_link_mode = cert`, Phase 1 should reject startup or configuration as unsupported
- `secure_link_require = true` is mainly useful for tests to ensure the path does not silently fall back to plaintext

### Phase 1 first implementation target

To reduce risk, the first runtime slice should aim for:

- one transport first, preferably `tcp` or `ws`
- one happy-path integration test
- one wrong-PSK rejection test
- one ciphertext tamper test

Once that slice is stable, the same secure-link envelope and PSK mode can be exercised across the remaining transports.

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
- the proposal does not yet bind the handshake transcript strongly enough to stop replay or active manipulation
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

Phase 0 finalization:

- no certificate chain beyond root -> leaf is planned for the first implementation phases
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

Recommended logical field names for Phase 0:

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
- `constraints` should start simple and may be empty in the first implementation phase
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

Phase 0 finalization:

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

Phase 0 cryptographic direction:

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

Phase 0 cipher decision:

- preferred first implementation cipher: `ChaCha20-Poly1305`
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

Phase 0 handshake decision:

- use a Noise-style authenticated handshake shape as the design model
- do not add a separate Noise framework dependency in the first implementation phase
- implement only after the secure-link layer contract and test strategy are ready

## Dependency strategy

This project should avoid heavy platform-fragile dependency chains.

Phase 0 dependency decision:

- Phase 0 itself remains documentation-only and adds no dependency
- Phase 1 or Phase 2 secure-link runtime work may introduce exactly one new mandatory crypto dependency: `cryptography`
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

2. optional phased rollout
- phase 1: no new security feature merged
- phase 2: add one focused dependency for secure-link only
- phase 3: make advanced admin issuance tooling optional

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

## Suggested rollout plan

### Phase 0: design and boundaries

- finalize trust model
- define certificate fields
- define layer boundaries
- decide dependency policy
- record those decisions in architecture and contributor-facing project documents without claiming delivery of secure-link runtime behavior

Acceptance criteria:

- the trust model, certificate/profile expectations, layer boundary, and dependency policy are documented and internally consistent
- the architecture docs state clearly which responsibilities belong to the secure-link layer versus transport/session, `ChannelMux`, runner wiring, and admin/web observability
- no product requirement claims delivered secure-link runtime behavior before code and black-box tests exist

Current status:

- fulfilled

Evidence:

- [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md):
  - `Phase 0 outcome`
  - `Phase 0 decision summary`
  - trust model, dependency policy, and certificate-profile sections
- [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md):
  - `2. Secure-link layer`
  - component decomposition and ownership boundary
- [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md):
  - secure-link certificate input profile and external responsibility split
- [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md):
  - active `REQ-AUT-*` versus planned `PLAN-AUT-*` separation

### Phase 1: PSK secure-link prototype

- implement secure-link framing hooks
- support optional PSK mode for development and testing
- validate layering with `ChannelMux` unchanged

Acceptance criteria:

- a delivered secure-link runtime slice exists below `ChannelMux` and above the transport/session layer
- `secure_link_mode=psk` works across the supported overlay transports
- the protected data phase authenticates and encrypts traffic without requiring `ChannelMux` changes
- wrong-PSK peers fail instead of reaching a false connected state
- the admin/API surface exposes first secure-link state visibility for operators

Current status:

- fulfilled for the PSK runtime slice
- certificate mode remains out of scope for this phase

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

### Phase 1.5: PSK hardening checklist

This phase hardens the delivered PSK runtime slice before or alongside broader operational use. The goal is not to change the trust model yet, but to make the existing PSK path safer and more explicit under long runtimes, malformed input, and transport churn.

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

#### Nonce and counter lifecycle

- define per-direction counter ownership explicitly
- define initial counter values for:
  - fresh session
  - reconnected session
  - rekeyed session
- bind counters to session identity so reconnect does not risk nonce reuse
- define counter-overflow behavior
- define whether any limited out-of-order tolerance is allowed or whether the model stays strictly monotonic

Current Phase 1 runtime decision:

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

Current Phase 1 runtime decision:

- malformed secure-link frames are treated as `decode` failures
- unexpected or out-of-order secure-link control messages are treated as `decode` or `lifecycle` failures depending on whether the violated invariant is structural or state-machine related
- once a peer enters secure-link failure, overlay forwarding stops for that peer
- listener/server-side mux routing state for the failed peer is dropped so stale channels cannot continue to route through an unauthenticated peer slot
- the failure remains observable through `/api/status` and `/api/peers` until a later healthy authenticated session replaces it

Acceptance criteria:

- no failure path can leave the overlay falsely reported as connected
- no failure path can silently accept plaintext when secure-link is required
- admin/API state and logs expose a stable machine reason plus human-readable detail
- repeated auth failures remain observable without destabilizing the surrounding runner state machine

Current Phase 1 runtime decision:

- repeated client-side PSK authentication failures now retry under bounded exponential backoff rather than immediate tight looping
- the current admin/API surface exposes `consecutive_failures`, `retry_backoff_sec`, and `next_retry_unix_ts` for that throttle window
- the current admin/API surface also exposes stronger operational diagnostics such as `failure_session_id`, `handshake_attempts_total`, `last_event`, `last_event_unix_ts`, `last_authenticated_unix_ts`, `authenticated_sessions_total`, and `rekeys_completed_total`

Current status:

- substantially fulfilled for the delivered PSK slice
- remaining work is mainly broader transport/runtime hardening rather than absence of basic fail-closed behavior

Evidence:

- runtime:
  - [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)
    malformed-frame rejection, auth-failure handling, retry throttling, and admin/API snapshot fields
- requirements:
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `REQ-AUT-007`, `REQ-AUT-008`, and `REQ-AUT-009`
- unit evidence:
  - [test_secure_link_psk.py](/home/ohnoohweh/quic_br/tests/unit/test_secure_link_psk.py):
    - malformed/out-of-order fail-closed tests
    - wrong-PSK retry/backoff tests
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

#### Test additions expected in Phase 1.5

Already generated:

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

Still missing:

- integration test for reconnect without nonce reuse
- integration test for replay rejection after reconnect and after rekey
- integration test for malformed-frame fail-closed behavior as a full subprocess case, not only unit-level verification

### Phase 2: certificate-based mutual authentication

- add identity keypairs
- add admin-signed certificates
- add mutual-authenticated handshake
- add traffic encryption

Acceptance criteria:

- both sides authenticate with admin-signed certificates before protected traffic is accepted
- trust-anchor mismatch, role mismatch, validity failure, deployment mismatch, or revocation all fail closed before the protected data phase
- the admin/API surface preserves the current secure-link visibility model while adding certificate/trust-validation diagnostics

Current status:

- not fulfilled yet

Evidence:

- planning/design only:
  - [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md)
  - [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
    `PLAN-AUT-004` to `PLAN-AUT-007`
  - [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md)
    `Planned certificate-mode secure-link integration test matrix`

### Phase 3: operational controls

- revocation list
- certificate expiry handling
- admin tooling for issuance and rotation
- admin UI visibility for peer identity metadata

Acceptance criteria:

- operators can revoke or expire credentials and see those effects enforced in runtime behavior
- operators have supported tooling/workflows for certificate issuance and rotation
- WebAdmin and admin APIs expose peer identity metadata and trust-validation results clearly enough for troubleshooting and audit

Current status:

- not fulfilled yet

Evidence:

- planning/design only:
  - [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md)
  - [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md)
  - planned requirement IDs in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)

## Minimal operational model

Recommended first operational model:

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

- add a transport-independent secure-link layer below `ChannelMux`
- use admin-signed peer certificates for mutual authentication
- use ephemeral ECDH plus HKDF for per-session key derivation
- use AEAD for traffic protection
- accept one focused mandatory crypto dependency if implementation proceeds
- avoid ad hoc custom crypto and avoid splitting the security model across transports

If dependency minimization remains the top concern, the best phased path is:

1. design the secure-link layer boundary now
2. implement an optional PSK prototype first if needed
3. move to certificate-based mutual authentication only when the project is ready to accept a single portable crypto dependency
