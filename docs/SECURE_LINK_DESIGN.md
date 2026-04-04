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

### Dependency policy

- Phase 0 adds no new mandatory runtime dependency
- if secure-link runtime implementation starts, the only planned mandatory crypto dependency is `cryptography`
- no second crypto framework should be introduced for the same feature without a deliberate redesign decision
- stdlib helpers may be used for configuration, serialization, hashing support, and HKDF-related glue, but not as a substitute for modern asymmetric crypto and AEAD primitives
- transport-specific TLS libraries are not the primary dependency strategy for secure-link

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

### Phase 1: PSK secure-link prototype

- implement secure-link framing hooks
- support optional PSK mode for development and testing
- validate layering with `ChannelMux` unchanged

### Phase 2: certificate-based mutual authentication

- add identity keypairs
- add admin-signed certificates
- add mutual-authenticated handshake
- add traffic encryption

### Phase 3: operational controls

- revocation list
- certificate expiry handling
- admin tooling for issuance and rotation
- admin UI visibility for peer identity metadata

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
