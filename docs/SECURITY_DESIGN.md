# Security Design

## Purpose

This document summarizes the security measures that exist across ObstacleBridge and explains how they fit together.

It is an umbrella design note. More detailed behavior remains owned by the narrower design documents:

- [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md) for peer authentication, tunnel encryption, replay protection, rekeying, and certificate policy
- [WEBADMIN_DESIGN.md](/home/ohnoohweh/quic_br/docs/WEBADMIN_DESIGN.md) for WebAdmin authentication, session handling, guarded config writes, and admin API behavior
- [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md) for what ObstacleBridge owns versus what the surrounding operating system, browser, network, and crypto libraries must provide

The goal is to make the security posture readable in one place without duplicating every implementation detail.

## Scope

This document covers project-owned security controls and their design intent:

- secure-link peer protection
- admin authentication
- guarded configuration writes
- secret redaction and persistence behavior
- controlled secret reveal in WebAdmin
- session and API access boundaries
- operational limits that still require HTTPS, localhost, or trusted network placement

It does not claim that every deployment is secure by default. ObstacleBridge can be intentionally exposed in many ways, and the operator remains responsible for network placement, operating-system hardening, firewall policy, TLS termination when needed, and protection of local config files and private key material.

## Security Goals

ObstacleBridge security measures are designed around these goals:

- keep overlay peers from accepting unauthenticated protected traffic when secure-link is enabled
- protect overlay payload confidentiality and integrity inside the ObstacleBridge layer
- make peer identity, trust, reload, and failure state visible to the operator
- prevent WebAdmin credentials and secret config values from being returned through normal read APIs
- bind sensitive admin operations to fresh operator intent
- avoid sending plaintext admin passwords or revealed secrets over the admin HTTP API
- fail closed when required credentials, trust material, or proofs are missing or invalid

The project also tries to keep trust boundaries explicit. Some mitigations are useful over plain HTTP, but they are not substitutes for HTTPS on an untrusted network because a man-in-the-middle can still tamper with delivered JavaScript or session traffic.

## Secure-Link Encryption Layer

Secure-link is the project-owned overlay encryption and authentication layer.

It is a purely security-driven layer: its purpose is not routing, multiplexing, reconnect behavior, or transport adaptation. Its purpose is to decide whether a peer is trusted, derive protected session keys, encrypt authenticated overlay frames, reject tampering or replay, and expose enough security state for operators to understand what happened.

Secure-link sits below `ChannelMux` and above the transport sessions so that UDP, TCP, WebSocket, QUIC, and `myudp` transports can share one security model.

Current and planned secure-link measures include:

- explicit opt-in secure-link mode
- PSK-based encryption and authentication for manually provisioned shared-secret deployments and test coverage
- certificate-based encryption and authentication for admin-root-signed peer identities
- mutual peer authentication before protected data is accepted
- transport-independent frame protection
- authenticated encryption using the project crypto dependency
- replay protection
- key derivation separated from long-term identity material
- rekey support, including operator-forced rekey from WebAdmin where a live authenticated session exists
- certificate revocation inputs and live reload hooks in certificate mode
- peer-scoped admin visibility for secure-link state, authentication state, failures, reload results, and identity metadata

Design intent:

- transport code handles sockets and reconnects
- secure-link handles trust, handshake, keying, encryption, integrity, replay, and rekey behavior as a separate security layer
- `ChannelMux` only sees plaintext after the secure-link layer has accepted the peer and decrypted the frame
- PSK mode and certificate mode are two trust/input models for the same security boundary, not separate transport features

## Admin Authentication

WebAdmin uses challenge-response authentication when `admin_web_username` and `admin_web_password` are configured and auth is not disabled.

The login flow is:

1. the browser requests a one-time challenge
2. the server returns a `challenge_id` and seed
3. the browser computes `sha256(seed:username:password)`
4. the browser sends only the proof
5. the server verifies the proof
6. the server issues an HttpOnly, SameSite session cookie

Security properties:

- the plaintext admin password is not submitted during login
- challenges are short-lived and single-use
- API requests require a valid authenticated session unless authentication is intentionally disabled
- the live WebSocket admin feed is protected by the same authenticated session check
- logout clears the server-side session token

Limit:

- on plain HTTP, a network attacker can still observe or tamper with session traffic and delivered JavaScript. The challenge-response protocol reduces password exposure, but HTTPS or a trusted local path is still the stronger deployment boundary.

## Guarded Configuration Writes

Saving configuration through WebAdmin requires a second password confirmation when admin authentication is enabled.

The confirmation is bound to the exact update block:

1. the browser prepares the pending config updates
2. the server issues a challenge for the canonical digest of those exact updates
3. the operator re-enters the current admin password
4. the browser computes `sha256(seed:username:password:updates_digest)`
5. the browser sends the update block, challenge id, and proof
6. the server recomputes the update digest and accepts only if the proof matches

Security properties:

- a proof for one config update cannot be reused for a different config update
- a man-in-the-middle cannot silently alter the saved update block without invalidating the proof
- sensitive changes such as `admin_web_password`, `secure_link_psk`, and auth settings reset admin auth state after save
- unknown and read-only config keys are rejected
- type checks are applied before updating runtime config

Limit:

- this protects the config-write protocol itself. It does not protect a browser that has already loaded attacker-modified JavaScript over an untrusted HTTP path.

## Secret Redaction

Normal admin config snapshots intentionally do not return secret values.

Current secret config keys include:

- `admin_web_password`
- `secure_link_psk`

Behavior:

- `/api/config` returns masked or empty values for secret fields
- the config editor treats secret fields as write-only by default
- secret values can be replaced by entering a new value
- leaving a secret editor blank preserves the existing secret
- logs and API response summaries avoid printing plaintext secret values

Design intent:

- a read-only config view should not become a secret exfiltration API
- normal operator edits should not require exposing the current secret
- secret display should require a deliberate extra action and fresh password proof

## Config Secret Persistence

When runtime configuration is saved to disk through the config-aware persistence path, configured secret fields are encrypted before writing.

This is an important protection for saved admin passwords and secure-link PSKs. The runtime should be able to restart from its saved config without leaving those secrets as plaintext JSON values on disk.

Current behavior:

- secret fields are encrypted with an `enc:v1:` prefix
- encryption uses `ChaCha20Poly1305`
- the encryption key is derived locally with HKDF from machine-related seed material
- the seed source prefers `/etc/machine-id`, then `/var/lib/dbus/machine-id`, then the local hostname fallback
- the HKDF derivation uses project-specific salt and info values so the derived key is scoped to ObstacleBridge config-secret encryption
- encrypted config secrets are decrypted when a config file is loaded

Security properties:

- saved JSON config files do not need to contain plaintext `admin_web_password` or `secure_link_psk`
- a copied config file is less useful on another machine because the decryption key is derived from machine-related local seed material
- the same plaintext secret saved twice does not produce the same encrypted value because each encryption uses a fresh nonce
- operators can keep durable config files while reducing accidental disclosure through backups, support bundles, screenshots, or copied sample configs

Limits:

- this is local-at-rest obfuscation/protection, not a full secrets-management system
- an attacker with code execution as the same runtime user on the same host may still be able to load or use the decrypted runtime values because the machine-related seed is available to that host
- moving an encrypted config file to a different host may require re-entering or regenerating secrets if the original machine-related seed is not available
- operators should still protect config files, service users, backups, and host access

## Controlled Secret Reveal

WebAdmin supports a controlled reveal flow for `secure_link_psk`.

This feature exists because operators sometimes need to inspect or copy the current PSK, but the normal config API must remain redacted.

The reveal flow is deliberately separate from normal config loading:

1. the operator clicks the eye button next to `secure_link_psk`
2. WebAdmin opens a popup and asks for the current admin password again
3. the browser requests a short-lived reveal challenge
4. the browser sends `sha256(seed:username:password:secure_link_psk)` as a one-time proof
5. the server verifies the proof
6. the server returns only an encrypted envelope, not plaintext PSK
7. the envelope is encrypted with AES-GCM using a PBKDF2-HMAC-SHA256 key derived from the configured admin password
8. the browser decrypts the PSK locally with Web Crypto

Remote HTTP origins are not secure browser contexts in Firefox, Safari/iOS, and other modern browsers, so they do not expose Web Crypto for the local PSK decrypt step. Operators who need remote secret reveal should prefer exposing the admin endpoint through the own-server/server-role overlay path, or open WebAdmin through HTTPS, localhost, a VPN/TUN route, or an SSH tunnel to localhost; the server does not downgrade this flow to return plaintext PSKs over HTTP.
9. the PSK is displayed inside the popup only
10. closing the popup clears the displayed value

Security properties:

- an authenticated WebAdmin session alone is not enough to reveal the PSK
- the operator must re-enter the admin password at the moment of reveal
- the admin password is not sent to the server
- the PSK is not sent over the API as plaintext
- the decrypted value is not placed into the config row or kept in the config editor after the popup closes

Limits:

- this protection assumes the browser is running the intended WebAdmin JavaScript
- over plain HTTP on an untrusted network, an active attacker may alter the page script before it performs local decryption
- for remote or hostile-network administration, use HTTPS, a trusted reverse proxy, SSH port forwarding, VPN access, or localhost-only binding

## API Access Boundary

Admin API routes are guarded by session authentication when auth is enabled.

Protected surfaces include:

- status and peer state
- connection tables
- debug logs
- config reads and writes
- restart and shutdown actions
- reconnect actions
- secure-link rekey and reload actions
- onboarding and invite generation APIs
- live WebSocket updates

Security properties:

- unauthenticated API requests receive an authentication error
- WebSocket upgrade requests are rejected unless the session is authenticated
- sensitive operator actions are handled as explicit POST-style API operations

Limit:

- if `admin_web_auth_disable` is enabled, the admin listener must be treated as fully trusted and should be bound only where exposure is intentional.

## Operational Exposure Controls

ObstacleBridge supports several admin exposure patterns because bootstrap and remote VPS setup sometimes need flexibility.

Security-relevant controls include:

- `admin_web_bind` for choosing loopback, LAN, or wider bind behavior
- `admin_web_port` for listener placement
- `admin_web_username` and `admin_web_password` for challenge-response auth
- `admin_web_auth_disable` for explicitly disabling auth
- startup notices that identify useful WebAdmin entrypoints

Recommended posture:

- prefer `127.0.0.1` binding for local administration
- use SSH forwarding, VPN, or a trusted reverse proxy for remote administration
- use HTTPS or an equivalent trusted transport path when the admin surface crosses an untrusted network
- do not disable admin auth on any listener reachable by untrusted clients
- rotate `admin_web_password` and `secure_link_psk` after suspected exposure

## Dependency Boundary

ObstacleBridge uses proven libraries for cryptographic primitives rather than inventing primitives locally.

Current crypto dependency policy:

- use `cryptography` for AEAD, KDF, asymmetric key, and certificate-mode primitives
- use Python stdlib hashing and HMAC for protocol glue where appropriate
- avoid adding a second crypto framework for the same purpose without an explicit design decision

Project-owned responsibility:

- choose the right primitive for each protocol job
- pass the correct inputs, salts, nonces, AAD, and policy data
- fail closed when crypto support is unavailable for a required feature
- maintain tests for security-relevant payload behavior

External dependency responsibility:

- implement the primitive-level crypto operations correctly
- provide platform support for the required algorithms

## Known Limits And Non-Goals

Current security measures are not meant to solve every surrounding risk.

Known limits:

- plain HTTP admin access is not protected against JavaScript tampering by an active network attacker
- local host compromise can expose runtime secrets
- config encryption is not a replacement for host access control or a dedicated secrets manager
- PSK mode depends on safe manual secret distribution
- certificate mode depends on safe generation, signing, distribution, and protection of key material
- WebAdmin cannot prove that the operator is viewing an untampered page unless the delivery path is trusted

Non-goals:

- replacing operating-system hardening
- replacing TLS for remote browser administration
- becoming a full certificate authority or secrets-management product
- inventing custom cryptographic primitives
- guaranteeing security when the admin listener is intentionally exposed without authentication

## Threat Scenarios

This section describes common threat scenarios and how the current design responds.

### Network Man-In-The-Middle Against Overlay Traffic

Scenario:

- an attacker can observe, inject, replay, delay, or modify packets between two ObstacleBridge peers
- the attacker may be on the same LAN, in the routed network path, or controlling an intermediate proxy

Mitigations:

- secure-link protects overlay payloads above the transport layer
- PSK mode authenticates peers that share the configured secret
- certificate mode authenticates peers using admin-root-signed identity material
- authenticated encryption detects modified ciphertext
- replay protection rejects reused protected frames
- key derivation avoids using long-term PSK or identity material directly as data-encryption keys
- rekey behavior limits long-lived session-key exposure

Residual risk:

- if secure-link is disabled, overlay traffic relies only on the selected underlying transport and deployment environment
- PSK mode depends on safe distribution and sufficient entropy of the shared secret
- certificate mode depends on safe private-key handling and correct trust-anchor provisioning

### Network Man-In-The-Middle Against WebAdmin

Scenario:

- an attacker can observe or alter traffic between the browser and WebAdmin
- the admin page is loaded over plain HTTP across an untrusted network

Mitigations:

- login uses challenge-response, so the plaintext admin password is not submitted during login
- config writes require a fresh challenge bound to the exact update block
- `secure_link_psk` reveal requires fresh password proof and returns only an encrypted envelope
- normal config snapshots redact secret fields

Residual risk:

- an active attacker can alter JavaScript delivered over plain HTTP before it runs in the browser
- session cookies and API traffic are only as protected as the transport path
- HTTPS, SSH port forwarding, VPN access, a trusted reverse proxy, or localhost-only binding is required for strong remote-administration protection

### Config File Theft Or Backup Exposure

Scenario:

- an attacker obtains a saved JSON config file from disk, a backup, a support bundle, or a copied deployment directory

Mitigations:

- configured secret fields such as `admin_web_password` and `secure_link_psk` are encrypted before config persistence writes them
- encrypted values are marked with the `enc:v1:` prefix
- the encryption key is derived from machine-related seed material through project-scoped HKDF
- each encryption uses a fresh nonce, so repeated saves of the same secret do not produce identical ciphertext

Residual risk:

- non-secret configuration values may still reveal deployment topology, ports, peer addresses, service mappings, or operational intent
- if the attacker also has access to the original host's machine-related seed material and runtime code path, they may be able to decrypt the saved secret values
- file permissions, backup policy, and support-bundle review still matter

### Local Host Or Runtime User Compromise

Scenario:

- an attacker gains shell access as the same user running ObstacleBridge, or gains equivalent local code execution

Mitigations:

- config secrets are not casually visible as plaintext in saved config files
- WebAdmin read APIs still redact secrets
- sensitive WebAdmin actions require authenticated session state and, for config writes or PSK reveal, fresh password proof

Residual risk:

- the runtime must eventually hold decrypted secrets in memory to authenticate peers, run WebAdmin auth, or save updated config
- a same-user attacker can often inspect process memory, alter files, call local APIs, or run the application code that decrypts local config secrets
- host hardening, service-user isolation, filesystem permissions, process isolation, and operating-system security controls are outside the project but essential

### Authenticated Session Misuse

Scenario:

- an attacker obtains or abuses an already-authenticated WebAdmin browser session
- the operator leaves an unlocked browser open

Mitigations:

- session cookies are HttpOnly and SameSite
- logout removes server-side session state
- config writes require the admin password again
- `secure_link_psk` reveal requires the admin password again
- an authenticated session alone cannot reveal `secure_link_psk`

Residual risk:

- an active authenticated session can still read non-secret status, peer, log, and config metadata
- an active authenticated session can trigger admin operations that do not require second-factor password confirmation
- operators should log out on shared machines and avoid exposing WebAdmin in browsers they do not trust

### Attack Over The Admin API

Scenario:

- an attacker calls WebAdmin API endpoints directly instead of using the browser UI
- the attacker tries unauthenticated API reads, restart/shutdown actions, config writes, reconnect actions, secure-link reload/rekey actions, onboarding APIs, or secret reveal endpoints
- the attacker attempts to replay an old proof, reuse a challenge, tamper with a config update after the operator approved it, or scrape secrets from read endpoints

Mitigations:

- API routes require an authenticated session when admin auth is enabled
- unauthenticated API requests receive an authentication error
- live WebSocket upgrade requests require the same authenticated session
- config writes require a fresh password proof bound to the exact canonical update payload
- config-change challenges are short-lived and consumed once
- `secure_link_psk` reveal uses a separate short-lived challenge and fresh password proof
- normal `/api/config` snapshots redact secret fields
- secret reveal returns only an encrypted envelope, not plaintext PSK
- unknown config keys, read-only keys, and type-invalid updates are rejected
- sensitive changes reset admin auth state where appropriate

Residual risk:

- if `admin_web_auth_disable` is enabled, the API must be treated as fully trusted and protected by bind address, firewall, tunnel, or reverse-proxy controls
- an attacker with a valid session can still call authenticated APIs directly
- APIs that intentionally perform operator actions can still cause disruption if exposed to an authenticated but malicious actor
- rate limiting, IP allowlisting, and external WAF-style controls are not currently project-owned protections
- HTTPS or an equivalent trusted transport path is needed to protect API traffic over untrusted networks

### Weak Or Reused Secrets

Scenario:

- the configured admin password or secure-link PSK is short, guessable, reused, or shared through unsafe channels

Mitigations:

- WebAdmin challenge-response avoids transmitting the password as plaintext during login
- secure-link PSK mode uses derived session keys rather than the PSK directly as the traffic key
- WebAdmin security advisor and operator guidance can flag weak secure-link PSK choices

Residual risk:

- low-entropy secrets remain vulnerable to guessing or offline attack if enough protocol material or local encrypted config material is exposed
- reused passwords increase blast radius across unrelated systems
- operators should use high-entropy unique secrets and rotate them after suspected exposure

### Malicious Or Misconfigured Peer

Scenario:

- a peer uses wrong secure-link material
- a peer has a revoked or unauthorized certificate
- a peer attempts to connect with a role or deployment identity it should not have

Mitigations:

- secure-link rejects failed PSK authentication
- certificate mode enforces issuer, deployment, role, identity, validity, and revocation policy
- peer-scoped WebAdmin diagnostics expose secure-link failure state and reason where available
- reload APIs allow trust and revocation updates to apply without a full restart in supported cases

Residual risk:

- policy inputs must be correct and current
- operators must protect trust anchors and private keys
- revocation only helps after the revocation input reaches the runtime and is reloaded

### Malformed Frames And Parser Abuse

Scenario:

- an attacker sends malformed overlay frames, truncated secure-link records, invalid handshake messages, unexpected frame types, oversized fields, corrupted ciphertext, bad authentication tags, invalid mux payloads, or protocol messages in the wrong state
- the attacker tries to crash the process, desynchronize state machines, bypass authentication, consume excessive resources, or cause plaintext processing before secure-link acceptance

Mitigations:

- secure-link validates handshake and protected-frame structure before accepting data
- authenticated encryption rejects corrupted ciphertext and invalid tags
- replay and session checks reject frames outside the expected protected-session context
- malformed secure-link frames fail closed rather than being passed upward to `ChannelMux`
- `ChannelMux` and transport/session layers keep decode counters and peer-scoped diagnostics where available
- peer-scoped WebAdmin diagnostics expose secure-link failure state, decode/unidentified-frame counters, and connection failure details where the runtime can report them
- tests cover malformed secure-link PSK frame handling and rejection behavior

Residual risk:

- parser and state-machine code remains security-sensitive and requires focused regression tests for new frame types
- malformed traffic can still consume CPU, logs, counters, sockets, or connection slots before it is rejected
- external rate limiting, firewall policy, and process supervision are still useful for hostile-network deployments

## Security Test Coverage

The repository contains focused tests for several security-relevant behaviors, including:

- secure-link PSK handshake success, rejection, replay, malformed frame, and rekey behavior
- secure-link certificate identity, trust, revocation, reload, and rejection behavior
- WebAdmin config snapshots masking secrets
- WebAdmin guarded config saves being bound to the exact update payload
- WebAdmin invite and onboarding payload masking
- WebAdmin controlled `secure_link_psk` reveal returning an encrypted envelope rather than plaintext

Design rule:

- security changes should include a focused regression test whenever the behavior is observable through API payloads, config persistence, peer state, or WebAdmin flows
