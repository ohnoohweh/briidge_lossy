# WebAdmin Design

## Purpose

This document records the current WebAdmin design as it is actually implemented in the runtime.

It focuses on the delivered admin surface and the concepts that shape it:

- challenge-response login
- session-cookie handling
- protected API routing
- live status updates over WebSocket
- peer-scoped secure-link visibility
- secret redaction in config snapshots
- operator actions such as restart, shutdown, rekey, and reload

## Scope

This is a runtime design note, not a product-requirements document.

It covers:

- how the admin page authenticates
- how login sessions are established and maintained
- how the UI talks to the admin API
- how the live update channel is protected
- how config and status payloads treat secret values
- which admin responsibilities belong to the WebAdmin layer versus the transport or secure-link layers

It does not redefine:

- product requirements already owned by [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- transport/session behavior already owned by [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
- secure-link handshake and trust behavior already owned by [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md)
- WebSocket transport splitting already owned by [WEBSOCKET_DESIGN.md](/home/ohnoohweh/quic_br/docs/WEBSOCKET_DESIGN.md)

## Current boundary

WebAdmin is the HTTP/UI layer responsible for exposing runtime state and letting an operator change supported settings.

It currently owns:

- the HTML/CSS/JavaScript admin page in `admin_web/`
- the HTTP API served from the admin listener
- the challenge-response auth flow
- the session cookie issued after successful login
- the live admin WebSocket feed used for status updates
- rendering of config, peers, connections, logs, restart, and secure-link controls

It does not own:

- transport socket lifecycle for overlay peers
- secure-link handshake state machines
- channel mux routing policy
- websocket listener/client bootstrap behavior outside the admin UI itself

## Authentication model

The current admin login model is a browser-side challenge-response flow.

The basic sequence is:

1. the browser requests `/api/auth/challenge`
2. the server returns a one-time `challenge_id` and `seed`
3. the browser computes `sha256(seed:username:password)` client-side
4. the browser submits the proof to `/api/auth/login`
5. the server compares the proof against the configured username/password pair
6. the server issues an HttpOnly, SameSite cookie that marks the admin session authenticated

Important properties of the current implementation:

- the plaintext password is not sent to the server during login
- the password is not returned by read-only config snapshots
- the session cookie is scoped to the admin web endpoint and is not intended for cross-site use
- auth state is checked on every API request by reading the session cookie

### HTTP and HTTPS behavior

The login flow is intentionally usable over plain HTTP as well as HTTPS.

When the browser is not in a secure context and Web Crypto is unavailable, the admin page uses a JavaScript SHA-256 implementation so the challenge-response login still works.

This keeps the authentication protocol usable on HTTP-only deployments and through proxy paths that do not preserve secure-context browser APIs.

Security note:

- the login protocol avoids sending the plaintext password
- the admin session cookie still travels over the transport path in use
- HTTPS is still preferred when the deployment path can support it, especially on untrusted networks
- HTTP login is acceptable only when the operator understands the transport trust boundary

## Session and state handling

After login, the browser stores the session only as a cookie-managed authenticated state.

The UI refreshes auth state by calling `/api/auth/state` and uses that to decide whether to keep the gate open.

When authentication expires or the session cookie disappears:

- the UI returns to the locked state
- the login prompt is shown again
- live updates are paused or retried as needed

The session model is deliberately simple so it remains easy to reason about under proxying and page reloads.

## Live updates

The live admin feed is a WebSocket session used to stream runtime snapshots and events.

Its purpose is to avoid polling for every UI refresh while still keeping the admin page thin:

- the browser opens `/api/live` as a WebSocket upgrade
- authenticated access is required when admin auth is enabled
- the server streams runtime payloads such as status, connections, peers, and metadata
- if the socket closes, the UI falls back to polling and tries to reconnect

The live feed is not a control channel for transport data. It is only an observability channel.

## Config and secret handling

WebAdmin is responsible for operator-visible configuration editing.

Current secret-handling rules:

- `admin_web_password` and `secure_link_psk` are writeable through the config update path
- those keys are masked on readback snapshots
- password inputs in the UI are rendered as password-style fields
- existing secret values are intentionally left blank when the UI loads a config snapshot

This keeps the UI useful for editing without exposing stored secrets back to the browser.

## Operator actions

WebAdmin exposes a small set of direct process actions:

- restart
- shutdown
- secure-link rekey
- secure-link reload

Those actions are HTTP API operations, not UI-only behavior.

Their design intent is that the operator can change runtime state without editing config files by hand or restarting the process unless the action explicitly requires it.

## Design considerations

### 1. WebAdmin is a presentation and control surface, not a transport owner

It should expose state and request changes, but it should not own peer transport state or secure-link cryptographic state.

### 2. The auth boundary must be explicit

The challenge-response flow is intentionally separate from the rest of the UI so the browser can prove knowledge of the configured secret without sending it in cleartext.

### 3. Live updates must remain optional and resilient

If the WebSocket feed fails, the admin page should degrade gracefully rather than taking down the whole UI.

### 4. Secret data must stay masked by default

Snapshots should help an operator reason about state without turning the admin UI into a secret exfiltration path.

### 5. Admin behavior should be explainable under logs

The runtime logs should make it obvious when auth challenges are issued, when login succeeds or fails, when sessions are invalidated, and when operator actions are accepted or rejected.

## Regression expectations

Future changes to WebAdmin should preserve these externally visible behaviors:

- auth-required deployments still expose a challenge-response login flow
- the admin page remains usable over HTTP and HTTPS
- the browser does not receive the plaintext admin password from the login flow
- `/api/config` still masks write-only secret values on read
- `/api/live` remains available only to authenticated clients when auth is enabled
- live updates continue to fall back or reconnect cleanly when the socket drops
- secure-link and peer state remain peer-scoped in `/api/peers` and the WebAdmin page

The current regression anchors live in [tests/unit/test_admin_web_payloads.py](/home/ohnoohweh/quic_br/tests/unit/test_admin_web_payloads.py) and the admin-web integration cases in [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py).

## Tradeoffs and future options

Current tradeoff:

- the login flow is intentionally lightweight and browser-side
- that keeps the admin surface easy to use, but it also means the transport path still matters for overall confidentiality

Future options if the admin surface needs stronger hardening:

- add transport-level HTTPS guidance or enforcement for deployments that require it
- bind login-session policy more tightly to deployment mode
- split additional admin privileges into separate controls if the single-session model becomes too coarse

The acceptance bar for any future rewrite should remain black-box: the admin page still needs to be usable, secure-link visibility still needs to stay peer-scoped, and secret values still need to remain masked in read-only snapshots.