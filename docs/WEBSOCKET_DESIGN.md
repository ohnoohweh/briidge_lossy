# WebSocket Design

## Purpose

This document records the current WebSocket transport design considerations that matter for runtime behavior, regression strategy, and future changes.

It focuses on the delivered runtime, especially the listener-side path where one public socket may need to serve both:

- ordinary HTTP requests for the static root page
- WebSocket upgrade requests for overlay peers

## Scope

This is a transport design note for the current runtime, not a speculative rewrite plan.

It covers:

- WebSocket listener/client responsibilities
- plain HTTP plus WebSocket coexistence on the WS listener port
- peer-isolation expectations around auxiliary listener activity
- known library constraints that shaped the current implementation
- regression expectations for future changes

It does not redefine:

- secure-link behavior already owned by [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md)
- mux/channel semantics already owned by [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
- product requirements already owned by [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)

## Current boundary

The WebSocket transport lives in the transport/session layer.

Listener-side responsibilities:

- accept TCP connections on the configured WS listener port
- distinguish plain HTTP requests from WebSocket upgrade requests
- serve the static HTTP root without disturbing overlay peers
- upgrade the accepted socket to a WebSocket session when the request is a valid upgrade
- keep listener-local request handling scoped to the originating socket so unrelated peer sessions remain unaffected

Peer-client responsibilities:

- establish the outbound WebSocket connection
- honor proxy/bootstrap behavior defined by the WebSocket client path
- on the direct client path, perform a separate `GET /` HTTP preflight on a separate TCP connection before the later WebSocket upgrade attempt
- require `200 OK` for that preflight, consume the full HTTP response body before continuing, and refuse the later WebSocket upgrade attempt when the preflight does not return `200`
- skip that HTTP preflight when the client is using an explicit proxy-tunneled socket path
- expose a byte/frame path upward to the secure-link and mux layers without leaking transport-specific policy upward

## Why the listener uses a front-end split

The original listener path used the WebSocket library's handshake interception hook to return non-upgrade HTTP responses from the same server object.

That model was insufficient for one specific requirement: ordinary browser-style keep-alive on plain HTTP requests before any later upgrade attempt on the same TCP connection.

The practical limitation is that the current `websockets` server path aborts the transport after non-`101` responses returned during the handshake interception flow. That means repeated plain HTTP requests on one socket cannot remain alive long enough to satisfy browser-style behavior.

The current listener therefore uses a small front-end split:

1. accept the socket directly
2. parse the initial HTTP request
3. if the request is ordinary HTTP, serve it directly with normal HTTP response rules and keep-alive decisions
4. if the request is a valid WebSocket upgrade, promote that same socket into the server-side WebSocket connection wrapper used by the existing session logic

This keeps the requirement centered on socket ownership and request scoping rather than on a specific library callback.

## Design considerations

### 1. Peer isolation comes first

Auxiliary HTTP activity on the WS listener is endpoint-local noise, not peer state. It must not:

- unregister healthy peers
- disturb authenticated secure-link state for another peer
- mutate mux routing for another peer
- starve healthy overlay traffic on a different transport in the same process

This is the main reason the static HTTP regressions are tied to `REQ-LST-007` and, for mixed listeners, `REQ-MUX-005`.

### 2. Plain HTTP and WebSocket upgrade share one socket, not one behavior

It is valid for the same public listener port to serve both plain HTTP and WebSocket upgrades.

It is not valid to assume both paths can share the exact same connection lifecycle rules. Plain HTTP requests may legitimately use keep-alive and remain un-upgraded across multiple requests. WebSocket upgrade requests must transition the socket into a long-lived framed session. The implementation needs an explicit branch between those lifecycles.

### 3. Library convenience is secondary to externally visible behavior

The listener originally used the WebSocket library's convenience hook for serving plain HTTP from the listener port. That reduced custom code but did not preserve the required same-connection keep-alive behavior.

The delivered implementation favors the externally observable contract over minimizing transport-specific code.

### 4. The server and client paths do not need symmetric implementations

The current runtime keeps the peer client on a mostly normal `websockets.connect(...)` path while the listener uses the custom front-end split.

The main extra client-side bootstrap step today is a direct-path `GET /` preflight before the later upgrade attempt. That preflight is used only on the non-proxied path, and it now forms part of the supported contract: the client downloads the full default-root HTTP body before continuing, and it does not attempt the later WebSocket upgrade when the preflight status is not `200 OK`.

That asymmetry is acceptable because the two sides have different responsibilities:

- the client needs outbound bootstrap and proxy support
- the listener needs local HTTP demultiplexing and same-socket keep-alive behavior

Symmetry would only be valuable if it improved maintainability without weakening the delivered listener behavior.

### 5. The bootstrap path must stay explainable under DEBUG logs

The direct peer-client preflight is intentionally observable when WebSocket logging is raised to `DEBUG`.

The client side should make it obvious:

- when the direct-path HTTP preflight starts
- which status/body length came back from `GET /`
- whether the later upgrade was refused because the preflight failed
- when proxy tunneling skipped the preflight entirely

The listener side should make it obvious:

- when a plain HTTP request was served instead of an upgrade
- which status/target/body length was returned
- when a real WebSocket upgrade request was actually attempted

### 6. Keep the WebSocket-specific code narrow

The front-end split should stay limited to concerns that are inherently WebSocket-listener specific:

- request parsing needed to distinguish HTTP from upgrade traffic
- static root response generation
- upgrade handshake validation and response
- minimal frame send/receive support needed to hand control back to the existing overlay session logic

It should not absorb mux policy, secure-link policy, or admin rendering concerns.

## Regression expectations

Future changes to the WebSocket listener path should preserve these externally visible behaviors:

- repeated plain HTTP reads from the WS listener still return the static root page
- two plain HTTP requests on the same TCP connection succeed before any later upgrade attempt
- the above remains true when a secure-link-authenticated `myudp` peer is active on the same mixed listener process
- healthy WebSocket overlay traffic still works after the plain HTTP requests
- a WS peer client can advertise its configured payload transfer form during upgrade and a listener with a different local default still adopts the correct per-peer codec automatically
- accepted WebSocket listener peers report live peer-local RTT in `/api/peers`, while the passive listener row remains zeroed with `rtt=n/a`
- on the direct non-proxied client path, `GET /` is completed before the later upgrade attempt
- when that direct-path preflight does not return `200 OK`, the client stays disconnected and does not attempt the later upgrade
- when client bootstrap or websocket-open fails, `/api/status` reports `peer_state=FAILED` with transport-level reason/detail until a later successful connect clears it

The current regression anchor is [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py), especially the `test_overlay_e2e_ws_static_http_root_*` family.

For the peer-client bootstrap path, the main regression anchors now live in both [tests/unit/test_ws_payload_mode.py](/home/ohnoohweh/quic_br/tests/unit/test_ws_payload_mode.py) and [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py), where payload-mode advertisement/adoption, the HTTP preflight body download, direct-path refusal-on-non-`200`, proxy failure handling, DNS failure classification, and user-visible failed-connection reporting are exercised as supported transport bootstrap behavior.

## Tradeoffs and future options

Current tradeoff:

- more listener-local code is owned in-project
- behavior is explicit and testable at the socket boundary

Future options if the current listener needs to evolve:

- factor shared HTTP/WebSocket parsing helpers if another runtime surface needs the same split
- replace the minimal wrapper with a more formal Sans-I/O integration if that reduces maintenance cost without regressing behavior
- keep the current design if future library versions still cannot provide the required same-socket plain HTTP behavior safely

The acceptance bar for any future rewrite should remain black-box: if the same-connection HTTP regressions or peer-isolation regressions weaken, the rewrite is not good enough regardless of internal elegance.