# System Boundary

This document separates three things that are easy to mix together:

1. user use-cases
2. external assumptions and dependencies
3. project-owned behavior

Only the third category belongs in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md) as a normative project requirement.

## How to read the boundary

- User use-case:
  - what the operator wants to achieve in the real world
- External assumption:
  - a condition that must already be true in the surrounding environment
- Project responsibility:
  - behavior ObstacleBridge itself is expected to provide
- Out of scope:
  - something the project may rely on, but does not itself guarantee

## General external assumptions

These assumptions apply broadly across the project and should not be mistaken for project requirements:

- the operating systems on the participating hosts allow local socket creation and loopback networking
- Python and the required runtime dependencies are installed and runnable on the participating hosts
- the selected overlay transport is allowed by the surrounding network path often enough for connection attempts to be meaningful
- name resolution, local routing, and firewall policy are configured well enough for the chosen deployment mode
- the browser used for the admin UI supports the required HTTP and WebSocket behavior
- third-party libraries such as `websockets` and `aioquic` provide the protocol mechanisms the project builds on

## Use-case boundary mapping

### NAS behind outbound-only internet

| Layer | Description |
|---|---|
| User use-case | Reach services on a NAS or home server that cannot accept inbound internet connections directly |
| External assumptions | A public VPS or other reachable listener host exists; the NAS can make outbound connections; the chosen service ports are allowed by local firewalls |
| Project responsibility | Establish the overlay between NAS and VPS, keep it observable in the admin UI, and forward the configured TCP or UDP services through the overlay |
| Out of scope | Public DNS correctness, VPS uptime, ISP routing quality, and the remote client software that consumes the exposed service |

### WireGuard bridge through inspected internet access

| Layer | Description |
|---|---|
| User use-case | Carry a local UDP VPN endpoint across an environment where direct VPN traffic is blocked or degraded |
| External assumptions | The inspected network still allows the selected fallback transport such as WebSocket; both sides can run ObstacleBridge; the local WireGuard or OpenVPN endpoint exists |
| Project responsibility | Recreate the configured UDP listener through the overlay and carry traffic between the two peers over the selected overlay transport |
| Out of scope | Whether the surrounding network will always permit WebSocket or HTTPS-shaped traffic, and the correctness of the VPN configuration itself |

### High-loss obstacle path

| Layer | Description |
|---|---|
| User use-case | Keep UDP-style service traffic usable on a path with heavy loss or retransmission pressure |
| External assumptions | The path still passes enough UDP for the `myudp` transport to operate; both peers have compatible local runtime environments |
| Project responsibility | Provide retransmission, liveness, multiplexing, and recovery behavior through the `myudp` overlay so the configured service remains usable |
| Out of scope | The baseline packet loss characteristics of the network and absolute throughput guarantees under hostile conditions |

### WebSocket proxy traversal

| Layer | Description |
|---|---|
| User use-case | Connect a WebSocket peer client through a corporate or environment-mandated HTTP proxy |
| External assumptions | The proxy is reachable; the OS or environment proxy settings are configured correctly; the `websockets` library can perform the WebSocket protocol once a direct or proxied socket path exists |
| Project responsibility | Determine the effective proxy policy, honor platform-default proxy discovery or explicit overrides, establish HTTP `CONNECT` before the WebSocket handshake, and surface failures without corrupting the overlay state machine |
| Out of scope | Proxy server availability, correctness of external proxy configuration, and behavior of transports other than the WebSocket client path unless explicitly documented |

## Relationship to the other project documents

- [README.md](/home/ohnoohweh/quic_br/README.md):
  - user-facing use-cases and assumptions
- [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md):
  - project-owned black-box requirements only
- [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md):
  - component and responsibility decomposition inside the project
- [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md):
  - test evidence mapped to those project-owned requirements
